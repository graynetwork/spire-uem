package db

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

func TestSealOpenSecretRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048) // smaller key keeps the test fast; scheme is identical
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	secret := "wifi-psk-$uper-Secret-2026"
	env, err := SealSecret(&priv.PublicKey, secret)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if !env.IsSealed() {
		t.Fatal("expected sealed envelope")
	}
	if env.Plaintext != "" {
		t.Fatal("sealed envelope must NOT carry plaintext")
	}
	// Ciphertext must not contain the plaintext.
	if env.Ciphertext == "" || env.EncryptedDEK == "" || env.Nonce == "" {
		t.Fatal("sealed envelope missing fields")
	}

	got, err := OpenSecret(priv, env)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got != secret {
		t.Fatalf("round trip mismatch: got %q want %q", got, secret)
	}
}

func TestSealEmptyIsNoOp(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	env, err := SealSecret(&priv.PublicKey, "")
	if err != nil {
		t.Fatalf("seal empty: %v", err)
	}
	if env.IsSealed() || env.HasValue() {
		t.Fatal("empty secret must yield an empty envelope")
	}
}

func TestOpenUnsealedReturnsPlaintext(t *testing.T) {
	env := types.SecretEnvelope{Plaintext: "already-plain"}
	got, err := OpenSecret(nil, env)
	if err != nil {
		t.Fatalf("open unsealed: %v", err)
	}
	if got != "already-plain" {
		t.Fatalf("expected passthrough plaintext, got %q", got)
	}
}

func TestSealOpenEAPTLSPrivateKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	pemKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y3...\n-----END RSA PRIVATE KEY-----"
	env, err := SealSecret(&priv.PublicKey, pemKey)
	if err != nil {
		t.Fatalf("seal eap-tls key: %v", err)
	}
	if !env.IsSealed() {
		t.Fatal("expected sealed envelope for client private key")
	}
	if env.Plaintext != "" {
		t.Fatal("sealed envelope must not carry plaintext")
	}

	unsealed, err := OpenSecret(priv, env)
	if err != nil {
		t.Fatalf("unseal eap-tls key: %v", err)
	}
	if unsealed != pemKey {
		t.Fatalf("unsealed key mismatch: got %q, want %q", unsealed, pemKey)
	}
}

func TestSecretEnvelopeUnmarshalJSONCompatibility(t *testing.T) {
	// Raw string format (legacy or manual API json)
	rawStringJSON := []byte(`"super-secret-key"`)
	var env1 types.SecretEnvelope
	if err := env1.UnmarshalJSON(rawStringJSON); err != nil {
		t.Fatalf("unmarshal raw string: %v", err)
	}
	if env1.Plaintext != "super-secret-key" {
		t.Fatalf("expected Plaintext to be set, got %q", env1.Plaintext)
	}

	// Object format (sealed envelope)
	objJSON := []byte(`{"ciphertext":"Y2lwaGVy","encrypted_dek":"ZGVr","nonce":"bm9uY2U="}`)
	var env2 types.SecretEnvelope
	if err := env2.UnmarshalJSON(objJSON); err != nil {
		t.Fatalf("unmarshal object: %v", err)
	}
	if env2.Ciphertext != "Y2lwaGVy" || env2.EncryptedDEK != "ZGVr" || env2.Nonce != "bm9uY2U=" {
		t.Fatalf("expected fields to match, got %+v", env2)
	}
	if !env2.IsSealed() {
		t.Fatal("expected envelope to be recognized as sealed")
	}
}

func TestSecretEnvelopeZeroize(t *testing.T) {
	env := types.SecretEnvelope{Plaintext: "sensitive-private-key"}
	env.Zeroize()
	if env.Plaintext != "" {
		t.Fatalf("expected Plaintext to be cleared, got %q", env.Plaintext)
	}
}
