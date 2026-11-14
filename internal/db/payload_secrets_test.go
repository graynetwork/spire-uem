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
