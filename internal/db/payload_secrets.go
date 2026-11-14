package db

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/spire-uem/spire-uem/internal/types"
)

// SealSecret seals a plaintext secret into a types.SecretEnvelope using the server's RSA-OAEP-4096
// + AES-256-GCM key-envelope scheme (identical to the LUKS recovery-key escrow). The returned
// envelope carries only base64-encoded ciphertext fields and NO plaintext, so it is safe to
// persist inside a policy payload. An empty plaintext yields an empty (unsealed) envelope.
func SealSecret(pub *rsa.PublicKey, plaintext string) (types.SecretEnvelope, error) {
	if plaintext == "" {
		return types.SecretEnvelope{}, nil
	}
	if pub == nil {
		return types.SecretEnvelope{}, errors.New("nil RSA public KEK: cannot seal payload secret")
	}
	encDEK, encSecret, nonce, err := EnvelopeEncryptRecoveryKey(pub, plaintext)
	if err != nil {
		return types.SecretEnvelope{}, fmt.Errorf("seal payload secret: %w", err)
	}
	return types.SecretEnvelope{
		Ciphertext:   base64.StdEncoding.EncodeToString(encSecret),
		EncryptedDEK: base64.StdEncoding.EncodeToString(encDEK),
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
	}, nil
}

// OpenSecret unseals a types.SecretEnvelope previously produced by SealSecret, returning the
// plaintext. An envelope that is not sealed (no ciphertext) returns its transient Plaintext field
// unchanged, so callers can treat "already plaintext" and "sealed" uniformly.
func OpenSecret(priv *rsa.PrivateKey, env types.SecretEnvelope) (string, error) {
	if !env.IsSealed() {
		return env.Plaintext, nil
	}
	if priv == nil {
		return "", errors.New("nil RSA private KEK: cannot open payload secret")
	}
	encSecret, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("decode sealed secret ciphertext: %w", err)
	}
	encDEK, err := base64.StdEncoding.DecodeString(env.EncryptedDEK)
	if err != nil {
		return "", fmt.Errorf("decode sealed secret DEK: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return "", fmt.Errorf("decode sealed secret nonce: %w", err)
	}
	pt, err := EnvelopeDecryptRecoveryKey(priv, encDEK, encSecret, nonce)
	if err != nil {
		return "", fmt.Errorf("open payload secret: %w", err)
	}
	return pt, nil
}
