package db

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
)

// GenerateKEKKeyPair generates a 4096-bit RSA Key Encryption Key (KEK) pair and its PEM-encoded public key.
func GenerateKEKKeyPair() (*rsa.PrivateKey, string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, "", fmt.Errorf("generate RSA-4096 KEK: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("marshal KEK public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})
	return priv, string(pubPEM), nil
}

// ParseRSAPublicKeyPEM parses a PEM-encoded PKIX or PKCS#1 RSA public key.
func ParseRSAPublicKeyPEM(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM block for RSA public key")
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, errors.New("public key is not RSA")
	}
	if rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return rsaPub, nil
	}
	return nil, errors.New("failed to parse RSA public key")
}

// EnvelopeEncryptRecoveryKey encrypts a plaintext LUKS2 recovery key using AES-256-GCM with an ephemeral
// 32-byte DEK, and wraps the DEK using RSA-OAEP-4096 (SHA-256) with the server's public KEK.
func EnvelopeEncryptRecoveryKey(pubKey *rsa.PublicKey, recoveryKey string) (encryptedDEK, encryptedRecoveryKey, nonce []byte, err error) {
	if pubKey == nil {
		return nil, nil, nil, errors.New("nil RSA public KEK")
	}

	dek := make([]byte, 32)
	defer clear(dek)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, nil, nil, fmt.Errorf("generate AES-256 DEK: %w", err)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("init AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("init AES-GCM: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("generate GCM nonce: %w", err)
	}

	pt := []byte(recoveryKey)
	defer clear(pt)
	encryptedRecoveryKey = gcm.Seal(nil, nonce, pt, nil)

	encryptedDEK, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, dek, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("RSA-OAEP-4096 encrypt DEK: %w", err)
	}

	return encryptedDEK, encryptedRecoveryKey, nonce, nil
}

// EnvelopeDecryptRecoveryKey unwraps the DEK using the server's RSA-OAEP-4096 private KEK
// and decrypts the AES-256-GCM LUKS2 recovery key.
func EnvelopeDecryptRecoveryKey(privKey *rsa.PrivateKey, encryptedDEK, encryptedRecoveryKey, nonce []byte) (string, error) {
	if privKey == nil {
		return "", errors.New("nil RSA private KEK")
	}

	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encryptedDEK, nil)
	if err != nil {
		return "", fmt.Errorf("RSA-OAEP-4096 decrypt DEK: %w", err)
	}
	defer clear(dek)

	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", fmt.Errorf("init AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("init AES-GCM: %w", err)
	}

	if len(nonce) != gcm.NonceSize() {
		return "", fmt.Errorf("invalid GCM nonce length: got %d, want %d", len(nonce), gcm.NonceSize())
	}

	plaintext, err := gcm.Open(nil, nonce, encryptedRecoveryKey, nil)
	if err != nil {
		return "", fmt.Errorf("AES-GCM decrypt recovery key: %w", err)
	}
	defer clear(plaintext)
	return strings.Clone(string(plaintext)), nil
}

// EncryptChallengeForEK encrypts a challenge nonce using RSA-OAEP (SHA-256) with the client's TPM Endorsement Key (EK).
func EncryptChallengeForEK(ekPublicPEM string, nonce string) ([]byte, error) {
	ekPub, err := ParseRSAPublicKeyPEM(ekPublicPEM)
	if err != nil {
		return nil, fmt.Errorf("parse client EK public PEM: %w", err)
	}
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, ekPub, []byte(nonce), nil)
	if err != nil {
		return nil, fmt.Errorf("encrypt challenge with EK: %w", err)
	}
	return ciphertext, nil
}

// VerifyQuoteSignature verifies an RSA-PKCS1v15 or RSA-PSS SHA-256 signature over the attestation quote digest.
func VerifyQuoteSignature(pubPEM string, quoteData, signature []byte) error {
	pub, err := ParseRSAPublicKeyPEM(pubPEM)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(quoteData)
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err == nil {
		return nil
	}
	if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], signature, nil); err == nil {
		return nil
	}
	return errors.New("quote signature verification failed")
}
