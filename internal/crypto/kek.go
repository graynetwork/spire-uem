package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// KeyEnvelopeManager defines operations for managing RSA-4096 Key Encryption Keys (KEK).
type KeyEnvelopeManager interface {
	PublicKeyPEM() []byte
	DecryptDEK(ctx context.Context, encryptedDEK []byte) ([]byte, error)
	Fingerprint() string
}

// PersistentRSAKeyEnvelopeManager implements KeyEnvelopeManager backed by a local RSA private key file.
type PersistentRSAKeyEnvelopeManager struct {
	mu          sync.RWMutex
	privKey     *rsa.PrivateKey
	pubKeyPEM   []byte
	fingerprint string
	path        string
}

// NewPersistentRSAKeyEnvelopeManager loads an existing RSA-4096 KEK from path or generates a new one (mode 0600).
func NewPersistentRSAKeyEnvelopeManager(path string) (*PersistentRSAKeyEnvelopeManager, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("KEK path cannot be empty")
	}

	m := &PersistentRSAKeyEnvelopeManager{path: path}

	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("decode PEM from %s: invalid PEM block", path)
		}

		var priv *rsa.PrivateKey
		if key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes); parseErr == nil {
			if rsaKey, ok := key.(*rsa.PrivateKey); ok {
				priv = rsaKey
			}
		}
		if priv == nil {
			var parseErr error
			priv, parseErr = x509.ParsePKCS1PrivateKey(block.Bytes)
			if parseErr != nil {
				return nil, fmt.Errorf("parse RSA private key from %s: %w", path, parseErr)
			}
		}

		if priv.N.BitLen() < 4096 {
			return nil, fmt.Errorf("RSA key size %d bits in %s is less than required 4096 bits", priv.N.BitLen(), path)
		}

		m.privKey = priv
	} else if os.IsNotExist(err) {
		priv, genErr := rsa.GenerateKey(rand.Reader, 4096)
		if genErr != nil {
			return nil, fmt.Errorf("generate RSA-4096 key: %w", genErr)
		}

		dir := filepath.Dir(path)
		if mkErr := os.MkdirAll(dir, 0700); mkErr != nil {
			return nil, fmt.Errorf("create directory for KEK %s: %w", dir, mkErr)
		}

		pkcs8Bytes, marErr := x509.MarshalPKCS8PrivateKey(priv)
		if marErr != nil {
			return nil, fmt.Errorf("marshal PKCS#8 private key: %w", marErr)
		}

		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8Bytes,
		})

		tmpFile := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
		if wErr := os.WriteFile(tmpFile, pemBytes, 0600); wErr != nil {
			return nil, fmt.Errorf("write temporary KEK %s: %w", tmpFile, wErr)
		}
		if renErr := os.Rename(tmpFile, path); renErr != nil {
			_ = os.Remove(tmpFile)
			return nil, fmt.Errorf("rename temporary KEK %s to %s: %w", tmpFile, path, renErr)
		}

		m.privKey = priv
	} else {
		return nil, fmt.Errorf("read KEK from %s: %w", path, err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&m.privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal KEK public key: %w", err)
	}
	m.pubKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	hash := sha256.Sum256(pubDER)
	m.fingerprint = hex.EncodeToString(hash[:])

	return m, nil
}

// PublicKeyPEM returns the PEM-encoded PKIX public key bytes.
func (m *PersistentRSAKeyEnvelopeManager) PublicKeyPEM() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()
	res := make([]byte, len(m.pubKeyPEM))
	copy(res, m.pubKeyPEM)
	return res
}

// DecryptDEK unwraps the RSA-OAEP-4096 (SHA-256) encrypted Data Encryption Key.
func (m *PersistentRSAKeyEnvelopeManager) DecryptDEK(ctx context.Context, encryptedDEK []byte) ([]byte, error) {
	_ = ctx
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.privKey == nil {
		return nil, errors.New("private key is nil")
	}

	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, m.privKey, encryptedDEK, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt DEK with RSA-OAEP: %w", err)
	}
	return dek, nil
}

// Fingerprint returns the hex-encoded SHA-256 fingerprint of the KEK's DER public key.
func (m *PersistentRSAKeyEnvelopeManager) Fingerprint() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.fingerprint
}

// PrivateKey returns the underlying RSA private key for operations requiring direct key access.
func (m *PersistentRSAKeyEnvelopeManager) PrivateKey() *rsa.PrivateKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.privKey
}
