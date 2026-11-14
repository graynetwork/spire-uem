package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// WipeSigner holds the server's Ed25519 key used to sign irreversible crypto-erase wipe
// orders. The agent pins the matching public key at enrollment and refuses any wipe order
// that is unsigned, mis-signed, or signed by a different key. The key is persisted so the
// pinned public key stays stable across server restarts.
type WipeSigner struct {
	mu   sync.RWMutex
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	path string
}

// NewWipeSigner loads an existing Ed25519 private key from path (PKCS#8 PEM) or generates
// and persists a new one (mode 0600). An empty path is refused.
func NewWipeSigner(path string) (*WipeSigner, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("wipe-signing key path cannot be empty")
	}
	s := &WipeSigner{path: path}

	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("decode PEM from %s: invalid PEM block", path)
		}
		key, perr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("parse Ed25519 wipe key from %s: %w", path, perr)
		}
		edPriv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key in %s is not an Ed25519 private key", path)
		}
		s.priv = edPriv
		s.pub = edPriv.Public().(ed25519.PublicKey)
		return s, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read wipe key from %s: %w", path, err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Ed25519 wipe key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal Ed25519 wipe key: %w", err)
	}
	if mkErr := os.MkdirAll(filepath.Dir(path), 0700); mkErr != nil {
		return nil, fmt.Errorf("create dir for wipe key %s: %w", filepath.Dir(path), mkErr)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	tmp := fmt.Sprintf("%s.tmp.%d", path, os.Getpid())
	if werr := os.WriteFile(tmp, pemBytes, 0600); werr != nil {
		return nil, fmt.Errorf("write temp wipe key %s: %w", tmp, werr)
	}
	if rerr := os.Rename(tmp, path); rerr != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("rename temp wipe key to %s: %w", path, rerr)
	}
	s.priv = priv
	s.pub = pub
	return s, nil
}

// Sign returns the Ed25519 signature over the canonical order bytes.
func (s *WipeSigner) Sign(order []byte) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return ed25519.Sign(s.priv, order)
}

// PublicKeyBase64 returns the raw 32-byte Ed25519 public key, standard-base64 encoded, as
// the agent pins it.
func (s *WipeSigner) PublicKeyBase64() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return base64.StdEncoding.EncodeToString(s.pub)
}

// PublicKey returns a copy of the raw Ed25519 public key.
func (s *WipeSigner) PublicKey() ed25519.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(ed25519.PublicKey, len(s.pub))
	copy(out, s.pub)
	return out
}

// VerifyWipeOrder checks an Ed25519 signature over order against a base64 (std) raw public
// key, exactly as the agent does. It is exported so both the agent and tests use one
// verifier. A malformed key or signature returns an error rather than a bare false.
func VerifyWipeOrder(pubKeyBase64 string, order, signature []byte) error {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubKeyBase64))
	if err != nil {
		return fmt.Errorf("decode pinned wipe public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("pinned wipe public key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("wipe order signature is %d bytes, want %d", len(signature), ed25519.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(raw), order, signature) {
		return errors.New("wipe order signature verification failed")
	}
	return nil
}
