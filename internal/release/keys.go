package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PEM block types for the release signing key pair. We use PKCS#8 for the private key and
// PKIX (SubjectPublicKeyInfo) for the public key so standard tooling can read them too.
const (
	privatePEMType = "PRIVATE KEY"
	publicPEMType  = "PUBLIC KEY"
)

// GenerateKey creates a fresh Ed25519 release key pair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// MarshalPrivatePEM encodes an Ed25519 private key as PKCS#8 PEM.
func MarshalPrivatePEM(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: privatePEMType, Bytes: der}), nil
}

// MarshalPublicPEM encodes an Ed25519 public key as PKIX PEM.
func MarshalPublicPEM(pub ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: publicPEMType, Bytes: der}), nil
}

// insecurePrivateKeyPerm reports whether a private-key file mode grants any group or world
// access. Release private keys are high value; a group/world-readable key is refused so a
// signing host misconfiguration is caught loudly instead of silently leaking the key.
func insecurePrivateKeyPerm(mode os.FileMode) bool {
	return mode.Perm()&0o077 != 0
}

// LoadPrivateKey reads an Ed25519 private key from a PKCS#8 PEM file. It REFUSES a key file
// that is group- or world-accessible (any permission bit in 0o077 set).
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if insecurePrivateKeyPerm(info.Mode()) {
		return nil, fmt.Errorf("refusing to use private key %s: permissions %04o are group/world accessible, expected 0600", path, info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(b)
}

// ParsePrivateKey decodes an Ed25519 private key from PKCS#8 PEM bytes.
func ParsePrivateKey(b []byte) (ed25519.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("no PEM block found in private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an Ed25519 private key (%T)", key)
	}
	return priv, nil
}

// ParsePublicKey decodes an Ed25519 public key from PKIX PEM bytes.
func ParsePublicKey(b []byte) (ed25519.PublicKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("no PEM block found in public key")
	}
	key, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an Ed25519 public key (%T)", key)
	}
	return pub, nil
}

// WritePrivateKey writes the private key PEM with mode 0600 (owner-only), creating parent
// directories with mode 0700.
func WritePrivateKey(path string, priv ed25519.PrivateKey) error {
	pemBytes, err := MarshalPrivatePEM(priv)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, pemBytes, 0o600)
}

// WritePublicKey writes the public key PEM with mode 0644.
func WritePublicKey(path string, pub ed25519.PublicKey) error {
	pemBytes, err := MarshalPublicPEM(pub)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, pemBytes, 0o644)
}

// LoadTrustAnchors reads every *.pub file in dir as an Ed25519 public key and returns a map
// of key_id -> public key for VerifyManifest. A missing directory yields an empty map and no
// error, so an agent without any pinned keys simply trusts nothing (and refuses every signed
// update) rather than crashing. A file that is not a valid key is skipped with its error
// collected, so one bad file does not discard the rest.
func LoadTrustAnchors(dir string) (map[string]ed25519.PublicKey, []error) {
	trust := map[string]ed25519.PublicKey{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return trust, nil
		}
		return trust, []error{err}
	}
	var errs []error
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".pub") {
			continue
		}
		p := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			continue
		}
		pub, err := ParsePublicKey(b)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", p, err))
			continue
		}
		trust[KeyID(pub)] = pub
	}
	return trust, errs
}
