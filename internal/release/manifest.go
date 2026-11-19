// Package release implements independently signed agent update manifests.
//
// A manifest is a detached JSON document that describes exactly one agent .deb and carries
// an Ed25519 signature over its canonical byte encoding. The signing key lives OFF the
// control plane (held by release engineering), so a compromised server that controls both
// the .deb bytes and the size+SHA-256 it advertises still cannot forge a manifest the agent
// will accept: the agent pins the public keys shipped inside its own package and verifies
// the signature before installing.
//
// This package is shared by cmd/spire-release (which signs, using the private key) and by
// the agent self-updater (which verifies, using the pinned public keys). It NEVER touches
// the database and has no server dependency.
package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// DefaultValidity is how long a signed manifest is valid for by default (90 days). A short
// validity limits the window in which a stolen-but-not-rotated signature can be replayed.
const DefaultValidity = 90 * 24 * time.Hour

// Payload is the signed body of a manifest: everything the agent checks before install. The
// JSON field order here is NOT what gets signed — CanonicalBytes produces the canonical
// encoding independently, so re-marshalling with a different field order cannot change the
// signed bytes.
type Payload struct {
	// Version is the agent release version this .deb contains (e.g. "0.2.0").
	Version string `json:"version"`
	// Package is the Debian package name (e.g. "spire-agent").
	Package string `json:"package"`
	// Architecture is the Debian architecture (e.g. "amd64").
	Architecture string `json:"architecture"`
	// SHA256 is the lowercase hex SHA-256 of the exact .deb bytes.
	SHA256 string `json:"sha256"`
	// Size is the exact size of the .deb in bytes.
	Size int64 `json:"size"`
	// IssuedAt is when the manifest was signed (UTC, RFC3339).
	IssuedAt time.Time `json:"issued_at"`
	// ExpiresAt is when the manifest stops being valid (UTC, RFC3339).
	ExpiresAt time.Time `json:"expires_at"`
	// KeyID identifies the signing key, so the agent can select the matching trust anchor
	// and rotation is possible without a flag day. It is the first 16 hex chars of the
	// SHA-256 of the raw public key (see KeyID).
	KeyID string `json:"key_id"`
}

// Manifest is the on-disk document: the signed Payload plus its detached base64 signature.
type Manifest struct {
	Payload   Payload `json:"payload"`
	Signature string  `json:"signature"` // base64 (std encoding) of the Ed25519 signature over CanonicalBytes
}

// KeyID derives the stable key identifier for an Ed25519 public key: the first 16 hex
// characters of the SHA-256 of the 32-byte raw public key. Trust-anchor files are named
// <key_id>.pub so the agent can find the right key in O(1).
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// CanonicalBytes returns the exact bytes that are signed and verified. It is a deterministic
// JSON object with keys in a FIXED sorted order and timestamps in RFC3339 UTC with second
// precision, so the same logical payload always yields identical bytes regardless of struct
// field order, map iteration order, or the signer's local timezone. Both the signer and the
// verifier call this; the stored Manifest.Payload JSON field order is irrelevant.
func CanonicalBytes(p Payload) ([]byte, error) {
	if p.IssuedAt.IsZero() || p.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("manifest payload is missing issued_at/expires_at")
	}
	fields := map[string]any{
		"version":      p.Version,
		"package":      p.Package,
		"architecture": p.Architecture,
		"sha256":       strings.ToLower(strings.TrimSpace(p.SHA256)),
		"size":         p.Size,
		"issued_at":    p.IssuedAt.UTC().Format(time.RFC3339),
		"expires_at":   p.ExpiresAt.UTC().Format(time.RFC3339),
		"key_id":       p.KeyID,
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := json.Marshal(fields[k])
		if err != nil {
			return nil, fmt.Errorf("canonicalize %q: %w", k, err)
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

// Sign produces a signed Manifest for the payload using the private key. It fills KeyID from
// the key and signs the canonical bytes.
func Sign(priv ed25519.PrivateKey, p Payload) (*Manifest, error) {
	if l := len(priv); l != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size %d", l)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("private key does not yield an Ed25519 public key")
	}
	p.KeyID = KeyID(pub)
	p.SHA256 = strings.ToLower(strings.TrimSpace(p.SHA256))
	canon, err := CanonicalBytes(p)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, canon)
	return &Manifest{Payload: p, Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

// VerifyError classifies why verification failed, so callers (and the agent) can react
// differently — an expired manifest is distinct from a forged one and an unknown key.
type VerifyError struct {
	Reason string
	Err    error
}

func (e *VerifyError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Reason, e.Err)
	}
	return e.Reason
}

// Distinct verification-failure reasons, so tests and the agent can assert on them.
const (
	ReasonMalformed    = "malformed manifest"
	ReasonUnknownKey   = "unknown key_id"
	ReasonBadSignature = "signature verification failed"
	ReasonExpired      = "manifest expired"
	ReasonNotYetValid  = "manifest not yet valid"
)

// VerifyManifest checks m's signature against the trust anchor whose KeyID equals the
// manifest's key_id, and that the manifest is within its validity window at time now. It
// returns the verified Payload on success, or a *VerifyError. trust maps key_id ->
// public key (built from the .pub files shipped in the agent package). It does NOT check
// sha256/size/version against a downloaded file — the caller does that against the SIGNED
// payload values (see engine.VerifySignedUpdate).
func VerifyManifest(m *Manifest, trust map[string]ed25519.PublicKey, now time.Time) (*Payload, error) {
	if m == nil {
		return nil, &VerifyError{Reason: ReasonMalformed, Err: fmt.Errorf("nil manifest")}
	}
	if strings.TrimSpace(m.Payload.KeyID) == "" {
		return nil, &VerifyError{Reason: ReasonMalformed, Err: fmt.Errorf("empty key_id")}
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(m.Signature))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, &VerifyError{Reason: ReasonMalformed, Err: fmt.Errorf("bad signature encoding")}
	}
	pub, ok := trust[m.Payload.KeyID]
	if !ok {
		return nil, &VerifyError{Reason: ReasonUnknownKey, Err: fmt.Errorf("key_id %s is not a pinned trust anchor", m.Payload.KeyID)}
	}
	canon, err := CanonicalBytes(m.Payload)
	if err != nil {
		return nil, &VerifyError{Reason: ReasonMalformed, Err: err}
	}
	if !ed25519.Verify(pub, canon, sig) {
		return nil, &VerifyError{Reason: ReasonBadSignature}
	}
	now = now.UTC()
	if now.Before(m.Payload.IssuedAt.UTC()) {
		return nil, &VerifyError{Reason: ReasonNotYetValid}
	}
	if now.After(m.Payload.ExpiresAt.UTC()) {
		return nil, &VerifyError{Reason: ReasonExpired}
	}
	p := m.Payload
	return &p, nil
}

// MarshalManifest renders a manifest as indented JSON for writing to <deb>.manifest.json.
func MarshalManifest(m *Manifest) ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

// ParseManifest decodes a manifest document.
func ParseManifest(b []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, &VerifyError{Reason: ReasonMalformed, Err: err}
	}
	return &m, nil
}
