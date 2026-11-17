package release_test

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/release"
)

func samplePayload(now time.Time) release.Payload {
	return release.Payload{
		Version:      "0.2.0",
		Package:      "spire-agent",
		Architecture: "amd64",
		SHA256:       "ABCDEF0123456789", // signer lowercases this
		Size:         4096,
		IssuedAt:     now,
		ExpiresAt:    now.Add(release.DefaultValidity),
	}
}

func TestCanonicalBytes_StableAcrossFieldReorderAndTimezone(t *testing.T) {
	loc, _ := time.LoadLocation("America/New_York")
	utc := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	p1 := samplePayload(utc)
	p1.KeyID = "deadbeef"
	// Same instants, different timezone representation.
	p2 := p1
	p2.IssuedAt = utc.In(loc)
	p2.ExpiresAt = p1.ExpiresAt.In(loc)

	c1, err := release.CanonicalBytes(p1)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := release.CanonicalBytes(p2)
	if err != nil {
		t.Fatal(err)
	}
	if string(c1) != string(c2) {
		t.Fatalf("canonical bytes differ across timezone:\n%s\n%s", c1, c2)
	}
	// Keys must be sorted — architecture precedes version, etc.
	if got := string(c1); got[:len(`{"architecture"`)] != `{"architecture"` {
		t.Errorf("canonical form not key-sorted: %s", got)
	}
}

func TestSignVerify_RoundTrip(t *testing.T) {
	pub, priv, _ := release.GenerateKey()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	m, err := release.Sign(priv, samplePayload(now))
	if err != nil {
		t.Fatal(err)
	}
	if m.Payload.KeyID != release.KeyID(pub) {
		t.Errorf("key_id = %s, want %s", m.Payload.KeyID, release.KeyID(pub))
	}
	if m.Payload.SHA256 != "abcdef0123456789" {
		t.Errorf("sha256 not normalized to lowercase: %s", m.Payload.SHA256)
	}
	trust := map[string]ed25519.PublicKey{release.KeyID(pub): pub}
	got, err := release.VerifyManifest(m, trust, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Version != "0.2.0" || got.Size != 4096 {
		t.Errorf("verified payload wrong: %+v", got)
	}
}

func TestVerify_WrongKey(t *testing.T) {
	_, priv, _ := release.GenerateKey()
	otherPub, _, _ := release.GenerateKey()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	m, _ := release.Sign(priv, samplePayload(now))
	// Trust anchor keyed by the manifest's key_id but holding a DIFFERENT key → bad sig.
	trust := map[string]ed25519.PublicKey{m.Payload.KeyID: otherPub}
	_, err := release.VerifyManifest(m, trust, now)
	assertReason(t, err, release.ReasonBadSignature)
}

func TestVerify_UnknownKeyID(t *testing.T) {
	_, priv, _ := release.GenerateKey()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	m, _ := release.Sign(priv, samplePayload(now))
	_, err := release.VerifyManifest(m, map[string]ed25519.PublicKey{}, now)
	assertReason(t, err, release.ReasonUnknownKey)
}

func TestVerify_Expired(t *testing.T) {
	pub, priv, _ := release.GenerateKey()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	m, _ := release.Sign(priv, samplePayload(now))
	trust := map[string]ed25519.PublicKey{release.KeyID(pub): pub}
	_, err := release.VerifyManifest(m, trust, now.Add(release.DefaultValidity+time.Hour))
	assertReason(t, err, release.ReasonExpired)
}

func TestVerify_NotYetValid(t *testing.T) {
	pub, priv, _ := release.GenerateKey()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	m, _ := release.Sign(priv, samplePayload(now))
	trust := map[string]ed25519.PublicKey{release.KeyID(pub): pub}
	_, err := release.VerifyManifest(m, trust, now.Add(-time.Hour))
	assertReason(t, err, release.ReasonNotYetValid)
}

func TestVerify_TamperedField(t *testing.T) {
	pub, priv, _ := release.GenerateKey()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	m, _ := release.Sign(priv, samplePayload(now))
	// Flip a signed field without re-signing: the signature no longer matches.
	m.Payload.Size = 9999
	trust := map[string]ed25519.PublicKey{release.KeyID(pub): pub}
	_, err := release.VerifyManifest(m, trust, now)
	assertReason(t, err, release.ReasonBadSignature)
}

func TestMarshalParse_RoundTrip(t *testing.T) {
	pub, priv, _ := release.GenerateKey()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	m, _ := release.Sign(priv, samplePayload(now))
	b, err := release.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := release.ParseManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	trust := map[string]ed25519.PublicKey{release.KeyID(pub): pub}
	if _, err := release.VerifyManifest(parsed, trust, now); err != nil {
		t.Fatalf("verify after marshal/parse: %v", err)
	}
}

func TestLoadPrivateKey_RefusesInsecurePerms(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := release.GenerateKey()
	path := filepath.Join(dir, "release.key")
	if err := release.WritePrivateKey(path, priv); err != nil {
		t.Fatal(err)
	}
	// WritePrivateKey writes 0600; it must load fine.
	if _, err := release.LoadPrivateKey(path); err != nil {
		t.Fatalf("expected 0600 key to load, got %v", err)
	}
	// Loosen to group-readable — must be refused.
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := release.LoadPrivateKey(path); err == nil {
		t.Fatal("expected refusal for group-readable private key")
	}
}

func TestLoadTrustAnchors(t *testing.T) {
	dir := t.TempDir()
	pub, _, _ := release.GenerateKey()
	if err := release.WritePublicKey(filepath.Join(dir, release.KeyID(pub)+".pub"), pub); err != nil {
		t.Fatal(err)
	}
	// A junk .pub is skipped, not fatal.
	if err := os.WriteFile(filepath.Join(dir, "junk.pub"), []byte("not a key"), 0o644); err != nil {
		t.Fatal(err)
	}
	trust, errs := release.LoadTrustAnchors(dir)
	if _, ok := trust[release.KeyID(pub)]; !ok {
		t.Error("valid key not loaded")
	}
	if len(errs) != 1 {
		t.Errorf("expected 1 skip error for junk.pub, got %d: %v", len(errs), errs)
	}
	// Missing dir → empty, no error.
	empty, errs := release.LoadTrustAnchors(filepath.Join(dir, "nope"))
	if len(empty) != 0 || len(errs) != 0 {
		t.Errorf("missing dir should be empty/no-error, got %d keys %v", len(empty), errs)
	}
}

func assertReason(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with reason %q, got nil", want)
	}
	ve, ok := err.(*release.VerifyError)
	if !ok {
		t.Fatalf("expected *release.VerifyError, got %T: %v", err, err)
	}
	if ve.Reason != want {
		t.Fatalf("reason = %q, want %q (err=%v)", ve.Reason, want, err)
	}
}
