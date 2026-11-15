package crypto

import (
	"path/filepath"
	"testing"
)

func TestWipeSigner_PersistsAndVerifies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wipe.pem")
	s1, err := NewWipeSigner(path)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	msg := []byte("canonical wipe order bytes")
	sig := s1.Sign(msg)
	if err := VerifyWipeOrder(s1.PublicKeyBase64(), msg, sig); err != nil {
		t.Fatalf("own signature should verify: %v", err)
	}

	// Re-loading the same path yields the same key (stable pin across restarts).
	s2, err := NewWipeSigner(path)
	if err != nil {
		t.Fatalf("reload signer: %v", err)
	}
	if s1.PublicKeyBase64() != s2.PublicKeyBase64() {
		t.Fatalf("reloaded signer must present the same public key")
	}
	if err := VerifyWipeOrder(s2.PublicKeyBase64(), msg, sig); err != nil {
		t.Fatalf("signature from the first instance must verify under the reloaded key: %v", err)
	}
}

func TestWipeSigner_EmptyPathRejected(t *testing.T) {
	if _, err := NewWipeSigner(""); err == nil {
		t.Fatalf("empty path must be rejected")
	}
}

func TestVerifyWipeOrder_RejectsWrongKeyAndSizes(t *testing.T) {
	a, _ := NewWipeSigner(filepath.Join(t.TempDir(), "a.pem"))
	b, _ := NewWipeSigner(filepath.Join(t.TempDir(), "b.pem"))
	msg := []byte("order")
	sig := a.Sign(msg)
	if err := VerifyWipeOrder(b.PublicKeyBase64(), msg, sig); err == nil {
		t.Fatalf("signature must not verify under a different key")
	}
	if err := VerifyWipeOrder(a.PublicKeyBase64(), msg, []byte("short")); err == nil {
		t.Fatalf("wrong-size signature must be rejected")
	}
}
