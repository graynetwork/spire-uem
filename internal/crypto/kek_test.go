package crypto_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/spire-uem/spire-uem/internal/crypto"
)

func TestPersistentRSAKeyEnvelopeManager(t *testing.T) {
	tempDir := t.TempDir()
	kekPath := filepath.Join(tempDir, "kek.pem")

	// 1. Initial generation
	mgr1, err := crypto.NewPersistentRSAKeyEnvelopeManager(kekPath)
	if err != nil {
		t.Fatalf("failed to create new KEK manager: %v", err)
	}

	info, err := os.Stat(kekPath)
	if err != nil {
		t.Fatalf("KEK file was not created: %v", err)
	}
	// Verify file mode 0600 (-rw-------)
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected KEK file perm 0600, got %o", info.Mode().Perm())
	}

	pubPEM1 := mgr1.PublicKeyPEM()
	if len(pubPEM1) == 0 {
		t.Fatalf("PublicKeyPEM returned empty bytes")
	}
	fp1 := mgr1.Fingerprint()
	if fp1 == "" {
		t.Fatalf("Fingerprint returned empty string")
	}

	// 2. Persistence: Loading existing key file
	mgr2, err := crypto.NewPersistentRSAKeyEnvelopeManager(kekPath)
	if err != nil {
		t.Fatalf("failed to reload existing KEK manager: %v", err)
	}

	pubPEM2 := mgr2.PublicKeyPEM()
	fp2 := mgr2.Fingerprint()

	if string(pubPEM1) != string(pubPEM2) {
		t.Errorf("reloaded public key PEM does not match original")
	}
	if fp1 != fp2 {
		t.Errorf("reloaded fingerprint (%s) does not match original (%s)", fp2, fp1)
	}

	// 3. DecryptDEK test
	pubKey, err := crypto.ParseRSAPublicKeyPEM(string(pubPEM1))
	if err != nil {
		t.Fatalf("ParseRSAPublicKeyPEM failed: %v", err)
	}

	testDEK := make([]byte, 32)
	if _, err := rand.Read(testDEK); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	encDEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, testDEK, nil)
	if err != nil {
		t.Fatalf("rsa.EncryptOAEP failed: %v", err)
	}

	decryptedDEK, err := mgr2.DecryptDEK(context.Background(), encDEK)
	if err != nil {
		t.Fatalf("DecryptDEK failed: %v", err)
	}
	if string(decryptedDEK) != string(testDEK) {
		t.Errorf("decrypted DEK does not match original test DEK")
	}

	// 4. Envelope Encrypt/Decrypt Recovery Key
	testRecoveryKey := "SPIRE-TEST-RECOVERY-KEY-ABCDEFGH12345678"
	encDEK2, encKey, nonce, err := crypto.EnvelopeEncryptRecoveryKey(pubKey, testRecoveryKey)
	if err != nil {
		t.Fatalf("EnvelopeEncryptRecoveryKey failed: %v", err)
	}

	decRecoveryKey, err := crypto.EnvelopeDecryptRecoveryKey(mgr2.PrivateKey(), encDEK2, encKey, nonce)
	if err != nil {
		t.Fatalf("EnvelopeDecryptRecoveryKey failed: %v", err)
	}
	if decRecoveryKey != testRecoveryKey {
		t.Errorf("decrypted recovery key (%s) != expected (%s)", decRecoveryKey, testRecoveryKey)
	}
}

func TestPersistentRSAKeyEnvelopeManager_InvalidPath(t *testing.T) {
	_, err := crypto.NewPersistentRSAKeyEnvelopeManager("")
	if err == nil {
		t.Errorf("expected error when passing empty path to NewPersistentRSAKeyEnvelopeManager")
	}
}
