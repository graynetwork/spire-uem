package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mkCert(t *testing.T, cn string, pub *rsa.PublicKey, parent *x509.Certificate, parentKey *rsa.PrivateKey, isCA bool) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: isCA, BasicConstraintsValid: true,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign
	}
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func pemOf(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func resetTPMTrust() {
	tpmTrustMu.Lock()
	tpmRoots, tpmIntermediates, tpmRootsConfigured = x509.NewCertPool(), x509.NewCertPool(), false
	tpmTrustMu.Unlock()
}

func TestVerifyEKCertificate_RequiresTrustedChain(t *testing.T) {
	t.Cleanup(resetTPMTrust)
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ca := mkCert(t, "TPM Vendor Root", &caKey.PublicKey, nil, caKey, true)
	ekKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ekCert := mkCert(t, "EK", &ekKey.PublicKey, ca, caKey, false)
	ekPubDER, _ := x509.MarshalPKIXPublicKey(&ekKey.PublicKey)
	ekPEM := string(pemOf("PUBLIC KEY", ekPubDER))
	ekCertPEM := pemOf("CERTIFICATE", ekCert.Raw)

	// No roots configured: fail closed.
	resetTPMTrust()
	if _, err := VerifyEKCertificate(ekCertPEM, ekPEM); !errors.Is(err, ErrNoTPMRoots) {
		t.Fatalf("expected ErrNoTPMRoots, got %v", err)
	}

	bundle := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(bundle, pemOf("CERTIFICATE", ca.Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if n, err := LoadTPMTrustBundle(bundle); err != nil || n != 1 {
		t.Fatalf("LoadTPMTrustBundle: n=%d err=%v", n, err)
	}
	if _, err := VerifyEKCertificate(ekCertPEM, ekPEM); err != nil {
		t.Fatalf("CA-issued EK cert rejected: %v", err)
	}

	// A self-signed "EK certificate" (what any software key holder can mint) is rejected.
	selfSigned := mkCert(t, "EK", &ekKey.PublicKey, nil, ekKey, false)
	if _, err := VerifyEKCertificate(pemOf("CERTIFICATE", selfSigned.Raw), ekPEM); err == nil {
		t.Fatal("self-signed EK certificate must be rejected")
	}

	// A valid cert for a different key does not vouch for the claimed EK.
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherDER, _ := x509.MarshalPKIXPublicKey(&otherKey.PublicKey)
	if _, err := VerifyEKCertificate(ekCertPEM, string(pemOf("PUBLIC KEY", otherDER))); err == nil {
		t.Fatal("EK cert/key mismatch must be rejected")
	}
}
