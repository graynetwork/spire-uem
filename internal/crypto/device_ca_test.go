package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestCA(t *testing.T) *FileDeviceCA {
	t.Helper()
	dir := t.TempDir()
	ca, err := NewFileDeviceCA(filepath.Join(dir, "device-ca.crt"), filepath.Join(dir, "device-ca.key"))
	if err != nil {
		t.Fatalf("NewFileDeviceCA: %v", err)
	}
	return ca
}

func p256CSR(t *testing.T, tmpl *x509.CertificateRequest) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return der, key
}

func TestDeviceCA_GenerateAndPersist(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	ca1, err := NewFileDeviceCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("first init: %v", err)
	}
	// Key file must be 0600.
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("CA key mode = %o, want 0600", info.Mode().Perm())
	}

	// Reload must produce the same CA certificate.
	ca2, err := NewFileDeviceCA(certPath, keyPath)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if string(ca1.CACertPEM()) != string(ca2.CACertPEM()) {
		t.Fatal("reloaded CA certificate differs from the generated one")
	}
}

func TestDeviceCA_IssueClientAuthLeaf(t *testing.T) {
	ca := newTestCA(t)
	csr, key := p256CSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "whatever"}})

	issued, err := ca.IssueFromCSR(csr, "device-123", 0)
	if err != nil {
		t.Fatalf("IssueFromCSR: %v", err)
	}
	leaf := parseLeaf(t, issued.CertPEM)

	// Client-auth only, not a CA.
	if leaf.IsCA {
		t.Fatal("issued leaf must not be a CA")
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("leaf ExtKeyUsage = %v, want [ClientAuth]", leaf.ExtKeyUsage)
	}
	// URI SAN must be spire://device/<id>, and only that.
	if got := DeviceIDFromCert(leaf); got != "device-123" {
		t.Fatalf("DeviceIDFromCert = %q, want device-123", got)
	}
	// The leaf's public key must match the CSR key (we certified the agent's key).
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("leaf public key does not match CSR key")
	}
	// Default validity ~30 days.
	gotValidity := issued.NotAfter.Sub(issued.NotBefore)
	if gotValidity < 29*24*time.Hour || gotValidity > 31*24*time.Hour {
		t.Fatalf("default validity = %v, want ~30d", gotValidity)
	}
	// Chains to the CA with client-auth usage.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     ca.CertPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("leaf does not verify against CA: %v", err)
	}
	if issued.Serial == "" || issued.FingerprintSHA256 == "" {
		t.Fatal("issued cert must carry serial and fingerprint")
	}
}

func TestDeviceCA_IgnoresRequestedSANs(t *testing.T) {
	ca := newTestCA(t)
	// A hostile CSR requesting a different device id, DNS names and an IP. All must be dropped.
	rogue := &url.URL{Scheme: "spire", Host: "device", Path: "/attacker-device"}
	csr, _ := p256CSR(t, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "attacker"},
		DNSNames: []string{"evil.example.com"},
		URIs:     []*url.URL{rogue},
	})
	issued, err := ca.IssueFromCSR(csr, "real-device", 0)
	if err != nil {
		t.Fatalf("IssueFromCSR: %v", err)
	}
	leaf := parseLeaf(t, issued.CertPEM)
	if got := DeviceIDFromCert(leaf); got != "real-device" {
		t.Fatalf("device id = %q, want real-device (requested SAN must be ignored)", got)
	}
	if len(leaf.DNSNames) != 0 {
		t.Fatalf("leaf must carry no DNS names, got %v", leaf.DNSNames)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].Path != "/real-device" {
		t.Fatalf("leaf URIs = %v, want only spire://device/real-device", leaf.URIs)
	}
}

func TestDeviceCA_RejectsBadSignature(t *testing.T) {
	ca := newTestCA(t)
	csr, _ := p256CSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}})
	// Flip a byte deep in the signature region to break the self-signature.
	tampered := make([]byte, len(csr))
	copy(tampered, csr)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := ca.IssueFromCSR(tampered, "device-123", 0); err == nil {
		t.Fatal("expected issuance to fail for a CSR with a bad signature")
	}
}

func TestDeviceCA_RejectsWrongKeyType(t *testing.T) {
	ca := newTestCA(t)
	// RSA CSR must be rejected.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, rsaKey)
	if err != nil {
		t.Fatalf("rsa CSR: %v", err)
	}
	if _, err := ca.IssueFromCSR(der, "device-123", 0); err == nil {
		t.Fatal("expected RSA CSR to be rejected")
	}

	// P-384 (wrong curve) must be rejected.
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p384: %v", err)
	}
	der384, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, ecKey)
	if err != nil {
		t.Fatalf("p384 CSR: %v", err)
	}
	if _, err := ca.IssueFromCSR(der384, "device-123", 0); err == nil {
		t.Fatal("expected P-384 CSR to be rejected")
	}
}

func TestDeviceCA_CustomValidity(t *testing.T) {
	ca := newTestCA(t)
	csr, _ := p256CSR(t, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}})
	issued, err := ca.IssueFromCSR(csr, "device-123", 48*time.Hour)
	if err != nil {
		t.Fatalf("IssueFromCSR: %v", err)
	}
	got := issued.NotAfter.Sub(issued.NotBefore)
	// 48h + the 2-minute backdating.
	if got < 48*time.Hour || got > 48*time.Hour+5*time.Minute {
		t.Fatalf("validity = %v, want ~48h", got)
	}
}

func parseLeaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("parse leaf: no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return cert
}
