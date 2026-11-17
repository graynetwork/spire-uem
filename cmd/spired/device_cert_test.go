package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestRenewalDue(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	na := nb.Add(30 * 24 * time.Hour) // 30-day lifetime; 2/3 => day 20

	// No certificate: never due.
	if renewalDue(nb, time.Time{}, nb.Add(time.Hour)) {
		t.Fatal("renewalDue should be false when there is no certificate")
	}
	// Fresh (day 1): not due.
	if renewalDue(nb, na, nb.Add(24*time.Hour)) {
		t.Fatal("renewalDue should be false on day 1")
	}
	// Just before 2/3 (day ~19): not due.
	if renewalDue(nb, na, nb.Add(19*24*time.Hour)) {
		t.Fatal("renewalDue should be false just before the 2/3 threshold")
	}
	// At/after 2/3 (day 21): due.
	if !renewalDue(nb, na, nb.Add(21*24*time.Hour)) {
		t.Fatal("renewalDue should be true past the 2/3 threshold")
	}
	// Expired: due.
	if !renewalDue(nb, na, na.Add(time.Hour)) {
		t.Fatal("renewalDue should be true once expired")
	}
	// Degenerate window (notAfter<=notBefore): due.
	if !renewalDue(nb, nb, nb) {
		t.Fatal("renewalDue should be true for a degenerate window")
	}
}

func TestNeedsCertificate(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	na := nb.Add(30 * 24 * time.Hour)
	if !needsCertificate(time.Time{}, time.Time{}, nb) {
		t.Fatal("no certificate held: a first certificate is needed")
	}
	if needsCertificate(nb, na, nb.Add(24*time.Hour)) {
		t.Fatal("fresh certificate: not needed")
	}
	if !needsCertificate(nb, na, nb.Add(21*24*time.Hour)) {
		t.Fatal("past 2/3 of lifetime: renewal needed")
	}
	if !needsCertificate(nb, na, na.Add(time.Hour)) {
		t.Fatal("expired certificate: replacement needed")
	}
}

func selfSignedPair(t *testing.T, notBefore, notAfter time.Time, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: notBefore, NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// An expired leaf, or one from a CA the server does not ask for, must not be presented:
// the server would fail the whole handshake and cut the agent off.
func TestClientCertUsable(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	valid := selfSignedPair(t, now.Add(-time.Hour), now.Add(time.Hour), "dev")
	expired := selfSignedPair(t, now.Add(-2*time.Hour), now.Add(-time.Hour), "dev")
	future := selfSignedPair(t, now.Add(time.Hour), now.Add(2*time.Hour), "dev")

	if !clientCertUsable(&valid, nil, now) {
		t.Fatal("valid leaf should be usable")
	}
	if clientCertUsable(&expired, nil, now) {
		t.Fatal("expired leaf must not be presented")
	}
	if clientCertUsable(&future, nil, now) {
		t.Fatal("not-yet-valid leaf must not be presented")
	}

	leaf, _ := x509.ParseCertificate(valid.Certificate[0])
	other := selfSignedPair(t, now.Add(-time.Hour), now.Add(time.Hour), "other-ca")
	otherLeaf, _ := x509.ParseCertificate(other.Certificate[0])
	schemes := []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}
	matching := &tls.CertificateRequestInfo{AcceptableCAs: [][]byte{leaf.RawSubject}, SignatureSchemes: schemes, Version: tls.VersionTLS13}
	foreign := &tls.CertificateRequestInfo{AcceptableCAs: [][]byte{otherLeaf.RawSubject}, SignatureSchemes: schemes, Version: tls.VersionTLS13}
	if !clientCertUsable(&valid, matching, now) {
		t.Fatal("leaf issued by an acceptable CA should be usable")
	}
	if clientCertUsable(&valid, foreign, now) {
		t.Fatal("leaf from a CA the server does not accept must not be presented")
	}
}

// An agent holding an EXPIRED certificate must still be able to reach the server. Before the
// fix it presented the expired leaf, the server's VerifyClientCertIfGiven rejected the whole
// handshake, and the agent could neither check in nor obtain a new certificate.
func TestBuildHTTPClient_ExpiredCertStillConnects(t *testing.T) {
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "test device CA"},
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "dev"},
		NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(-time.Hour), // expired
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &devKey.PublicKey, caKey)

	dir := t.TempDir()
	paths := deviceCertPaths{certPath: dir + "/device.crt", keyPath: dir + "/device.key"}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(devKey)
	if err := os.WriteFile(paths.keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(caCert)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			http.Error(w, "unexpected client cert", http.StatusTeapot)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{ClientCAs: clientCAs, ClientAuth: tls.VerifyClientCertIfGiven, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	serverCA := dir + "/server-ca.pem"
	if err := os.WriteFile(serverCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := buildHTTPClient(5*time.Second, paths, serverCA, "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(srv.URL + "/api/v1/desktop/checkin")
	if err != nil {
		t.Fatalf("agent with an expired certificate could not connect: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with no client cert presented, got %d", resp.StatusCode)
	}
}
