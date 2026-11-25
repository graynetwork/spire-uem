package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/types"
)

// fakeIssuer is an httptest TLS server that behaves like POST /api/v1/desktop/cert/issue: it
// issues real network leaves from a throwaway device CA.
type fakeIssuer struct {
	t        *testing.T
	srv      *httptest.Server
	ca       *crypto.FileDeviceCA
	mu       sync.Mutex
	requests []types.DeviceCertIssueRequest
	auth     []string
	fail     int  // when non-zero, answer with this HTTP status
	wrongKey bool // issue a certificate for a different key than the CSR's
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	dir := t.TempDir()
	ca, err := crypto.NewFileDeviceCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIssuer{t: t, ca: ca}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Path != "/api/v1/desktop/cert/issue" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	var req types.DeviceCertIssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad", 400)
		return
	}
	f.requests = append(f.requests, req)
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	if f.fail != 0 {
		http.Error(w, "nope", f.fail)
		return
	}
	block, _ := pem.Decode([]byte(req.CSRPEM))
	csrDER := block.Bytes
	if f.wrongKey {
		other, _ := newTestCSR(f.t)
		csrDER = other
	}
	issued, err := f.ca.IssueWithOptions(csrDER, crypto.IssueOptions{DeviceID: "dev-123", Purpose: crypto.CertPurposeNetwork, Validity: 30 * 24 * time.Hour})
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_ = json.NewEncoder(w).Encode(types.DeviceCertIssueResponse{
		Purpose:              types.CertPurposeNetwork,
		DeviceCertificatePEM: string(issued.CertPEM),
		DeviceCACertPEM:      string(f.ca.CACertPEM()),
	})
}

func (f *fakeIssuer) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.requests)
}

func newTestCSR(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := loadOrCreateDeviceKey(filepath.Join(t.TempDir(), "k"))
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := buildDeviceCSR(key, "x")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode([]byte(csrPEM))
	return b.Bytes, key
}

func newTestManager(t *testing.T, f *fakeIssuer) (*networkCertManager, *int) {
	t.Helper()
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("bearer-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	issued := 0
	m := newNetworkCertManager(f.srv.Client(), f.srv.URL, tokenPath, "hw-1", func() { issued++ })
	return m, &issued
}

// storedPair loads the on-disk network key and certificate and checks they belong together.
func storedPair(t *testing.T, m *networkCertManager) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	certPEM, err := os.ReadFile(m.paths.Cert)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(m.paths.Key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("stored key and certificate do not match: %v", err)
	}
	cb, _ := pem.Decode(certPEM)
	leaf, _ := x509.ParseCertificate(cb.Bytes)
	kb, _ := pem.Decode(keyPEM)
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf, k.(*ecdsa.PrivateKey)
}

func TestNetworkCertNeeded(t *testing.T) {
	mk := func(p types.NetworkProfilePayload) types.AssignedPolicy {
		raw, _ := json.Marshal(p)
		return types.AssignedPolicy{ID: "p", PolicyType: types.PolicyTypeNetworkProfile, Payload: raw}
	}
	device := types.NetworkProfilePayload{Kind: types.NetworkProfileWiredDot1x, Wired: &types.WiredDot1xProfile{EAP: types.EAPTLS, ClientCertSource: types.ClientCertSourceDevice}}
	inline := types.NetworkProfilePayload{Kind: types.NetworkProfileWiredDot1x, Wired: &types.WiredDot1xProfile{EAP: types.EAPTLS}}
	other := types.AssignedPolicy{ID: "o", PolicyType: types.PolicyTypeSysctlSetting, Payload: json.RawMessage(`{"client_cert_source":"device"}`)}

	if networkCertNeeded(nil) || networkCertNeeded([]types.AssignedPolicy{mk(inline), other}) {
		t.Fatal("needed without a device-certificate profile")
	}
	if !networkCertNeeded([]types.AssignedPolicy{other, mk(inline), mk(device)}) {
		t.Fatal("device-certificate profile not detected")
	}
	if networkCertNeeded([]types.AssignedPolicy{{ID: "x", PolicyType: types.PolicyTypeNetworkProfile, Payload: json.RawMessage(`not json`)}}) {
		t.Fatal("a broken payload counted as needing a certificate")
	}
}

func TestNetworkCertRequestedOnlyWhenNeeded(t *testing.T) {
	f := newFakeIssuer(t)
	m, issued := newTestManager(t, f)
	ctx := context.Background()

	// Nothing is known about the assigned policies yet: no request, nothing deleted.
	if err := os.MkdirAll(filepath.Dir(m.paths.Key), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.paths.Key, []byte("keep me"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.reconcile(ctx); err != nil || f.count() != 0 {
		t.Fatalf("before the first check-in: err=%v requests=%d", err, f.count())
	}
	if _, err := os.Stat(m.paths.Key); err != nil {
		t.Fatal("an existing key was deleted before the manager knew what is assigned")
	}
	_ = os.Remove(m.paths.Key)

	// A check-in says no profile uses it: still no request.
	m.setNeeded(false)
	if err := m.reconcile(ctx); err != nil || f.count() != 0 {
		t.Fatalf("not needed: err=%v requests=%d", err, f.count())
	}

	// A profile needs it: one request, with the right purpose, token and a CSR for the stored key.
	m.setNeeded(true)
	if err := m.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if f.count() != 1 || *issued != 1 {
		t.Fatalf("requests=%d onIssued=%d, want 1 and 1", f.count(), *issued)
	}
	if got := f.requests[0]; got.Purpose != types.CertPurposeNetwork || got.User != "" {
		t.Fatalf("request = %+v", got)
	}
	if f.auth[0] != "Bearer bearer-token" {
		t.Fatalf("authorization = %q", f.auth[0])
	}
	leaf, key := storedPair(t, m)
	if crypto.DeviceIDFromCert(leaf) != "dev-123" {
		t.Fatal("stored certificate names the wrong device")
	}
	csrBlock, _ := pem.Decode([]byte(f.requests[0].CSRPEM))
	csr, _ := x509.ParseCertificateRequest(csrBlock.Bytes)
	if !csr.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Fatal("the CSR was not made from the stored key")
	}
	if fi, _ := os.Stat(m.paths.Key); fi.Mode().Perm() != 0600 {
		t.Fatalf("network.key mode = %v, want 0600", fi.Mode().Perm())
	}
	if _, err := os.Stat(m.paths.CA); err != nil {
		t.Fatal("device-ca.crt was not stored")
	}
	for _, p := range []string{m.paths.Key + ".new", m.paths.Cert + ".new"} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("staging file %s left behind", p)
		}
	}
	// The agent's own device key is untouched and different from the network key.
	if filepath.Base(m.paths.Key) != "network.key" {
		t.Fatalf("unexpected key name %s", m.paths.Key)
	}

	// Still valid: no second request.
	if err := m.reconcile(ctx); err != nil || f.count() != 1 {
		t.Fatalf("second pass: err=%v requests=%d", err, f.count())
	}
}

func TestNetworkCertRenewedWithFreshKey(t *testing.T) {
	f := newFakeIssuer(t)
	m, issued := newTestManager(t, f)
	ctx := context.Background()
	m.setNeeded(true)
	if err := m.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	oldLeaf, oldKey := storedPair(t, m)

	// Day 19 of 30: not yet.
	m.now = func() time.Time { return time.Now().Add(19 * 24 * time.Hour) }
	if err := m.reconcile(ctx); err != nil || f.count() != 1 {
		t.Fatalf("day 19: err=%v requests=%d", err, f.count())
	}
	// Day 21 (past 2/3): renewed with a new key.
	m.now = func() time.Time { return time.Now().Add(21 * 24 * time.Hour) }
	if err := m.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if f.count() != 2 || *issued != 2 {
		t.Fatalf("requests=%d onIssued=%d, want 2 and 2", f.count(), *issued)
	}
	newLeaf, newKey := storedPair(t, m)
	if newKey.Equal(oldKey) || newLeaf.SerialNumber.Cmp(oldLeaf.SerialNumber) == 0 {
		t.Fatal("renewal reused the old key or certificate")
	}
	if f.requests[0].CSRPEM == f.requests[1].CSRPEM {
		t.Fatal("renewal sent the same CSR")
	}
}

func TestNetworkCertFailureKeepsCurrentPair(t *testing.T) {
	f := newFakeIssuer(t)
	m, issued := newTestManager(t, f)
	ctx := context.Background()
	m.setNeeded(true)
	if err := m.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	certBefore, _ := os.ReadFile(m.paths.Cert)
	keyBefore, _ := os.ReadFile(m.paths.Key)
	m.now = func() time.Time { return time.Now().Add(22 * 24 * time.Hour) }

	assertUnchanged := func(label string) {
		t.Helper()
		certAfter, _ := os.ReadFile(m.paths.Cert)
		keyAfter, _ := os.ReadFile(m.paths.Key)
		if string(certAfter) != string(certBefore) || string(keyAfter) != string(keyBefore) {
			t.Fatalf("%s: the current key or certificate changed", label)
		}
		for _, p := range []string{m.paths.Key + ".new", m.paths.Cert + ".new"} {
			if _, err := os.Stat(p); err == nil {
				t.Fatalf("%s: staging file %s left behind", label, p)
			}
		}
	}

	f.fail = http.StatusForbidden
	if err := m.reconcile(ctx); err == nil {
		t.Fatal("a refused issuance returned no error")
	}
	assertUnchanged("HTTP 403")

	f.fail = 0
	f.wrongKey = true
	if err := m.reconcile(ctx); err == nil {
		t.Fatal("a certificate for another key was installed")
	}
	assertUnchanged("certificate for a different key")
	if *issued != 1 {
		t.Fatalf("onIssued ran for a failed issuance (%d)", *issued)
	}

	// Server back to normal: the next pass renews.
	f.wrongKey = false
	if err := m.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	storedPair(t, m)
	if *issued != 2 {
		t.Fatalf("onIssued = %d, want 2", *issued)
	}
}

func TestNetworkCertMismatchedPairIsReissued(t *testing.T) {
	f := newFakeIssuer(t)
	m, _ := newTestManager(t, f)
	ctx := context.Background()
	m.setNeeded(true)
	if err := m.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	// A crash between the two renames leaves a key that does not match the certificate.
	foreign := newForeignKeyPEM(t)
	if err := os.WriteFile(m.paths.Key, foreign, 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if f.count() != 2 {
		t.Fatalf("requests = %d, want a second issuance", f.count())
	}
	storedPair(t, m)
}

func newForeignKeyPEM(t *testing.T) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "k")
	if _, err := loadOrCreateDeviceKey(p); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	return b
}

func TestNetworkCertDeletedWhenNoLongerNeeded(t *testing.T) {
	f := newFakeIssuer(t)
	m, _ := newTestManager(t, f)
	ctx := context.Background()
	m.setNeeded(true)
	if err := m.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(m.paths.Key+".new", []byte("staged"), 0600)
	m.setNeeded(false)
	if err := m.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	for _, p := range m.paths.all() {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s still exists after the last profile was removed", p)
		}
	}
	if f.count() != 1 {
		t.Fatalf("requests = %d; deleting must not contact the server", f.count())
	}
	// Idempotent.
	if err := m.reconcile(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkCertRunLoopIssuesOnWake(t *testing.T) {
	f := newFakeIssuer(t)
	m, _ := newTestManager(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.run(ctx); close(done) }()
	m.setNeeded(true)
	deadline := time.Now().Add(5 * time.Second)
	for f.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if f.count() != 1 {
		t.Fatalf("requests = %d, want 1", f.count())
	}
}

func TestResetIdentityRemovesNetworkCert(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	p := networkCertFiles(tokenPath)
	for _, f := range p.all() {
		if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	_ = resetDeviceIdentity(tokenPath)
	for _, f := range p.all() {
		if _, err := os.Stat(f); err == nil {
			t.Fatalf("%s survived reset-identity", f)
		}
	}
}
