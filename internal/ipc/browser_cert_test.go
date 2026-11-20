package ipc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/ipc"
	"github.com/spire-uem/spire-uem/internal/types"
)

func testCSR(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func p256CSR(t *testing.T) string {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return testCSR(t, k)
}

type fakeControlPlane struct {
	*httptest.Server
	mu      sync.Mutex
	calls   int
	auth    string
	gotReq  types.DeviceCertIssueRequest
	status  int
	purpose types.CertPurpose
}

func newFakeControlPlane(t *testing.T) *fakeControlPlane {
	f := &fakeControlPlane{status: http.StatusOK, purpose: types.CertPurposeBrowser}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls++
		f.auth = r.Header.Get("Authorization")
		if r.URL.Path != "/api/v1/desktop/cert/issue" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&f.gotReq)
		if f.status != http.StatusOK {
			w.WriteHeader(f.status)
			_, _ = w.Write([]byte(`{"error":"nope"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(types.DeviceCertIssueResponse{
			Purpose:              f.purpose,
			DeviceCertificatePEM: "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----",
			DeviceCACertPEM:      "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----",
			NotAfter:             "2030-01-01T00:00:00Z",
		})
	}))
	t.Cleanup(f.Close)
	return f
}

type bcFixture struct {
	srv *ipc.Server
	cp  *fakeControlPlane
	dir string
}

func newBCFixture(t *testing.T, withPolicy bool) *bcFixture {
	t.Helper()
	cp := newFakeControlPlane(t)
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("dev-token"), 0600); err != nil {
		t.Fatal(err)
	}
	srv := ipc.NewServer(filepath.Join(dir, "agent.sock"), cp.URL, tokenPath, "hw", "host", nil, nil, nil)
	srv.SetBrowserCertHooksForTest(
		func(uid uint32) (string, error) {
			switch uid {
			case 1000:
				return "alice", nil
			case 1001:
				return "bob", nil
			case 1002:
				return "bad name", nil
			}
			return "", fmt.Errorf("no such user")
		},
		func() uint32 { return 1000 }, 0)
	if withPolicy {
		srv.UpdateDevicePolicies("dev", []types.AssignedPolicy{{ID: "p1", PolicyType: types.PolicyTypeBrowserCertificate}}, nil)
	}
	return &bcFixture{srv: srv, cp: cp, dir: dir}
}

func (f *bcFixture) issue(t *testing.T, uid uint32, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://unix/v1/browser-cert/issue", strings.NewReader(body))
	req = req.WithContext(ipc.WithPeerCred(req.Context(), &syscall.Ucred{Uid: uid}))
	rec := httptest.NewRecorder()
	f.srv.HandleBrowserCertIssueForTest(rec, req)
	return rec
}

func csrBody(csr string) string {
	b, _ := json.Marshal(map[string]string{"csr_pem": csr})
	return string(b)
}

func TestBrowserCertIssue_UserComesFromPeerUID(t *testing.T) {
	f := newBCFixture(t, true)
	// The request tries to name another user; the field must be ignored.
	body, _ := json.Marshal(map[string]string{"csr_pem": p256CSR(t), "user": "root", "purpose": "network"})
	rec := f.issue(t, 1001, string(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d: %s", rec.Code, rec.Body.String())
	}
	if f.cp.gotReq.User != "bob" || f.cp.gotReq.Purpose != types.CertPurposeBrowser {
		t.Errorf("server saw user=%q purpose=%q, want bob/browser", f.cp.gotReq.User, f.cp.gotReq.Purpose)
	}
	if f.cp.auth != "Bearer dev-token" {
		t.Errorf("bearer = %q", f.cp.auth)
	}
	var resp ipc.BrowserCertIssueResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.User != "bob" || !strings.Contains(resp.CertificatePEM, "LEAF") || !strings.Contains(resp.DeviceCAPEM, "CA") {
		t.Errorf("response = %+v", resp)
	}
}

func TestBrowserCertIssue_RefusedWithoutPolicy(t *testing.T) {
	f := newBCFixture(t, false)
	rec := f.issue(t, 1000, csrBody(p256CSR(t)))
	if rec.Code != http.StatusForbidden || f.cp.calls != 0 {
		t.Fatalf("got %d calls=%d: %s", rec.Code, f.cp.calls, rec.Body.String())
	}
}

func TestBrowserCertIssue_RefusesRootAndSystemAccounts(t *testing.T) {
	f := newBCFixture(t, true)
	for _, uid := range []uint32{0, 1, 33, 999, 65534, 4294967295} {
		rec := f.issue(t, uid, csrBody(p256CSR(t)))
		if rec.Code != http.StatusForbidden {
			t.Errorf("uid %d: got %d want 403", uid, rec.Code)
		}
	}
	// Account name that cannot go in a certificate.
	if rec := f.issue(t, 1002, csrBody(p256CSR(t))); rec.Code != http.StatusForbidden {
		t.Errorf("bad account name: got %d want 403", rec.Code)
	}
	// Unknown uid.
	if rec := f.issue(t, 1500, csrBody(p256CSR(t))); rec.Code != http.StatusForbidden {
		t.Errorf("unknown uid: got %d want 403", rec.Code)
	}
	if f.cp.calls != 0 {
		t.Errorf("the server was contacted %d times for refused callers", f.cp.calls)
	}
}

func TestBrowserCertIssue_DistributionUIDMinRaisesThreshold(t *testing.T) {
	login := filepath.Join(t.TempDir(), "login.defs")
	_ = os.WriteFile(login, []byte("# comment\nUID_MIN\t\t5000\nUID_MAX 60000\n"), 0644)
	defer ipc.SetLoginDefsPathForTest(login)()
	if got := ipc.LocalUIDMinForTest(); got != 5000 {
		t.Fatalf("UID_MIN = %d, want 5000", got)
	}
	// A UID_MIN below 1000 never lowers the floor.
	_ = os.WriteFile(login, []byte("UID_MIN 500\n"), 0644)
	if got := ipc.LocalUIDMinForTest(); got != 1000 {
		t.Fatalf("UID_MIN 500 gave %d, want 1000", got)
	}
}

func TestBrowserCertIssue_BadCSRRefused(t *testing.T) {
	f := newBCFixture(t, true)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	good := p256CSR(t)
	block, _ := pem.Decode([]byte(good))
	tampered := append([]byte(nil), block.Bytes...)
	tampered[len(tampered)-3] ^= 0xff // break the signature
	cases := map[string]string{
		"empty":       csrBody(""),
		"not pem":     csrBody("hello"),
		"wrong block": csrBody(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}))),
		"rsa key":     csrBody(testCSR(t, rsaKey)),
		"p384 key":    csrBody(testCSR(t, p384)),
		"bad sig":     csrBody(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: tampered}))),
		"not json":    "{",
	}
	for name, body := range cases {
		if rec := f.issue(t, 1000, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d want 400 (%s)", name, rec.Code, rec.Body.String())
		}
	}
	if f.cp.calls != 0 {
		t.Errorf("the server saw %d bad requests", f.cp.calls)
	}
}

func TestBrowserCertIssue_RateLimitedPerUID(t *testing.T) {
	f := newBCFixture(t, true)
	f.srv.SetBrowserCertHooksForTest(nil, nil, 3)
	for i := 0; i < 3; i++ {
		if rec := f.issue(t, 1000, csrBody(p256CSR(t))); rec.Code != http.StatusOK {
			t.Fatalf("request %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	if rec := f.issue(t, 1000, csrBody(p256CSR(t))); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th request: got %d want 429", rec.Code)
	}
	// Another user has their own allowance.
	if rec := f.issue(t, 1001, csrBody(p256CSR(t))); rec.Code != http.StatusOK {
		t.Fatalf("other uid: got %d", rec.Code)
	}
	if f.cp.calls != 4 {
		t.Errorf("server calls = %d, want 4", f.cp.calls)
	}
}

func TestBrowserCertIssue_ServerFailuresFailClosed(t *testing.T) {
	f := newBCFixture(t, true)
	f.cp.status = http.StatusForbidden
	if rec := f.issue(t, 1000, csrBody(p256CSR(t))); rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), "LEAF") {
		t.Fatalf("server refusal: got %d %s", rec.Code, rec.Body.String())
	}
	f.cp.status = http.StatusOK
	f.cp.purpose = types.CertPurposeNetwork
	if rec := f.issue(t, 1000, csrBody(p256CSR(t))); rec.Code != http.StatusBadGateway {
		t.Fatalf("wrong purpose in response: got %d", rec.Code)
	}
	// Not enrolled: no token.
	_ = os.Remove(filepath.Join(f.dir, "token"))
	f.cp.purpose = types.CertPurposeBrowser
	if rec := f.issue(t, 1000, csrBody(p256CSR(t))); rec.Code != http.StatusBadGateway {
		t.Fatalf("no token: got %d", rec.Code)
	}
}

func TestBrowserCertConfig(t *testing.T) {
	get := func(f *bcFixture, uid uint32) ipc.BrowserCertConfig {
		req := httptest.NewRequest(http.MethodGet, "http://unix/v1/browser-cert/config", nil)
		req = req.WithContext(ipc.WithPeerCred(req.Context(), &syscall.Ucred{Uid: uid}))
		rec := httptest.NewRecorder()
		f.srv.HandleBrowserCertConfigForTest(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("config: %d", rec.Code)
		}
		var c ipc.BrowserCertConfig
		_ = json.Unmarshal(rec.Body.Bytes(), &c)
		return c
	}
	off := newBCFixture(t, false)
	if c := get(off, 1000); c.Enabled || !c.Eligible {
		t.Errorf("no policy: %+v", c)
	}
	on := newBCFixture(t, true)
	if c := get(on, 1000); !c.Enabled || !c.Eligible || c.DeviceCAPEM != "" {
		t.Errorf("policy, before first issue: %+v", c)
	}
	if c := get(on, 0); !c.Enabled || c.Eligible {
		t.Errorf("root must not be eligible: %+v", c)
	}
	if rec := on.issue(t, 1000, csrBody(p256CSR(t))); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	if c := get(on, 1000); !strings.Contains(c.DeviceCAPEM, "CA") {
		t.Errorf("CA not remembered after issue: %+v", c)
	}
	// Policy removed: disabled again.
	on.srv.UpdateDevicePolicies("dev", []types.AssignedPolicy{}, nil)
	if c := get(on, 1000); c.Enabled {
		t.Errorf("policy removed but still enabled: %+v", c)
	}
}

// Through the real socket and the kernel's SO_PEERCRED: the user is the account of the
// process that connected.
func TestBrowserCertIssue_OverRealSocketUsesKernelPeerCred(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("run as a non-root user")
	}
	uid := uint32(os.Getuid())
	t.Setenv("SPIRE_SEAT0_UID", fmt.Sprint(uid))
	f := newBCFixture(t, true)
	// A unix socket path must stay under ~100 bytes, which the usual test directory does not.
	short, err := os.MkdirTemp("/tmp", "bc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(short) })
	f.srv = ipc.NewServer(filepath.Join(short, "a.sock"), f.cp.URL, filepath.Join(f.dir, "token"), "hw", "host", nil, nil, nil)
	f.srv.UpdateDevicePolicies("dev", []types.AssignedPolicy{{ID: "p1", PolicyType: types.PolicyTypeBrowserCertificate}}, nil)
	f.srv.SetBrowserCertHooksForTest(func(u uint32) (string, error) {
		if u == uid {
			return "tester", nil
		}
		return "", fmt.Errorf("unexpected uid %d", u)
	}, func() uint32 { return 1 }, 0)
	sock := filepath.Join(short, "a.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = f.srv.Run(ctx) }()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}, Timeout: 5 * time.Second}
	body, _ := json.Marshal(map[string]string{"csr_pem": p256CSR(t), "user": "root"})
	resp, err := client.Post("http://unix/v1/browser-cert/issue", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if f.cp.gotReq.User != "tester" {
		t.Errorf("server saw user %q, want tester", f.cp.gotReq.User)
	}
}
