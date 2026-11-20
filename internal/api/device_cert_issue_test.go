package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/api"
	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

func newCSR(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}

func postIssue(t *testing.T, client *http.Client, url, token string, req types.DeviceCertIssueRequest) (int, types.DeviceCertIssueResponse, string) {
	t.Helper()
	body, _ := json.Marshal(req)
	hr, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	hr.Header.Set("Authorization", "Bearer "+token)
	hr.Header.Set("X-Spire-Agent-Version", "9.9.9")
	hr.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(hr)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out types.DeviceCertIssueResponse
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode issue response: %v", err)
		}
	}
	return resp.StatusCode, out, string(raw)
}

// TestPurposeCerts_Integration drives POST /api/v1/desktop/cert/issue and checks that only an
// AGENT certificate authenticates the agent API.
func TestPurposeCerts_Integration(t *testing.T) {
	pool := mtlsTestPool(t)
	defer pool.Close()
	ctx := context.Background()

	caDir := t.TempDir()
	ca, err := crypto.NewFileDeviceCA(caDir+"/ca.crt", caDir+"/ca.key")
	if err != nil {
		t.Fatal(err)
	}
	repo := db.NewRepository(pool)
	repo.SetDeviceCA(ca)

	uniq := time.Now().Format("150405.000000000")
	devID, token, leaf, key := claimDevice(t, ctx, repo, ca, "purpose-A-"+uniq)
	_, tokenB, _, _ := claimDevice(t, ctx, repo, ca, "purpose-B-"+uniq)

	r := chi.NewRouter()
	api.RegisterRoutesWithAlertsAndMTLS(r, repo, nil, t.TempDir(), nil, "optional", 30*24*time.Hour)
	serverCert, serverRoots := makeServerTLS(t)
	const addr = "127.0.0.1:19318"
	srv := &http.Server{
		Addr:    addr,
		Handler: r,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    ca.CertPool(),
			ClientAuth:   tls.VerifyClientCertIfGiven,
		},
	}
	ln := mustListen(t, addr)
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()
	waitForTLS(t, addr, serverRoots)

	issueURL := "https://" + addr + "/api/v1/desktop/cert/issue"
	statusURL := "https://" + addr + "/api/v1/desktop/status"
	agent := clientForLeaf(t, serverRoots, leaf, key)
	noCert := clientForLeaf(t, serverRoots, "", nil)

	// No agent certificate: refused even with a valid bearer token.
	csr, _ := newCSR(t)
	if code, _, body := postIssue(t, noCert, issueURL, token, types.DeviceCertIssueRequest{Purpose: types.CertPurposeNetwork, CSRPEM: csr}); code != http.StatusUnauthorized {
		t.Fatalf("issue without agent cert: got %d (%s), want 401", code, body)
	}
	// Agent certificate of device A with device B's bearer token: refused.
	if code, _, body := postIssue(t, agent, issueURL, tokenB, types.DeviceCertIssueRequest{Purpose: types.CertPurposeNetwork, CSRPEM: csr}); code != http.StatusForbidden {
		t.Fatalf("issue with another device's token: got %d (%s), want 403", code, body)
	}
	// Bad purposes and users.
	for name, req := range map[string]types.DeviceCertIssueRequest{
		"agent purpose":        {Purpose: types.CertPurposeAgent, CSRPEM: csr},
		"unknown purpose":      {Purpose: "vpn", CSRPEM: csr},
		"network with user":    {Purpose: types.CertPurposeNetwork, CSRPEM: csr, User: "alice"},
		"browser without user": {Purpose: types.CertPurposeBrowser, CSRPEM: csr},
		"browser bad user":     {Purpose: types.CertPurposeBrowser, CSRPEM: csr, User: "alice/../root"},
		"not a csr":            {Purpose: types.CertPurposeNetwork, CSRPEM: "garbage"},
	} {
		if code, _, body := postIssue(t, agent, issueURL, token, req); code != http.StatusBadRequest {
			t.Fatalf("%s: got %d (%s), want 400", name, code, body)
		}
	}

	// A network certificate is issued, recorded with its purpose, and returns the CA.
	netCSR, netKey := newCSR(t)
	code, netResp, body := postIssue(t, agent, issueURL, token, types.DeviceCertIssueRequest{Purpose: types.CertPurposeNetwork, CSRPEM: netCSR})
	if code != http.StatusOK {
		t.Fatalf("issue network: got %d (%s)", code, body)
	}
	if netResp.DeviceCACertPEM == "" || netResp.Purpose != types.CertPurposeNetwork {
		t.Fatalf("issue network: response missing CA or purpose: %+v", netResp)
	}
	rec, err := repo.GetDeviceCertificateBySerial(ctx, netResp.Serial)
	if err != nil || rec == nil || rec.Purpose != types.CertPurposeNetwork || rec.DeviceID != devID {
		t.Fatalf("network cert record: %+v, %v", rec, err)
	}

	// The network certificate chains to the device CA and names the device, but it must not
	// authenticate the agent API, nor be usable to get further certificates.
	netClient := clientForLeaf(t, serverRoots, netResp.DeviceCertificatePEM, netKey)
	if code := doGET(t, netClient, statusURL, token); code != http.StatusForbidden {
		t.Fatalf("network cert on agent API: got %d, want 403", code)
	}
	csr2, _ := newCSR(t)
	if code, _, body := postIssue(t, netClient, issueURL, token, types.DeviceCertIssueRequest{Purpose: types.CertPurposeNetwork, CSRPEM: csr2}); code != http.StatusForbidden {
		t.Fatalf("issue using a network cert: got %d (%s), want 403", code, body)
	}
	renewBody, _ := json.Marshal(types.DeviceCertRenewRequest{CSRPEM: csr2})
	rr, _ := http.NewRequest(http.MethodPost, "https://"+addr+"/api/v1/desktop/cert/renew", bytes.NewReader(renewBody))
	rr.Header.Set("Authorization", "Bearer "+token)
	rr.Header.Set("X-Spire-Agent-Version", "9.9.9")
	resp, err := netClient.Do(rr)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("renew using a network cert: got %d, want 403", resp.StatusCode)
	}
	// The agent certificate still works.
	if code := doGET(t, agent, statusURL, token); code != http.StatusOK {
		t.Fatalf("agent cert on agent API: got %d, want 200", code)
	}

	// A browser certificate names the user, and only the newest two per user stay live.
	var serials []string
	for i := 0; i < 3; i++ {
		c, _ := newCSR(t)
		code, br, body := postIssue(t, agent, issueURL, token, types.DeviceCertIssueRequest{Purpose: types.CertPurposeBrowser, CSRPEM: c, User: "alice"})
		if code != http.StatusOK {
			t.Fatalf("issue browser %d: got %d (%s)", i, code, body)
		}
		blk, _ := pem.Decode([]byte(br.DeviceCertificatePEM))
		leafCert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if crypto.UserFromCert(leafCert) != "alice" || crypto.DeviceIDFromCert(leafCert) != devID {
			t.Fatalf("browser leaf SANs: %v", leafCert.URIs)
		}
		serials = append(serials, br.Serial)
	}
	first, _ := repo.GetDeviceCertificateBySerial(ctx, serials[0])
	last, _ := repo.GetDeviceCertificateBySerial(ctx, serials[2])
	if first == nil || !first.Revoked() || last == nil || last.Revoked() {
		t.Fatalf("prune: oldest browser cert should be revoked, newest live: %+v / %+v", first, last)
	}

	// The per-device user cap: alice holds one already, so 7 more users fill it.
	for i := 0; i < 7; i++ {
		c, _ := newCSR(t)
		if code, _, body := postIssue(t, agent, issueURL, token, types.DeviceCertIssueRequest{Purpose: types.CertPurposeBrowser, CSRPEM: c, User: fmt.Sprintf("user%d", i)}); code != http.StatusOK {
			t.Fatalf("issue browser user%d: got %d (%s)", i, code, body)
		}
	}
	c, _ := newCSR(t)
	if code, _, body := postIssue(t, agent, issueURL, token, types.DeviceCertIssueRequest{Purpose: types.CertPurposeBrowser, CSRPEM: c, User: "one-too-many"}); code != http.StatusConflict {
		t.Fatalf("browser user cap: got %d (%s), want 409", code, body)
	}
	// An existing user can still renew at the cap.
	if code, _, body := postIssue(t, agent, issueURL, token, types.DeviceCertIssueRequest{Purpose: types.CertPurposeBrowser, CSRPEM: c, User: "alice"}); code != http.StatusOK {
		t.Fatalf("browser renew at cap: got %d (%s), want 200", code, body)
	}

	// Agent renewals keep only the newest two agent certificates live: after two renewals
	// the original agent certificate is revoked.
	for i := 0; i < 2; i++ {
		c, _ := newCSR(t)
		rb, _ := json.Marshal(types.DeviceCertRenewRequest{CSRPEM: c})
		req, _ := http.NewRequest(http.MethodPost, "https://"+addr+"/api/v1/desktop/cert/renew", bytes.NewReader(rb))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Spire-Agent-Version", "9.9.9")
		resp, err := agent.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("agent renew %d: got %d", i, resp.StatusCode)
		}
		// The second renewal revokes the certificate this client presents, so open a new
		// connection each time rather than reuse a verified one.
		agent.CloseIdleConnections()
	}
	live, err := repo.ListDeviceCertificates(ctx, devID, true, 0)
	if err != nil {
		t.Fatal(err)
	}
	agentLive := 0
	for _, c := range live {
		if c.Purpose == types.CertPurposeAgent {
			agentLive++
		}
	}
	if agentLive != 2 {
		t.Fatalf("after two agent renewals: %d live agent certificates, want 2", agentLive)
	}
	if code := doGET(t, agent, statusURL, token); code != http.StatusForbidden {
		t.Fatalf("original agent cert after two renewals: got %d, want 403", code)
	}

	// Revoking the device revokes every purpose.
	if _, err := repo.RevokeDevice(ctx, devID); err != nil {
		t.Fatal(err)
	}
	certs, err := repo.ListDeviceCertificates(ctx, devID, true, 0)
	if err != nil || len(certs) != 0 {
		t.Fatalf("after device revoke: %d active certs (%v)", len(certs), err)
	}
}
