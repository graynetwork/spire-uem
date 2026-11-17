package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/api"
	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

func mtlsTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connStr := os.Getenv("SPIRE_TEST_DB_URL")
	if connStr == "" {
		t.Skip("skipping mTLS integration test: SPIRE_TEST_DB_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Skipf("skipping: cannot connect to postgres: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("skipping: postgres ping failed: %v", err)
	}
	if err := db.RunMigrations(ctx, pool, "../../migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return pool
}

// makeServerTLS generates a throwaway server leaf for 127.0.0.1 so the client can dial a real
// TLS endpoint. Returns the tls cert and a RootCAs pool trusting it.
func makeServerTLS(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: bigOne(),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	tmpl.IPAddresses = append(tmpl.IPAddresses, parseIP("127.0.0.1"))
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	tlsCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
	_ = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tlsCert, pool
}

// clientForLeaf builds an HTTPS client that trusts serverRoots and presents the given leaf
// (built from leafPEM + key) as its client certificate, or no client cert when leafPEM is "".
func clientForLeaf(t *testing.T, serverRoots *x509.CertPool, leafPEM string, key *ecdsa.PrivateKey) *http.Client {
	t.Helper()
	cfg := &tls.Config{RootCAs: serverRoots, MinVersion: tls.VersionTLS12}
	if leafPEM != "" {
		keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		pair, err := tls.X509KeyPair([]byte(leafPEM), keyPEM)
		if err != nil {
			t.Fatalf("build client keypair: %v", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}
}

// claimDevice approves a device, claims its token, and issues it a client cert from the CA,
// mirroring what the enroll/claim path does. Returns device id, bearer token, leaf PEM, key.
func claimDevice(t *testing.T, ctx context.Context, repo *db.Repository, ca crypto.DeviceCA, hw string) (string, string, string, *ecdsa.PrivateKey) {
	t.Helper()
	dev, _, err := repo.GetOrCreateDevice(ctx, hw, hw+"-host")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.ApproveDevice(ctx, dev.ID); err != nil {
		t.Fatal(err)
	}
	dev, _ = repo.GetDeviceByID(ctx, dev.ID)
	token, err := repo.ClaimApprovedToken(ctx, dev)
	if err != nil {
		t.Fatalf("claim token: %v", err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hw}}, key)
	issued, err := ca.IssueFromCSR(csrDER, dev.ID, 0)
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	if _, err := repo.StoreDeviceCertificate(ctx, dev.ID, issued.Serial, issued.FingerprintSHA256, issued.NotBefore, issued.NotAfter); err != nil {
		t.Fatalf("store cert: %v", err)
	}
	return dev.ID, token, string(issued.CertPEM), key
}

func TestMTLS_RequiredMode_Integration(t *testing.T) {
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

	// Two devices: A (the caller) and B (whose cert A will try to misuse).
	uniq := time.Now().Format("150405.000000000")
	devA, tokenA, leafA, keyA := claimDevice(t, ctx, repo, ca, "mtls-A-"+uniq)
	devB, _, leafB, keyB := claimDevice(t, ctx, repo, ca, "mtls-B-"+uniq)
	_ = devA
	_ = devB

	r := chi.NewRouter()
	api.RegisterRoutesWithAlertsAndMTLS(r, repo, nil, t.TempDir(), nil, "required", 30*24*time.Hour)

	serverCert, serverRoots := makeServerTLS(t)
	srv := &http.Server{
		Addr:    "127.0.0.1:19310",
		Handler: r,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    ca.CertPool(),
			ClientAuth:   tls.VerifyClientCertIfGiven,
		},
	}
	ln := mustListen(t, "127.0.0.1:19310")
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()
	waitForTLS(t, "127.0.0.1:19310", serverRoots)

	url := "https://127.0.0.1:19310/api/v1/desktop/status"

	// 1. Required mode, NO client cert -> rejected (403).
	noCert := clientForLeaf(t, serverRoots, "", nil)
	if code := doGET(t, noCert, url, tokenA); code != http.StatusForbidden {
		t.Fatalf("no-cert in required mode: got %d, want 403", code)
	}

	// 2. Valid matching cert + matching bearer token -> accepted (200).
	okClient := clientForLeaf(t, serverRoots, leafA, keyA)
	if code := doGET(t, okClient, url, tokenA); code != http.StatusOK {
		t.Fatalf("valid cert+token: got %d, want 200", code)
	}

	// 3. Cert belongs to device B but the bearer token is device A -> rejected (403).
	mismatch := clientForLeaf(t, serverRoots, leafB, keyB)
	if code := doGET(t, mismatch, url, tokenA); code != http.StatusForbidden {
		t.Fatalf("cert/token device mismatch: got %d, want 403", code)
	}

	// 4. Revoke device A (which revokes its cert) -> its previously-valid cert is rejected.
	if _, err := repo.RevokeDevice(ctx, devA); err != nil {
		t.Fatal(err)
	}
	if code := doGET(t, okClient, url, tokenA); code != http.StatusForbidden {
		t.Fatalf("revoked cert: got %d, want 403", code)
	}
}

func doGET(t *testing.T, client *http.Client, url, token string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Spire-Agent-Version", "9.9.9")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestMTLS_RenewEndpoint_Integration drives the renewal endpoint: it requires a valid current
// client cert AND the device's bearer token, and returns a fresh leaf.
func TestMTLS_RenewEndpoint_Integration(t *testing.T) {
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
	_, token, leaf, key := claimDevice(t, ctx, repo, ca, "mtls-renew-"+uniq)

	r := chi.NewRouter()
	api.RegisterRoutesWithAlertsAndMTLS(r, repo, nil, t.TempDir(), nil, "required", 30*24*time.Hour)
	serverCert, serverRoots := makeServerTLS(t)
	srv := &http.Server{
		Addr:    "127.0.0.1:19311",
		Handler: r,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    ca.CertPool(),
			ClientAuth:   tls.VerifyClientCertIfGiven,
		},
	}
	ln := mustListen(t, "127.0.0.1:19311")
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()
	waitForTLS(t, "127.0.0.1:19311", serverRoots)

	url := "https://127.0.0.1:19311/api/v1/desktop/cert/renew"
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "renew"}}, newKey)
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	body, _ := json.Marshal(types.DeviceCertRenewRequest{CSRPEM: csrPEM})

	client := clientForLeaf(t, serverRoots, leaf, key)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Spire-Agent-Version", "9.9.9")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("renew: got %d, want 200 (%s)", resp.StatusCode, b)
	}
	var out types.DeviceCertRenewResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.DeviceCertificatePEM == "" {
		t.Fatal("renew returned no certificate")
	}

	// Renewal with no client cert must be refused even with a valid token.
	noCert := clientForLeaf(t, serverRoots, "", nil)
	req2, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("X-Spire-Agent-Version", "9.9.9")
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := noCert.Do(req2)
	if err != nil {
		t.Fatalf("renew no-cert: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Fatal("renewal without a client certificate must not succeed")
	}
}

// TestMTLS_OptionalMode_Integration verifies optional mode: a request with no client cert is
// allowed on the bearer token alone, but a presented cert must still be valid and match.
func TestMTLS_OptionalMode_Integration(t *testing.T) {
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
	_, tokenA, _, _ := claimDevice(t, ctx, repo, ca, "mtls-optA-"+uniq)
	_, _, leafB, keyB := claimDevice(t, ctx, repo, ca, "mtls-optB-"+uniq)

	r := chi.NewRouter()
	api.RegisterRoutesWithAlertsAndMTLS(r, repo, nil, t.TempDir(), nil, "optional", 30*24*time.Hour)
	serverCert, serverRoots := makeServerTLS(t)
	srv := &http.Server{
		Addr:    "127.0.0.1:19312",
		Handler: r,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    ca.CertPool(),
			ClientAuth:   tls.VerifyClientCertIfGiven,
		},
	}
	ln := mustListen(t, "127.0.0.1:19312")
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()
	waitForTLS(t, "127.0.0.1:19312", serverRoots)
	url := "https://127.0.0.1:19312/api/v1/desktop/status"

	// No client cert: allowed on the bearer token alone (optional mode).
	noCert := clientForLeaf(t, serverRoots, "", nil)
	if code := doGET(t, noCert, url, tokenA); code != http.StatusOK {
		t.Fatalf("optional mode, no cert: got %d, want 200", code)
	}
	// A presented cert that belongs to device B with device A's token is still rejected.
	mismatch := clientForLeaf(t, serverRoots, leafB, keyB)
	if code := doGET(t, mismatch, url, tokenA); code != http.StatusForbidden {
		t.Fatalf("optional mode, mismatched cert: got %d, want 403", code)
	}
}

func mustListen(t *testing.T, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	return ln
}

func waitForTLS(t *testing.T, addr string, roots *x509.CertPool) {
	t.Helper()
	for i := 0; i < 50; i++ {
		c, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots})
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s did not come up", addr)
}

func bigOne() *big.Int { return big.NewInt(time.Now().UnixNano()) }

func parseIP(s string) net.IP { return net.ParseIP(s) }

// TestMTLS_FirstIssueWithoutCert_Integration covers devices that have no active certificate
// (enrolled before mTLS, or certificate expired while offline). In required mode they may
// obtain a first certificate with their bearer token alone; once they hold one, a no-cert
// request is refused again. The resulting certificate is then accepted by gated endpoints.
func TestMTLS_FirstIssueWithoutCert_Integration(t *testing.T) {
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

	// Approve and claim WITHOUT issuing a certificate (a pre-mTLS device).
	hw := "mtls-first-" + time.Now().Format("150405.000000000")
	dev, _, err := repo.GetOrCreateDevice(ctx, hw, hw+"-host")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.ApproveDevice(ctx, dev.ID); err != nil {
		t.Fatal(err)
	}
	dev, _ = repo.GetDeviceByID(ctx, dev.ID)
	token, err := repo.ClaimApprovedToken(ctx, dev)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	api.RegisterRoutesWithAlertsAndMTLS(r, repo, nil, t.TempDir(), nil, "required", 30*24*time.Hour)
	serverCert, serverRoots := makeServerTLS(t)
	srv := &http.Server{
		Addr:    "127.0.0.1:19313",
		Handler: r,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    ca.CertPool(),
			ClientAuth:   tls.VerifyClientCertIfGiven,
		},
	}
	ln := mustListen(t, "127.0.0.1:19313")
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	defer srv.Close()
	waitForTLS(t, "127.0.0.1:19313", serverRoots)

	renewURL := "https://127.0.0.1:19313/api/v1/desktop/cert/renew"
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hw}}, key)
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	body, _ := json.Marshal(types.DeviceCertRenewRequest{CSRPEM: csrPEM})
	post := func(c *http.Client, tok string) (int, types.DeviceCertRenewResponse) {
		req, _ := http.NewRequest(http.MethodPost, renewURL, bytes.NewReader(body))
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("renew request: %v", err)
		}
		defer resp.Body.Close()
		var out types.DeviceCertRenewResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	noCert := clientForLeaf(t, serverRoots, "", nil)

	// No bearer token: refused.
	if code, _ := post(noCert, ""); code != http.StatusForbidden {
		t.Fatalf("first issue without token: got %d, want 403", code)
	}
	// Bearer token, no active cert: a first certificate is issued.
	code, out := post(noCert, token)
	if code != http.StatusOK || out.DeviceCertificatePEM == "" {
		t.Fatalf("first issue with token: got %d (cert empty=%v), want 200 with a cert", code, out.DeviceCertificatePEM == "")
	}
	// The new certificate works on a gated endpoint.
	withCert := clientForLeaf(t, serverRoots, out.DeviceCertificatePEM, key)
	if c := doGET(t, withCert, "https://127.0.0.1:19313/api/v1/desktop/status", token); c != http.StatusOK {
		t.Fatalf("gated endpoint with first-issued cert: got %d, want 200", c)
	}
	// Now that an active certificate exists, a token-only request is refused.
	if code, _ := post(noCert, token); code != http.StatusUnauthorized {
		t.Fatalf("token-only issuance with an active cert: got %d, want 401", code)
	}
}
