package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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

func enrollTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connStr := os.Getenv("SPIRE_TEST_DB_URL")
	if connStr == "" {
		t.Skip("skipping enrollment API test: SPIRE_TEST_DB_URL not set")
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

func enrollKey(seed string) string {
	for len(seed) < 64 {
		seed += "abcdef0123456789"
	}
	return seed[:64]
}

func buildCSR(t *testing.T, hw string) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hw}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func postRegister(t *testing.T, srv *httptest.Server, body types.EnrollmentRegisterRequest) (int, types.EnrollmentRegisterResponse, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := srv.Client().Post(srv.URL+"/api/v1/enrollment/register", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out types.EnrollmentRegisterResponse
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, string(raw)
}

func TestRegisterWithToken_AutoApproveIssuesCert(t *testing.T) {
	pool := enrollTestPool(t)
	defer pool.Close()
	ctx := context.Background()
	caDir := t.TempDir()
	ca, err := crypto.NewFileDeviceCA(caDir+"/ca.crt", caDir+"/ca.key")
	if err != nil {
		t.Fatal(err)
	}
	repo := db.NewRepository(pool)
	repo.SetDeviceCA(ca)

	tok, raw, err := repo.CreateEnrollmentToken(ctx, types.CreateTokenRequest{Description: "api-auto", TargetRing: types.RingProduction, CreatedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	api.RegisterRoutesWithAlertsAndMTLS(r, repo, nil, t.TempDir(), nil, "optional", 30*24*time.Hour)
	srv := httptest.NewServer(r)
	defer srv.Close()

	hw := "api-auto-" + time.Now().Format("150405.000000")
	code, out, body := postRegister(t, srv, types.EnrollmentRegisterRequest{
		Token: raw, HardwareUUID: hw, Hostname: "auto-host", EnrollmentKey: enrollKey("autok"), CSRPEM: buildCSR(t, hw),
	})
	if code != http.StatusOK {
		t.Fatalf("auto-approve expected 200, got %d: %s", code, body)
	}
	if out.Status != types.StatusApproved || out.AuthToken == "" {
		t.Fatalf("expected APPROVED with bearer token, got status=%s token=%q", out.Status, out.AuthToken)
	}
	if out.DeviceCertificatePEM == "" {
		t.Fatalf("a device certificate must be issued at token registration when a CA is configured")
	}
	// History must record an 'approved' row.
	hist, _ := repo.ListEnrollmentRegistrations(ctx, tok.ID, 10)
	if len(hist) != 1 || hist[0].Result != types.EnrollResultApproved {
		t.Fatalf("expected one approved history row, got %+v", hist)
	}
}

func TestRegisterWithToken_UniformRefusalHidesExistence(t *testing.T) {
	pool := enrollTestPool(t)
	defer pool.Close()
	repo := db.NewRepository(pool)

	// A real revoked token and a totally bogus token must return the SAME status and body.
	tok, raw, _ := repo.CreateEnrollmentToken(context.Background(), types.CreateTokenRequest{Description: "revme", CreatedBy: "admin"})
	_ = repo.RevokeEnrollmentToken(context.Background(), tok.ID)

	r := chi.NewRouter()
	api.RegisterRoutesWithAlertsAndMTLS(r, repo, nil, t.TempDir(), nil, "optional", time.Hour)
	srv := httptest.NewServer(r)
	defer srv.Close()

	hw := "api-ref-" + time.Now().Format("150405.000000")
	codeRevoked, _, bodyRevoked := postRegister(t, srv, types.EnrollmentRegisterRequest{Token: raw, HardwareUUID: hw, Hostname: "h", EnrollmentKey: enrollKey("k1")})
	codeBogus, _, bodyBogus := postRegister(t, srv, types.EnrollmentRegisterRequest{Token: "spire_tok_deadbeef", HardwareUUID: hw + "x", Hostname: "h", EnrollmentKey: enrollKey("k2")})

	if codeRevoked != http.StatusUnauthorized || codeBogus != http.StatusUnauthorized {
		t.Fatalf("both must be 401, got revoked=%d bogus=%d", codeRevoked, codeBogus)
	}
	if bodyRevoked != bodyBogus {
		t.Fatalf("refusal body must be uniform; revoked=%q bogus=%q", bodyRevoked, bodyBogus)
	}
}

func TestRegisterWithToken_HostnamePatternRefused(t *testing.T) {
	pool := enrollTestPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	tok, raw, _ := repo.CreateEnrollmentToken(ctx, types.CreateTokenRequest{Description: "host", HostnamePattern: "lab-*", CreatedBy: "admin"})

	r := chi.NewRouter()
	api.RegisterRoutesWithAlertsAndMTLS(r, repo, nil, t.TempDir(), nil, "optional", time.Hour)
	srv := httptest.NewServer(r)
	defer srv.Close()

	// Non-matching hostname: refused, nothing registered, history records a refusal.
	code, _, _ := postRegister(t, srv, types.EnrollmentRegisterRequest{Token: raw, HardwareUUID: "api-hp-bad-" + time.Now().Format("150405.000000"), Hostname: "corp-ws1", EnrollmentKey: enrollKey("hp1")})
	if code != http.StatusUnauthorized {
		t.Fatalf("non-matching hostname must be refused, got %d", code)
	}
	// Matching hostname: accepted.
	code2, out2, body2 := postRegister(t, srv, types.EnrollmentRegisterRequest{Token: raw, HardwareUUID: "api-hp-ok-" + time.Now().Format("150405.000000"), Hostname: "lab-42", EnrollmentKey: enrollKey("hp2")})
	if code2 != http.StatusOK || out2.Status != types.StatusApproved {
		t.Fatalf("matching hostname must register, got %d: %s", code2, body2)
	}
	hist, _ := repo.ListEnrollmentRegistrations(ctx, tok.ID, 10)
	var refused, approved int
	for _, h := range hist {
		switch h.Result {
		case types.EnrollResultRefused:
			refused++
		case types.EnrollResultApproved:
			approved++
		}
	}
	if refused != 1 || approved != 1 {
		t.Fatalf("expected 1 refused + 1 approved history rows, got refused=%d approved=%d", refused, approved)
	}
}

func TestRegisterWithToken_RequireApprovalNoToken(t *testing.T) {
	pool := enrollTestPool(t)
	defer pool.Close()
	repo := db.NewRepository(pool)
	_, raw, _ := repo.CreateEnrollmentToken(context.Background(), types.CreateTokenRequest{Description: "manual", RequireApproval: true, CreatedBy: "admin"})

	r := chi.NewRouter()
	api.RegisterRoutesWithAlertsAndMTLS(r, repo, nil, t.TempDir(), nil, "optional", time.Hour)
	srv := httptest.NewServer(r)
	defer srv.Close()

	hw := "api-manual-" + time.Now().Format("150405.000000")
	code, out, body := postRegister(t, srv, types.EnrollmentRegisterRequest{Token: raw, HardwareUUID: hw, Hostname: "h", EnrollmentKey: enrollKey("mk")})
	if code != http.StatusOK {
		t.Fatalf("require_approval registration should be 200, got %d: %s", code, body)
	}
	if out.Status != types.StatusPendingApproval || out.AuthToken != "" {
		t.Fatalf("require_approval must return PENDING_APPROVAL with no token, got status=%s token=%q", out.Status, out.AuthToken)
	}
}

func TestRegisterWithToken_RateLimited(t *testing.T) {
	pool := enrollTestPool(t)
	defer pool.Close()
	repo := db.NewRepository(pool)

	r := chi.NewRouter()
	api.RegisterRoutesWithAlertsAndMTLS(r, repo, nil, t.TempDir(), nil, "optional", time.Hour)
	srv := httptest.NewServer(r)
	defer srv.Close()

	// 10 failures per minute per IP is the default; the 11th failed attempt must be 429.
	var got429 bool
	for i := 0; i < 15; i++ {
		code, _, _ := postRegister(t, srv, types.EnrollmentRegisterRequest{Token: "spire_tok_bad", HardwareUUID: fmt.Sprintf("rl-%d", i), Hostname: "h", EnrollmentKey: enrollKey("rk")})
		if code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatalf("expected a 429 after repeated failed enrollment attempts from one IP")
	}
}
