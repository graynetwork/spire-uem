package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/api"
	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// TestRenew_BearerOnlyRefusedAfterAdminRevoke covers the revoke gap: after an admin revokes a
// device's agent certificate, the bearer token alone must not fetch a new one until an admin
// re-approves issuance. A device whose certificate merely expired keeps the old behaviour.
func TestRenew_BearerOnlyRefusedAfterAdminRevoke(t *testing.T) {
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
	r := chi.NewRouter()
	api.RegisterRoutesWithAlertsAndMTLS(r, repo, nil, t.TempDir(), nil, "optional", 30*24*time.Hour)

	renew := func(token string) *httptest.ResponseRecorder {
		csr, _ := newCSR(t)
		body, _ := json.Marshal(types.DeviceCertRenewRequest{CSRPEM: csr})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/desktop/cert/renew", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}
	uniq := time.Now().Format("150405.000000000")

	// 1. An admin revokes the agent certificate: bearer-only renewal is refused.
	devID, token, _, _ := claimDevice(t, ctx, repo, ca, "reapprove-A-"+uniq)
	certs, _ := repo.ListDeviceCertificates(ctx, devID, true, 0)
	if len(certs) != 1 {
		t.Fatalf("want 1 active certificate, got %d", len(certs))
	}
	if c, err := repo.RevokeDeviceCertificateByAdmin(ctx, devID, certs[0].ID); err != nil || c == nil {
		t.Fatalf("revoke: %v %v", c, err)
	}
	if rec := renew(token); rec.Code != http.StatusForbidden {
		t.Fatalf("bearer-only renew after admin revoke: got %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	if active, _ := repo.GetActiveDeviceCertificate(ctx, devID); active != nil {
		t.Fatalf("a refused renew must not issue a certificate")
	}

	// 2. Re-approval: the same request now works.
	if was, found, err := repo.ApproveDeviceCertIssuance(ctx, devID); err != nil || !found || !was {
		t.Fatalf("approve issuance: was=%v found=%v err=%v", was, found, err)
	}
	if rec := renew(token); rec.Code != http.StatusOK {
		t.Fatalf("bearer-only renew after re-approval: got %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	// And the flag is not set again by the issuance.
	if blocked, _ := repo.DeviceCertReapprovalRequired(ctx, devID); blocked {
		t.Fatalf("flag must stay clear after re-approval")
	}

	// 3. An expired, unrevoked certificate keeps today's behaviour.
	devB, tokenB, _, _ := claimDevice(t, ctx, repo, ca, "reapprove-B-"+uniq)
	if _, err := pool.Exec(ctx, `UPDATE device_certificates SET not_before = now() - interval '2 days', not_after = now() - interval '1 hour' WHERE device_id = $1`, devB); err != nil {
		t.Fatal(err)
	}
	if blocked, _ := repo.DeviceCertReapprovalRequired(ctx, devB); blocked {
		t.Fatalf("an expired certificate must not set the flag")
	}
	if rec := renew(tokenB); rec.Code != http.StatusOK {
		t.Fatalf("bearer-only renew with an expired certificate: got %d, want 200 (%s)", rec.Code, rec.Body.String())
	}

	// 4. A device that never held a certificate keeps today's behaviour.
	dev, _, _ := repo.GetOrCreateDevice(ctx, "reapprove-C-"+uniq, "reapprove-C-"+uniq+"-host")
	_, _, _ = repo.ApproveDevice(ctx, dev.ID)
	dev, _ = repo.GetDeviceByID(ctx, dev.ID)
	tokenC, err := repo.ClaimApprovedToken(ctx, dev)
	if err != nil {
		t.Fatal(err)
	}
	if rec := renew(tokenC); rec.Code != http.StatusOK {
		t.Fatalf("bearer-only renew for a device that never had a certificate: got %d, want 200 (%s)", rec.Code, rec.Body.String())
	}

	// 5. Revoking a NETWORK certificate does not set the flag.
	devD, _, _, _ := claimDevice(t, ctx, repo, ca, "reapprove-D-"+uniq)
	nc, err := repo.StoreDeviceCertificateFor(ctx, devD, types.CertPurposeNetwork, "", "net-"+uniq, "fp-"+uniq, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if c, err := repo.RevokeDeviceCertificateByAdmin(ctx, devD, nc.ID); err != nil || c == nil {
		t.Fatalf("revoke network cert: %v %v", c, err)
	}
	if blocked, _ := repo.DeviceCertReapprovalRequired(ctx, devD); blocked {
		t.Fatalf("revoking a network certificate must not set the re-approval flag")
	}
}
