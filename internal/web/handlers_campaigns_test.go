package web_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/audit"
	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/web"
	"github.com/spire-uem/spire-uem/internal/types"
)

func campaignWebPool(t *testing.T) *pgxpool.Pool {
	connStr := os.Getenv("SPIRE_TEST_DB_URL")
	if connStr == "" {
		t.Skip("SPIRE_TEST_DB_URL not set")
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Skipf("cannot connect: %v", err)
		return nil
	}
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("ping failed: %v", err)
		return nil
	}
	_ = db.RunMigrations(ctx, pool, "../../migrations")
	return pool
}

func seedAdmin(r *http.Request, u *types.AdminUser) *http.Request {
	ctx := context.WithValue(r.Context(), web.AdminUserObjCtxKey, u)
	ctx = context.WithValue(ctx, web.AdminUserCtxKey, u.Username)
	ctx = context.WithValue(ctx, web.AdminRoleCtxKey, u.Role)
	return r.WithContext(ctx)
}

func TestWebCampaign_CreateValidationAndScoping(t *testing.T) {
	pool := campaignWebPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	repo := db.NewRepository(pool)
	h, err := web.NewHandler(repo, nil, audit.NewForwarder(repo, ""))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	sfx := time.Now().Format("150405.000000")

	superAdmin := &types.AdminUser{ID: "sa", Username: "sa", Role: types.RoleSuperAdmin}
	financeAdmin := &types.AdminUser{ID: "fa", Username: "fa", Role: types.RoleSecurityAdmin, AllowedTags: []string{"finance-" + sfx}}

	// Invalid package name is rejected.
	badBody := `{"name":"bad","target_kind":"packages","packages":["-rf"]}`
	req := seedAdmin(httptest.NewRequest(http.MethodPost, "/admin/campaigns", strings.NewReader(badBody)), superAdmin)
	rec := httptest.NewRecorder()
	h.CreateCampaign(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid package should be rejected, got %d", rec.Code)
	}

	// Valid campaign by the finance-scoped admin.
	goodBody := `{"name":"finance-cmp-` + sfx + `","target_kind":"packages","packages":["curl"]}`
	req = seedAdmin(httptest.NewRequest(http.MethodPost, "/admin/campaigns", strings.NewReader(goodBody)), financeAdmin)
	rec = httptest.NewRecorder()
	h.CreateCampaign(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid campaign should be created, got %d body=%s", rec.Code, rec.Body.String())
	}
	var created campaign.Campaign
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if len(created.CreatorScopedTags) == 0 {
		t.Errorf("scoped admin's campaign should carry creator_scoped_tags")
	}

	// A fleet-wide campaign by the super admin.
	req = seedAdmin(httptest.NewRequest(http.MethodPost, "/admin/campaigns", strings.NewReader(`{"name":"fleet-cmp-`+sfx+`","target_kind":"packages","packages":["curl"]}`)), superAdmin)
	rec = httptest.NewRecorder()
	h.CreateCampaign(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("super admin campaign should be created, got %d", rec.Code)
	}

	// The finance admin's list must include their own campaign but NOT the fleet-wide one.
	req = seedAdmin(httptest.NewRequest(http.MethodGet, "/admin/campaigns", nil), financeAdmin)
	rec = httptest.NewRecorder()
	h.ListCampaigns(rec, req)
	var out struct {
		Campaigns []campaign.Campaign `json:"campaigns"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	sawOwn, sawFleet := false, false
	for _, c := range out.Campaigns {
		if c.Name == "finance-cmp-"+sfx {
			sawOwn = true
		}
		if c.Name == "fleet-cmp-"+sfx {
			sawFleet = true
		}
	}
	if !sawOwn {
		t.Errorf("finance admin should see their own campaign")
	}
	if sawFleet {
		t.Errorf("finance admin must NOT see the super admin's fleet-wide campaign")
	}
}

func TestWebRiskAcceptance_ExpiryCapAndScope(t *testing.T) {
	pool := campaignWebPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	repo := db.NewRepository(pool)
	h, err := web.NewHandler(repo, nil, audit.NewForwarder(repo, ""))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	sfx := time.Now().Format("150405.000000")
	superAdmin := &types.AdminUser{ID: "sa", Username: "sa", Role: types.RoleSuperAdmin}
	financeAdmin := &types.AdminUser{ID: "fa", Username: "fa", Role: types.RoleSecurityAdmin, AllowedTags: []string{"finance-" + sfx}}

	// Over-180-day expiry is rejected.
	over := `{"cve_id":"CVE-W-1","scope_kind":"all","reason":"x","expiry_days":200}`
	req := seedAdmin(httptest.NewRequest(http.MethodPost, "/admin/risk-acceptances", strings.NewReader(over)), superAdmin)
	rec := httptest.NewRecorder()
	h.CreateRiskAcceptance(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("over-180-day expiry must be rejected, got %d", rec.Code)
	}

	// A scoped admin cannot create a fleet-wide (all) acceptance.
	allByScoped := `{"cve_id":"CVE-W-2","scope_kind":"all","reason":"x","expiry_days":30}`
	req = seedAdmin(httptest.NewRequest(http.MethodPost, "/admin/risk-acceptances", strings.NewReader(allByScoped)), financeAdmin)
	rec = httptest.NewRecorder()
	h.CreateRiskAcceptance(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("scoped admin must not create a fleet-wide acceptance, got %d", rec.Code)
	}

	// A scoped admin scoping to a tag OUTSIDE their own is refused.
	outTag := `{"cve_id":"CVE-W-3","scope_kind":"tags","tags":["hr"],"reason":"x","expiry_days":30}`
	req = seedAdmin(httptest.NewRequest(http.MethodPost, "/admin/risk-acceptances", strings.NewReader(outTag)), financeAdmin)
	rec = httptest.NewRecorder()
	h.CreateRiskAcceptance(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("scoped admin must not scope outside their tags, got %d", rec.Code)
	}

	// A valid in-scope acceptance is created.
	inTag := `{"cve_id":"CVE-W-4","scope_kind":"tags","tags":["finance-` + sfx + `"],"reason":"compensating control","expiry_days":30}`
	req = seedAdmin(httptest.NewRequest(http.MethodPost, "/admin/risk-acceptances", strings.NewReader(inTag)), financeAdmin)
	rec = httptest.NewRecorder()
	h.CreateRiskAcceptance(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid in-scope acceptance should be created, got %d body=%s", rec.Code, rec.Body.String())
	}
}
