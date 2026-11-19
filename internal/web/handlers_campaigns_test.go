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

	"github.com/go-chi/chi/v5"
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

// TestWebCampaign_ResumeControls: resuming a HALTED campaign re-queues the stage's failed
// devices (otherwise the stale failure re-halts it at once, as seen on a real VM), and a
// finished campaign can be neither resumed nor paused back to life.
func TestWebCampaign_ResumeControls(t *testing.T) {
	pool := campaignWebPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	h, err := web.NewHandler(repo, nil, audit.NewForwarder(repo, ""))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	sfx := time.Now().Format("150405.000000000")
	superAdmin := &types.AdminUser{ID: "sa", Username: "sa", Role: types.RoleSuperAdmin}

	c, err := repo.CreateCampaign(ctx, &campaign.Campaign{Name: "resume-" + sfx, TargetKind: campaign.TargetPackages, Packages: []string{"curl"}, RebootPolicy: campaign.RebootNever, CreatedBy: "sa"})
	if err != nil {
		t.Fatal(err)
	}
	dev, _, err := repo.GetOrCreateDevice(ctx, "resume-"+sfx, "resume-host")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO campaign_device_work (campaign_id, device_id, stage, state, failure_class, last_output, dispatched_at)
		VALUES ($1,$2,0,'FAILED','held','E: Held packages were changed', NOW())`, c.ID, dev.ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetCampaignState(ctx, c.ID, campaign.StateHalted); err != nil {
		t.Fatal(err)
	}

	control := func(action string, fn func(http.ResponseWriter, *http.Request)) int {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", c.ID)
		req := httptest.NewRequest(http.MethodPost, "/admin/campaigns/"+c.ID+"/"+action, nil)
		req = seedAdmin(req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx)), superAdmin)
		w := httptest.NewRecorder()
		fn(w, req)
		return w.Code
	}

	if code := control("resume", h.ResumeCampaign); code != http.StatusOK {
		t.Fatalf("resume HTTP %d", code)
	}
	var state, class string
	var dispatched *time.Time
	if err := pool.QueryRow(ctx, `SELECT state, failure_class, dispatched_at FROM campaign_device_work WHERE campaign_id=$1 AND device_id=$2`, c.ID, dev.ID).Scan(&state, &class, &dispatched); err != nil {
		t.Fatal(err)
	}
	if state != "PENDING" || class != "" || dispatched != nil {
		t.Fatalf("failed device should be re-queued cleanly, got state=%s class=%q dispatched=%v", state, class, dispatched)
	}
	if got, _ := repo.GetCampaign(ctx, c.ID); got.State != campaign.StateRunning {
		t.Fatalf("state = %s, want RUNNING", got.State)
	}

	if code := control("cancel", h.CancelCampaign); code != http.StatusOK {
		t.Fatalf("cancel HTTP %d", code)
	}
	for action, fn := range map[string]func(http.ResponseWriter, *http.Request){
		"resume": h.ResumeCampaign, "pause": h.PauseCampaign, "cancel": h.CancelCampaign,
	} {
		if code := control(action, fn); code != http.StatusBadRequest {
			t.Errorf("%s of a cancelled campaign must be refused, got HTTP %d", action, code)
		}
	}
	if got, _ := repo.GetCampaign(ctx, c.ID); got.State != campaign.StateCancelled {
		t.Fatalf("state = %s, want CANCELLED", got.State)
	}
}
