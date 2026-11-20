package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/posture"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/web"
)

var _ web.FleetPostureEvaluator = (*posture.Service)(nil)

func (e *apiEnv) mkPATFor(role types.AdminRole, tags []string) string {
	u, err := e.repo.CreateLocalAdminUser(context.Background(), types.CreateUserRequest{
		Username: e.uniq("pu"), Email: e.uniq("pm") + "@example.test", DisplayName: "t",
		Password: "Sup3r-secret-pw!", Role: role, AllowedTags: tags})
	if err != nil {
		e.t.Fatalf("user: %v", err)
	}
	raw, hash, prefix, _ := web.GeneratePAT()
	if _, err := e.repo.CreatePersonalAccessToken(context.Background(), hash, prefix, "t", u.ID, role, "test", time.Now().Add(time.Hour)); err != nil {
		e.t.Fatalf("pat: %v", err)
	}
	return raw
}

// formPost sends an urlencoded POST to an /admin route with a PAT (CSRF-exempt like Basic).
func (e *apiEnv) formPost(path, token string, form url.Values) apiResp {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.RemoteAddr = "192.0.2.30:4000"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return apiResp{rec}
}

func (e *apiEnv) activeQuarantine(id string) *types.DeviceQuarantine {
	q, err := e.repo.GetActiveQuarantine(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return q
}

func (e *apiEnv) auditCount(action, target string) int {
	var n int
	_ = e.pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM system_audit_events WHERE action=$1 AND target_id=$2`, action, target).Scan(&n)
	return n
}

// Quarantine and release through the real router and auth middleware: role floor, scope,
// tag scope with no existence oracle, mandatory reason, audit.
func TestPosture_AdminAPIQuarantineAuthorization(t *testing.T) {
	e := newAPIEnv(t)
	tag := e.uniq("pq")
	inDev, outDev := e.mkDevice(tag), e.mkDevice(e.uniq("other"))
	scoped := e.mkPATFor(types.RoleSecurityAdmin, []string{tag})
	op := e.mkPATFor(types.RoleOperator, []string{tag})
	aud := e.mkPATFor(types.RoleAuditor, nil)
	qPath := func(id string) string { return apiBase + "/devices/" + id + "/quarantine" }
	rPath := func(id string) string { return apiBase + "/devices/" + id + "/release" }
	body := `{"reason":"suspected compromise"}`

	if got := e.call("POST", qPath(inDev.ID), op, body); got.Code != 403 || got.errCode() != "insufficient_role" {
		t.Errorf("operator must not quarantine: %d %s", got.Code, got.errCode())
	}
	if got := e.call("POST", qPath(inDev.ID), aud, body); got.Code != 403 {
		t.Errorf("auditor must not quarantine: %d", got.Code)
	}
	if got := e.call("POST", qPath(inDev.ID), "", body); got.Code != 401 {
		t.Errorf("anonymous quarantine: %d", got.Code)
	}
	if e.activeQuarantine(inDev.ID) != nil {
		t.Fatal("a refused request created a quarantine")
	}

	// Out of tag scope looks exactly like an unknown device.
	outRes := e.call("POST", qPath(outDev.ID), scoped, body)
	unknown := e.call("POST", qPath("00000000-0000-4000-8000-000000000000"), scoped, body)
	if outRes.Code != 404 || unknown.Code != 404 || outRes.errCode() != unknown.errCode() {
		t.Errorf("out-of-scope %d/%s vs unknown %d/%s must be identical", outRes.Code, outRes.errCode(), unknown.Code, unknown.errCode())
	}
	if e.activeQuarantine(outDev.ID) != nil {
		t.Fatal("scoped admin quarantined an out-of-scope device")
	}

	if got := e.call("POST", qPath(inDev.ID), scoped, `{"reason":"  "}`); got.Code != 400 {
		t.Errorf("blank reason: %d, want 400", got.Code)
	}
	if got := e.call("POST", qPath(inDev.ID), scoped, body); got.Code != 200 {
		t.Fatalf("scoped security admin quarantine in scope: %d %s", got.Code, got.Body.String())
	}
	q := e.activeQuarantine(inDev.ID)
	if q == nil || q.Reason != "suspected compromise" || q.Source != types.QuarantineSourceManual {
		t.Fatalf("quarantine record = %+v", q)
	}
	if e.auditCount("DEVICE_QUARANTINE", inDev.ID) != 1 {
		t.Error("quarantine was not audited")
	}
	if got := e.call("POST", qPath(inDev.ID), scoped, body); got.Code != 200 {
		t.Errorf("repeat quarantine: %d", got.Code)
	}
	if e.auditCount("DEVICE_QUARANTINE", inDev.ID) != 1 {
		t.Error("repeat quarantine was audited twice")
	}

	if got := e.call("POST", rPath(inDev.ID), op, body); got.Code != 403 {
		t.Errorf("operator must not release: %d", got.Code)
	}
	if got := e.call("POST", rPath(outDev.ID), scoped, body); got.Code != 404 {
		t.Errorf("scoped release out of scope: %d, want 404", got.Code)
	}
	if got := e.call("POST", rPath(inDev.ID), scoped, `{}`); got.Code != 400 {
		t.Errorf("release without reason: %d, want 400", got.Code)
	}
	if e.activeQuarantine(inDev.ID) == nil {
		t.Fatal("refused releases ended the quarantine")
	}
	if got := e.call("POST", rPath(inDev.ID), scoped, `{"reason":"cleaned"}`); got.Code != 200 {
		t.Fatalf("release: %d %s", got.Code, got.Body.String())
	}
	if e.activeQuarantine(inDev.ID) != nil {
		t.Fatal("release did not end the quarantine")
	}
	if e.auditCount("DEVICE_RELEASE", inDev.ID) != 1 {
		t.Error("release was not audited")
	}
}

// The same rules hold on the /admin routes used by the device page.
func TestPosture_AdminUIQuarantineAuthorization(t *testing.T) {
	e := newAPIEnv(t)
	tag := e.uniq("pu")
	inDev, outDev := e.mkDevice(tag), e.mkDevice(e.uniq("other"))
	scoped := e.mkPATFor(types.RoleSecurityAdmin, []string{tag})
	full := e.mkPATFor(types.RoleSecurityAdmin, nil)
	op := e.mkPATFor(types.RoleOperator, nil)
	aud := e.mkPATFor(types.RoleAuditor, nil)
	form := url.Values{"reason": {"lab test"}}

	if got := e.formPost("/admin/devices/"+inDev.ID+"/quarantine", op, form); got.Code != 403 {
		t.Errorf("operator quarantine: %d", got.Code)
	}
	if got := e.formPost("/admin/devices/"+inDev.ID+"/quarantine", aud, form); got.Code != 403 {
		t.Errorf("auditor quarantine: %d", got.Code)
	}
	if got := e.formPost("/admin/devices/"+outDev.ID+"/quarantine", scoped, form); got.Code != 404 {
		t.Errorf("scoped admin out-of-scope quarantine: %d, want 404", got.Code)
	}
	if e.activeQuarantine(outDev.ID) != nil {
		t.Fatal("out-of-scope quarantine was created")
	}
	if got := e.formPost("/admin/devices/"+inDev.ID+"/quarantine", scoped, url.Values{}); got.Code != 400 {
		t.Errorf("quarantine without reason: %d, want 400", got.Code)
	}
	if got := e.formPost("/admin/devices/"+inDev.ID+"/quarantine", scoped, form); got.Code != 200 {
		t.Fatalf("in-scope quarantine: %d %s", got.Code, got.Body.String())
	}
	if got := e.formPost("/admin/devices/"+outDev.ID+"/release", scoped, form); got.Code != 404 {
		t.Errorf("scoped release out of scope: %d", got.Code)
	}
	if got := e.formPost("/admin/devices/"+inDev.ID+"/release", scoped, form); got.Code != 200 {
		t.Errorf("in-scope release: %d", got.Code)
	}
	if got := e.formPost("/admin/devices/"+outDev.ID+"/quarantine", full, form); got.Code != 200 {
		t.Errorf("unscoped quarantine: %d", got.Code)
	}
	if e.activeQuarantine(outDev.ID) == nil {
		t.Error("unscoped quarantine not recorded")
	}
}

func TestPosture_RuleSetEditAuthorizationAndAudit(t *testing.T) {
	e := newAPIEnv(t)
	ctx := context.Background()
	orig, err := e.repo.GetAccessRuleSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cur, _ := e.repo.GetAccessRuleSet(ctx)
		_, _ = e.repo.SaveAccessRuleSet(ctx, orig, cur.Version, "restore")
	})
	scoped := e.mkPATFor(types.RoleSecurityAdmin, []string{e.uniq("t")})
	full := e.mkPATFor(types.RoleSecurityAdmin, nil)
	op := e.mkPATFor(types.RoleOperator, nil)
	aud := e.mkPATFor(types.RoleAuditor, nil)

	mkForm := func() url.Values {
		cur, _ := e.repo.GetAccessRuleSet(ctx)
		return url.Values{"expected_version": {strconv.Itoa(cur.Version)}, "checkin_enabled": {"1"}, "checkin_hours": {"12"}, "disk_enabled": {"1"}}
	}

	for name, tok := range map[string]string{"auditor": aud, "operator": op, "scoped": scoped, "full": full} {
		req := httptest.NewRequest("GET", "/admin/access-posture", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		e.router.ServeHTTP(rec, req)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "Access Posture") {
			t.Errorf("%s GET page: %d", name, rec.Code)
		}
	}

	before, _ := e.repo.GetAccessRuleSet(ctx)
	if got := e.formPost("/admin/access-posture", aud, mkForm()); got.Code != 403 {
		t.Errorf("auditor edit: %d, want 403", got.Code)
	}
	if got := e.formPost("/admin/access-posture", op, mkForm()); got.Code != 403 {
		t.Errorf("operator edit: %d, want 403", got.Code)
	}
	// Fleet-wide rules: a tag-scoped admin must not change verdicts outside their tags.
	if got := e.formPost("/admin/access-posture", scoped, mkForm()); got.Code != 403 {
		t.Errorf("tag-scoped admin edit: %d, want 403", got.Code)
	}
	after, _ := e.repo.GetAccessRuleSet(ctx)
	if after.Version != before.Version {
		t.Fatal("a refused edit changed the rule set")
	}

	form := mkForm()
	if got := e.formPost("/admin/access-posture", full, form); got.Code != 200 {
		t.Fatalf("security admin edit: %d %s", got.Code, got.Body.String())
	}
	cur, _ := e.repo.GetAccessRuleSet(ctx)
	if cur.Version != before.Version+1 || !cur.DiskEncrypted.Enabled || cur.CheckinFresh.MaxAgeHours != 12 {
		t.Fatalf("saved rule set = %+v", cur)
	}
	if got := e.formPost("/admin/access-posture", full, form); got.Code != 409 {
		t.Errorf("stale edit: %d, want 409", got.Code)
	}
	bad := mkForm()
	bad.Set("cve_enabled", "1")
	bad.Set("cve_min_urgency", "extreme")
	if got := e.formPost("/admin/access-posture", full, bad); got.Code != 400 {
		t.Errorf("invalid urgency: %d, want 400", got.Code)
	}
	var n int
	_ = e.pool.QueryRow(ctx, `SELECT COUNT(*) FROM system_audit_events WHERE action='ACCESS_RULESET_UPDATE' AND created_at > NOW() - interval '1 minute'`).Scan(&n)
	if n < 1 {
		t.Error("rule-set edit was not audited")
	}
}
