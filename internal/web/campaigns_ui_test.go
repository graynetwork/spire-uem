package web_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/audit"
	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/web"
)

// uiEnv drives the real router and auth middleware with real session cookies, so RBAC, CSRF
// and tag scoping are exercised exactly as in production.
type uiEnv struct {
	t      *testing.T
	pool   *pgxpool.Pool
	repo   *db.Repository
	router chi.Router
	sfx    string
}

type uiUser struct {
	name   string
	cookie *http.Cookie
	csrf   string
}

func newUIEnv(t *testing.T) *uiEnv {
	t.Helper()
	pool := campaignWebPool(t)
	if pool == nil {
		t.SkipNow()
	}
	t.Cleanup(pool.Close)
	repo := db.NewRepository(pool)
	h, err := web.NewHandler(repo, nil, audit.NewForwarder(repo, ""))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	router := chi.NewRouter()
	h.RegisterRoutes(router, "breakglass", "")
	return &uiEnv{t: t, pool: pool, repo: repo, router: router, sfx: strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")}
}

func (e *uiEnv) user(tag string, role types.AdminRole, allowed ...string) *uiUser {
	e.t.Helper()
	name := tag + "-" + e.sfx
	if _, err := e.repo.CreateLocalAdminUser(context.Background(), types.CreateUserRequest{
		Username: name, Email: name + "@example.test", Password: "correct-horse-battery", Role: role, AllowedTags: allowed,
	}); err != nil {
		e.t.Fatalf("create user %s: %v", name, err)
	}
	cookie, csrf, err := web.IssueSession(context.Background(), e.repo, name, false)
	if err != nil {
		e.t.Fatalf("issue session: %v", err)
	}
	return &uiUser{name: name, cookie: cookie, csrf: csrf}
}

// do sends a request through the real router. accept may be "" (no Accept header).
func (e *uiEnv) do(u *uiUser, method, path, accept string, form url.Values, withCSRF bool) *httptest.ResponseRecorder {
	e.t.Helper()
	var body *strings.Reader
	if form != nil {
		if withCSRF {
			form.Set("csrf_token", u.csrf)
		}
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.AddCookie(u.cookie)
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

const htmlAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

func (e *uiEnv) device(name string, tags ...string) *types.Device {
	e.t.Helper()
	d, _, err := e.repo.GetOrCreateDevice(context.Background(), "uid-"+name+"-"+e.sfx, name+"-"+e.sfx)
	if err != nil {
		e.t.Fatalf("create device: %v", err)
	}
	if _, err := e.repo.UpdateDeviceTags(context.Background(), d.ID, tags); err != nil {
		e.t.Fatalf("tag device: %v", err)
	}
	return d
}

func (e *uiEnv) campaign(name string, creatorTags, targetTags []string) *campaign.Campaign {
	e.t.Helper()
	c, err := e.repo.CreateCampaign(context.Background(), &campaign.Campaign{
		Name: name, TargetKind: campaign.TargetPackages, Packages: []string{"curl"},
		Stages: campaign.DefaultStages(), RebootPolicy: campaign.RebootNotify, MaxDeferrals: 3,
		CreatorScopedTags: creatorTags, TargetTags: targetTags, CreatedBy: "seed",
	})
	if err != nil {
		e.t.Fatalf("create campaign: %v", err)
	}
	return c
}

// failedWork gives the device a FAILED result whose output is attacker-controlled text.
func (e *uiEnv) failedWork(c *campaign.Campaign, d *types.Device, output string) {
	e.t.Helper()
	ctx := context.Background()
	if err := e.repo.UpsertCampaignWork(ctx, c.ID, d.ID, 0, []campaign.PackageWork{{Package: "curl", Target: "latest"}}); err != nil {
		e.t.Fatalf("upsert work: %v", err)
	}
	if _, err := e.pool.Exec(ctx, `UPDATE campaign_device_work SET state='DISPATCHED' WHERE campaign_id=$1 AND device_id=$2`, c.ID, d.ID); err != nil {
		e.t.Fatalf("dispatch: %v", err)
	}
	err := e.repo.RecordCampaignResult(ctx, c.ID, d.ID, campaign.DeviceRunResult{
		CampaignID: c.ID,
		Packages: []campaign.PackageResult{{Package: "curl", State: campaign.PkgDpkgError,
			FromVersion: "7.88.1-10", ToVersion: "", Output: output}},
	}, campaign.WorkFailed, campaign.FailDpkg)
	if err != nil {
		e.t.Fatalf("record result: %v", err)
	}
}

func TestCampaignUI_ContentNegotiation(t *testing.T) {
	e := newUIEnv(t)
	admin := e.user("neg-sa", types.RoleSuperAdmin)
	c := e.campaign("neg-camp-"+e.sfx, nil, nil)
	risk, err := e.repo.CreateRiskAcceptance(context.Background(), &campaign.RiskAcceptance{
		CVEID: "CVE-2099-" + e.sfx, ScopeKind: campaign.RiskScopeAll, Reason: "neg", CreatedBy: "seed",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct{ path, key, marker string }{
		{"/admin/campaigns", "campaigns", c.Name},
		{"/admin/campaigns/" + c.ID, "campaign", c.Name},
		{"/admin/risk-acceptances", "risk_acceptances", risk.CVEID},
	}
	for _, tc := range cases {
		// No Accept header, */* and application/json: exactly today's JSON.
		for _, accept := range []string{"", "*/*", "application/json"} {
			rec := e.do(admin, http.MethodGet, tc.path, accept, nil, false)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s accept=%q: %d %s", tc.path, accept, rec.Code, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("%s accept=%q: content-type %q, want JSON", tc.path, accept, ct)
			}
			var m map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
				t.Fatalf("%s accept=%q: not JSON: %v", tc.path, accept, err)
			}
			if _, ok := m[tc.key]; !ok {
				t.Errorf("%s accept=%q: JSON lacks %q key: %v", tc.path, accept, tc.key, m)
			}
		}
		// A browser Accept gets the HTML page.
		rec := e.do(admin, http.MethodGet, tc.path, htmlAccept, nil, false)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s html: %d", tc.path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("%s html: content-type %q", tc.path, ct)
		}
		body := rec.Body.String()
		if !strings.Contains(body, tc.marker) {
			t.Errorf("%s html: missing %q", tc.path, tc.marker)
		}
		if !strings.Contains(body, `href="/admin/campaigns"`) {
			t.Errorf("%s html: layout nav link to /admin/campaigns missing", tc.path)
		}
	}
}

func TestCampaignUI_RBAC(t *testing.T) {
	e := newUIEnv(t)
	c := e.campaign("rbac-camp-"+e.sfx, nil, nil)
	for _, role := range []types.AdminRole{types.RoleOperator, types.RoleAuditor} {
		u := e.user("rbac-"+strings.ToLower(string(role)), role)
		for _, p := range []string{"/admin/campaigns", "/admin/campaigns/" + c.ID, "/admin/risk-acceptances", "/admin/campaigns/" + c.ID + "/export"} {
			if rec := e.do(u, http.MethodGet, p, htmlAccept, nil, false); rec.Code != http.StatusForbidden {
				t.Errorf("%s GET %s html: got %d, want 403", role, p, rec.Code)
			}
		}
		rec := e.do(u, http.MethodPost, "/admin/campaigns/"+c.ID+"/start", htmlAccept, url.Values{}, true)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s start: got %d, want 403", role, rec.Code)
		}
		rec = e.do(u, http.MethodPost, "/admin/campaigns", htmlAccept, url.Values{"name": {"x"}}, true)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s create form: got %d, want 403", role, rec.Code)
		}
	}
	got, _ := e.repo.GetCampaign(context.Background(), c.ID)
	if got.State != campaign.StateDraft {
		t.Errorf("campaign changed state to %s despite 403s", got.State)
	}
}

func TestCampaignUI_ScopedAdminSeesOnlyScope(t *testing.T) {
	e := newUIEnv(t)
	engTag, finTag := "eng-"+e.sfx, "fin-"+e.sfx
	scoped := e.user("scoped-sec", types.RoleSecurityAdmin, engTag)

	engDev := e.device("eng-host", engTag)
	finDev := e.device("fin-host", finTag)

	// In scope: created by an eng-scoped admin, but it holds work for BOTH devices.
	mine := e.campaign("mine-"+e.sfx, []string{engTag}, nil)
	e.failedWork(mine, engDev, "eng-visible-output")
	e.failedWork(mine, finDev, "FIN-SECRET-OUTPUT")
	// Out of scope: fleet-wide campaign and a finance campaign.
	fleet := e.campaign("fleet-"+e.sfx, nil, nil)
	e.failedWork(fleet, finDev, "fleet-output")
	fin := e.campaign("finance-"+e.sfx, []string{finTag}, []string{finTag})

	rec := e.do(scoped, http.MethodGet, "/admin/campaigns", htmlAccept, nil, false)
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, mine.Name) {
		t.Fatalf("scoped list: %d, own campaign missing", rec.Code)
	}
	for _, n := range []string{fleet.Name, fin.Name} {
		if strings.Contains(body, n) {
			t.Errorf("scoped admin's HTML list shows out-of-scope campaign %q", n)
		}
	}
	// The HTML list must match the JSON list.
	var js struct {
		Campaigns []campaign.Campaign `json:"campaigns"`
	}
	jrec := e.do(scoped, http.MethodGet, "/admin/campaigns", "application/json", nil, false)
	_ = json.Unmarshal(jrec.Body.Bytes(), &js)
	for _, c := range js.Campaigns {
		if !strings.Contains(body, c.Name) {
			t.Errorf("HTML list lacks %q that the JSON list returns", c.Name)
		}
	}

	// Out-of-scope detail is a 404 in HTML and JSON alike.
	for _, c := range []*campaign.Campaign{fleet, fin} {
		for _, accept := range []string{htmlAccept, "application/json"} {
			if rec := e.do(scoped, http.MethodGet, "/admin/campaigns/"+c.ID, accept, nil, false); rec.Code != http.StatusNotFound {
				t.Errorf("detail %s accept=%.9s: got %d, want 404", c.Name, accept, rec.Code)
			}
		}
		// And the control POSTs are refused the same way.
		if rec := e.do(scoped, http.MethodPost, "/admin/campaigns/"+c.ID+"/start", htmlAccept, url.Values{}, true); rec.Code != http.StatusNotFound {
			t.Errorf("start %s: got %d, want 404", c.Name, rec.Code)
		}
	}
	if got, _ := e.repo.GetCampaign(context.Background(), fleet.ID); got.State != campaign.StateDraft {
		t.Errorf("out-of-scope campaign was started by a scoped admin")
	}

	// In-scope detail: only in-scope device rows and results, counts exclude the other device.
	rec = e.do(scoped, http.MethodGet, "/admin/campaigns/"+mine.ID, htmlAccept, nil, false)
	body = rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("scoped detail: %d", rec.Code)
	}
	if !strings.Contains(body, engDev.Hostname) || !strings.Contains(body, "eng-visible-output") {
		t.Errorf("in-scope device row or output missing from detail")
	}
	if strings.Contains(body, finDev.Hostname) || strings.Contains(body, "FIN-SECRET-OUTPUT") {
		t.Errorf("detail leaks an out-of-scope device row or its output")
	}
	if !strings.Contains(body, "Devices (1)") {
		t.Errorf("detail device count should be 1 for the scoped admin")
	}

	// An unscoped admin sees everything.
	root := e.user("scoped-root", types.RoleSuperAdmin)
	body = e.do(root, http.MethodGet, "/admin/campaigns/"+mine.ID, htmlAccept, nil, false).Body.String()
	if !strings.Contains(body, finDev.Hostname) || !strings.Contains(body, "Devices (2)") {
		t.Errorf("unscoped admin should see both devices")
	}
}

func TestCampaignUI_DeviceOutputEscaped(t *testing.T) {
	e := newUIEnv(t)
	admin := e.user("esc-sa", types.RoleSuperAdmin)
	d := e.device("esc-host")
	c := e.campaign("esc-<b>camp</b>-"+e.sfx, nil, nil)
	payload := `<script>alert("pwned")</script><img src=x onerror=alert(1)>`
	e.failedWork(c, d, payload)

	body := e.do(admin, http.MethodGet, "/admin/campaigns/"+c.ID, htmlAccept, nil, false).Body.String()
	if strings.Contains(body, "<script>alert(\"pwned\")") || strings.Contains(body, "<img src=x") {
		t.Fatalf("device output rendered unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(") {
		t.Errorf("escaped device output not found in page")
	}
	if strings.Contains(body, "<b>camp</b>") {
		t.Errorf("campaign name rendered unescaped")
	}
	// Failure class, versions are shown.
	for _, want := range []string{"dpkg", "7.88.1-10"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail missing %q", want)
		}
	}
}

func TestCampaignUI_ButtonsFollowStateMachine(t *testing.T) {
	e := newUIEnv(t)
	admin := e.user("btn-sa", types.RoleSuperAdmin)
	c := e.campaign("btn-"+e.sfx, nil, nil)
	ctx := context.Background()

	has := func(body, action string) bool {
		return strings.Contains(body, `action="/admin/campaigns/`+c.ID+`/`+action+`"`)
	}
	cases := []struct {
		state campaign.CampaignState
		want  map[string]bool
	}{
		{campaign.StateDraft, map[string]bool{"start": true, "pause": false, "resume": false, "cancel": true}},
		{campaign.StateRunning, map[string]bool{"start": false, "pause": true, "resume": false, "cancel": true}},
		{campaign.StatePaused, map[string]bool{"start": true, "pause": false, "resume": true, "cancel": true}},
		{campaign.StateHalted, map[string]bool{"start": false, "pause": false, "resume": true, "cancel": true}},
		{campaign.StateCompleted, map[string]bool{"start": false, "pause": false, "resume": false, "cancel": false}},
		{campaign.StateCancelled, map[string]bool{"start": false, "pause": false, "resume": false, "cancel": false}},
	}
	for _, tc := range cases {
		if err := e.repo.SetCampaignState(ctx, c.ID, tc.state); err != nil {
			t.Fatal(err)
		}
		body := e.do(admin, http.MethodGet, "/admin/campaigns/"+c.ID, htmlAccept, nil, false).Body.String()
		for action, want := range tc.want {
			if got := has(body, action); got != want {
				t.Errorf("state %s: button %q shown=%v, want %v", tc.state, action, got, want)
			}
			// The backend must agree with the page: a hidden button's POST is refused, and a
			// shown button's POST is accepted (checked below for one transition).
			if !want {
				rec := e.do(admin, http.MethodPost, "/admin/campaigns/"+c.ID+"/"+action, "application/json", url.Values{}, true)
				if rec.Code != http.StatusBadRequest {
					t.Errorf("state %s: POST %s not refused by backend (got %d)", tc.state, action, rec.Code)
				}
			}
		}
		if got, _ := e.repo.GetCampaign(ctx, c.ID); got.State != tc.state {
			t.Errorf("refused POSTs changed state %s -> %s", tc.state, got.State)
		}
	}

	// A refused control from the HTML form re-renders the page with the reason, state unchanged.
	if err := e.repo.SetCampaignState(ctx, c.ID, campaign.StateDraft); err != nil {
		t.Fatal(err)
	}
	rec := e.do(admin, http.MethodPost, "/admin/campaigns/"+c.ID+"/pause", htmlAccept, url.Values{}, true)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "only a running campaign can be paused") {
		t.Errorf("html refused pause: %d %.200s", rec.Code, rec.Body.String())
	}

	// A shown button works end to end: Start redirects back to the page and the state moves.
	rec = e.do(admin, http.MethodPost, "/admin/campaigns/"+c.ID+"/start", htmlAccept, url.Values{}, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/campaigns/"+c.ID {
		t.Fatalf("html start: %d loc=%q", rec.Code, rec.Header().Get("Location"))
	}
	if got, _ := e.repo.GetCampaign(ctx, c.ID); got.State != campaign.StateRunning {
		t.Errorf("start did not run the campaign: %s", got.State)
	}
	body := e.do(admin, http.MethodGet, "/admin/campaigns/"+c.ID, htmlAccept, nil, false).Body.String()
	if !strings.Contains(body, "<strong>start</strong>") {
		t.Errorf("start event missing from history")
	}
	// Without a CSRF token the form POST is rejected.
	if rec := e.do(admin, http.MethodPost, "/admin/campaigns/"+c.ID+"/pause", htmlAccept, url.Values{}, false); rec.Code != http.StatusForbidden {
		t.Errorf("pause without CSRF: got %d, want 403", rec.Code)
	}
}

func TestCampaignUI_CreateForm(t *testing.T) {
	e := newUIEnv(t)
	admin := e.user("form-sa", types.RoleSuperAdmin)
	ctx := context.Background()

	valid := func() url.Values {
		return url.Values{
			"name": {"form-camp-" + e.sfx}, "description": {"from the form"},
			"target_kind": {"packages"}, "packages": {"curl, libcurl4\nvim"},
			"reboot_policy": {"force"}, "max_deferrals": {"2"}, "deadline_at": {"2030-01-02T03:04"},
			"blackout_cron": {"0 8 * * 1-5"}, "blackout_duration_minutes": {"480"},
			"respect_maintenance_window": {"1"},
			"stage_0_enabled":            {"1"}, "stage_0_name": {"CANARY"}, "stage_0_min_devices": {"1"}, "stage_0_success_pct": {"90"},
			"stage_0_soak_minutes": {"30"}, "stage_0_halt_pct": {"20"}, "stage_0_halt_count": {"3"}, "stage_0_promotion": {"manual"},
			"stage_1_name":    {"PILOT"},
			"stage_2_enabled": {"1"}, "stage_2_name": {"PRODUCTION"}, "stage_2_min_devices": {"0"}, "stage_2_success_pct": {"95"},
			"stage_2_soak_minutes": {"0"}, "stage_2_halt_pct": {"10"}, "stage_2_halt_count": {"0"}, "stage_2_promotion": {"auto"},
		}
	}
	rec := e.do(admin, http.MethodPost, "/admin/campaigns", htmlAccept, valid(), true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("valid form: %d %.300s", rec.Code, rec.Body.String())
	}
	id := strings.TrimPrefix(rec.Header().Get("Location"), "/admin/campaigns/")
	c, err := e.repo.GetCampaign(ctx, id)
	if err != nil || c == nil {
		t.Fatalf("created campaign not found: %v", err)
	}
	if c.State != campaign.StateDraft || c.RebootPolicy != campaign.RebootForce || c.MaxDeferrals != 2 ||
		strings.Join(c.Packages, ",") != "curl,libcurl4,vim" || c.BlackoutCron != "0 8 * * 1-5" ||
		c.BlackoutDurationMinutes != 480 || c.DeadlineAt == nil || c.DeadlineAt.Year() != 2030 || !c.RespectMaintenanceWindow {
		t.Errorf("campaign fields not stored as submitted: %+v", c)
	}
	if len(c.Stages) != 2 || c.Stages[0].Name != "CANARY" || c.Stages[0].Promotion != campaign.PromotionManual ||
		c.Stages[0].FailureHaltCount != 3 || c.Stages[1].Name != "PRODUCTION" || c.Stages[1].Order != 1 {
		t.Errorf("stages not stored as submitted: %+v", c.Stages)
	}

	// Server-side validation errors appear next to the form, with the typed values kept.
	bad := []struct {
		name   string
		mutate func(url.Values)
		want   string
		code   int
	}{
		{"missing name", func(v url.Values) { v.Set("name", "") }, "name is required", 400},
		{"bad package", func(v url.Values) { v.Set("packages", "curl -rf") }, "invalid package name: -rf", 400},
		{"no packages", func(v url.Values) { v.Set("packages", "") }, "Enter at least one package name", 400},
		{"no group", func(v url.Values) { v.Set("target_kind", "group") }, "Choose a group", 400},
		{"bad cron", func(v url.Values) { v.Set("blackout_cron", "every day") }, "5-field cron", 400},
		{"bad number", func(v url.Values) { v.Set("max_deferrals", "lots") }, "Deferral limit must be a whole number", 400},
		{"bad percent", func(v url.Values) { v.Set("stage_0_success_pct", "150") }, "success threshold must be 0..100", 400},
		{"no stages", func(v url.Values) { v.Del("stage_0_enabled"); v.Del("stage_2_enabled") }, "Enable at least one stage", 400},
		{"bad deadline", func(v url.Values) { v.Set("deadline_at", "tomorrow") }, "Deadline must be a date", 400},
	}
	for _, tc := range bad {
		v := valid()
		v.Set("name", "bad-"+e.sfx)
		tc.mutate(v)
		rec := e.do(admin, http.MethodPost, "/admin/campaigns", htmlAccept, v, true)
		body := rec.Body.String()
		if rec.Code != tc.code || !strings.Contains(body, tc.want) {
			t.Errorf("%s: got %d, want %d containing %q", tc.name, rec.Code, tc.code, tc.want)
			continue
		}
		if !strings.Contains(body, `id="campaign-form"`) || !strings.Contains(body, "The campaign was not created") {
			t.Errorf("%s: error page does not re-render the form", tc.name)
		}
		if tc.name != "missing name" && !strings.Contains(body, `value="bad-`+e.sfx+`"`) {
			t.Errorf("%s: form values were not preserved", tc.name)
		}
	}
	list, _ := e.repo.ListCampaigns(ctx, db.Unscoped)
	for _, c := range list {
		if c.Name == "bad-"+e.sfx {
			t.Errorf("a rejected form still created campaign %q", c.Name)
		}
	}
	// No CSRF token: refused.
	if rec := e.do(admin, http.MethodPost, "/admin/campaigns", htmlAccept, valid(), false); rec.Code != http.StatusForbidden {
		t.Errorf("create without CSRF: got %d", rec.Code)
	}

	// A scoped admin's form-created campaign carries their scope (so only they can see it).
	eng := "eng-form-" + e.sfx
	scoped := e.user("form-scoped", types.RoleSecurityAdmin, eng)
	v := valid()
	v.Set("name", "scoped-form-"+e.sfx)
	rec = e.do(scoped, http.MethodPost, "/admin/campaigns", htmlAccept, v, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("scoped create: %d", rec.Code)
	}
	sc, _ := e.repo.GetCampaign(ctx, strings.TrimPrefix(rec.Header().Get("Location"), "/admin/campaigns/"))
	if sc == nil || len(sc.CreatorScopedTags) != 1 || sc.CreatorScopedTags[0] != eng {
		t.Errorf("scoped admin's campaign not stamped with scope: %+v", sc)
	}
}

// The JSON API keeps its behaviour; the shared blackout validation also applies to it.
func TestCampaignUI_JSONCreateUnchanged(t *testing.T) {
	e := newUIEnv(t)
	admin := e.user("json-sa", types.RoleSuperAdmin)
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/campaigns", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", admin.csrf)
		req.AddCookie(admin.cookie)
		rec := httptest.NewRecorder()
		e.router.ServeHTTP(rec, req)
		return rec
	}
	rec := post(`{"name":"json-` + e.sfx + `","target_kind":"packages","packages":["curl"]}`)
	if rec.Code != http.StatusCreated || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("json create: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post(`{"name":"x","target_kind":"packages","packages":["curl"],"blackout_cron":"nonsense"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("malformed blackout cron via JSON: got %d, want 400", rec.Code)
	}
	if rec := post(`{"name":"","target_kind":"packages"}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "name is required") {
		t.Errorf("json validation message changed: %d %q", rec.Code, rec.Body.String())
	}
}

func TestRiskUI_ListCreateDelete(t *testing.T) {
	e := newUIEnv(t)
	admin := e.user("risk-sa", types.RoleSuperAdmin)
	ctx := context.Background()

	// An expired acceptance stays listed, marked expired.
	_, err := e.repo.CreateRiskAcceptance(ctx, &campaign.RiskAcceptance{
		CVEID: "CVE-2001-" + e.sfx, ScopeKind: campaign.RiskScopeAll, Reason: "old", CreatedBy: "seed",
		ExpiresAt: time.Now().Add(-24 * time.Hour),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"cve_id": {"CVE-2002-" + e.sfx}, "package": {"vim"}, "scope_kind": {"all"},
		"reason": {"compensating control <i>x</i>"}, "expiry_days": {"30"}}
	rec := e.do(admin, http.MethodPost, "/admin/risk-acceptances", htmlAccept, form, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/risk-acceptances" {
		t.Fatalf("create: %d %.300s", rec.Code, rec.Body.String())
	}
	body := e.do(admin, http.MethodGet, "/admin/risk-acceptances", htmlAccept, nil, false).Body.String()
	for _, want := range []string{"CVE-2001-" + e.sfx, "CVE-2002-" + e.sfx, "expired", "active", "not hidden"} {
		if !strings.Contains(body, want) {
			t.Errorf("risk page missing %q", want)
		}
	}
	if strings.Contains(body, "<i>x</i>") {
		t.Errorf("reason rendered unescaped")
	}

	// Expiry is mandatory and capped; errors show beside the form with values kept.
	for _, tc := range []struct{ name, days, want string }{
		{"missing", "", "An expiry is required"},
		{"zero", "0", "1 or more"},
		{"too long", "181", "exceeds the 180-day maximum"},
		{"junk", "soon", "whole number of days"},
	} {
		f := url.Values{"cve_id": {"CVE-3000-" + e.sfx}, "scope_kind": {"all"}, "reason": {"r"}, "expiry_days": {tc.days}}
		rec := e.do(admin, http.MethodPost, "/admin/risk-acceptances", htmlAccept, f, true)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: got %d, want 400 containing %q", tc.name, rec.Code, tc.want)
		}
	}
	f := url.Values{"cve_id": {"CVE-3001-" + e.sfx}, "scope_kind": {"all"}, "reason": {" "}, "expiry_days": {"10"}}
	if rec := e.do(admin, http.MethodPost, "/admin/risk-acceptances", htmlAccept, f, true); rec.Code != 400 || !strings.Contains(rec.Body.String(), "reason is required") {
		t.Errorf("blank reason: %d", rec.Code)
	}

	// Delete through the page's form route.
	list, _ := e.repo.ListAllRiskAcceptances(ctx, db.Unscoped)
	var id string
	for _, ra := range list {
		if ra.CVEID == "CVE-2002-"+e.sfx {
			id = ra.ID
		}
	}
	if id == "" {
		t.Fatal("created acceptance not found")
	}
	rec = e.do(admin, http.MethodPost, "/admin/risk-acceptances/"+id+"/delete", htmlAccept, url.Values{}, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("delete: %d", rec.Code)
	}
	if ra, _ := e.repo.GetRiskAcceptanceScoped(ctx, id, db.Unscoped); ra != nil {
		t.Errorf("acceptance still present after delete")
	}
}

func TestRiskUI_ScopedAdmin(t *testing.T) {
	e := newUIEnv(t)
	ctx := context.Background()
	engTag, finTag := "eng-"+e.sfx, "fin-"+e.sfx
	scoped := e.user("risk-scoped", types.RoleSecurityAdmin, engTag)

	mk := func(cve string, kind campaign.RiskScopeKind, tags, creator []string) *campaign.RiskAcceptance {
		ra, err := e.repo.CreateRiskAcceptance(ctx, &campaign.RiskAcceptance{
			CVEID: cve, ScopeKind: kind, Tags: tags, Reason: "seed", CreatedBy: "seed",
			ExpiresAt: time.Now().Add(48 * time.Hour),
		}, creator)
		if err != nil {
			t.Fatal(err)
		}
		return ra
	}
	mine := mk("CVE-4001-"+e.sfx, campaign.RiskScopeTags, []string{engTag}, []string{engTag})
	fleet := mk("CVE-4002-"+e.sfx, campaign.RiskScopeAll, nil, nil)
	fin := mk("CVE-4003-"+e.sfx, campaign.RiskScopeTags, []string{finTag}, []string{finTag})

	body := e.do(scoped, http.MethodGet, "/admin/risk-acceptances", htmlAccept, nil, false).Body.String()
	if !strings.Contains(body, mine.CVEID) {
		t.Errorf("scoped admin cannot see own acceptance")
	}
	if strings.Contains(body, fleet.CVEID) || strings.Contains(body, fin.CVEID) {
		t.Errorf("scoped admin's HTML list shows out-of-scope acceptances")
	}
	if strings.Contains(body, `<option value="all"`) {
		t.Errorf("fleet-wide scope offered to a scoped admin")
	}

	// The backend refuses what the page does not offer.
	f := url.Values{"cve_id": {"CVE-4004-" + e.sfx}, "scope_kind": {"all"}, "reason": {"r"}, "expiry_days": {"5"}}
	if rec := e.do(scoped, http.MethodPost, "/admin/risk-acceptances", htmlAccept, f, true); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "cannot create a fleet-wide") {
		t.Errorf("scoped fleet-wide create: %d", rec.Code)
	}
	f = url.Values{"cve_id": {"CVE-4005-" + e.sfx}, "scope_kind": {"tags"}, "tags": {finTag}, "reason": {"r"}, "expiry_days": {"5"}}
	if rec := e.do(scoped, http.MethodPost, "/admin/risk-acceptances", htmlAccept, f, true); rec.Code != http.StatusForbidden {
		t.Errorf("scoped out-of-tag create: %d", rec.Code)
	}

	// Deleting an out-of-scope acceptance is a 404 (HTML form and API) and the row survives.
	for _, accept := range []string{htmlAccept, "application/json"} {
		for _, ra := range []*campaign.RiskAcceptance{fleet, fin} {
			if rec := e.do(scoped, http.MethodPost, "/admin/risk-acceptances/"+ra.ID+"/delete", accept, url.Values{}, true); rec.Code != http.StatusNotFound {
				t.Errorf("scoped delete of %s: got %d, want 404", ra.CVEID, rec.Code)
			}
			if got, _ := e.repo.GetRiskAcceptanceScoped(ctx, ra.ID, db.Unscoped); got == nil {
				t.Errorf("out-of-scope acceptance %s was deleted by a scoped admin", ra.CVEID)
			}
		}
	}
	// In scope it works.
	if rec := e.do(scoped, http.MethodPost, "/admin/risk-acceptances/"+mine.ID+"/delete", htmlAccept, url.Values{}, true); rec.Code != http.StatusSeeOther {
		t.Errorf("scoped delete of own acceptance: %d", rec.Code)
	}
	if got, _ := e.repo.GetRiskAcceptanceScoped(ctx, mine.ID, db.Unscoped); got != nil {
		t.Errorf("own acceptance not deleted")
	}
}

// TestCampaignJSON_ScopedReportAndGroupTarget covers two scoping gaps in the JSON API: the
// detail report counted devices outside the admin's tags, and a scoped admin could create a
// campaign against a fleet-wide group.
func TestCampaignJSON_ScopedReportAndGroupTarget(t *testing.T) {
	e := newUIEnv(t)
	ctx := context.Background()
	teamA := "team-a-" + e.sfx
	teamB := "team-b-" + e.sfx
	scoped := e.user("rep-scoped", types.RoleSecurityAdmin, teamA)

	c := e.campaign("report-"+e.sfx, nil, []string{teamA, teamB})
	e.failedWork(c, e.device("rep-in", teamA), "in scope")
	e.failedWork(c, e.device("rep-out1", teamB), "out of scope")
	e.failedWork(c, e.device("rep-out2", teamB), "out of scope")

	rec := e.do(scoped, http.MethodGet, "/admin/campaigns/"+c.ID, "application/json", nil, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail: %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Report campaign.CampaignReport `json:"report"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	total := 0
	for _, s := range body.Report.StageStates {
		total += s.Count
	}
	failed := 0
	for _, f := range body.Report.FailureClasses {
		failed += f.Count
	}
	if total != 1 || failed != 1 {
		t.Errorf("scoped report counts devices outside scope: stage total %d, failures %d (want 1, 1)", total, failed)
	}

	// A fleet-wide group (created by an unscoped admin) is refused for a scoped admin.
	fleet, err := e.repo.CreateGroup(ctx, db.CreateGroupInput{Name: "fleet-" + e.sfx, Kind: types.GroupKindTarget, CreatedBy: "seed"})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	post := func(u *uiUser, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/campaigns", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", u.csrf)
		req.AddCookie(u.cookie)
		rec := httptest.NewRecorder()
		e.router.ServeHTTP(rec, req)
		return rec
	}
	if rec := post(scoped, `{"name":"g-`+e.sfx+`","target_kind":"group","group_id":"`+fleet.ID+`"}`); rec.Code != http.StatusForbidden {
		t.Errorf("scoped admin targeting a fleet-wide group: got %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	if rec := post(scoped, `{"name":"g2-`+e.sfx+`","target_kind":"group","group_id":"00000000-0000-0000-0000-000000000001"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown group: got %d, want 400", rec.Code)
	}
	own, err := e.repo.CreateGroup(ctx, db.CreateGroupInput{Name: "own-" + e.sfx, Kind: types.GroupKindTarget, CreatedBy: scoped.name, CreatorScopedTags: []string{teamA}})
	if err != nil {
		t.Fatalf("create own group: %v", err)
	}
	if rec := post(scoped, `{"name":"g3-`+e.sfx+`","target_kind":"group","group_id":"`+own.ID+`"}`); rec.Code != http.StatusCreated {
		t.Errorf("scoped admin targeting their own group: got %d, want 201 (%s)", rec.Code, rec.Body.String())
	}
	super := e.user("rep-super", types.RoleSuperAdmin)
	if rec := post(super, `{"name":"g4-`+e.sfx+`","target_kind":"group","group_id":"`+fleet.ID+`"}`); rec.Code != http.StatusCreated {
		t.Errorf("super admin targeting a fleet group: got %d, want 201", rec.Code)
	}
}
