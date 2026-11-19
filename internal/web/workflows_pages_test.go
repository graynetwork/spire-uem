package web_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/alerts"
	"github.com/spire-uem/spire-uem/internal/audit"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/web"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

// wfUser is an admin with a real DB row and a real session, so requests go through the
// production auth, CSRF and RBAC middleware.
type wfUser struct {
	name   string
	cookie *http.Cookie
	csrf   string
}

type wfEnv struct {
	t      *testing.T
	router chi.Router
	repo   *db.Repository
	pool   *pgxpool.Pool
	eng    *workflows.Engine
	sfx    string

	super, sec, auditor *wfUser
	scopedA, scopedB    *wfUser
	tagA, tagB          string
}

func newWFEnv(t *testing.T) *wfEnv {
	t.Helper()
	connStr := os.Getenv("SPIRE_TEST_DB_URL")
	if connStr == "" {
		t.Skip("SPIRE_TEST_DB_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Skipf("cannot connect: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("ping failed: %v", err)
	}
	if err := db.RunMigrations(ctx, pool, "../../migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	t.Cleanup(pool.Close)
	repo := db.NewRepository(pool)
	h, err := web.NewHandler(repo, nil, audit.NewForwarder(repo, ""))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	eng := workflows.NewEngine(repo.WorkflowStore(), workflows.NewRegistry(), workflows.DefaultConfig())
	repo.NewWorkflowActions(alerts.NopNotifier{}, "quarantine").RegisterBuiltins(eng.Registry())
	repo.RegisterCampaignWorkflowAction(eng.Registry())
	h.SetWorkflowEngine(eng)
	router := chi.NewRouter()
	h.RegisterRoutes(router, "admin", "unused-break-glass-pass")

	e := &wfEnv{t: t, router: router, repo: repo, pool: pool, eng: eng, sfx: time.Now().Format("150405.000000000")}
	e.tagA, e.tagB = "wfa-"+e.sfx, "wfb-"+e.sfx
	e.super = e.mkUser("super", types.RoleSuperAdmin, nil)
	e.sec = e.mkUser("sec", types.RoleSecurityAdmin, nil)
	e.auditor = e.mkUser("aud", types.RoleAuditor, nil)
	e.scopedA = e.mkUser("sca", types.RoleSecurityAdmin, []string{e.tagA})
	e.scopedB = e.mkUser("scb", types.RoleSecurityAdmin, []string{e.tagB})
	return e
}

func (e *wfEnv) mkUser(prefix string, role types.AdminRole, tags []string) *wfUser {
	e.t.Helper()
	ctx := context.Background()
	name := strings.ReplaceAll(prefix+"-"+e.sfx, ".", "")
	if _, err := e.repo.CreateLocalAdminUser(ctx, types.CreateUserRequest{
		Username: name, Email: name + "@example.test", Password: "Password-12345", Role: role, AllowedTags: tags,
	}); err != nil {
		e.t.Fatalf("create user: %v", err)
	}
	cookie, csrf, err := web.IssueSession(ctx, e.repo, name, false)
	if err != nil {
		e.t.Fatalf("issue session: %v", err)
	}
	return &wfUser{name: name, cookie: cookie, csrf: csrf}
}

// do sends a request through the real router. accept may be "" (no Accept header).
func (e *wfEnv) do(u *wfUser, method, path, accept, body string) *httptest.ResponseRecorder {
	e.t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if u != nil {
		req.AddCookie(u.cookie)
		if method != http.MethodGet {
			req.Header.Set("X-CSRF-Token", u.csrf)
		}
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func (e *wfEnv) mkDevice(tags []string, hostname string) string {
	e.t.Helper()
	ctx := context.Background()
	dev, _, err := e.repo.GetOrCreateDevice(ctx, "wfui-"+e.sfx+"-"+hostname, hostname)
	if err != nil {
		e.t.Fatalf("device: %v", err)
	}
	if _, _, err := e.repo.ApproveDevice(ctx, dev.ID); err != nil {
		e.t.Fatalf("approve: %v", err)
	}
	if _, err := e.repo.UpdateDeviceTags(ctx, dev.ID, tags); err != nil {
		e.t.Fatalf("tags: %v", err)
	}
	return dev.ID
}

func (e *wfEnv) mkWorkflow(name string, scope []string, then ...workflows.Action) string {
	e.t.Helper()
	if len(then) == 0 {
		then = []workflows.Action{{Type: workflows.ActionAddTag, Tag: "x"}}
	}
	id, err := e.repo.CreateWorkflow(context.Background(), &workflows.Workflow{
		Name: name, Enabled: true, DryRun: true,
		Trigger:           &workflows.Trigger{Kind: workflows.EventAgentStarted},
		ThenActions:       then,
		CreatedBy:         "seed",
		CreatorScopedTags: scope,
	})
	if err != nil {
		e.t.Fatalf("create workflow: %v", err)
	}
	return id
}

// mkRun records a finished run (with one action) and returns the run id.
func (e *wfEnv) mkRun(wfID, wfName, deviceID string, eventFields map[string]any, detail string) string {
	e.t.Helper()
	ctx := context.Background()
	var evID *int64
	if eventFields != nil {
		b, _ := json.Marshal(eventFields)
		var id int64
		if err := e.pool.QueryRow(ctx, `INSERT INTO workflow_events (kind, device_id, fields, status) VALUES ('cve_matched', $1, $2::jsonb, 'PROCESSED') RETURNING id`, deviceID, string(b)).Scan(&id); err != nil {
			e.t.Fatalf("event: %v", err)
		}
		evID = &id
	}
	yes := true
	store := e.repo.WorkflowStore()
	runID, err := store.StartRun(ctx, workflows.RunRecord{
		WorkflowID: wfID, WorkflowName: wfName, WorkflowVersion: 1, DeviceID: deviceID,
		Trigger: "cve_matched", EventID: evID, ConditionResult: &yes, Branch: "then", DryRun: true,
	})
	if err != nil {
		e.t.Fatalf("start run: %v", err)
	}
	if err := store.RecordActionResult(ctx, runID, 0, workflows.Action{Type: workflows.ActionAddTag, Tag: "t"}, workflows.ResultDryRun, detail); err != nil {
		e.t.Fatalf("record action: %v", err)
	}
	if err := store.FinishRun(ctx, runID, "DRY_RUN", detail); err != nil {
		e.t.Fatalf("finish run: %v", err)
	}
	return runID
}

func (e *wfEnv) mkApproval(wfID, wfName string, scope []string, deviceID string, remaining []workflows.Action) string {
	e.t.Helper()
	runID := e.mkRun(wfID, wfName, deviceID, nil, "paused")
	id, err := e.repo.WorkflowStore().CreateApproval(context.Background(), runID,
		&workflows.Workflow{ID: wfID, Name: wfName, CreatorScopedTags: scope}, deviceID, remaining, time.Now().Add(time.Hour))
	if err != nil {
		e.t.Fatalf("create approval: %v", err)
	}
	return id
}

const htmlAccept = "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8"

func runNames(t *testing.T, body []byte) map[string]bool {
	t.Helper()
	var out struct {
		Runs []struct{ WorkflowName string } `json:"runs"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode runs: %v body=%s", err, body)
	}
	m := map[string]bool{}
	for _, r := range out.Runs {
		m[r.WorkflowName] = true
	}
	return m
}

// --- content negotiation ---

func TestWorkflowPages_ContentNegotiation(t *testing.T) {
	e := newWFEnv(t)
	e.mkWorkflow("neg-"+e.sfx, nil)

	for _, p := range []struct{ path, jsonKey, marker string }{
		{"/admin/workflows", "workflows", "Automation Workflows"},
		{"/admin/workflows/runs", "runs", "Automation Workflows"},
		{"/admin/workflows/approvals", "approvals", "Automation Workflows"},
	} {
		// HTML only when the client asks for text/html.
		rec := e.do(e.sec, http.MethodGet, p.path, htmlAccept, "")
		if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") || !strings.Contains(rec.Body.String(), p.marker) {
			t.Errorf("%s with Accept html: code=%d ct=%q", p.path, rec.Code, rec.Header().Get("Content-Type"))
		}
		// Everything else is exactly the old JSON.
		for _, accept := range []string{"", "application/json", "*/*"} {
			rec := e.do(e.sec, http.MethodGet, p.path, accept, "")
			if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
				t.Errorf("%s Accept=%q: code=%d ct=%q", p.path, accept, rec.Code, rec.Header().Get("Content-Type"))
				continue
			}
			var m map[string]json.RawMessage
			if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
				t.Errorf("%s Accept=%q: not JSON: %v", p.path, accept, err)
				continue
			}
			if _, ok := m[p.jsonKey]; !ok || len(m) != 1 {
				t.Errorf("%s Accept=%q: JSON shape changed: %v", p.path, accept, m)
			}
		}
	}
	// The sidebar link is present on every page.
	rec := e.do(e.sec, http.MethodGet, "/admin/workflows", htmlAccept, "")
	if !strings.Contains(rec.Body.String(), `href="/admin/workflows"`) {
		t.Error("Workflows nav link missing")
	}
	// Unauthenticated requests never get a page.
	rec = e.do(nil, http.MethodGet, "/admin/workflows", htmlAccept, "")
	if rec.Code == 200 {
		t.Error("unauthenticated request must not be served the workflows page")
	}
}

// --- AUDITOR is read only ---

func TestWorkflowPages_AuditorReadOnly(t *testing.T) {
	e := newWFEnv(t)
	id := e.mkWorkflow("aud-"+e.sfx, nil)
	devID := e.mkDevice(nil, "aud-host")
	e.mkRun(id, "aud-"+e.sfx, devID, nil, "ok")
	apID := e.mkApproval(id, "aud-"+e.sfx, nil, devID, []workflows.Action{{Type: workflows.ActionLock}})

	for _, p := range []string{"/admin/workflows", "/admin/workflows/runs"} {
		rec := e.do(e.auditor, http.MethodGet, p, htmlAccept, "")
		if rec.Code != 200 {
			t.Fatalf("auditor GET %s = %d", p, rec.Code)
		}
		body := rec.Body.String()
		for _, forbidden := range []string{`id="wf-new"`, "data-wf-toggle", "data-wf-edit", "data-wf-delete", `id="wf-config"`, "data-wf-decide", "/admin/workflows/approvals"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("auditor page %s exposes mutating control %q", p, forbidden)
			}
		}
	}
	if rec := e.do(e.auditor, http.MethodGet, "/admin/workflows", htmlAccept, ""); !strings.Contains(rec.Body.String(), "aud-"+e.sfx) {
		t.Error("auditor should still see the workflow list")
	}
	// Approvals are SECURITY_ADMIN+.
	if rec := e.do(e.auditor, http.MethodGet, "/admin/workflows/approvals", htmlAccept, ""); rec.Code != 403 {
		t.Errorf("auditor GET approvals = %d, want 403", rec.Code)
	}
	// Every mutation is refused.
	valid := `{"name":"x","trigger":{"Kind":"agent_started"},"then_actions":[{"type":"lock"}]}`
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/admin/workflows", valid},
		{"POST", "/admin/workflows/" + id, valid},
		{"POST", "/admin/workflows/" + id + "/toggle", ""},
		{"DELETE", "/admin/workflows/" + id, ""},
		{"POST", "/admin/workflows/approvals/" + apID + "/approve", ""},
		{"POST", "/admin/workflows/approvals/" + apID + "/reject", ""},
	} {
		if rec := e.do(e.auditor, c.method, c.path, "application/json", c.body); rec.Code != 403 {
			t.Errorf("auditor %s %s = %d, want 403", c.method, c.path, rec.Code)
		}
	}
	if wf, _ := e.repo.GetWorkflow(context.Background(), id); wf == nil || !wf.Enabled {
		t.Error("auditor mutation must not have changed the workflow")
	}
}

// --- tag scoping of runs and approvals (regression: runs used to be unscoped) ---

func TestWorkflowRuns_ScopedAdminSeesOnlyInScope(t *testing.T) {
	e := newWFEnv(t)
	ctx := context.Background()
	devA := e.mkDevice([]string{e.tagA}, "scope-a-host")
	devB := e.mkDevice([]string{e.tagB}, "scope-b-host")
	devBoth := e.mkDevice([]string{e.tagA, e.tagB}, "scope-ab-host")

	nameA, nameB, nameU, nameGone := "wf-A-"+e.sfx, "wf-B-"+e.sfx, "wf-U-"+e.sfx, "wf-gone-"+e.sfx
	idA := e.mkWorkflow(nameA, []string{e.tagA})
	idB := e.mkWorkflow(nameB, []string{e.tagB})
	idU := e.mkWorkflow(nameU, nil)
	idGone := e.mkWorkflow(nameGone, []string{e.tagA})
	mark := func(n string) string { return "marker-" + n }
	e.mkRun(idA, nameA, devA, nil, mark(nameA))
	e.mkRun(idB, nameB, devB, nil, mark(nameB))
	e.mkRun(idU, nameU, devA, nil, mark(nameU))
	e.mkRun(idGone, nameGone, devA, nil, mark(nameGone))
	if err := e.repo.DeleteWorkflow(ctx, idGone); err != nil { // run survives with workflow_id NULL
		t.Fatal(err)
	}
	// A's workflow ran on a device that carries B's tag only: the device is out of A's scope.
	nameAonB := "wf-AonB-" + e.sfx
	idAonB := e.mkWorkflow(nameAonB, []string{e.tagA})
	e.mkRun(idAonB, nameAonB, devB, nil, mark(nameAonB))
	_ = devBoth

	check := func(label, accept string) {
		rec := e.do(e.scopedA, http.MethodGet, "/admin/workflows/runs", accept, "")
		if rec.Code != 200 {
			t.Fatalf("%s: %d", label, rec.Code)
		}
		var seen map[string]bool
		if strings.Contains(accept, "html") {
			seen = map[string]bool{}
			for _, n := range []string{nameA, nameB, nameU, nameGone, nameAonB} {
				seen[n] = strings.Contains(rec.Body.String(), mark(n))
			}
		} else {
			seen = runNames(t, rec.Body.Bytes())
		}
		if !seen[nameA] {
			t.Errorf("%s: scoped admin A must see own-scope run", label)
		}
		for n, what := range map[string]string{
			nameB: "another scope's run", nameU: "an unscoped workflow's run",
			nameGone: "a deleted workflow's run (no scope to verify)", nameAonB: "a run on an out-of-scope device",
		} {
			if seen[n] {
				t.Errorf("%s: scoped admin A must NOT see %s (%s)", label, what, n)
			}
		}
	}
	check("json", "application/json")
	check("html", htmlAccept)

	// Filtering by another scope's workflow id yields nothing.
	rec := e.do(e.scopedA, http.MethodGet, "/admin/workflows/runs?workflow_id="+idB, "application/json", "")
	if names := runNames(t, rec.Body.Bytes()); len(names) != 0 {
		t.Errorf("filter by out-of-scope workflow leaked runs: %v", names)
	}
	// An unscoped admin still sees everything, including the orphaned run.
	rec = e.do(e.sec, http.MethodGet, "/admin/workflows/runs", "application/json", "")
	names := runNames(t, rec.Body.Bytes())
	for _, n := range []string{nameA, nameB, nameU, nameGone} {
		if !names[n] {
			t.Errorf("unscoped admin should see run of %s", n)
		}
	}
	// The workflow filter dropdown only lists the scoped admin's workflows.
	rec = e.do(e.scopedA, http.MethodGet, "/admin/workflows/runs", htmlAccept, "")
	if strings.Contains(rec.Body.String(), `value="`+idB+`"`) {
		t.Error("run filter dropdown lists an out-of-scope workflow")
	}
}

func TestWorkflowApprovals_ScopedAdminSeesAndDecidesOnlyInScope(t *testing.T) {
	e := newWFEnv(t)
	devA := e.mkDevice([]string{e.tagA}, "ap-a-host")
	devB := e.mkDevice([]string{e.tagB}, "ap-b-host")
	nameA, nameB := "ap-A-"+e.sfx, "ap-B-"+e.sfx
	idA := e.mkWorkflow(nameA, []string{e.tagA})
	idB := e.mkWorkflow(nameB, []string{e.tagB})
	apA := e.mkApproval(idA, nameA, []string{e.tagA}, devA, []workflows.Action{{Type: workflows.ActionAddTag, Tag: "approved-by-a"}})
	apB := e.mkApproval(idB, nameB, []string{e.tagB}, devB, []workflows.Action{{Type: workflows.ActionLock}})

	for label, accept := range map[string]string{"html": htmlAccept, "json": "application/json"} {
		rec := e.do(e.scopedA, http.MethodGet, "/admin/workflows/approvals", accept, "")
		body := rec.Body.String()
		if rec.Code != 200 || !strings.Contains(body, nameA) {
			t.Fatalf("%s: scoped A should see own approval (code %d)", label, rec.Code)
		}
		if strings.Contains(body, nameB) || strings.Contains(body, apB) {
			t.Errorf("%s: scoped A sees another scope's approval", label)
		}
	}
	// What will happen is spelled out.
	rec := e.do(e.scopedA, http.MethodGet, "/admin/workflows/approvals", htmlAccept, "")
	if !strings.Contains(rec.Body.String(), `Add tag &#34;approved-by-a&#34;`) || !strings.Contains(rec.Body.String(), "data-wf-decide") {
		t.Error("approval page should describe the pending action and offer Approve/Reject")
	}
	// Deciding another scope's approval is refused and leaves it pending.
	if rec := e.do(e.scopedA, http.MethodPost, "/admin/workflows/approvals/"+apB+"/approve", "application/json", ""); rec.Code != 404 {
		t.Errorf("scoped A approving B's approval = %d, want 404", rec.Code)
	}
	if ap, _ := e.repo.GetPendingApproval(context.Background(), apB); ap == nil {
		t.Error("B's approval must remain pending")
	}
	// Deciding the in-scope one works end to end.
	if rec := e.do(e.scopedA, http.MethodPost, "/admin/workflows/approvals/"+apA+"/reject", "application/json", ""); rec.Code != 200 {
		t.Errorf("scoped A rejecting own approval = %d body=%s", rec.Code, rec.Body.String())
	}
	if ap, _ := e.repo.GetPendingApproval(context.Background(), apA); ap != nil {
		t.Error("A's approval should be decided")
	}
	// An unscoped admin sees B's.
	rec = e.do(e.sec, http.MethodGet, "/admin/workflows/approvals", htmlAccept, "")
	if !strings.Contains(rec.Body.String(), nameB) {
		t.Error("unscoped admin should see B's approval")
	}
}

// --- escaping of untrusted text ---

func TestWorkflowPages_EscapeUntrustedText(t *testing.T) {
	e := newWFEnv(t)
	xssName := `</script><script>alert("wfname")</script>` + e.sfx
	const (
		xssEvent  = `<img src=x onerror=alert("evt")>`
		xssHost   = `<b onmouseover=alert("host")>h</b>`
		xssDetail = `<svg onload=alert("detail")>`
		xssSubj   = `<iframe src=javascript:alert("subj")>`
	)
	devID := e.mkDevice(nil, xssHost)
	id := e.mkWorkflow(xssName, nil, workflows.Action{Type: workflows.ActionSendAlert, Severity: "INFO", Subject: xssSubj})
	e.mkRun(id, xssName, devID, map[string]any{"id": xssEvent}, xssDetail)
	e.mkApproval(id, xssName, nil, devID, []workflows.Action{{Type: workflows.ActionSendAlert, Severity: "INFO", Subject: xssSubj}})

	for _, p := range []string{"/admin/workflows", "/admin/workflows/runs", "/admin/workflows/approvals"} {
		rec := e.do(e.sec, http.MethodGet, p, htmlAccept, "")
		if rec.Code != 200 {
			t.Fatalf("%s = %d", p, rec.Code)
		}
		body := rec.Body.String()
		for _, raw := range []string{`<script>alert("wfname")`, `<img src=x`, `<b onmouseover`, `<svg onload`, `<iframe src=javascript`} {
			if strings.Contains(body, raw) {
				t.Errorf("%s renders untrusted text unescaped: %q", p, raw)
			}
		}
	}
	// The stored text still shows up, escaped.
	rec := e.do(e.sec, http.MethodGet, "/admin/workflows/runs", htmlAccept, "")
	for _, esc := range []string{"&lt;img src=x onerror=", "&lt;svg onload=", "&lt;b onmouseover="} {
		if !strings.Contains(rec.Body.String(), esc) {
			t.Errorf("runs page missing escaped text %q", esc)
		}
	}
	// The editor's JSON config block cannot be broken out of with </script>.
	list := e.do(e.sec, http.MethodGet, "/admin/workflows", htmlAccept, "").Body.String()
	if strings.Contains(list, `</script><script>alert`) {
		t.Error("workflow name broke out of the config <script> block")
	}
}

// --- editor: create / edit round trip through the same JSON the page's JS sends ---

var configRe = regexp.MustCompile(`(?s)<script type="application/json" id="wf-config">(.*?)</script>`)

func pageConfig(t *testing.T, body string) (cfg struct {
	EventKinds []struct{ Kind, Fields string } `json:"event_kinds"`
	Actions    []string                        `json:"action_types"`
	Groups     []struct{ ID, Name string }     `json:"groups"`
	Campaigns  []struct{ ID, Name string }     `json:"campaigns"`
	Fields     []struct{ Name string }         `json:"fields"`
	Workflows  []map[string]any                `json:"workflows"`
}) {
	t.Helper()
	m := configRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no wf-config block on the page")
	}
	if err := json.Unmarshal([]byte(m[1]), &cfg); err != nil {
		t.Fatalf("decode wf-config: %v\n%s", err, m[1])
	}
	return cfg
}

func TestWorkflowEditor_ConfigAndCreateEditRoundTrip(t *testing.T) {
	e := newWFEnv(t)
	ctx := context.Background()

	grp, err := e.repo.CreateGroup(ctx, db.CreateGroupInput{Name: "wfui-grp-" + e.sfx, Kind: types.GroupKindTarget, CreatedBy: "seed"})
	if err != nil {
		t.Fatalf("group: %v", err)
	}

	body := e.do(e.sec, http.MethodGet, "/admin/workflows", htmlAccept, "").Body.String()
	cfg := pageConfig(t, body)
	// Dropdowns come from the real lists.
	if len(cfg.EventKinds) != len(workflows.AllEventKinds) {
		t.Errorf("event kinds on page = %d, engine has %d", len(cfg.EventKinds), len(workflows.AllEventKinds))
	}
	if len(cfg.Fields) == 0 {
		t.Error("condition field reference missing")
	}
	wantActions := []string{"add_tag", "remove_tag", "set_ring", "group_include", "group_exclude", "run_script", "send_alert", "lock", "quarantine", "require_approval", "start_campaign"}
	have := map[string]bool{}
	for _, a := range cfg.Actions {
		have[a] = true
	}
	for _, a := range wantActions {
		if !have[a] {
			t.Errorf("action type %q not offered by the editor", a)
		}
	}
	foundGrp := false
	for _, g := range cfg.Groups {
		if g.ID == grp.ID {
			foundGrp = true
		}
	}
	if !foundGrp {
		t.Error("group dropdown missing the created group")
	}

	// The exact shape the page's JS posts: Trigger/Schedule keys are the engine's Go names.
	create := fmt.Sprintf(`{
	  "name":"form-%[1]s","description":"made on the page","enabled":true,"dry_run":false,"cooldown_seconds":60,
	  "trigger":{"Kind":"attribute_changed","Filter":{"key":"wfui.%[1]s"}},
	  "condition":{"all":[{"field":"device.status","op":"eq","value":"APPROVED"},{"field":"device.pending_updates","op":"gte","value":0}]},
	  "then_actions":[
	    {"type":"add_tag","tag":"from-ui"},
	    {"type":"set_ring","ring":"PILOT"},
	    {"type":"group_include","group_id":"%[2]s"},
	    {"type":"send_alert","severity":"WARNING","subject":"hello"},
	    {"type":"require_approval"},
	    {"type":"remove_tag","tag":"from-ui"}
	  ],
	  "else_actions":[{"type":"lock","message":"nope"}]
	}`, e.sfx, grp.ID)
	rec := e.do(e.sec, http.MethodPost, "/admin/workflows", "application/json", create)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	var created struct{ ID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	// It is listed on the HTML page with its trigger.
	list := e.do(e.sec, http.MethodGet, "/admin/workflows", htmlAccept, "").Body.String()
	if !strings.Contains(list, "form-"+e.sfx) || !strings.Contains(list, "attribute_changed") {
		t.Error("created workflow missing from the list page")
	}

	// The engine accepts it: fire an event, the run appears with its actions, the
	// require_approval step parks, and approving through the page's route finishes the run.
	devID := e.mkDevice(nil, "ui-engine-host")
	e.repo.EmitEvent(ctx, workflows.EventAttributeChanged, devID, map[string]any{"key": "wfui." + e.sfx, "old": "1", "new": "2"}, false)
	for i := 0; i < 50; i++ {
		e.eng.DrainEvents(ctx)
	}
	runsHTML := e.do(e.sec, http.MethodGet, "/admin/workflows/runs?workflow_id="+created.ID, htmlAccept, "").Body.String()
	if !strings.Contains(runsHTML, "AWAITING_APPROVAL") || !strings.Contains(runsHTML, "add_tag") || !strings.Contains(runsHTML, "key=wfui."+e.sfx) {
		t.Fatalf("run for the page-created workflow not shown as expected:\n%s", runsHTML)
	}
	aps, _ := e.repo.ListPendingApprovals(ctx, db.Unscoped)
	var apID string
	for _, a := range aps {
		if a.WorkflowID == created.ID {
			apID = a.ID
		}
	}
	if apID == "" {
		t.Fatal("no pending approval from the page-created workflow")
	}
	if rec := e.do(e.sec, http.MethodPost, "/admin/workflows/approvals/"+apID+"/approve", "application/json", ""); rec.Code != 200 {
		t.Fatalf("approve = %d %s", rec.Code, rec.Body.String())
	}
	runsHTML = e.do(e.sec, http.MethodGet, "/admin/workflows/runs?workflow_id="+created.ID, htmlAccept, "").Body.String()
	if !strings.Contains(runsHTML, "COMPLETED") && !strings.Contains(runsHTML, "DRY_RUN") {
		t.Errorf("run did not finish after approval:\n%s", runsHTML)
	}

	// Edit round trip: the page's embedded definition posts back unchanged and is accepted.
	cfg = pageConfig(t, e.do(e.sec, http.MethodGet, "/admin/workflows", htmlAccept, "").Body.String())
	var def map[string]any
	for _, w := range cfg.Workflows {
		if w["id"] == created.ID {
			def = w
		}
	}
	if def == nil {
		t.Fatal("created workflow missing from editor config")
	}
	def["description"] = "edited on the page"
	b, _ := json.Marshal(def)
	if rec := e.do(e.sec, http.MethodPost, "/admin/workflows/"+created.ID, "application/json", string(b)); rec.Code != 200 {
		t.Fatalf("edit round trip = %d %s", rec.Code, rec.Body.String())
	}
	if wf, _ := e.repo.GetWorkflow(ctx, created.ID); wf == nil || wf.Description != "edited on the page" || len(wf.ThenActions) != 6 || wf.Trigger == nil || wf.Trigger.Kind != workflows.EventAttributeChanged {
		t.Errorf("edit not applied cleanly: %+v", wf)
	}

	// A schedule workflow round-trips too, in the Go-named shape.
	sched := `{"name":"sched-` + e.sfx + `","enabled":false,"dry_run":true,"schedule":{"Cron":"0 3 * * 1","TargetKind":"ring","TargetRing":"CANARY"},"then_actions":[{"type":"add_tag","tag":"weekly"}]}`
	if rec := e.do(e.sec, http.MethodPost, "/admin/workflows", "application/json", sched); rec.Code != http.StatusCreated {
		t.Fatalf("schedule create = %d %s", rec.Code, rec.Body.String())
	}
	list = e.do(e.sec, http.MethodGet, "/admin/workflows", htmlAccept, "").Body.String()
	if !strings.Contains(list, "cron 0 3 * * 1 over ring CANARY") {
		t.Error("schedule trigger not described on the list page")
	}

	// Toggle through the page's route flips the flag and the page reflects it.
	if rec := e.do(e.sec, http.MethodPost, "/admin/workflows/"+created.ID+"/toggle", "application/json", ""); rec.Code != 200 {
		t.Fatalf("toggle = %d", rec.Code)
	}
	if wf, _ := e.repo.GetWorkflow(ctx, created.ID); wf.Enabled {
		t.Error("toggle did not disable the workflow")
	}
}

func TestWorkflowEditor_ValidationErrorsAreReturnedForTheForm(t *testing.T) {
	e := newWFEnv(t)
	for name, c := range map[string]struct{ body, want string }{
		"bad cron":      {`{"name":"v","schedule":{"Cron":"nope","TargetKind":"ring","TargetRing":"CANARY"},"then_actions":[{"type":"lock"}]}`, "invalid schedule cron"},
		"no actions":    {`{"name":"v","trigger":{"Kind":"agent_started"}}`, "at least one"},
		"bad ring":      {`{"name":"v","trigger":{"Kind":"agent_started"},"then_actions":[{"type":"set_ring","ring":"NOPE"}]}`, "ring must be"},
		"bad condition": {`{"name":"v","trigger":{"Kind":"agent_started"},"condition":{"all":[{"field":"nope.x","op":"eq","value":1}]},"then_actions":[{"type":"lock"}]}`, "invalid condition"},
		"unknown event": {`{"name":"v","trigger":{"Kind":"nope"},"then_actions":[{"type":"lock"}]}`, "unknown event trigger"},
	} {
		rec := e.do(e.sec, http.MethodPost, "/admin/workflows", "application/json", c.body)
		var out struct{ Error string }
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		if rec.Code != 400 || !strings.Contains(out.Error, c.want) {
			t.Errorf("%s: code=%d error=%q, want 400 containing %q", name, rec.Code, out.Error, c.want)
		}
	}
	// CSRF still applies to the page's POSTs.
	req := httptest.NewRequest(http.MethodPost, "/admin/workflows", strings.NewReader(`{}`))
	req.AddCookie(e.sec.cookie)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Errorf("POST without CSRF token = %d, want 403", rec.Code)
	}
}

// Group names are visible to every admin on the Groups page already (only member counts are
// scoped), so the picker uses the same scoped list call and adds no new exposure.
func TestWorkflowEditor_ScopedAdminSeesOnlyOwnWorkflowsAndPickers(t *testing.T) {
	e := newWFEnv(t)
	ctx := context.Background()
	nameA, nameB, nameU := "ed-A-"+e.sfx, "ed-B-"+e.sfx, "ed-U-"+e.sfx
	e.mkWorkflow(nameA, []string{e.tagA})
	e.mkWorkflow(nameB, []string{e.tagB})
	e.mkWorkflow(nameU, nil)
	gA, _ := e.repo.CreateGroup(ctx, db.CreateGroupInput{Name: "grpA-" + e.sfx, Kind: types.GroupKindTarget, CreatedBy: "seed", CreatorScopedTags: []string{e.tagA}})

	body := e.do(e.scopedA, http.MethodGet, "/admin/workflows", htmlAccept, "").Body.String()
	for _, n := range []string{nameB, nameU} {
		if strings.Contains(body, n) {
			t.Errorf("scoped A's workflows page leaks %q", n)
		}
	}
	for _, n := range []string{nameA, gA.Name} {
		if !strings.Contains(body, n) {
			t.Errorf("scoped A's workflows page is missing %q", n)
		}
	}
}
