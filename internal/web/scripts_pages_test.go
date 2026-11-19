package web_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/audit"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/web"
)

// These tests drive the scripts/sensors pages through the REAL router and session auth
// middleware (cookie + CSRF), with real Postgres rows, not through handler functions.

const (
	secretDefault = "S3CR3T-DEFAULT-VALUE"
	secretRunVal  = "S3CR3T-RUN-VALUE"
	xssOutput     = `<script>alert("pwned")</script>`
)

type scriptsEnv struct {
	t       *testing.T
	repo    *db.Repository
	router  chi.Router
	cookies map[string]*http.Cookie
	csrf    map[string]string
	sfx     string
}

func newScriptsEnv(t *testing.T) *scriptsEnv {
	t.Helper()
	pool := invWebPool(t)
	t.Cleanup(pool.Close)
	repo := db.NewRepository(pool)
	h, err := web.NewHandler(repo, nil, audit.NewForwarder(repo, ""))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	router := chi.NewRouter()
	h.RegisterRoutes(router, "admin", "unused-break-glass-pass")
	return &scriptsEnv{t: t, repo: repo, router: router,
		cookies: map[string]*http.Cookie{}, csrf: map[string]string{},
		sfx: strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "")}
}

func (e *scriptsEnv) user(name string, role types.AdminRole, tags []string) {
	e.t.Helper()
	ctx := context.Background()
	uname := fmt.Sprintf("%s-%s", name, e.sfx)
	if _, err := e.repo.CreateLocalAdminUser(ctx, types.CreateUserRequest{
		Username: uname, Email: uname + "@example.test", Password: "pw-" + e.sfx, Role: role, AllowedTags: tags,
	}); err != nil {
		e.t.Fatalf("create user %s: %v", name, err)
	}
	cookie, csrf, err := web.IssueSession(ctx, e.repo, uname, false)
	if err != nil {
		e.t.Fatalf("issue session: %v", err)
	}
	e.cookies[name], e.csrf[name] = cookie, csrf
}

// do issues a request as the named user. accept "" sends no Accept header at all.
func (e *scriptsEnv) do(user, method, path, accept string, body any) *httptest.ResponseRecorder {
	e.t.Helper()
	var rdr *strings.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = strings.NewReader(string(b))
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, "http://localhost"+path, rdr)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if user != "" {
		req.AddCookie(e.cookies[user])
		if method != http.MethodGet {
			req.Header.Set("X-CSRF-Token", e.csrf[user])
		}
	}
	w := httptest.NewRecorder()
	e.router.ServeHTTP(w, req)
	return w
}

const browserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

func (e *scriptsEnv) seedDevice(tag string) types.Device {
	e.t.Helper()
	ctx := context.Background()
	dev, _, err := e.repo.GetOrCreateDevice(ctx, tag+"-hw-"+e.sfx, tag+"-host-"+e.sfx)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.repo.UpdateDeviceTags(ctx, dev.ID, []string{tag}); err != nil {
		e.t.Fatal(err)
	}
	if _, _, err := e.repo.ApproveDevice(ctx, dev.ID); err != nil {
		e.t.Fatal(err)
	}
	return *dev
}

func (e *scriptsEnv) seedScript(params []types.ScriptParam) (*types.Script, *types.ScriptVersion) {
	e.t.Helper()
	ctx := context.Background()
	s, err := e.repo.CreateScript(ctx, &types.Script{
		Name: "uiscript-" + e.sfx, Description: "page test", Interpreter: types.InterpreterBash, RunAs: types.RunAsRoot,
	}, "#!/bin/bash\necho hi\n", params, "seed")
	if err != nil {
		e.t.Fatalf("create script: %v", err)
	}
	full, err := e.repo.GetScript(ctx, s.ID)
	if err != nil || full == nil || full.CurrentVersion == nil {
		e.t.Fatalf("get script: %v", err)
	}
	return full, full.CurrentVersion
}

func (e *scriptsEnv) seedRun(dev types.Device, v *types.ScriptVersion, stdout, stderr string, secret map[string]string) string {
	e.t.Helper()
	ctx := context.Background()
	runID, err := e.repo.QueueScriptRun(ctx, dev.ID, v, types.TriggerOnDemand, map[string]string{}, secret, "seeder")
	if err != nil {
		e.t.Fatalf("queue run: %v", err)
	}
	if err := e.repo.RecordScriptRunResult(ctx, dev.ID, types.ScriptRunResult{
		RunID: runID, Status: types.ScriptRunCompleted, ExitCode: 0, Stdout: stdout, Stderr: stderr, DurationMS: 12,
	}); err != nil {
		e.t.Fatalf("record run: %v", err)
	}
	return runID
}

// ---------------------------------------------------------------------------------------

func TestScriptsPages_ContentNegotiation(t *testing.T) {
	e := newScriptsEnv(t)
	e.user("sec", types.RoleSecurityAdmin, nil)
	s, _ := e.seedScript(nil)

	paths := []struct{ path, jsonKey string }{
		{"/admin/scripts", "scripts"},
		{"/admin/scripts/" + s.ID, "script"},
		{"/admin/sensors", "sensors"},
	}
	for _, p := range paths {
		// No Accept, */*, and application/json must all keep returning the JSON API shape.
		var bodies []string
		for _, accept := range []string{"", "*/*", "application/json"} {
			w := e.do("sec", http.MethodGet, p.path, accept, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("%s Accept=%q: status %d", p.path, accept, w.Code)
			}
			if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("%s Accept=%q: content-type %q, want JSON", p.path, accept, ct)
			}
			var m map[string]json.RawMessage
			if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
				t.Fatalf("%s Accept=%q: not JSON: %v", p.path, accept, err)
			}
			if _, ok := m[p.jsonKey]; !ok {
				t.Errorf("%s Accept=%q: JSON lacks key %q: %s", p.path, accept, p.jsonKey, w.Body.String())
			}
			bodies = append(bodies, w.Body.String())
		}
		if bodies[0] != bodies[1] || bodies[1] != bodies[2] {
			t.Errorf("%s: JSON differs between Accept values", p.path)
		}
		// A browser Accept header gets the HTML page inside the layout.
		w := e.do("sec", http.MethodGet, p.path, browserAccept, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s html: status %d", p.path, w.Code)
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("%s html: content-type %q", p.path, ct)
		}
		if !strings.Contains(w.Body.String(), "<html") || !strings.Contains(w.Body.String(), `href="/admin/scripts"`) {
			t.Errorf("%s html: not the layout page", p.path)
		}
	}
	// The page lists the seeded script and links to it.
	w := e.do("sec", http.MethodGet, "/admin/scripts", browserAccept, nil)
	if !strings.Contains(w.Body.String(), s.Name) || !strings.Contains(w.Body.String(), "/admin/scripts/"+s.ID) {
		t.Error("list page does not show the seeded script")
	}
	// Unknown script: HTML request gets a 404, not a blank page.
	w = e.do("sec", http.MethodGet, "/admin/scripts/00000000-0000-0000-0000-000000000000", browserAccept, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("unknown script html: status %d, want 404", w.Code)
	}
	// Unauthenticated HTML request is not served the page.
	w = e.do("", http.MethodGet, "/admin/scripts", browserAccept, nil)
	if w.Code == http.StatusOK {
		t.Error("unauthenticated request must not render the scripts page")
	}
}

func TestScriptsPages_AuditorReadOnly(t *testing.T) {
	e := newScriptsEnv(t)
	e.user("aud", types.RoleAuditor, nil)
	s, v := e.seedScript(nil)
	if _, err := e.repo.CreateSensor(context.Background(), &types.Sensor{
		Name: "ui_sensor_" + strings.ToLower(strings.ReplaceAll(e.sfx, ".", "")), ScriptVersionID: v.ID,
		ReturnType: types.SensorString, IntervalSeconds: 3600, TargetTags: []string{}, Enabled: true,
	}, "seed"); err != nil {
		t.Fatalf("create sensor: %v", err)
	}

	for _, path := range []string{"/admin/scripts", "/admin/scripts/" + s.ID, "/admin/sensors"} {
		w := e.do("aud", http.MethodGet, path, browserAccept, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: auditor status %d", path, w.Code)
		}
		body := w.Body.String()
		// Scope the check to the scripts content: the layout itself has its own forms.
		start := strings.Index(body, `id="scripts-root"`)
		end := strings.Index(body, `<script>
(function () {`)
		if start < 0 || end < start {
			t.Fatalf("%s: could not locate page content", path)
		}
		content := body[start:end]
		for _, forbidden := range []string{"<form", "<button", "createScript", "deleteScript", "saveMeta", "addVersion", "setCurrent", "toggleSensor", "deleteSensor", "createSensor", `id="run-form"`} {
			if strings.Contains(content, forbidden) {
				t.Errorf("%s: auditor page renders mutating control %q", path, forbidden)
			}
		}
		if !strings.Contains(content, "Read-only view") {
			t.Errorf("%s: auditor page lacks the read-only note", path)
		}
	}

	// Server-side RBAC stays the authority: every mutation is refused for an auditor.
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/admin/scripts", map[string]any{"name": "x", "interpreter": "bash", "run_as": "root", "content": "echo"}},
		{"POST", "/admin/scripts/" + s.ID, map[string]any{"name": "x", "interpreter": "bash", "run_as": "root"}},
		{"POST", "/admin/scripts/" + s.ID + "/versions", map[string]any{"content": "echo"}},
		{"POST", "/admin/scripts/" + s.ID + "/versions/" + v.ID + "/current", map[string]any{}},
		{"POST", "/admin/scripts/" + s.ID + "/run", map[string]any{"tags": []string{"x"}}},
		{"DELETE", "/admin/scripts/" + s.ID, nil},
		{"POST", "/admin/sensors", map[string]any{"name": "zz", "script_version_id": v.ID, "return_type": "string", "interval_seconds": 3600}},
	} {
		w := e.do("aud", c.method, c.path, "application/json", c.body)
		if w.Code != http.StatusForbidden {
			t.Errorf("auditor %s %s: status %d, want 403", c.method, c.path, w.Code)
		}
	}
	if got, err := e.repo.GetScript(context.Background(), s.ID); err != nil || got == nil {
		t.Error("script must survive the auditor's delete attempt")
	}
}

func TestScriptsPages_ScopedOperator(t *testing.T) {
	e := newScriptsEnv(t)
	e.user("op", types.RoleOperator, []string{"eng"})
	inDev := e.seedDevice("eng")
	outDev := e.seedDevice("finance")
	s, v := e.seedScript(nil)
	e.seedRun(inDev, v, "inscope-output-marker", "", nil)
	e.seedRun(outDev, v, "outscope-output-marker", "", nil)

	// A group holding ONLY the out-of-scope device.
	ctx := context.Background()
	g, err := e.repo.CreateGroup(ctx, db.CreateGroupInput{Name: "outgrp-" + e.sfx, Kind: types.GroupKindTarget, IncludeDeviceIDs: []string{outDev.ID}, CreatedBy: "seed"})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, _, err := e.repo.RecomputeGroupMembership(ctx, g.ID); err != nil {
		t.Fatalf("recompute group: %v", err)
	}

	w := e.do("op", http.MethodGet, "/admin/scripts/"+s.ID, browserAccept, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("detail: status %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, inDev.Hostname) {
		t.Error("scoped operator should see the in-scope device")
	}
	if strings.Contains(body, outDev.Hostname) || strings.Contains(body, outDev.ID) {
		t.Error("scoped operator must not see the out-of-scope device on the page")
	}
	if !strings.Contains(body, "inscope-output-marker") {
		t.Error("in-scope run output should be listed")
	}
	if strings.Contains(body, "outscope-output-marker") {
		t.Error("out-of-scope run output leaked into the page")
	}
	// An operator gets the run dialog but no create/edit/delete controls.
	if !strings.Contains(body, `id="run-form"`) {
		t.Error("operator should see the run dialog")
	}
	for _, forbidden := range []string{`id="meta-form"`, `id="version-form"`, `id="script-delete-btn"`} {
		if strings.Contains(body, forbidden) {
			t.Errorf("operator page renders edit control %s", forbidden)
		}
	}

	// Running through the endpoint the page calls: out-of-scope targets resolve to nothing.
	for name, req := range map[string]map[string]any{
		"device id": {"device_ids": []string{outDev.ID}},
		"tag":       {"tags": []string{"finance"}},
		"group":     {"group_id": g.ID},
	} {
		w := e.do("op", http.MethodPost, "/admin/scripts/"+s.ID+"/run", "application/json", req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("run by %s on out-of-scope device: status %d (%s), want 400", name, w.Code, w.Body.String())
		}
	}
	runs, _ := e.repo.ListScriptRunsForDevice(ctx, outDev.ID, 50)
	if len(runs) != 1 { // only the seeded one
		t.Errorf("out-of-scope device has %d runs, want 1 (seed only)", len(runs))
	}
	// A mixed request is intersected with scope: only the in-scope device is queued.
	w = e.do("op", http.MethodPost, "/admin/scripts/"+s.ID+"/run", "application/json",
		map[string]any{"device_ids": []string{inDev.ID, outDev.ID}})
	if w.Code != http.StatusCreated {
		t.Fatalf("mixed run: status %d (%s)", w.Code, w.Body.String())
	}
	var res struct{ Queued int }
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if res.Queued != 1 {
		t.Errorf("mixed run queued %d, want 1", res.Queued)
	}
	// Operator mutations of scripts are refused.
	w = e.do("op", http.MethodDelete, "/admin/scripts/"+s.ID, "application/json", nil)
	if w.Code != http.StatusForbidden {
		t.Errorf("operator delete: status %d, want 403", w.Code)
	}
}

func TestScriptsPages_RunByGroupAndRing(t *testing.T) {
	e := newScriptsEnv(t)
	e.user("sec", types.RoleSecurityAdmin, nil)
	dev := e.seedDevice("eng")
	s, _ := e.seedScript(nil)
	ctx := context.Background()
	g, err := e.repo.CreateGroup(ctx, db.CreateGroupInput{Name: "ingrp-" + e.sfx, Kind: types.GroupKindTarget, IncludeDeviceIDs: []string{dev.ID}, CreatedBy: "seed"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.repo.RecomputeGroupMembership(ctx, g.ID); err != nil {
		t.Fatal(err)
	}
	w := e.do("sec", http.MethodGet, "/admin/scripts/"+s.ID, browserAccept, nil)
	if !strings.Contains(w.Body.String(), g.Name) || !strings.Contains(w.Body.String(), `id="run-ring"`) {
		t.Error("run dialog should offer groups and rings")
	}
	w = e.do("sec", http.MethodPost, "/admin/scripts/"+s.ID+"/run", "application/json", map[string]any{"group_id": g.ID})
	if w.Code != http.StatusCreated {
		t.Fatalf("run by group: status %d (%s)", w.Code, w.Body.String())
	}
}

func TestScriptsPages_SecretsNeverRendered(t *testing.T) {
	e := newScriptsEnv(t)
	e.user("sec", types.RoleSecurityAdmin, nil)
	e.user("op", types.RoleOperator, nil)
	dev := e.seedDevice("eng")
	s, v := e.seedScript([]types.ScriptParam{
		{Name: "API_TOKEN", Type: types.ScriptParamString, Secret: true, Default: secretDefault},
		{Name: "PORT", Type: types.ScriptParamInteger, Default: "8080"},
	})
	e.seedRun(dev, v, "ok", "", map[string]string{"API_TOKEN": secretRunVal})

	for _, user := range []string{"sec", "op"} {
		for _, path := range []string{"/admin/scripts", "/admin/scripts/" + s.ID, "/admin/sensors"} {
			w := e.do(user, http.MethodGet, path, browserAccept, nil)
			if w.Code != http.StatusOK {
				t.Fatalf("%s %s: %d", user, path, w.Code)
			}
			body := w.Body.String()
			for _, secret := range []string{secretDefault, secretRunVal} {
				if strings.Contains(body, secret) {
					t.Errorf("%s %s: rendered secret value %q", user, path, secret)
				}
			}
		}
	}
	w := e.do("sec", http.MethodGet, "/admin/scripts/"+s.ID, browserAccept, nil)
	body := w.Body.String()
	// The declaration is shown, flagged as secret with a hidden default; the plain default is shown.
	if !strings.Contains(body, "API_TOKEN") || !strings.Contains(body, "set (hidden)") {
		t.Error("secret parameter should show as declared with a hidden default")
	}
	if !strings.Contains(body, `type="password"`) {
		t.Error("run dialog should take secret parameter values in a password field")
	}
	if !strings.Contains(body, "8080") {
		t.Error("non-secret default should be shown")
	}
}

func TestScriptsPages_DeviceOutputEscaped(t *testing.T) {
	e := newScriptsEnv(t)
	e.user("aud", types.RoleAuditor, nil)
	dev := e.seedDevice("eng")
	s, v := e.seedScript(nil)
	e.seedRun(dev, v, xssOutput, `<img src=x onerror=alert(1)>`, nil)

	w := e.do("aud", http.MethodGet, "/admin/scripts/"+s.ID, browserAccept, nil)
	body := w.Body.String()
	if strings.Contains(body, xssOutput) || strings.Contains(body, "<img src=x") {
		t.Fatal("device output rendered unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(&#34;pwned&#34;)&lt;/script&gt;") {
		t.Errorf("escaped stdout not found in page")
	}
	if !strings.Contains(body, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Errorf("escaped stderr not found in page")
	}
}

func TestScriptsPages_ManageFlowThroughRoutes(t *testing.T) {
	e := newScriptsEnv(t)
	e.user("sec", types.RoleSecurityAdmin, nil)
	name := "flow-" + e.sfx

	// Create, exactly as the page's form posts it.
	w := e.do("sec", http.MethodPost, "/admin/scripts", "application/json", map[string]any{
		"name": name, "description": "d", "interpreter": "bash", "run_as": "root", "content": "echo one",
		"params": []map[string]any{{"name": "MODE", "type": "string", "required": false, "secret": false, "default": "fast"}},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created struct{ Script types.Script }
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	id := created.Script.ID

	w = e.do("sec", http.MethodPost, "/admin/scripts/"+id+"/versions", "application/json", map[string]any{"content": "echo two"})
	if w.Code != http.StatusCreated {
		t.Fatalf("add version: %d %s", w.Code, w.Body.String())
	}
	page := e.do("sec", http.MethodGet, "/admin/scripts/"+id, browserAccept, nil).Body.String()
	if !strings.Contains(page, "echo one") || !strings.Contains(page, "echo two") {
		t.Error("version history should show the content of every version")
	}
	if !strings.Contains(page, types.ComputeScriptSHA256("echo one")) || !strings.Contains(page, types.ComputeScriptSHA256("echo two")) {
		t.Error("version history should show each version's SHA-256")
	}
	versions, _ := e.repo.ListScriptVersions(context.Background(), id)
	var v1 string
	for _, v := range versions {
		if v.Version == 1 {
			v1 = v.ID
		}
	}
	if w = e.do("sec", http.MethodPost, "/admin/scripts/"+id+"/versions/"+v1+"/current", "application/json", map[string]any{}); w.Code != http.StatusOK {
		t.Fatalf("set current: %d %s", w.Code, w.Body.String())
	}
	if got, _ := e.repo.GetScript(context.Background(), id); got.CurrentVersionID == nil || *got.CurrentVersionID != v1 {
		t.Error("current version was not switched")
	}
	if w = e.do("sec", http.MethodPost, "/admin/scripts/"+id, "application/json", map[string]any{
		"name": name, "description": "changed", "interpreter": "python3", "run_as": "root", "timeout_seconds": 60, "max_output_bytes": 1024,
	}); w.Code != http.StatusOK {
		t.Fatalf("update meta: %d %s", w.Code, w.Body.String())
	}

	// Sensors: create, disable, edit, delete.
	cur, _ := e.repo.GetScript(context.Background(), id)
	sname := "flow_" + strings.ToLower(strings.ReplaceAll(e.sfx, ".", ""))
	w = e.do("sec", http.MethodPost, "/admin/sensors", "application/json", map[string]any{
		"name": sname, "script_version_id": cur.CurrentVersion.ID, "return_type": "string", "interval_seconds": 3600, "target_tags": []string{"eng"}, "ring": "BETA", "enabled": true,
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create sensor: %d %s", w.Code, w.Body.String())
	}
	var sc struct{ Sensor types.Sensor }
	_ = json.Unmarshal(w.Body.Bytes(), &sc)
	sp := e.do("sec", http.MethodGet, "/admin/sensors", browserAccept, nil).Body.String()
	if !strings.Contains(sp, sname) || !strings.Contains(sp, "every 3600s") || !strings.Contains(sp, "tags: eng") || !strings.Contains(sp, "ring BETA") {
		t.Error("sensor page should show name, interval and targeting")
	}
	if w = e.do("sec", http.MethodPost, "/admin/sensors/"+sc.Sensor.ID, "application/json", map[string]any{
		"description": "x", "script_version_id": cur.CurrentVersion.ID, "return_type": "string", "interval_seconds": 3600, "target_tags": []string{"eng"}, "ring": "BETA", "enabled": false,
	}); w.Code != http.StatusOK {
		t.Fatalf("disable sensor: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(e.do("sec", http.MethodGet, "/admin/sensors", browserAccept, nil).Body.String(), "disabled") {
		t.Error("sensor page should show the sensor as disabled")
	}
	if w = e.do("sec", http.MethodDelete, "/admin/sensors/"+sc.Sensor.ID, "application/json", nil); w.Code != http.StatusOK {
		t.Fatalf("delete sensor: %d", w.Code)
	}

	// Delete the script.
	if w = e.do("sec", http.MethodDelete, "/admin/scripts/"+id, "application/json", nil); w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if w = e.do("sec", http.MethodGet, "/admin/scripts/"+id, browserAccept, nil); w.Code != http.StatusNotFound {
		t.Errorf("deleted script page: %d, want 404", w.Code)
	}
	// Mutations without the CSRF token are refused even for a security admin.
	req := httptest.NewRequest(http.MethodPost, "http://localhost/admin/scripts", strings.NewReader(`{"name":"nocsrf","interpreter":"bash","run_as":"root","content":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(e.cookies["sec"])
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("create without CSRF token: %d, want 403", rec.Code)
	}
}
