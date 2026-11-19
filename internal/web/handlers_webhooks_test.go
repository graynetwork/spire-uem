package web_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/audit"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/web"
	"github.com/spire-uem/spire-uem/internal/webhooks"
)

const (
	whBGUser = "bg-admin"
	whBGPass = "bg-pass-1234567890"
)

type whEnv struct {
	t      *testing.T
	repo   *db.Repository
	router http.Handler
	cookie *http.Cookie
	csrf   string
}

func newWhEnv(t *testing.T) *whEnv {
	pool := campaignWebPool(t)
	if pool == nil {
		t.SkipNow()
	}
	t.Cleanup(pool.Close)
	repo := db.NewRepositoryWithKEK(pool, filepath.Join(t.TempDir(), "kek.pem"))
	h, err := web.NewHandler(repo, nil, audit.NewForwarder(repo, ""))
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	h.RegisterRoutes(r, whBGUser, whBGPass)
	cookie, csrf, err := web.IssueSession(context.Background(), repo, whBGUser, false)
	if err != nil {
		t.Fatal(err)
	}
	return &whEnv{t: t, repo: repo, router: r, cookie: cookie, csrf: csrf}
}

// do sends a request through the real router. auth: "cookie" (session + CSRF header),
// "cookie-nocsrf", "basic" (break-glass), or "user:pass" (a DB admin via Basic).
func (e *whEnv) do(method, path, auth, accept, ctype, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	switch {
	case auth == "cookie":
		req.AddCookie(e.cookie)
		req.Header.Set("X-CSRF-Token", e.csrf)
	case auth == "cookie-nocsrf":
		req.AddCookie(e.cookie)
	case auth == "basic":
		req.SetBasicAuth(whBGUser, whBGPass)
	case strings.Contains(auth, ":"):
		u, p, _ := strings.Cut(auth, ":")
		req.SetBasicAuth(u, p)
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func (e *whEnv) createJSON(name, url string, types_ []string, allowPrivate bool) *httptest.ResponseRecorder {
	b, _ := json.Marshal(map[string]any{"name": name, "url": url, "event_types": types_, "allow_private_network": allowPrivate})
	return e.do("POST", "/admin/webhooks", "cookie", "application/json", "application/json", string(b))
}

func TestWebhooksAdmin_RBAC_SuperAdminOnly(t *testing.T) {
	e := newWhEnv(t)
	ctx := context.Background()
	sfx := strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	roles := []types.AdminRole{types.RoleSecurityAdmin, types.RoleOperator, types.RoleAuditor}
	routes := []struct{ method, path string }{
		{"GET", "/admin/webhooks"}, {"POST", "/admin/webhooks"}, {"POST", "/admin/webhooks/x"},
		{"POST", "/admin/webhooks/x/rotate"}, {"POST", "/admin/webhooks/x/test"},
		{"POST", "/admin/webhooks/x/delete"}, {"DELETE", "/admin/webhooks/x"},
		{"GET", "/admin/webhooks/x/deliveries"}, {"POST", "/admin/webhooks/deliveries/x/redeliver"},
	}
	for _, role := range roles {
		uname := "whrbac-" + strings.ToLower(string(role)) + "-" + sfx
		if _, err := e.repo.CreateLocalAdminUser(ctx, types.CreateUserRequest{Username: uname, Email: uname + "@x.test", Password: "Passw0rd-xyz-123", Role: role}); err != nil {
			t.Fatalf("create %s: %v", role, err)
		}
		for _, rt := range routes {
			rec := e.do(rt.method, rt.path, uname+":Passw0rd-xyz-123", "application/json", "", "")
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s %s: got %d, want 403", role, rt.method, rt.path, rec.Code)
			}
		}
	}
	if rec := e.do("GET", "/admin/webhooks", "basic", "application/json", "", ""); rec.Code != 200 {
		t.Fatalf("super admin GET: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("GET", "/admin/webhooks", "", "application/json", "", ""); rec.Code == 200 {
		t.Fatalf("unauthenticated GET must not succeed")
	}
}

func TestWebhooksAdmin_CSRFRequiredForMutations(t *testing.T) {
	e := newWhEnv(t)
	b := `{"name":"csrf-` + time.Now().Format("150405.000000") + `","url":"https://hooks.example.com/x","event_types":["device_approved"]}`
	if rec := e.do("POST", "/admin/webhooks", "cookie-nocsrf", "application/json", "application/json", b); rec.Code != http.StatusForbidden {
		t.Fatalf("cookie POST without CSRF token: got %d, want 403", rec.Code)
	}
	rec := e.do("POST", "/admin/webhooks", "cookie", "application/json", "application/json", b)
	if rec.Code != http.StatusCreated {
		t.Fatalf("cookie POST with CSRF token: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Webhook struct{ ID string } `json:"webhook"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	t.Cleanup(func() { _ = e.repo.WebhookStore().DeleteSubscription(context.Background(), out.Webhook.ID) })
	if rec := e.do("POST", "/admin/webhooks/"+out.Webhook.ID+"/rotate", "cookie-nocsrf", "application/json", "", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("rotate without CSRF: %d", rec.Code)
	}
	if rec := e.do("POST", "/admin/webhooks/"+out.Webhook.ID+"/delete", "cookie-nocsrf", "application/json", "", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("delete without CSRF: %d", rec.Code)
	}
}

func TestWebhooksAdmin_SSRFRejectedAtSave(t *testing.T) {
	e := newWhEnv(t)
	sfx := time.Now().Format("150405.000000")
	cases := []struct {
		url   string
		allow bool
	}{
		{"http://hooks.example.com/x", false},              // https required
		{"https://127.0.0.1/x", false},                     // loopback
		{"https://127.0.0.1:8443/x", true},                 // loopback stays blocked with the flag
		{"https://localhost/x", true},                      // (resolves to loopback; blocked at connect time too)
		{"https://169.254.169.254/latest/meta-data", true}, // cloud metadata
		{"https://[::1]/x", true},
		{"https://10.1.2.3/x", false}, // private needs the flag
		{"https://user:pw@example.com/x", false},
		{"gopher://example.com/x", false},
	}
	for i, c := range cases {
		rec := e.createJSON("ssrf-"+sfx+"-"+string(rune('a'+i)), c.url, []string{"device_approved"}, c.allow)
		// "localhost" is a name, so save-time passes and the connect-time hook is the control;
		// every IP-literal case must be refused at save.
		if c.url == "https://localhost/x" {
			if rec.Code == http.StatusCreated {
				var out struct{ Webhook struct{ ID string } }
				_ = json.Unmarshal(rec.Body.Bytes(), &out)
				_ = e.repo.WebhookStore().DeleteSubscription(context.Background(), out.Webhook.ID)
			}
			continue
		}
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s allow=%v: got %d, want 400 (%s)", c.url, c.allow, rec.Code, rec.Body)
		}
	}
	// A private https target IS accepted with the flag, and the flag change is audited.
	rec := e.createJSON("priv-"+sfx, "https://10.1.2.3/x", []string{"device_approved"}, true)
	if rec.Code != http.StatusCreated {
		t.Fatalf("private target with the flag: %d %s", rec.Code, rec.Body)
	}
	var out struct{ Webhook struct{ ID string } }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	t.Cleanup(func() { _ = e.repo.WebhookStore().DeleteSubscription(context.Background(), out.Webhook.ID) })
	var n int
	_ = e.repo.Pool().QueryRow(context.Background(),
		`SELECT COUNT(*) FROM system_audit_events WHERE action='WEBHOOK_ALLOW_PRIVATE_NETWORK' AND target_id=$1`, out.Webhook.ID).Scan(&n)
	if n != 1 {
		t.Errorf("enabling allow-private-network must be audited, got %d rows", n)
	}
}

func TestWebhooksAdmin_SecretShownOnceNeverOnGET_ContentNegotiation(t *testing.T) {
	e := newWhEnv(t)
	sfx := strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	rec := e.createJSON("secret-"+sfx, "https://hooks.example.com/secret", []string{"device_approved", "policy_created"}, false)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created struct {
		Webhook struct{ ID string } `json:"webhook"`
		Secret  string              `json:"secret"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	t.Cleanup(func() { _ = e.repo.WebhookStore().DeleteSubscription(context.Background(), created.Webhook.ID) })
	if !strings.HasPrefix(created.Secret, "whsec_") {
		t.Fatalf("create must return the secret once, got %q", created.Secret)
	}

	assertNoSecret := func(label string, rec *httptest.ResponseRecorder, secret string) {
		if strings.Contains(rec.Body.String(), secret) {
			t.Errorf("%s leaked the signing secret", label)
		}
	}
	// JSON by default, and with an explicit JSON Accept.
	for _, accept := range []string{"", "application/json", "*/*"} {
		g := e.do("GET", "/admin/webhooks", "basic", accept, "", "")
		if g.Code != 200 || !strings.HasPrefix(g.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("Accept=%q: want JSON 200, got %d %s", accept, g.Code, g.Header().Get("Content-Type"))
		}
		assertNoSecret("GET json Accept="+accept, g, created.Secret)
		if !strings.Contains(g.Body.String(), `"has_secret":true`) {
			t.Errorf("list should expose only a has_secret flag")
		}
	}
	// HTML only when the client asks for it.
	h := e.do("GET", "/admin/webhooks", "basic", "text/html,application/xhtml+xml", "", "")
	if h.Code != 200 || !strings.HasPrefix(h.Header().Get("Content-Type"), "text/html") || !strings.Contains(h.Body.String(), "secret-"+sfx) {
		t.Fatalf("HTML page: %d %s", h.Code, h.Header().Get("Content-Type"))
	}
	assertNoSecret("GET html", h, created.Secret)
	assertNoSecret("GET deliveries", e.do("GET", "/admin/webhooks/"+created.Webhook.ID+"/deliveries", "basic", "", "", ""), created.Secret)

	// Rotate: the new secret is returned once; the old one is gone; GETs never show either.
	rot := e.do("POST", "/admin/webhooks/"+created.Webhook.ID+"/rotate", "cookie", "application/json", "", "")
	var rotated struct{ Secret string }
	_ = json.Unmarshal(rot.Body.Bytes(), &rotated)
	if rot.Code != 200 || rotated.Secret == "" || rotated.Secret == created.Secret {
		t.Fatalf("rotate: %d %s", rot.Code, rot.Body)
	}
	for _, accept := range []string{"application/json", "text/html"} {
		g := e.do("GET", "/admin/webhooks", "basic", accept, "", "")
		assertNoSecret("GET after rotate", g, rotated.Secret)
		assertNoSecret("GET after rotate", g, created.Secret)
	}

	// An HTML form create shows the secret in that one response and never again.
	form := "name=form-" + sfx + "&url=https%3A%2F%2Fhooks.example.com%2Fform&event_types=device_approved&enabled=true&csrf_token=" + e.csrf
	fr := e.do("POST", "/admin/webhooks", "cookie", "text/html", "application/x-www-form-urlencoded", form)
	if fr.Code != 200 || !strings.Contains(fr.Body.String(), "whsec_") {
		t.Fatalf("HTML create should render the one-time secret: %d", fr.Code)
	}
	formList, _ := e.repo.WebhookStore().ListSubscriptions(context.Background())
	for _, s := range formList {
		if s.Name == "form-"+sfx {
			id := s.ID
			t.Cleanup(func() { _ = e.repo.WebhookStore().DeleteSubscription(context.Background(), id) })
		}
	}
	again := e.do("GET", "/admin/webhooks", "basic", "text/html", "", "")
	if strings.Contains(again.Body.String(), "whsec_") {
		t.Fatal("a later page load must not show any secret")
	}
}

// Create through the HTTP stack, trigger the real producer, deliver through the worker, and
// verify the signature at a real receiver; also test event, delivery log and redeliver.
func TestWebhooksAdmin_EndToEnd_ThroughRouter(t *testing.T) {
	e := newWhEnv(t)
	ctx := context.Background()
	sfx := strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	var got int32
	var sigOK int32
	var secret string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if webhooks.Verify(secret, r.Header.Get(webhooks.HeaderSignature), body, time.Now(), 5*time.Minute) == nil &&
			r.Header.Get(webhooks.HeaderEventID) != "" {
			atomic.AddInt32(&sigOK, 1)
		}
		atomic.AddInt32(&got, 1)
		w.WriteHeader(204)
	}))
	defer srv.Close()

	rec := e.createJSON("e2e-"+sfx, "https://hooks.example.com/e2e", []string{"policy_toggled"}, false)
	var created struct {
		Webhook struct{ ID string } `json:"webhook"`
		Secret  string              `json:"secret"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	secret = created.Secret
	id := created.Webhook.ID
	t.Cleanup(func() { _ = e.repo.WebhookStore().DeleteSubscription(ctx, id) })
	// Point at the local receiver (save-time validation correctly refuses loopback).
	_, _ = e.repo.Pool().Exec(ctx, `UPDATE webhook_subscriptions SET url=$2, allow_private_network=TRUE WHERE id=$1`, id, srv.URL)

	// Real producer: create then toggle a policy.
	pol, err := e.repo.CreatePolicy(ctx, "wh-web-pol-"+sfx, "d", types.PolicyTypePackagePresence, json.RawMessage(`{"package_name":"curl"}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.repo.TogglePolicyActive(ctx, pol.ID); err != nil {
		t.Fatal(err)
	}
	// Admin test event + delivery.
	if rec := e.do("POST", "/admin/webhooks/"+id+"/test", "cookie", "application/json", "", ""); rec.Code != http.StatusAccepted {
		t.Fatalf("test event: %d %s", rec.Code, rec.Body)
	}
	wk := webhooks.NewWorker(e.repo.WebhookStore().RestrictedTo(id), webhooks.NewSender(webhooks.UnsafeAllowLoopbackForTests()))
	for i := 0; i < 5 && wk.DrainOnce(ctx) > 0; i++ {
	}
	if atomic.LoadInt32(&got) != 2 || atomic.LoadInt32(&sigOK) != 2 {
		t.Fatalf("receiver got %d deliveries (%d with a valid signature), want 2/2 (policy_toggled + webhook.test)", got, sigOK)
	}

	// Delivery log JSON (with attempt log) and redeliver.
	dl := e.do("GET", "/admin/webhooks/"+id+"/deliveries", "basic", "application/json", "", "")
	var logOut struct {
		Deliveries []struct {
			ID, EventType, Status string
			AttemptLog            []struct {
				StatusCode int `json:"status_code"`
			} `json:"attempt_log"`
		}
	}
	_ = json.Unmarshal(dl.Body.Bytes(), &logOut)
	if len(logOut.Deliveries) != 2 {
		t.Fatalf("delivery log: %s", dl.Body)
	}
	for _, d := range logOut.Deliveries {
		if d.Status != "DELIVERED" || len(d.AttemptLog) != 1 || d.AttemptLog[0].StatusCode != 204 {
			t.Errorf("delivery %+v", d)
		}
	}
	rd := e.do("POST", "/admin/webhooks/deliveries/"+logOut.Deliveries[0].ID+"/redeliver", "cookie", "application/json", "", "")
	if rd.Code != http.StatusAccepted {
		t.Fatalf("redeliver: %d %s", rd.Code, rd.Body)
	}
	for i := 0; i < 5 && wk.DrainOnce(ctx) > 0; i++ {
	}
	if atomic.LoadInt32(&got) != 3 {
		t.Fatalf("redeliver should send once more, got %d total", got)
	}
	// The HTML page renders the log with real data and working buttons.
	page := e.do("GET", "/admin/webhooks?sub="+id, "basic", "text/html", "", "")
	body := page.Body.String()
	if page.Code != 200 || !strings.Contains(body, "Delivery log: e2e-"+sfx) || !strings.Contains(body, "/admin/webhooks/deliveries/") || !strings.Contains(body, "policy_toggled") {
		t.Fatalf("HTML delivery log did not render: %d", page.Code)
	}

	// Disable: a disabled subscription gets no test event and no new deliveries.
	off := e.do("POST", "/admin/webhooks/"+id, "cookie", "application/json", "application/json",
		`{"name":"e2e-`+sfx+`","url":"https://hooks.example.com/e2e","event_types":["policy_toggled"],"enabled":false}`)
	if off.Code != 200 {
		t.Fatalf("update: %d %s", off.Code, off.Body)
	}
	if rec := e.do("POST", "/admin/webhooks/"+id+"/test", "cookie", "application/json", "", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("test event on a disabled webhook should be refused, got %d", rec.Code)
	}
}
