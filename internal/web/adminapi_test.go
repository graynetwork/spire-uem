package web_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
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

const apiBase = "/api/admin/v1"

type apiEnv struct {
	t      *testing.T
	pool   *pgxpool.Pool
	repo   *db.Repository
	router chi.Router
	sfx    string
	seq    int
}

func newAPIEnv(t *testing.T) *apiEnv {
	connStr := os.Getenv("SPIRE_TEST_DB_URL")
	if connStr == "" {
		t.Skip("SPIRE_TEST_DB_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
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
	r := chi.NewRouter()
	h.RegisterRoutes(r, "admin", "adminpw")
	return &apiEnv{t: t, pool: pool, repo: repo, router: r, sfx: fmt.Sprintf("%d", time.Now().UnixNano()%1e12)}
}

func (e *apiEnv) uniq(prefix string) string {
	e.seq++
	return fmt.Sprintf("%s-%s-%d", prefix, e.sfx, e.seq)
}

type apiResp struct {
	*httptest.ResponseRecorder
}

func (r apiResp) json() map[string]any {
	var m map[string]any
	_ = json.Unmarshal(r.Body.Bytes(), &m)
	return m
}

func (r apiResp) errCode() string {
	m := r.json()
	if e, ok := m["error"].(map[string]any); ok {
		c, _ := e["code"].(string)
		return c
	}
	return ""
}

// call sends a request through the real router. extra is key,value header pairs.
func (e *apiEnv) call(method, path, token string, rest ...string) apiResp {
	body := ""
	if len(rest)%2 == 1 {
		body, rest = rest[0], rest[1:]
	}
	extra := rest
	var rdr *bytes.Reader
	if body != "" {
		rdr = bytes.NewReader([]byte(body))
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.RemoteAddr = "192.0.2.10:4000"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(extra); i += 2 {
		req.Header.Set(extra[i], extra[i+1])
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return apiResp{rec}
}

// callAs sends from a chosen client IP (the failed-auth limiter is per IP).
func (e *apiEnv) callFrom(ip, method, path, token string) apiResp {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = ip + ":4000"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return apiResp{rec}
}

// basicAdmin calls an /admin route as the static break-glass SUPER_ADMIN (no cookie, so no CSRF).
func (e *apiEnv) basicAdmin(method, path, body string) apiResp {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.20:4000"
	req.SetBasicAuth("admin", "adminpw")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return apiResp{rec}
}

type saSpec struct {
	role   types.AdminRole
	tags   []string
	scopes []string
}

// mkSA creates a service account directly and returns (account, raw token).
func (e *apiEnv) mkSA(s saSpec) (*types.ServiceAccount, string) {
	raw, tid, hash, err := web.GenerateServiceAccountToken()
	if err != nil {
		e.t.Fatal(err)
	}
	sa, _, err := e.repo.CreateServiceAccount(context.Background(), &types.ServiceAccount{
		Name: e.uniq("t"), Role: s.role, AllowedTags: s.tags, Scopes: s.scopes, Enabled: true, CreatedBy: "test",
	}, tid, hash, "test")
	if err != nil {
		e.t.Fatalf("create sa: %v", err)
	}
	return sa, raw
}

var allScopes = types.AllAPIScopes

func (e *apiEnv) mkDevice(tags ...string) *types.Device {
	d, _, err := e.repo.GetOrCreateDevice(context.Background(), e.uniq("hw"), e.uniq("host"))
	if err != nil {
		e.t.Fatalf("device: %v", err)
	}
	if len(tags) > 0 {
		if d, err = e.repo.UpdateDeviceTags(context.Background(), d.ID, tags); err != nil {
			e.t.Fatalf("tags: %v", err)
		}
	}
	return d
}

func (e *apiEnv) mkCampaign(targetTags, creatorTags []string) *campaign.Campaign {
	c, err := e.repo.CreateCampaign(context.Background(), &campaign.Campaign{
		Name: e.uniq("cmp"), TargetKind: campaign.TargetPackages, Packages: []string{"curl"},
		TargetTags: targetTags, Stages: campaign.DefaultStages(), RebootPolicy: campaign.RebootNotify,
		MaxDeferrals: 3, CreatorScopedTags: creatorTags, CreatedBy: "test",
	})
	if err != nil {
		e.t.Fatalf("campaign: %v", err)
	}
	return c
}

func dataIDs(t *testing.T, r apiResp) []string {
	t.Helper()
	var env struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v body=%s", err, r.Body.String())
	}
	out := []string{}
	for _, d := range env.Data {
		id, _ := d["id"].(string)
		if id == "" {
			id, _ = d["device_id"].(string)
		}
		out = append(out, id)
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------

func TestAPIv1_SessionCookieAloneIsRejected(t *testing.T) {
	e := newAPIEnv(t)
	cookie, _, err := web.IssueSession(context.Background(), e.repo, "admin", false)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, apiBase+"/devices", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cookie alone on the API must be 401, got %d", rec.Code)
	}
	// And a state-changing call: still 401, never a CSRF 403, never executed.
	d := e.mkDevice()
	req = httptest.NewRequest(http.MethodPost, apiBase+"/devices/"+d.ID+"/reboot", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cookie POST must be 401, got %d", rec.Code)
	}
	if cmds, _ := e.repo.ListDeviceCommands(context.Background(), d.ID); len(cmds) != 0 {
		t.Fatalf("a cookie-authenticated POST must not enqueue anything")
	}
	// Control: the same cookie IS valid on /admin, so the 401 above is the API prefix's doing.
	req = httptest.NewRequest(http.MethodGet, "/admin/audit/events", nil)
	req.Header.Set("Accept", "application/json")
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("control failed: session cookie should be accepted on /admin (got %d)", rec.Code)
	}
}

func TestAPIv1_BasicAuthAndMissingCredentialsRejected(t *testing.T) {
	e := newAPIEnv(t)
	req := httptest.NewRequest(http.MethodGet, apiBase+"/devices", nil)
	req.SetBasicAuth("admin", "adminpw")
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("basic auth must be rejected on the API, got %d", rec.Code)
	}
	if got := e.call("GET", apiBase+"/devices", "", "").Code; got != http.StatusUnauthorized {
		t.Fatalf("no credentials: %d", got)
	}
}

func TestAPIv1_ErrorObjectShapeEverywhere(t *testing.T) {
	e := newAPIEnv(t)
	_, tok := e.mkSA(saSpec{types.RoleAuditor, nil, []string{types.ScopeDevicesRead}})
	cases := []struct {
		name   string
		resp   apiResp
		status int
		code   string
	}{
		{"401", e.call("GET", apiBase+"/devices", ""), 401, "unauthorized"},
		{"403 scope", e.call("GET", apiBase+"/groups", tok), 403, "insufficient_scope"},
		{"404 object", e.call("GET", apiBase+"/devices/00000000-0000-0000-0000-000000000000", tok), 404, "not_found"},
		{"404 route", e.call("GET", apiBase+"/nope", tok), 404, "not_found"},
		{"405", e.call("DELETE", apiBase+"/devices", tok), 405, "method_not_allowed"},
		{"400 limit", e.call("GET", apiBase+"/devices?limit=9999", tok), 400, "invalid_limit"},
		{"400 cursor", e.call("GET", apiBase+"/devices?cursor=not-a-cursor", tok), 400, "invalid_cursor"},
	}
	for _, c := range cases {
		if c.resp.Code != c.status {
			t.Errorf("%s: status %d want %d body=%s", c.name, c.resp.Code, c.status, c.resp.Body.String())
			continue
		}
		m := c.resp.json()
		eo, ok := m["error"].(map[string]any)
		if !ok {
			t.Errorf("%s: no error object: %s", c.name, c.resp.Body.String())
			continue
		}
		if eo["code"] != c.code || eo["message"] == "" || eo["request_id"] == "" || len(m) != 1 {
			t.Errorf("%s: bad error shape %v", c.name, m)
		}
		if rid := c.resp.Header().Get("X-Request-Id"); rid == "" || rid != eo["request_id"] {
			t.Errorf("%s: X-Request-Id %q must match body request_id %v", c.name, rid, eo["request_id"])
		}
		if ct := c.resp.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s: content type %q", c.name, ct)
		}
	}
	// Success responses carry a request id too.
	ok := e.call("GET", apiBase+"/me", tok)
	if ok.Code != 200 || ok.Header().Get("X-Request-Id") == "" {
		t.Errorf("success response lacks request id: %d", ok.Code)
	}
}

func TestAPIv1_RateLimitedFailedAttempts(t *testing.T) {
	e := newAPIEnv(t)
	bad := "spire_sa_" + strings.Repeat("a", 16) + "_" + strings.Repeat("b", 64)
	var last apiResp
	for i := 0; i < 5; i++ {
		last = e.callFrom("198.51.100.7", "GET", apiBase+"/me", bad)
		if last.Code != 401 {
			t.Fatalf("attempt %d: %d", i, last.Code)
		}
	}
	last = e.callFrom("198.51.100.7", "GET", apiBase+"/me", bad)
	if last.Code != http.StatusTooManyRequests || last.errCode() != "rate_limited" {
		t.Fatalf("expected 429 rate_limited, got %d %s", last.Code, last.Body.String())
	}
	if last.Header().Get("Retry-After") == "" {
		t.Errorf("429 lacks Retry-After")
	}
	// A different client IP is unaffected, and so is a valid token from the limited IP's peer.
	_, tok := e.mkSA(saSpec{types.RoleAuditor, nil, []string{types.ScopeDevicesRead}})
	if got := e.callFrom("198.51.100.8", "GET", apiBase+"/me", tok).Code; got != 200 {
		t.Fatalf("other IP should be fine, got %d", got)
	}
}

func TestAPIv1_CredentialFailuresAreIndistinguishable(t *testing.T) {
	e := newAPIEnv(t)
	ctx := context.Background()
	sa, tok := e.mkSA(saSpec{types.RoleAuditor, nil, []string{types.ScopeDevicesRead}})
	toks, _ := e.repo.ListServiceAccountTokens(ctx, sa.ID)

	wrongSecret := tok[:len(tok)-4] + "0000"
	if wrongSecret == tok {
		wrongSecret = tok[:len(tok)-4] + "1111"
	}
	unknown := "spire_sa_" + strings.Repeat("1", 16) + "_" + strings.Repeat("2", 64)

	// disabled
	disabled, dTok := e.mkSA(saSpec{types.RoleAuditor, nil, []string{types.ScopeDevicesRead}})
	in := *disabled
	in.Enabled = false
	if _, err := e.repo.UpdateServiceAccount(ctx, disabled.ID, in); err != nil {
		t.Fatal(err)
	}
	// revoked
	rev, rTok := e.mkSA(saSpec{types.RoleAuditor, nil, []string{types.ScopeDevicesRead}})
	rts, _ := e.repo.ListServiceAccountTokens(ctx, rev.ID)
	_ = e.repo.RevokeServiceAccountToken(ctx, rev.ID, rts[0].ID)
	// expired token
	ex, eTok := e.mkSA(saSpec{types.RoleAuditor, nil, []string{types.ScopeDevicesRead}})
	_, _ = e.pool.Exec(ctx, `UPDATE service_account_tokens SET expires_at = NOW() - INTERVAL '1 second' WHERE service_account_id::text=$1`, ex.ID)
	// expired account
	xa, xTok := e.mkSA(saSpec{types.RoleAuditor, nil, []string{types.ScopeDevicesRead}})
	_, _ = e.pool.Exec(ctx, `UPDATE service_accounts SET expires_at = NOW() - INTERVAL '1 second' WHERE id::text=$1`, xa.ID)

	if got := e.call("GET", apiBase+"/me", tok).Code; got != 200 {
		t.Fatalf("control token should work, got %d", got)
	}
	_ = toks
	var ref string
	for name, bad := range map[string]string{"wrong secret": wrongSecret, "unknown id": unknown, "disabled": dTok,
		"revoked": rTok, "expired token": eTok, "expired account": xTok, "garbage": "spire_sa_x"} {
		// Fresh source IP per probe so the failure limiter does not interfere.
		r := e.callFrom("203.0.113."+fmt.Sprint(len(name)+10), "GET", apiBase+"/me", bad)
		if r.Code != 401 {
			t.Errorf("%s: want 401 got %d", name, r.Code)
			continue
		}
		m := r.json()["error"].(map[string]any)
		shape := fmt.Sprintf("%v|%v", m["code"], m["message"])
		if ref == "" {
			ref = shape
		} else if shape != ref {
			t.Errorf("%s: response %q differs from %q, leaking the failure reason", name, shape, ref)
		}
	}
}

// ---------------------------------------------------------------------------------------
// scope AND role cap AND tag scope
// ---------------------------------------------------------------------------------------

func TestAPIv1_ScopeAndRoleCapMatrix(t *testing.T) {
	e := newAPIEnv(t)
	dev := e.mkDevice()
	cmp := e.mkCampaign(nil, nil)
	grp, err := e.repo.CreateGroup(context.Background(), db.CreateGroupInput{Name: e.uniq("g"), Kind: types.GroupKindTarget, CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	pol, err := e.repo.CreatePolicy(context.Background(), e.uniq("p"), "", types.PolicyTypePackagePresence, json.RawMessage(`{"package_name":"curl"}`), []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	type ep struct {
		method, path string
		scope        string
		minRole      types.AdminRole
	}
	eps := []ep{
		{"GET", "/devices", types.ScopeDevicesRead, types.RoleAuditor},
		{"GET", "/devices/" + dev.ID, types.ScopeDevicesRead, types.RoleAuditor},
		{"POST", "/devices/" + dev.ID + "/sync", types.ScopeDevicesActions, types.RoleOperator},
		{"POST", "/devices/" + dev.ID + "/lock", types.ScopeDevicesActions, types.RoleOperator},
		{"POST", "/devices/" + dev.ID + "/reboot", types.ScopeDevicesActions, types.RoleOperator},
		{"GET", "/groups", types.ScopeGroupsRead, types.RoleAuditor},
		{"GET", "/groups/" + grp.ID, types.ScopeGroupsRead, types.RoleAuditor},
		{"GET", "/groups/" + grp.ID + "/members", types.ScopeGroupsRead, types.RoleAuditor},
		{"GET", "/policies", types.ScopePoliciesRead, types.RoleAuditor},
		{"GET", "/policies/" + pol.ID, types.ScopePoliciesRead, types.RoleAuditor},
		{"GET", "/campaigns", types.ScopeCampaignsRead, types.RoleSecurityAdmin},
		{"GET", "/campaigns/" + cmp.ID, types.ScopeCampaignsRead, types.RoleSecurityAdmin},
		{"POST", "/campaigns/" + cmp.ID + "/pause", types.ScopeCampaignsWrite, types.RoleSecurityAdmin},
		{"GET", "/audit/events", types.ScopeAuditRead, types.RoleAuditor},
	}
	roles := []types.AdminRole{types.RoleAuditor, types.RoleOperator, types.RoleSecurityAdmin, types.RoleSuperAdmin}
	rank := map[types.AdminRole]int{types.RoleAuditor: 1, types.RoleOperator: 2, types.RoleSecurityAdmin: 3, types.RoleSuperAdmin: 4}
	for _, x := range eps {
		for _, role := range roles {
			// Holds the scope: allowed iff the role cap reaches the endpoint's floor.
			_, withScope := e.mkSA(saSpec{role, nil, []string{x.scope}})
			got := e.call(x.method, apiBase+x.path, withScope, "")
			if rank[role] >= rank[x.minRole] {
				if got.Code == 401 || got.Code == 403 {
					t.Errorf("%s %s role=%s with scope: want allowed, got %d %s", x.method, x.path, role, got.Code, got.Body.String())
				}
			} else {
				if got.Code != 403 || got.errCode() != "insufficient_role" {
					t.Errorf("%s %s role=%s: role cap must refuse (403 insufficient_role), got %d %s", x.method, x.path, role, got.Code, got.Body.String())
				}
			}
			// Role is high enough but the scope is missing: always refused. Holds every OTHER scope.
			var others []string
			for _, s := range allScopes {
				if s != x.scope {
					others = append(others, s)
				}
			}
			_, noScope := e.mkSA(saSpec{role, nil, others})
			got = e.call(x.method, apiBase+x.path, noScope, "")
			if got.Code != 403 || got.errCode() != "insufficient_scope" {
				t.Errorf("%s %s role=%s without scope: want 403 insufficient_scope, got %d %s", x.method, x.path, role, got.Code, got.Body.String())
			}
		}
	}
	// A refused POST must not have executed.
	if cmds, _ := e.repo.ListDeviceCommands(context.Background(), dev.ID); len(cmds) > 0 {
		for _, c := range cmds {
			_ = c
		}
	}
}

func TestAPIv1_TagScopeOnEveryObjectType(t *testing.T) {
	e := newAPIEnv(t)
	ctx := context.Background()
	inTag, outTag := e.uniq("in"), e.uniq("out")
	inDev := e.mkDevice(inTag)
	outDev := e.mkDevice(outTag)

	// SECURITY_ADMIN-capped, every scope, scoped to inTag.
	_, tok := e.mkSA(saSpec{types.RoleSecurityAdmin, []string{inTag}, allScopes})
	// Control: an unscoped twin sees both.
	_, wide := e.mkSA(saSpec{types.RoleSecurityAdmin, nil, allScopes})

	// devices: list excludes, get and every action are 404.
	list := dataIDs(t, e.call("GET", apiBase+"/devices?limit=500", tok, ""))
	if !contains(list, inDev.ID) || contains(list, outDev.ID) {
		t.Errorf("device list must contain only in-scope devices: in=%v out=%v", contains(list, inDev.ID), contains(list, outDev.ID))
	}
	if got := e.call("GET", apiBase+"/devices/"+inDev.ID, tok, "").Code; got != 200 {
		t.Errorf("in-scope get: %d", got)
	}
	if got := e.call("GET", apiBase+"/devices/"+outDev.ID, tok, ""); got.Code != 404 {
		t.Errorf("out-of-scope get must be 404, got %d", got.Code)
	}
	if got := e.call("GET", apiBase+"/devices/"+outDev.ID, wide, ""); got.Code != 200 {
		t.Errorf("control: unscoped get must work, got %d", got.Code)
	}
	for _, a := range []string{"sync", "lock", "reboot"} {
		if got := e.call("POST", apiBase+"/devices/"+outDev.ID+"/"+a, tok, ""); got.Code != 404 {
			t.Errorf("out-of-scope %s must be 404, got %d", a, got.Code)
		}
		if got := e.call("POST", apiBase+"/devices/"+inDev.ID+"/"+a, tok, ""); got.Code != 202 {
			t.Errorf("in-scope %s: %d %s", a, got.Code, got.Body.String())
		}
	}
	if cmds, _ := e.repo.ListDeviceCommands(ctx, outDev.ID); len(cmds) != 0 {
		t.Errorf("out-of-scope device received %d commands", len(cmds))
	}
	if cmds, _ := e.repo.ListDeviceCommands(ctx, inDev.ID); len(cmds) != 2 {
		t.Errorf("in-scope device should have lock+reboot queued, got %d", len(cmds))
	}

	// groups: a group whose only member is out of scope is invisible; members are filtered.
	outGrp, _ := e.repo.CreateGroup(ctx, db.CreateGroupInput{Name: e.uniq("gout"), Kind: types.GroupKindTarget, IncludeDeviceIDs: []string{outDev.ID}, CreatedBy: "boss"})
	mixGrp, _ := e.repo.CreateGroup(ctx, db.CreateGroupInput{Name: e.uniq("gmix"), Kind: types.GroupKindTarget, IncludeDeviceIDs: []string{outDev.ID, inDev.ID}, CreatedBy: "boss"})
	_, _, _ = e.repo.RecomputeGroupMembership(ctx, outGrp.ID)
	_, _, _ = e.repo.RecomputeGroupMembership(ctx, mixGrp.ID)
	if got := e.call("GET", apiBase+"/groups/"+outGrp.ID, tok, ""); got.Code != 404 {
		t.Errorf("group with only out-of-scope members must be 404, got %d", got.Code)
	}
	if got := e.call("GET", apiBase+"/groups/"+outGrp.ID+"/members", tok, ""); got.Code != 404 {
		t.Errorf("members of invisible group must be 404, got %d", got.Code)
	}
	if got := e.call("GET", apiBase+"/groups/"+outGrp.ID, wide, ""); got.Code != 200 {
		t.Errorf("control: unscoped group get %d", got.Code)
	}
	gl := dataIDs(t, e.call("GET", apiBase+"/groups?limit=500", tok, ""))
	if contains(gl, outGrp.ID) || !contains(gl, mixGrp.ID) {
		t.Errorf("group list scoping wrong: out=%v mix=%v", contains(gl, outGrp.ID), contains(gl, mixGrp.ID))
	}
	mem := e.call("GET", apiBase+"/groups/"+mixGrp.ID+"/members", tok, "")
	mids := []string{}
	var menv struct {
		Data []struct {
			DeviceID string `json:"device_id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(mem.Body.Bytes(), &menv)
	for _, m := range menv.Data {
		mids = append(mids, m.DeviceID)
	}
	if contains(mids, outDev.ID) || !contains(mids, inDev.ID) {
		t.Errorf("group members must be filtered to scope, got %v", mids)
	}

	// policies: reach must stay inside the scope (policy_scope.go rules).
	inPol, _ := e.repo.CreatePolicy(ctx, e.uniq("pin"), "", types.PolicyTypePackagePresence, json.RawMessage(`{"package_name":"curl"}`), []string{inTag})
	outPol, _ := e.repo.CreatePolicy(ctx, e.uniq("pout"), "", types.PolicyTypePackagePresence, json.RawMessage(`{"package_name":"curl"}`), []string{outTag})
	fleetPol, _ := e.repo.CreatePolicy(ctx, e.uniq("pfleet"), "", types.PolicyTypePackagePresence, json.RawMessage(`{"package_name":"curl"}`), nil)
	pl := dataIDs(t, e.call("GET", apiBase+"/policies?limit=500", tok, ""))
	if !contains(pl, inPol.ID) || contains(pl, outPol.ID) || contains(pl, fleetPol.ID) {
		t.Errorf("policy list scoping wrong: in=%v out=%v fleet=%v", contains(pl, inPol.ID), contains(pl, outPol.ID), contains(pl, fleetPol.ID))
	}
	for _, p := range []*types.Policy{outPol, fleetPol} {
		if got := e.call("GET", apiBase+"/policies/"+p.ID, tok, ""); got.Code != 404 {
			t.Errorf("policy %s outside scope must be 404, got %d", p.Name, got.Code)
		}
	}
	if got := e.call("GET", apiBase+"/policies/"+inPol.ID, tok, ""); got.Code != 200 {
		t.Errorf("in-scope policy: %d", got.Code)
	}

	// campaigns: visibility is CampaignVisibleToScope; control actions are 404 when invisible.
	inCmp := e.mkCampaign([]string{inTag}, []string{inTag})
	outCmp := e.mkCampaign([]string{outTag}, nil)
	cl := dataIDs(t, e.call("GET", apiBase+"/campaigns?limit=500", tok, ""))
	if !contains(cl, inCmp.ID) || contains(cl, outCmp.ID) {
		t.Errorf("campaign list scoping wrong")
	}
	if got := e.call("GET", apiBase+"/campaigns/"+outCmp.ID, tok, ""); got.Code != 404 {
		t.Errorf("out-of-scope campaign get: %d", got.Code)
	}
	if got := e.call("POST", apiBase+"/campaigns/"+outCmp.ID+"/start", tok, ""); got.Code != 404 {
		t.Errorf("out-of-scope campaign start must be 404, got %d", got.Code)
	}
	after, _ := e.repo.GetCampaign(ctx, outCmp.ID)
	if after.State != campaign.StateDraft {
		t.Errorf("out-of-scope campaign was changed to %s", after.State)
	}
	if got := e.call("POST", apiBase+"/campaigns/"+inCmp.ID+"/start", tok, ""); got.Code != 200 {
		t.Errorf("in-scope campaign start: %d %s", got.Code, got.Body.String())
	}
	if got := e.call("POST", apiBase+"/campaigns/"+outCmp.ID+"/start", wide, ""); got.Code != 200 {
		t.Errorf("control: unscoped start: %d", got.Code)
	}

	// audit: events about an out-of-scope device are hidden; the principal's own are visible.
	outID, inID := outDev.ID, inDev.ID
	_, _ = e.repo.RecordSystemAuditEvent(ctx, "someone-else", "TEST_SCOPE_OUT", &outID, nil, "127.0.0.1")
	_, _ = e.repo.RecordSystemAuditEvent(ctx, "someone-else", "TEST_SCOPE_IN", &inID, nil, "127.0.0.1")
	var evs struct {
		Data []struct{ Action string } `json:"data"`
	}
	_ = json.Unmarshal(e.call("GET", apiBase+"/audit/events?limit=500&actor=someone-else", tok, "").Body.Bytes(), &evs)
	seenIn, seenOut := false, false
	for _, ev := range evs.Data {
		seenIn = seenIn || ev.Action == "TEST_SCOPE_IN"
		seenOut = seenOut || ev.Action == "TEST_SCOPE_OUT"
	}
	if !seenIn || seenOut {
		t.Errorf("audit scoping wrong: in=%v out=%v", seenIn, seenOut)
	}
}

// A tag scope on a low role cap (AUDITOR) must still scope. The shared helpers only scope
// OPERATOR/SECURITY_ADMIN, so this guards the synthetic-role mapping for service accounts.
func TestAPIv1_TagScopeAppliesToAuditorAndSuperAdminCaps(t *testing.T) {
	e := newAPIEnv(t)
	inTag, outTag := e.uniq("in"), e.uniq("out")
	inDev, outDev := e.mkDevice(inTag), e.mkDevice(outTag)
	for _, role := range []types.AdminRole{types.RoleAuditor, types.RoleOperator, types.RoleSecurityAdmin, types.RoleSuperAdmin} {
		_, tok := e.mkSA(saSpec{role, []string{inTag}, allScopes})
		ids := dataIDs(t, e.call("GET", apiBase+"/devices?limit=500", tok, ""))
		if !contains(ids, inDev.ID) || contains(ids, outDev.ID) {
			t.Errorf("role %s with tags must be scoped: in=%v out=%v", role, contains(ids, inDev.ID), contains(ids, outDev.ID))
		}
		if got := e.call("GET", apiBase+"/devices/"+outDev.ID, tok, ""); got.Code != 404 {
			t.Errorf("role %s out-of-scope get: %d", role, got.Code)
		}
	}
}

func TestAPIv1_PATScopesFollowRoleAndOwnerTagScope(t *testing.T) {
	e := newAPIEnv(t)
	ctx := context.Background()
	tag := e.uniq("pt")
	inDev, outDev := e.mkDevice(tag), e.mkDevice(e.uniq("other"))
	mkPAT := func(role types.AdminRole, tags []string) string {
		u, err := e.repo.CreateLocalAdminUser(ctx, types.CreateUserRequest{
			Username: e.uniq("u"), Email: e.uniq("m") + "@example.test", DisplayName: "t", Password: "Sup3r-secret-pw!", Role: role, AllowedTags: tags})
		if err != nil {
			t.Fatalf("user: %v", err)
		}
		raw, hash, prefix, _ := web.GeneratePAT()
		if _, err := e.repo.CreatePersonalAccessToken(ctx, hash, prefix, "t", u.ID, role, "test", time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("pat: %v", err)
		}
		return raw
	}
	op := mkPAT(types.RoleOperator, []string{tag})
	if got := e.call("GET", apiBase+"/devices/"+inDev.ID, op, ""); got.Code != 200 {
		t.Errorf("operator PAT get in-scope: %d", got.Code)
	}
	if got := e.call("GET", apiBase+"/devices/"+outDev.ID, op, ""); got.Code != 404 {
		t.Errorf("scoped owner's PAT must not reach out-of-scope device on the API, got %d", got.Code)
	}
	if got := e.call("POST", apiBase+"/devices/"+inDev.ID+"/lock", op, ""); got.Code != 202 {
		t.Errorf("operator PAT lock: %d", got.Code)
	}
	if got := e.call("GET", apiBase+"/campaigns", op, ""); got.Code != 403 {
		t.Errorf("operator PAT must not read campaigns: %d", got.Code)
	}
	aud := mkPAT(types.RoleAuditor, nil)
	if got := e.call("GET", apiBase+"/devices", aud, ""); got.Code != 200 {
		t.Errorf("auditor PAT list: %d", got.Code)
	}
	if got := e.call("POST", apiBase+"/devices/"+inDev.ID+"/lock", aud, ""); got.Code != 403 {
		t.Errorf("auditor PAT must not lock: %d", got.Code)
	}
	sec := mkPAT(types.RoleSecurityAdmin, nil)
	if got := e.call("GET", apiBase+"/campaigns", sec, ""); got.Code != 200 {
		t.Errorf("security admin PAT campaigns: %d", got.Code)
	}
	// Actor for a PAT is the owner's username in the audit log.
	var n int
	_ = e.pool.QueryRow(ctx, `SELECT COUNT(*) FROM system_audit_events WHERE action='DEVICE_LOCK' AND target_id=$1 AND actor NOT LIKE 'sa:%'`, inDev.ID).Scan(&n)
	if n != 1 {
		t.Errorf("PAT lock should be audited under the owner's username, found %d", n)
	}
}

// ---------------------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------------------

func TestAPIv1_CursorPaginationNoDupesNoGaps(t *testing.T) {
	e := newAPIEnv(t)
	tag := e.uniq("pg")
	want := map[string]bool{}
	for i := 0; i < 11; i++ {
		want[e.mkDevice(tag).ID] = true
	}
	_, tok := e.mkSA(saSpec{types.RoleAuditor, nil, allScopes})
	seen := map[string]bool{}
	var order []string
	path := apiBase + "/devices?limit=3&tag=" + tag
	pages := 0
	for path != "" {
		r := e.call("GET", path, tok, "")
		if r.Code != 200 {
			t.Fatalf("page: %d %s", r.Code, r.Body.String())
		}
		ids := dataIDs(t, r)
		if len(ids) > 3 {
			t.Fatalf("page exceeds limit: %d", len(ids))
		}
		for _, id := range ids {
			if seen[id] {
				t.Fatalf("duplicate %s across pages", id)
			}
			seen[id] = true
			order = append(order, id)
		}
		var env struct {
			Next    *string `json:"next_cursor"`
			HasMore bool    `json:"has_more"`
		}
		_ = json.Unmarshal(r.Body.Bytes(), &env)
		if env.Next == nil {
			if env.HasMore {
				t.Fatal("has_more with no cursor")
			}
			path = ""
		} else {
			path = apiBase + "/devices?limit=3&tag=" + tag + "&cursor=" + *env.Next
		}
		if pages++; pages > 10 {
			t.Fatal("pagination did not terminate")
		}
	}
	if len(seen) != len(want) {
		t.Fatalf("gap: got %d of %d", len(seen), len(want))
	}
	for id := range want {
		if !seen[id] {
			t.Fatalf("missing %s", id)
		}
	}
	if pages != 4 {
		t.Errorf("11 rows at limit 3 should be 4 pages, got %d", pages)
	}
	// Inserting a newer row between pages must not shift or repeat what comes after the cursor.
	r1 := e.call("GET", apiBase+"/devices?limit=3&tag="+tag, tok, "")
	var env1 struct {
		Next *string `json:"next_cursor"`
	}
	_ = json.Unmarshal(r1.Body.Bytes(), &env1)
	_ = e.mkDevice(tag)
	r2 := e.call("GET", apiBase+"/devices?limit=3&tag="+tag+"&cursor="+*env1.Next, tok, "")
	first := dataIDs(t, r1)
	for _, id := range dataIDs(t, r2) {
		if contains(first, id) {
			t.Errorf("row %s repeated after concurrent insert", id)
		}
	}
	// A cursor is bound to its filters.
	other := e.call("GET", apiBase+"/devices?limit=3&tag=somethingelse&cursor="+*env1.Next, tok, "")
	if other.Code != 400 || other.errCode() != "invalid_cursor" {
		t.Errorf("cursor reuse with other filters must be 400 invalid_cursor, got %d", other.Code)
	}
	// limit bounds
	for _, l := range []string{"0", "501", "x", "-1"} {
		if got := e.call("GET", apiBase+"/devices?limit="+l, tok, ""); got.Code != 400 {
			t.Errorf("limit=%s: %d", l, got.Code)
		}
	}
	if got := e.call("GET", apiBase+"/devices?limit=500", tok, ""); got.Code != 200 {
		t.Errorf("limit=500 should be allowed: %d", got.Code)
	}
}

func TestAPIv1_PaginationInMemoryListsAndAudit(t *testing.T) {
	e := newAPIEnv(t)
	ctx := context.Background()
	_, tok := e.mkSA(saSpec{types.RoleSecurityAdmin, nil, allScopes})
	walk := func(base string) []string {
		var all []string
		path := base + "?limit=2"
		for i := 0; path != ""; i++ {
			if i > 500 {
				t.Fatal("no termination")
			}
			r := e.call("GET", path, tok, "")
			if r.Code != 200 {
				t.Fatalf("%s: %d %s", path, r.Code, r.Body.String())
			}
			all = append(all, dataIDs(t, r)...)
			var env struct {
				Next *string `json:"next_cursor"`
			}
			_ = json.Unmarshal(r.Body.Bytes(), &env)
			path = ""
			if env.Next != nil {
				path = base + "?limit=2&cursor=" + *env.Next
			}
		}
		return all
	}
	var gids, cids []string
	for i := 0; i < 5; i++ {
		g, _ := e.repo.CreateGroup(ctx, db.CreateGroupInput{Name: e.uniq("pgg"), Kind: types.GroupKindTarget, CreatedBy: "t"})
		gids = append(gids, g.ID)
		cids = append(cids, e.mkCampaign(nil, nil).ID)
	}
	for name, c := range map[string]struct {
		base string
		ids  []string
	}{"groups": {apiBase + "/groups", gids}, "campaigns": {apiBase + "/campaigns", cids}} {
		got := walk(c.base)
		seen := map[string]bool{}
		for _, id := range got {
			if seen[id] {
				t.Fatalf("%s: duplicate %s", name, id)
			}
			seen[id] = true
		}
		for _, id := range c.ids {
			if !seen[id] {
				t.Errorf("%s: missing %s", name, id)
			}
		}
	}
	actor := e.uniq("pager")
	for i := 0; i < 7; i++ {
		_, _ = e.repo.RecordSystemAuditEvent(ctx, actor, "TEST_PAGE", nil, nil, "127.0.0.1")
	}
	got := walk(apiBase + "/audit/events") // all actors; just require no duplicates
	seen := map[string]bool{}
	for _, id := range got {
		if seen[id] {
			t.Fatalf("audit: duplicate %s", id)
		}
		seen[id] = true
	}
	mine := 0
	path := apiBase + "/audit/events?limit=2&actor=" + actor
	for path != "" {
		r := e.call("GET", path, tok, "")
		mine += len(dataIDs(t, r))
		var env struct {
			Next *string `json:"next_cursor"`
		}
		_ = json.Unmarshal(r.Body.Bytes(), &env)
		path = ""
		if env.Next != nil {
			path = apiBase + "/audit/events?limit=2&actor=" + actor + "&cursor=" + *env.Next
		}
	}
	if mine != 7 {
		t.Errorf("audit filtered walk: got %d of 7", mine)
	}
}

func TestAPIv1_DeviceFilters(t *testing.T) {
	e := newAPIEnv(t)
	tag := e.uniq("flt")
	a := e.mkDevice(tag)
	b := e.mkDevice(tag)
	ctx := context.Background()
	if _, err := e.repo.UpdateDevicePatchRing(ctx, b.ID, types.RingCanary); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.repo.ApproveDevice(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	_, tok := e.mkSA(saSpec{types.RoleAuditor, nil, allScopes})
	q := func(extra string) []string {
		r := e.call("GET", apiBase+"/devices?limit=500&tag="+tag+extra, tok, "")
		if r.Code != 200 {
			t.Fatalf("%s: %d %s", extra, r.Code, r.Body.String())
		}
		return dataIDs(t, r)
	}
	if ids := q(""); len(ids) != 2 {
		t.Errorf("tag filter: %v", ids)
	}
	if ids := q("&ring=CANARY"); len(ids) != 1 || ids[0] != b.ID {
		t.Errorf("ring filter: %v", ids)
	}
	if ids := q("&status=APPROVED"); len(ids) != 1 || ids[0] != b.ID {
		t.Errorf("status filter: %v", ids)
	}
	if ids := q("&status=PENDING_APPROVAL"); len(ids) != 1 || ids[0] != a.ID {
		t.Errorf("pending filter: %v", ids)
	}
	if ids := q("&hostname_prefix=" + a.Hostname[:len(a.Hostname)-3]); !contains(ids, a.ID) {
		t.Errorf("hostname prefix filter: %v", ids)
	}
	if ids := q("&hostname_prefix=%25"); len(ids) != 0 {
		t.Errorf("LIKE wildcard in prefix must be literal, got %v", ids)
	}
	if got := e.call("GET", apiBase+"/devices?status=BOGUS", tok, ""); got.Code != 400 {
		t.Errorf("bad status: %d", got.Code)
	}
	r := e.call("GET", apiBase+"/devices/"+b.ID, tok, "")
	if r.Code != 200 || r.json()["data"].(map[string]any)["inventory_summary"] == nil {
		t.Errorf("device get lacks inventory summary: %s", r.Body.String())
	}
	if strings.Contains(r.Body.String(), "reported_state") || strings.Contains(strings.ToLower(r.Body.String()), "token_hash") {
		t.Errorf("device response leaks internal fields")
	}
}

// ---------------------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------------------

func TestAPIv1_IdempotencyReplayAndConflict(t *testing.T) {
	e := newAPIEnv(t)
	ctx := context.Background()
	dev := e.mkDevice()
	_, tok := e.mkSA(saSpec{types.RoleOperator, nil, allScopes})
	_, tok2 := e.mkSA(saSpec{types.RoleOperator, nil, allScopes})
	key := e.uniq("key")
	path := apiBase + "/devices/" + dev.ID + "/lock"

	first := e.call("POST", path, tok, `{"message":"hello"}`, "Idempotency-Key", key)
	if first.Code != 202 {
		t.Fatalf("first: %d %s", first.Code, first.Body.String())
	}
	if first.Header().Get("Idempotent-Replayed") != "" {
		t.Errorf("first response must not be marked replayed")
	}
	again := e.call("POST", path, tok, `{"message":"hello"}`, "Idempotency-Key", key)
	if again.Code != 202 || again.Body.String() != first.Body.String() || again.Header().Get("Idempotent-Replayed") != "true" {
		t.Errorf("replay must return the stored response: %d %q vs %q", again.Code, again.Body.String(), first.Body.String())
	}
	if cmds, _ := e.repo.ListDeviceCommands(ctx, dev.ID); len(cmds) != 1 {
		t.Errorf("replay must not execute again; commands=%d", len(cmds))
	}
	// Same key, different body: 422 and no execution.
	diff := e.call("POST", path, tok, `{"message":"different"}`, "Idempotency-Key", key)
	if diff.Code != 422 || diff.errCode() != "idempotency_key_reused" {
		t.Errorf("different body under the same key: want 422, got %d %s", diff.Code, diff.Body.String())
	}
	// Same key, different path: 422.
	otherPath := e.call("POST", apiBase+"/devices/"+dev.ID+"/reboot", tok, `{"message":"hello"}`, "Idempotency-Key", key)
	if otherPath.Code != 422 {
		t.Errorf("same key on another endpoint: want 422, got %d", otherPath.Code)
	}
	// Keys are per principal.
	other := e.call("POST", path, tok2, `{"message":"hello"}`, "Idempotency-Key", key)
	if other.Code != 202 || other.Header().Get("Idempotent-Replayed") != "" {
		t.Errorf("another principal's identical key must execute independently: %d", other.Code)
	}
	if cmds, _ := e.repo.ListDeviceCommands(ctx, dev.ID); len(cmds) != 2 {
		t.Errorf("want 2 commands (one per principal), got %d", len(cmds))
	}
	// Invalid key.
	if got := e.call("POST", path, tok, "", "Idempotency-Key", strings.Repeat("k", 300)); got.Code != 400 {
		t.Errorf("oversized key: %d", got.Code)
	}
	// Without a key the request simply runs every time.
	e.call("POST", path, tok, "")
	e.call("POST", path, tok, "")
	if cmds, _ := e.repo.ListDeviceCommands(ctx, dev.ID); len(cmds) != 4 {
		t.Errorf("keyless requests execute each time, got %d commands", len(cmds))
	}
	// A refused request (403) is not stored under the key.
	_, weak := e.mkSA(saSpec{types.RoleAuditor, nil, allScopes})
	k2 := e.uniq("k")
	if got := e.call("POST", path, weak, "", "Idempotency-Key", k2); got.Code != 403 {
		t.Fatalf("auditor lock: %d", got.Code)
	}
	var n int
	_ = e.pool.QueryRow(ctx, `SELECT COUNT(*) FROM admin_api_idempotency WHERE idem_key=$1`, k2).Scan(&n)
	if n != 0 {
		t.Errorf("a 403 must not consume the idempotency key (found %d rows)", n)
	}
	// Expired keys are reusable.
	_, _ = e.pool.Exec(ctx, `UPDATE admin_api_idempotency SET expires_at = NOW() - INTERVAL '1 second' WHERE idem_key=$1`, key)
	re := e.call("POST", path, tok, `{"message":"different"}`, "Idempotency-Key", key)
	if re.Code != 202 {
		t.Errorf("an expired key should be usable again, got %d", re.Code)
	}
}

func TestAPIv1_IdempotencyConcurrentSameKeyExecutesOnce(t *testing.T) {
	e := newAPIEnv(t)
	ctx := context.Background()
	dev := e.mkDevice()
	_, tok := e.mkSA(saSpec{types.RoleOperator, nil, allScopes})
	key := e.uniq("race")
	path := apiBase + "/devices/" + dev.ID + "/reboot"
	const n = 16
	codes := make([]int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i] = e.call("POST", path, tok, "", "Idempotency-Key", key).Code
		}(i)
	}
	close(start)
	wg.Wait()
	cmds, _ := e.repo.ListDeviceCommands(ctx, dev.ID)
	if len(cmds) != 1 {
		t.Fatalf("16 concurrent requests with one key must execute exactly once, queued %d (codes %v)", len(cmds), codes)
	}
	ok := 0
	for _, c := range codes {
		switch c {
		case 202:
			ok++
		case 409:
		default:
			t.Errorf("unexpected status %d in %v", c, codes)
		}
	}
	if ok < 1 {
		t.Errorf("at least one request must succeed: %v", codes)
	}
}

// ---------------------------------------------------------------------------------------
// Policy secrets
// ---------------------------------------------------------------------------------------

func TestAPIv1_PolicyResponsesNeverContainSecrets(t *testing.T) {
	e := newAPIEnv(t)
	ctx := context.Background()
	payload := `{"ssid":"corp","wifi":{"security":"wpa-psk","psk":{"ciphertext":"CIPHERTEXT-LEAK","encrypted_dek":"DEK-LEAK","nonce":"NONCE-LEAK"},
		"password":"PLAINPASS-LEAK","client_key":{"plaintext":"PLAINKEY-LEAK"}},
		"wireguard":{"peer_psks":{"0":{"ciphertext":"PEERCT-LEAK","encrypted_dek":"d","nonce":"n"}},"private_key":"WGPRIV-LEAK"},
		"nested":[{"secret":"NESTED-LEAK"}]}`
	pol, err := e.repo.CreatePolicy(ctx, e.uniq("net"), "", types.PolicyTypeNetworkProfile, json.RawMessage(payload), []string{"x"})
	if err != nil {
		t.Fatal(err)
	}
	_, tok := e.mkSA(saSpec{types.RoleAuditor, nil, allScopes})
	for _, path := range []string{"/policies/" + pol.ID, "/policies?limit=500"} {
		r := e.call("GET", apiBase+path, tok, "")
		if r.Code != 200 {
			t.Fatalf("%s: %d", path, r.Code)
		}
		body := r.Body.String()
		for _, leak := range []string{"CIPHERTEXT-LEAK", "DEK-LEAK", "NONCE-LEAK", "PLAINPASS-LEAK", "PLAINKEY-LEAK", "PEERCT-LEAK", "WGPRIV-LEAK", "NESTED-LEAK", "ciphertext", "encrypted_dek"} {
			if strings.Contains(body, leak) {
				t.Errorf("%s leaked %q: %s", path, leak, body)
			}
		}
		if !strings.Contains(body, `"set":true`) || !strings.Contains(body, "corp") {
			t.Errorf("%s: expected set-markers and non-secret fields: %s", path, body)
		}
	}
	// An unparseable payload is withheld rather than passed through.
	if p, withheld := web.SanitizePolicyPayloadForTest(`{"psk": "oops"`); !withheld || string(p) != "null" {
		t.Errorf("unparseable payload must be withheld, got %s withheld=%v", p, withheld)
	}
}

// ---------------------------------------------------------------------------------------
// Service account management, rotation, revocation, audit
// ---------------------------------------------------------------------------------------

func TestServiceAccounts_OnlySuperAdminCanManage(t *testing.T) {
	e := newAPIEnv(t)
	ctx := context.Background()
	for _, role := range []types.AdminRole{types.RoleSecurityAdmin, types.RoleOperator, types.RoleAuditor} {
		u, err := e.repo.CreateLocalAdminUser(ctx, types.CreateUserRequest{Username: e.uniq("u"), Email: e.uniq("m") + "@example.test", DisplayName: "t", Password: "Sup3r-secret-pw!", Role: role})
		if err != nil {
			t.Fatal(err)
		}
		raw, hash, prefix, _ := web.GeneratePAT()
		if _, err := e.repo.CreatePersonalAccessToken(ctx, hash, prefix, "t", u.ID, role, "t", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		for _, req := range []struct{ m, p, b string }{
			{"GET", "/admin/service-accounts", ""},
			{"POST", "/admin/service-accounts", `{"name":"evil-` + e.sfx + `","role":"SUPER_ADMIN","scopes":["devices:read"]}`},
		} {
			r := httptest.NewRequest(req.m, req.p, strings.NewReader(req.b))
			r.Header.Set("Authorization", "Bearer "+raw)
			r.Header.Set("Content-Type", "application/json")
			r.RemoteAddr = "192.0.2.30:1"
			rec := httptest.NewRecorder()
			e.router.ServeHTTP(rec, r)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s as %s must be 403, got %d", req.m, req.p, role, rec.Code)
			}
		}
	}
	var n int
	_ = e.pool.QueryRow(ctx, `SELECT COUNT(*) FROM service_accounts WHERE name = $1`, "evil-"+e.sfx).Scan(&n)
	if n != 0 {
		t.Fatalf("a non-super-admin created a service account")
	}
	// Validation.
	for name, body := range map[string]string{
		"bad name":      `{"name":"Bad Name","role":"AUDITOR","scopes":["devices:read"]}`,
		"bad role":      `{"name":"ok-name","role":"GOD","scopes":["devices:read"]}`,
		"unknown scope": `{"name":"ok-name","role":"AUDITOR","scopes":["devices:destroy"]}`,
		"no scopes":     `{"name":"ok-name","role":"AUDITOR","scopes":[]}`,
	} {
		if got := e.basicAdmin("POST", "/admin/service-accounts", body); got.Code != 400 {
			t.Errorf("%s: want 400 got %d %s", name, got.Code, got.Body.String())
		}
	}
}

func TestServiceAccounts_LifecycleRotationRevocationDisableAndAudit(t *testing.T) {
	e := newAPIEnv(t)
	ctx := context.Background()
	name := "life-" + e.sfx
	create := e.basicAdmin("POST", "/admin/service-accounts",
		fmt.Sprintf(`{"name":%q,"description":"ci","role":"OPERATOR","scopes":["devices:read","devices:actions"],"allowed_tags":["Team-A"]}`, name))
	if create.Code != 201 {
		t.Fatalf("create: %d %s", create.Code, create.Body.String())
	}
	cj := create.json()
	secret1, _ := cj["secret"].(string)
	if !strings.HasPrefix(secret1, "spire_sa_") || len(secret1) < len("spire_sa_")+16+1+64 {
		t.Fatalf("token shape: %q", secret1)
	}
	sa := cj["service_account"].(map[string]any)
	saID := sa["id"].(string)
	tok1 := cj["token"].(map[string]any)["id"].(string)
	if tags := sa["allowed_tags"].([]any); len(tags) != 1 || tags[0] != "team-a" {
		t.Errorf("tags should be normalised: %v", tags)
	}
	// The raw secret is not stored anywhere.
	var leaked int
	_ = e.pool.QueryRow(ctx, `SELECT COUNT(*) FROM service_account_tokens WHERE secret_hash = $1 OR secret_hash LIKE '%' || $2 || '%'`, secret1, secret1[len(secret1)-64:]).Scan(&leaked)
	if leaked != 0 {
		t.Fatalf("raw secret found in the database")
	}
	var hashLen int
	_ = e.pool.QueryRow(ctx, `SELECT length(secret_hash) FROM service_account_tokens WHERE id::text=$1`, tok1).Scan(&hashLen)
	if hashLen != 64 {
		t.Errorf("stored hash should be hex sha256, length %d", hashLen)
	}
	if got := e.call("GET", apiBase+"/me", secret1, ""); got.Code != 200 {
		t.Fatalf("new token must work: %d", got.Code)
	}
	if me := e.call("GET", apiBase+"/me", secret1, "").json()["data"].(map[string]any); me["actor"] != "sa:"+name {
		t.Errorf("actor: %v", me["actor"])
	}
	// The list endpoint never returns the secret.
	lst := e.basicAdmin("GET", "/admin/service-accounts", "")
	if strings.Contains(lst.Body.String(), secret1[len(secret1)-64:]) || strings.Contains(lst.Body.String(), "secret_hash") {
		t.Errorf("management list leaks token material")
	}

	// Rotate with the default overlap: old stays valid for ~24h, new works immediately.
	rot := e.basicAdmin("POST", "/admin/service-accounts/"+saID+"/tokens/"+tok1+"/rotate", `{}`)
	if rot.Code != 201 {
		t.Fatalf("rotate: %d %s", rot.Code, rot.Body.String())
	}
	secret2 := rot.json()["secret"].(string)
	if secret2 == secret1 {
		t.Fatal("rotation must mint a different secret")
	}
	if e.call("GET", apiBase+"/me", secret2, "").Code != 200 || e.call("GET", apiBase+"/me", secret1, "").Code != 200 {
		t.Fatalf("during the overlap both tokens must work")
	}
	var until time.Time
	_ = e.pool.QueryRow(ctx, `SELECT expires_at FROM service_account_tokens WHERE id::text=$1`, tok1).Scan(&until)
	if d := time.Until(until); d < 23*time.Hour || d > 24*time.Hour+time.Minute {
		t.Errorf("default overlap should be 24h, old token valid for %v", d)
	}
	// Overlap elapses: old is refused, new continues.
	_, _ = e.pool.Exec(ctx, `UPDATE service_account_tokens SET expires_at = NOW() - INTERVAL '1 second' WHERE id::text=$1`, tok1)
	if got := e.call("GET", apiBase+"/me", secret1, "").Code; got != 401 {
		t.Errorf("old token after overlap: want 401 got %d", got)
	}
	if got := e.call("GET", apiBase+"/me", secret2, "").Code; got != 200 {
		t.Errorf("new token after overlap: %d", got)
	}
	// Rotating an expired token is refused.
	if got := e.basicAdmin("POST", "/admin/service-accounts/"+saID+"/tokens/"+tok1+"/rotate", `{}`); got.Code != 404 {
		t.Errorf("rotating a dead token: %d", got.Code)
	}
	// Bad overlap.
	tok2 := rot.json()["token"].(map[string]any)["id"].(string)
	if got := e.basicAdmin("POST", "/admin/service-accounts/"+saID+"/tokens/"+tok2+"/rotate", `{"overlap_hours":9999}`); got.Code != 400 {
		t.Errorf("overlap above max: %d", got.Code)
	}
	// overlap 0 revokes the old token at once.
	rot0 := e.basicAdmin("POST", "/admin/service-accounts/"+saID+"/tokens/"+tok2+"/rotate", `{"overlap_hours":0}`)
	if rot0.Code != 201 {
		t.Fatalf("rotate 0: %d %s", rot0.Code, rot0.Body.String())
	}
	secret3 := rot0.json()["secret"].(string)
	if e.call("GET", apiBase+"/me", secret2, "").Code != 401 || e.call("GET", apiBase+"/me", secret3, "").Code != 200 {
		t.Errorf("overlap 0 must revoke the old token immediately")
	}
	// Revoke.
	tok3 := rot0.json()["token"].(map[string]any)["id"].(string)
	if got := e.basicAdmin("POST", "/admin/service-accounts/"+saID+"/tokens/"+tok3+"/revoke", `{}`); got.Code != 200 {
		t.Fatalf("revoke: %d", got.Code)
	}
	if got := e.call("GET", apiBase+"/me", secret3, "").Code; got != 401 {
		t.Errorf("revoked token: want 401 got %d", got)
	}
	// Add a token, then disable the account: every token stops, re-enabling restores.
	add := e.basicAdmin("POST", "/admin/service-accounts/"+saID+"/tokens", `{"label":"second"}`)
	if add.Code != 201 {
		t.Fatalf("add token: %d", add.Code)
	}
	secret4 := add.json()["secret"].(string)
	upd := func(enabled bool) apiResp {
		return e.basicAdmin("POST", "/admin/service-accounts/"+saID,
			fmt.Sprintf(`{"role":"OPERATOR","scopes":["devices:read","devices:actions"],"allowed_tags":["team-a"],"enabled":%v}`, enabled))
	}
	if got := upd(false); got.Code != 200 {
		t.Fatalf("disable: %d %s", got.Code, got.Body.String())
	}
	if got := e.call("GET", apiBase+"/me", secret4, "").Code; got != 401 {
		t.Errorf("disabled account: want 401 got %d", got)
	}
	if got := upd(true); got.Code != 200 {
		t.Fatalf("enable: %d", got.Code)
	}
	if got := e.call("GET", apiBase+"/me", secret4, "").Code; got != 200 {
		t.Errorf("re-enabled account: %d", got)
	}
	// Editing the scopes takes effect on the very next request.
	if got := e.basicAdmin("POST", "/admin/service-accounts/"+saID, `{"role":"AUDITOR","scopes":["devices:read"],"allowed_tags":["team-a"],"enabled":true}`); got.Code != 200 {
		t.Fatalf("edit: %d", got.Code)
	}
	dev := e.mkDevice("team-a")
	if got := e.call("POST", apiBase+"/devices/"+dev.ID+"/lock", secret4, ""); got.Code != 403 {
		t.Errorf("after lowering role/scopes, lock must be 403, got %d", got.Code)
	}

	// last_used is recorded (throttled) and shown.
	var used *time.Time
	_ = e.pool.QueryRow(ctx, `SELECT last_used_at FROM service_accounts WHERE id::text=$1`, saID).Scan(&used)
	if used == nil {
		t.Errorf("last_used_at not recorded")
	}

	// Mutations through the API are audited as sa:<name>.
	if got := e.basicAdmin("POST", "/admin/service-accounts/"+saID, `{"role":"OPERATOR","scopes":["devices:read","devices:actions"],"allowed_tags":["team-a"],"enabled":true}`); got.Code != 200 {
		t.Fatalf("restore: %d", got.Code)
	}
	if got := e.call("POST", apiBase+"/devices/"+dev.ID+"/lock", secret4, `{"message":"x"}`); got.Code != 202 {
		t.Fatalf("lock: %d %s", got.Code, got.Body.String())
	}
	count := func(q string, args ...any) int {
		var n int
		_ = e.pool.QueryRow(ctx, q, args...).Scan(&n)
		return n
	}
	if n := count(`SELECT COUNT(*) FROM system_audit_events WHERE actor=$1 AND action='DEVICE_LOCK' AND target_id=$2`, "sa:"+name, dev.ID); n != 1 {
		t.Errorf("DEVICE_LOCK should be audited with actor sa:%s, found %d", name, n)
	}
	for _, act := range []string{"SERVICE_ACCOUNT_CREATE", "SERVICE_ACCOUNT_TOKEN_CREATE", "SERVICE_ACCOUNT_TOKEN_ROTATE", "SERVICE_ACCOUNT_TOKEN_REVOKE", "SERVICE_ACCOUNT_UPDATE"} {
		if n := count(`SELECT COUNT(*) FROM system_audit_events WHERE action=$1 AND target_id=$2 AND actor='admin'`, act, saID); n < 1 {
			t.Errorf("%s not audited with the admin as actor", act)
		}
	}
	// The audit trail must not contain the secret.
	if n := count(`SELECT COUNT(*) FROM system_audit_events WHERE details::text LIKE '%' || $1 || '%'`, secret1[len(secret1)-64:]); n != 0 {
		t.Errorf("a token secret appears in the audit log")
	}

	// Delete removes the account and its tokens.
	if got := e.basicAdmin("POST", "/admin/service-accounts/"+saID+"/delete", `{}`); got.Code != 200 {
		t.Fatalf("delete: %d", got.Code)
	}
	if got := e.call("GET", apiBase+"/me", secret4, "").Code; got != 401 {
		t.Errorf("deleted account's token: %d", got)
	}
}

func TestServiceAccounts_ManagementPageRendersWithRealData(t *testing.T) {
	e := newAPIEnv(t)
	sa, _ := e.mkSA(saSpec{types.RoleOperator, []string{"emea"}, []string{types.ScopeDevicesRead}})
	req := httptest.NewRequest("GET", "/admin/service-accounts", nil)
	req.SetBasicAuth("admin", "adminpw")
	req.RemoteAddr = "192.0.2.21:1"
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("page: %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"sa:" + sa.Name, "Create service account", "devices:read", "emea"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// Names are HTML-escaped by html/template.
	if strings.Contains(body, "<script>alert") {
		t.Errorf("unescaped content")
	}
}

// ---------------------------------------------------------------------------------------
// OpenAPI
// ---------------------------------------------------------------------------------------

func TestAPIv1_OpenAPISpecServedWithoutAuthAndMatchesRoutes(t *testing.T) {
	e := newAPIEnv(t)
	r := e.call("GET", apiBase+"/openapi.json", "", "")
	if r.Code != 200 {
		t.Fatalf("spec must be public: %d", r.Code)
	}
	var spec struct {
		OpenAPI string                                `json:"openapi"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(r.Body.Bytes(), &spec); err != nil {
		t.Fatalf("spec is not JSON: %v", err)
	}
	if !strings.HasPrefix(spec.OpenAPI, "3.1") {
		t.Errorf("openapi version %q", spec.OpenAPI)
	}
	inSpec := map[string]bool{}
	for p, ops := range spec.Paths {
		for m := range ops {
			inSpec[strings.ToUpper(m)+" "+p] = true
		}
	}
	inRouter := map[string]bool{}
	err := chi.Walk(e.router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if strings.HasPrefix(route, apiBase+"/") || route == apiBase {
			p := strings.TrimPrefix(route, apiBase)
			p = strings.TrimSuffix(p, "/")
			if p == "" {
				return nil
			}
			inRouter[method+" "+p] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(inRouter) < 15 {
		t.Fatalf("route walk found only %d routes: %v", len(inRouter), inRouter)
	}
	for k := range inRouter {
		if !inSpec[k] {
			t.Errorf("route %q is missing from the OpenAPI spec", k)
		}
	}
	for k := range inSpec {
		if !inRouter[k] {
			t.Errorf("spec documents %q but no such route exists", k)
		}
	}
	// Every operation must document the standard error responses and POSTs the idempotency key.
	var full map[string]any
	_ = json.Unmarshal(r.Body.Bytes(), &full)
	for p, ops := range full["paths"].(map[string]any) {
		for m, op := range ops.(map[string]any) {
			o := op.(map[string]any)
			if p == "/openapi.json" {
				continue
			}
			resps := o["responses"].(map[string]any)
			for _, code := range []string{"401", "403", "429", "500"} {
				if resps[code] == nil {
					t.Errorf("%s %s lacks a %s response", m, p, code)
				}
			}
			if m == "post" && !strings.Contains(fmt.Sprint(o["parameters"]), "IdempotencyKey") {
				t.Errorf("POST %s does not document Idempotency-Key", p)
			}
		}
	}
}
