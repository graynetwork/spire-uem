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

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

const certTestPassword = "Sup3r-secret-pw!"

// mkAdminUser creates a local admin with a known password.
func (e *apiEnv) mkAdminUser(role types.AdminRole, tags []string) string {
	e.t.Helper()
	name := e.uniq("cu")
	if _, err := e.repo.CreateLocalAdminUser(context.Background(), types.CreateUserRequest{
		Username: name, Email: name + "@example.test", DisplayName: "t", Password: certTestPassword, Role: role, AllowedTags: tags,
	}); err != nil {
		e.t.Fatalf("create user: %v", err)
	}
	return name
}

// adminSession is a browser session obtained through the real POST /login.
type adminSession struct {
	e      *apiEnv
	cookie *http.Cookie
	csrf   string
}

func (e *apiEnv) login(username string) *adminSession {
	e.t.Helper()
	form := url.Values{"username": {username}, "password": {certTestPassword}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.RemoteAddr = "192.0.2.40:4000"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	if rec.Code != 200 {
		e.t.Fatalf("login %s: %d %s", username, rec.Code, rec.Body.String())
	}
	var out struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	for _, c := range rec.Result().Cookies() {
		if c.Value != "" && out.CSRF != "" {
			return &adminSession{e: e, cookie: c, csrf: out.CSRF}
		}
	}
	e.t.Fatalf("login %s gave no session cookie/CSRF token", username)
	return nil
}

// do sends a request with the session cookie. csrf=true adds the X-CSRF-Token header.
func (s *adminSession) do(method, path string, csrf bool, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "192.0.2.40:4000"
	req.AddCookie(s.cookie)
	if csrf {
		req.Header.Set("X-CSRF-Token", s.csrf)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	s.e.router.ServeHTTP(rec, req)
	return rec
}

// devicePage fetches the device detail drawer (the fragment the device list loads).
func (s *adminSession) devicePage(id, query string) *httptest.ResponseRecorder {
	return s.do("GET", "/admin/devices/"+id+query, false, "HX-Request", "true")
}

func (e *apiEnv) mkCert(deviceID string, purpose types.CertPurpose, user string, notBefore, notAfter time.Time) *db.DeviceCertificate {
	e.t.Helper()
	c, err := e.repo.StoreDeviceCertificateFor(context.Background(), deviceID, purpose, user, e.uniq("serial"), e.uniq("fp"), notBefore, notAfter)
	if err != nil {
		e.t.Fatalf("store cert: %v", err)
	}
	return c
}

func (e *apiEnv) certRevoked(id string) bool {
	var revoked bool
	if err := e.pool.QueryRow(context.Background(), `SELECT revoked_at IS NOT NULL FROM device_certificates WHERE id=$1`, id).Scan(&revoked); err != nil {
		e.t.Fatal(err)
	}
	return revoked
}

func tail16(s string) string {
	if len(s) <= 16 {
		return s
	}
	return s[len(s)-16:]
}

func TestDeviceCertsPage_ListsOnlyOwnEscapesAndHidesButtonsFromAuditor(t *testing.T) {
	e := newAPIEnv(t)
	now := time.Now()
	devA, devB := e.mkApproved(), e.mkApproved()
	agent := e.mkCert(devA.ID, types.CertPurposeAgent, "", now.Add(-time.Hour), now.Add(24*time.Hour))
	network := e.mkCert(devA.ID, types.CertPurposeNetwork, "", now.Add(-time.Hour), now.Add(24*time.Hour))
	evil := e.mkCert(devA.ID, types.CertPurposeBrowser, "<script>alert(1)</script>", now.Add(-time.Hour), now.Add(24*time.Hour))
	oldRevoked := e.mkCert(devA.ID, types.CertPurposeNetwork, "", now.Add(-48*time.Hour), now.Add(24*time.Hour))
	if _, err := e.repo.RevokeDeviceCertificate(context.Background(), devA.ID, oldRevoked.ID); err != nil {
		t.Fatal(err)
	}
	expired := e.mkCert(devA.ID, types.CertPurposeNetwork, "", now.Add(-72*time.Hour), now.Add(-time.Hour))
	other := e.mkCert(devB.ID, types.CertPurposeAgent, "", now.Add(-time.Hour), now.Add(24*time.Hour))

	sec := e.login(e.mkAdminUser(types.RoleSecurityAdmin, nil))
	rec := sec.devicePage(devA.ID, "")
	wantStatus(t, rec, 200, "security admin page")
	body := rec.Body.String()
	for _, c := range []*db.DeviceCertificate{agent, network, evil} {
		if !strings.Contains(body, tail16(c.Serial)) {
			t.Errorf("active certificate %s (%s) missing from the table", c.Serial, c.Purpose)
		}
		if !strings.Contains(body, "/certificates/"+c.ID+"/revoke") {
			t.Errorf("no Revoke button for active certificate %s", c.ID)
		}
	}
	if strings.Contains(body, other.Serial) || strings.Contains(body, "/certificates/"+other.ID) {
		t.Errorf("another device's certificate appears on this page")
	}
	for _, c := range []*db.DeviceCertificate{oldRevoked, expired} {
		if strings.Contains(body, "/certificates/"+c.ID) || strings.Contains(body, tail16(c.Serial)) {
			t.Errorf("inactive certificate %s listed by default", c.ID)
		}
	}
	if !strings.Contains(body, "certs=all") {
		t.Errorf("no show-all link")
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Errorf("browser certificate user name was not escaped")
	}
	if !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Errorf("escaped user name not shown")
	}

	all := sec.devicePage(devA.ID, "?certs=all").Body.String()
	for _, c := range []*db.DeviceCertificate{oldRevoked, expired} {
		if !strings.Contains(all, tail16(c.Serial)) {
			t.Errorf("show-all misses %s", c.ID)
		}
		if strings.Contains(all, "/certificates/"+c.ID+"/revoke") {
			t.Errorf("inactive certificate %s has a Revoke button", c.ID)
		}
	}
	if !strings.Contains(all, ">revoked<") || !strings.Contains(all, ">expired<") {
		t.Errorf("show-all does not label revoked and expired status")
	}

	aud := e.login(e.mkAdminUser(types.RoleAuditor, nil))
	ab := aud.devicePage(devA.ID, "").Body.String()
	if !strings.Contains(ab, tail16(agent.Serial)) {
		t.Errorf("auditor does not see the table")
	}
	if strings.Contains(ab, "/certificates/") {
		t.Errorf("auditor page contains certificate action URLs")
	}
	wantStatus(t, aud.do("POST", "/admin/devices/"+devA.ID+"/certificates/"+agent.ID+"/revoke", true), 403, "auditor revoke")
	if e.certRevoked(agent.ID) {
		t.Errorf("auditor revoked a certificate")
	}
}

func TestDeviceCerts_TagScopedAdminCannotSeeOrRevokeOutsideTags(t *testing.T) {
	e := newAPIEnv(t)
	now := time.Now()
	in, out := e.mkApproved("team-a"), e.mkApproved("team-b")
	cin := e.mkCert(in.ID, types.CertPurposeNetwork, "", now.Add(-time.Hour), now.Add(time.Hour))
	cout := e.mkCert(out.ID, types.CertPurposeNetwork, "", now.Add(-time.Hour), now.Add(time.Hour))
	s := e.login(e.mkAdminUser(types.RoleSecurityAdmin, []string{"team-a"}))

	wantStatus(t, s.devicePage(out.ID, ""), 404, "page of a device outside the tags")
	wantStatus(t, s.do("POST", "/admin/devices/"+out.ID+"/certificates/"+cout.ID+"/revoke", true), 404, "revoke outside the tags")
	wantStatus(t, s.do("POST", "/admin/devices/"+out.ID+"/certificates/reapprove", true), 404, "re-approve outside the tags")
	if e.certRevoked(cout.ID) {
		t.Fatalf("a tag-scoped admin revoked a certificate outside their tags")
	}
	wantStatus(t, s.devicePage(in.ID, ""), 200, "page of a device inside the tags")
	wantStatus(t, s.do("POST", "/admin/devices/"+in.ID+"/certificates/"+cin.ID+"/revoke", true), 200, "revoke inside the tags")
	if !e.certRevoked(cin.ID) {
		t.Fatalf("in-scope revoke did not happen")
	}
}

func TestDeviceCerts_RevokeOfAnotherDevicesCertificateIs404(t *testing.T) {
	e := newAPIEnv(t)
	now := time.Now()
	devA, devB := e.mkApproved(), e.mkApproved()
	bCert := e.mkCert(devB.ID, types.CertPurposeNetwork, "", now.Add(-time.Hour), now.Add(time.Hour))
	s := e.login(e.mkAdminUser(types.RoleSecurityAdmin, nil))

	wantStatus(t, s.do("POST", "/admin/devices/"+devA.ID+"/certificates/"+bCert.ID+"/revoke", true), 404, "page revoke with the other device's id")
	wantStatus(t, s.do("POST", "/admin/devices/"+devA.ID+"/certificates/not-a-uuid/revoke", true), 404, "page revoke with a malformed id")
	if e.certRevoked(bCert.ID) {
		t.Fatalf("revoking via the wrong device changed the certificate")
	}
	if e.auditCount("DEVICE_CERT_REVOKE", devA.ID) != 0 || e.auditCount("DEVICE_CERT_REVOKE", devB.ID) != 0 {
		t.Errorf("a refused revoke wrote an audit event")
	}

	_, tok := e.mkSA(saSpec{role: types.RoleSecurityAdmin, scopes: allScopes})
	r := e.call("POST", apiBase+"/devices/"+devA.ID+"/certificates/"+bCert.ID+"/revoke", tok)
	if r.Code != 404 || r.errCode() != "not_found" {
		t.Fatalf("API revoke of another device's certificate: %d %s", r.Code, r.Body.String())
	}
	if e.certRevoked(bCert.ID) {
		t.Fatalf("API revoke via the wrong device changed the certificate")
	}
}

func TestDeviceCerts_RevokeThroughSessionIsCSRFProtectedAudited(t *testing.T) {
	e := newAPIEnv(t)
	now := time.Now()
	dev := e.mkApproved()
	browser := e.mkCert(dev.ID, types.CertPurposeBrowser, "alice", now.Add(-time.Hour), now.Add(time.Hour))
	path := "/admin/devices/" + dev.ID + "/certificates/" + browser.ID + "/revoke"
	s := e.login(e.mkAdminUser(types.RoleSecurityAdmin, nil))

	wantStatus(t, s.do("POST", path, false), 403, "revoke without a CSRF token")
	if e.certRevoked(browser.ID) {
		t.Fatalf("revoke without CSRF token went through")
	}
	wantStatus(t, s.do("POST", path, true), 200, "revoke with a CSRF token")
	if !e.certRevoked(browser.ID) {
		t.Fatalf("revoke did not happen")
	}
	var details string
	if err := e.pool.QueryRow(context.Background(), `SELECT details::text FROM system_audit_events WHERE action='DEVICE_CERT_REVOKE' AND target_id=$1`, dev.ID).Scan(&details); err != nil {
		t.Fatalf("no DEVICE_CERT_REVOKE audit event: %v", err)
	}
	for _, want := range []string{"browser", browser.Serial, "alice"} {
		if !strings.Contains(details, want) {
			t.Errorf("audit details %s lack %s", details, want)
		}
	}
	if blocked, _ := e.repo.DeviceCertReapprovalRequired(context.Background(), dev.ID); blocked {
		t.Errorf("revoking a browser certificate set the re-approval flag")
	}
	wantStatus(t, s.do("POST", path, true), 404, "second revoke")
	if n := e.auditCount("DEVICE_CERT_REVOKE", dev.ID); n != 1 {
		t.Errorf("audit events = %d, want 1", n)
	}
}

func TestDeviceCerts_RevokeAgentCertSetsFlagPageShowsAndReapproves(t *testing.T) {
	e := newAPIEnv(t)
	now := time.Now()
	dev := e.mkApproved()
	agent := e.mkCert(dev.ID, types.CertPurposeAgent, "", now.Add(-time.Hour), now.Add(time.Hour))
	s := e.login(e.mkAdminUser(types.RoleSecurityAdmin, nil))

	wantStatus(t, s.do("POST", "/admin/devices/"+dev.ID+"/certificates/"+agent.ID+"/revoke", true), 200, "revoke agent cert")
	if blocked, _ := e.repo.DeviceCertReapprovalRequired(context.Background(), dev.ID); !blocked {
		t.Fatalf("revoking the agent certificate must set the re-approval flag")
	}
	if !strings.Contains(s.devicePage(dev.ID, "").Body.String(), "/certificates/reapprove") {
		t.Errorf("page offers no re-approve button")
	}
	aud := e.login(e.mkAdminUser(types.RoleAuditor, nil))
	if strings.Contains(aud.devicePage(dev.ID, "").Body.String(), "/certificates/reapprove") {
		t.Errorf("auditor is offered the re-approve button")
	}
	wantStatus(t, aud.do("POST", "/admin/devices/"+dev.ID+"/certificates/reapprove", true), 403, "auditor re-approve")
	if blocked, _ := e.repo.DeviceCertReapprovalRequired(context.Background(), dev.ID); !blocked {
		t.Fatalf("auditor cleared the flag")
	}
	wantStatus(t, s.do("POST", "/admin/devices/"+dev.ID+"/certificates/reapprove", true), 200, "re-approve")
	if blocked, _ := e.repo.DeviceCertReapprovalRequired(context.Background(), dev.ID); blocked {
		t.Fatalf("re-approve did not clear the flag")
	}
	if n := e.auditCount("DEVICE_CERT_REAPPROVE", dev.ID); n != 1 {
		t.Errorf("DEVICE_CERT_REAPPROVE audit events = %d, want 1", n)
	}
}
