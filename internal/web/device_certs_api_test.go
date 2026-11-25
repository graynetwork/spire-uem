package web_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

func TestDeviceCertsAPI_ScopesTagsPaginationRevoke(t *testing.T) {
	e := newAPIEnv(t)
	now := time.Now()
	in, out := e.mkApproved("t-in"), e.mkApproved("t-out")
	var ids []string
	for i := 0; i < 5; i++ {
		c := e.mkCert(in.ID, types.CertPurposeNetwork, "", now.Add(-time.Hour), now.Add(time.Hour))
		ids = append(ids, c.ID)
		time.Sleep(2 * time.Millisecond)
	}
	expired := e.mkCert(in.ID, types.CertPurposeNetwork, "", now.Add(-72*time.Hour), now.Add(-time.Hour))
	e.mkCert(out.ID, types.CertPurposeNetwork, "", now.Add(-time.Hour), now.Add(time.Hour))

	_, readTok := e.mkSA(saSpec{role: types.RoleAuditor, scopes: []string{types.ScopeDevicesRead}})
	_, noScope := e.mkSA(saSpec{role: types.RoleSecurityAdmin, scopes: []string{types.ScopeGroupsRead}})
	_, operatorTok := e.mkSA(saSpec{role: types.RoleOperator, scopes: allScopes})
	_, secTok := e.mkSA(saSpec{role: types.RoleSecurityAdmin, scopes: allScopes})
	_, scopedTok := e.mkSA(saSpec{role: types.RoleSecurityAdmin, scopes: allScopes, tags: []string{"t-in"}})
	list := apiBase + "/devices/" + in.ID + "/certificates"

	if r := e.call("GET", list, ""); r.Code != 401 {
		t.Errorf("no token: %d", r.Code)
	}
	if r := e.call("GET", list, noScope); r.Code != 403 || r.errCode() != "insufficient_scope" {
		t.Errorf("missing devices:read: %d %s", r.Code, r.Body.String())
	}
	r1 := e.call("GET", list+"?limit=4", readTok)
	if r1.Code != 200 {
		t.Fatalf("list: %d %s", r1.Code, r1.Body.String())
	}
	m := r1.json()
	if len(m["data"].([]any)) != 4 || m["has_more"] != true || m["next_cursor"] == nil {
		t.Fatalf("first page: %s", r1.Body.String())
	}
	r2 := e.call("GET", list+"?limit=4&cursor="+m["next_cursor"].(string), readTok)
	m2 := r2.json()
	if r2.Code != 200 || len(m2["data"].([]any)) != 2 || m2["has_more"] != false {
		t.Fatalf("second page: %d %s", r2.Code, r2.Body.String())
	}
	seen := map[string]bool{}
	for _, id := range append(dataIDs(t, r1), dataIDs(t, r2)...) {
		if seen[id] {
			t.Errorf("certificate %s on two pages", id)
		}
		seen[id] = true
	}
	if len(seen) != 6 || !seen[expired.ID] {
		t.Errorf("pages cover %d certificates, want 6 including the expired one", len(seen))
	}
	if r := e.call("GET", list+"?active=true&cursor="+m["next_cursor"].(string), readTok); r.Code != 400 {
		t.Errorf("a cursor reused with a different filter must be 400, got %d", r.Code)
	}
	if r := e.call("GET", list+"?active=maybe", readTok); r.Code != 400 {
		t.Errorf("bad active filter: %d", r.Code)
	}
	ra := e.call("GET", list+"?active=true", readTok)
	if got := dataIDs(t, ra); len(got) != 5 || contains(got, expired.ID) {
		t.Errorf("active=true returned %v", got)
	}
	first := ra.json()["data"].([]any)[0].(map[string]any)
	if first["status"] != "active" || first["purpose"] != "network" || first["user"] != nil || first["serial"] == "" {
		t.Errorf("unexpected certificate shape: %v", first)
	}

	if r := e.call("GET", apiBase+"/devices/"+out.ID+"/certificates", scopedTok); r.Code != 404 {
		t.Errorf("out-of-scope list: %d", r.Code)
	}
	if r := e.call("GET", list, scopedTok); r.Code != 200 {
		t.Errorf("in-scope list: %d", r.Code)
	}

	rev := func(tok, devID, certID string) apiResp {
		return e.call("POST", apiBase+"/devices/"+devID+"/certificates/"+certID+"/revoke", tok)
	}
	if r := rev(readTok, in.ID, ids[0]); r.Code != 403 {
		t.Errorf("read-only credential revoke: %d", r.Code)
	}
	if r := rev(operatorTok, in.ID, ids[0]); r.Code != 403 || r.errCode() != "insufficient_role" {
		t.Errorf("OPERATOR revoke: %d %s", r.Code, r.Body.String())
	}
	if e.certRevoked(ids[0]) {
		t.Fatalf("a refused revoke changed the certificate")
	}
	outCerts, _ := e.repo.ListDeviceCertificates(context.Background(), out.ID, true, 0)
	if r := rev(scopedTok, out.ID, outCerts[0].ID); r.Code != 404 || e.certRevoked(outCerts[0].ID) {
		t.Errorf("tag-scoped revoke outside the tags: %d", r.Code)
	}
	r := rev(secTok, in.ID, ids[0])
	if r.Code != 200 {
		t.Fatalf("revoke: %d %s", r.Code, r.Body.String())
	}
	d := r.json()["data"].(map[string]any)
	if d["reapproval_required"] != false || d["certificate"].(map[string]any)["status"] != "revoked" {
		t.Errorf("revoke response: %s", r.Body.String())
	}
	if r := rev(secTok, in.ID, ids[0]); r.Code != 409 || r.errCode() != "already_revoked" {
		t.Errorf("second revoke: %d %s", r.Code, r.Body.String())
	}
	k := e.uniq("idem")
	a := e.call("POST", apiBase+"/devices/"+in.ID+"/certificates/"+ids[1]+"/revoke", secTok, "Idempotency-Key", k)
	b := e.call("POST", apiBase+"/devices/"+in.ID+"/certificates/"+ids[1]+"/revoke", secTok, "Idempotency-Key", k)
	if a.Code != 200 || b.Code != 200 || b.Header().Get("Idempotent-Replayed") != "true" {
		t.Errorf("idempotent revoke: %d then %d replayed=%q", a.Code, b.Code, b.Header().Get("Idempotent-Replayed"))
	}
	if n := e.auditCount("DEVICE_CERT_REVOKE", in.ID); n != 2 {
		t.Errorf("audit events = %d, want 2 (one per real revoke)", n)
	}

	now2 := time.Now()
	agent := e.mkCert(out.ID, types.CertPurposeAgent, "", now2.Add(-time.Hour), now2.Add(time.Hour))
	ra2 := rev(secTok, out.ID, agent.ID)
	if ra2.Code != 200 || ra2.json()["data"].(map[string]any)["reapproval_required"] != true {
		t.Fatalf("agent revoke: %d %s", ra2.Code, ra2.Body.String())
	}
	re := func(tok string) apiResp {
		return e.call("POST", apiBase+"/devices/"+out.ID+"/certificates/reapprove", tok)
	}
	if r := re(operatorTok); r.Code != 403 {
		t.Errorf("OPERATOR re-approve: %d", r.Code)
	}
	if r := re(scopedTok); r.Code != 404 {
		t.Errorf("tag-scoped re-approve outside the tags: %d", r.Code)
	}
	if blocked, _ := e.repo.DeviceCertReapprovalRequired(context.Background(), out.ID); !blocked {
		t.Fatalf("flag cleared by a refused call")
	}
	if r := re(secTok); r.Code != 200 || r.json()["data"].(map[string]any)["was_blocked"] != true {
		t.Errorf("re-approve: %d %s", r.Code, r.Body.String())
	}
	if blocked, _ := e.repo.DeviceCertReapprovalRequired(context.Background(), out.ID); blocked {
		t.Errorf("re-approve did not clear the flag")
	}
	if r := re(secTok); r.Code != 200 || r.json()["data"].(map[string]any)["was_blocked"] != false {
		t.Errorf("repeat re-approve: %d %s", r.Code, r.Body.String())
	}
}

func TestDeviceCAEndpointsAndPage(t *testing.T) {
	e := newAPIEnv(t)
	t.Cleanup(func() { e.repo.SetDeviceCA(nil) })

	_, narrow := e.mkSA(saSpec{role: types.RoleAuditor, scopes: []string{types.ScopeGroupsRead}, tags: []string{"nothing-here"}})
	if r := e.call("GET", apiBase+"/pki/device-ca", ""); r.Code != 401 {
		t.Errorf("anonymous CA read: %d", r.Code)
	}

	e.repo.SetDeviceCA(nil)
	if r := e.call("GET", apiBase+"/pki/device-ca", narrow); r.Code != 404 || r.errCode() != "no_device_ca" {
		t.Errorf("no CA: %d %s", r.Code, r.Body.String())
	}
	s := e.login(e.mkAdminUser(types.RoleAuditor, []string{"x"}))
	rec := s.do("GET", "/admin/device-ca", false, "Accept", "text/html")
	wantStatus(t, rec, 200, "page without a CA")
	if !strings.Contains(rec.Body.String(), "No device CA is configured") {
		t.Errorf("page does not say that no CA is configured")
	}
	wantStatus(t, s.do("GET", "/admin/device-ca.pem", false), 404, "PEM download without a CA")

	ca := newTestCA(t)
	e.repo.SetDeviceCA(ca)
	r := e.call("GET", apiBase+"/pki/device-ca", narrow)
	if r.Code != 200 {
		t.Fatalf("CA read: %d %s", r.Code, r.Body.String())
	}
	d := r.json()["data"].(map[string]any)
	fp, _ := d["fingerprint_sha256"].(string)
	if len(fp) != 64 || d["pem"] != string(ca.CACertPEM()) || d["subject"] == "" || d["not_after"] == nil {
		t.Errorf("CA data: %v", d)
	}
	rec = s.do("GET", "/admin/device-ca", false, "Accept", "text/html")
	wantStatus(t, rec, 200, "page with a CA")
	body := rec.Body.String()
	if !strings.Contains(body, fp) || !strings.Contains(body, "/admin/device-ca.pem") {
		t.Errorf("page lacks the fingerprint or the download link")
	}
	dl := s.do("GET", "/admin/device-ca.pem", false)
	wantStatus(t, dl, 200, "PEM download")
	if dl.Body.String() != string(ca.CACertPEM()) || !strings.Contains(dl.Header().Get("Content-Disposition"), "attachment") {
		t.Errorf("PEM download body/headers wrong: %q", dl.Header())
	}
	if strings.Contains(body, "PRIVATE KEY") || strings.Contains(dl.Body.String(), "PRIVATE KEY") || strings.Contains(r.Body.String(), "PRIVATE KEY") {
		t.Errorf("a private key is exposed")
	}
	anon := httptest.NewRecorder()
	e.router.ServeHTTP(anon, httptest.NewRequest("GET", "/admin/device-ca.pem", nil))
	if anon.Code == 200 {
		t.Errorf("anonymous PEM download succeeded")
	}
}
