package web_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/audit"
	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/web"
)

// ---------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------

const testProxyAddr = "192.0.2.50"

func (e *apiEnv) mkApproved(tags ...string) *types.Device {
	d := e.mkDevice(tags...)
	if _, _, err := e.repo.ApproveDevice(context.Background(), d.ID); err != nil {
		e.t.Fatalf("approve: %v", err)
	}
	return d
}

// freshIP returns a documentation-range address no other device holds.
func (e *apiEnv) freshIP() string {
	var b [2]byte
	_, _ = rand.Read(b[:])
	ip := fmt.Sprintf("198.18.%d.%d", 1+int(b[0])%250, 1+int(b[1])%250)
	if _, err := e.pool.Exec(context.Background(), `UPDATE devices SET last_seen_ip = NULL WHERE last_seen_ip = $1`, ip); err != nil {
		e.t.Fatal(err)
	}
	return ip
}

func (e *apiEnv) seenAt(d *types.Device, ip string) {
	if err := e.repo.UpdateDeviceSeenFacts(context.Background(), d.ID, ip, ""); err != nil {
		e.t.Fatal(err)
	}
}

func (e *apiEnv) setPosture(d *types.Device, state types.PostureState, validFor time.Duration) {
	now := time.Now().UTC()
	p := &types.DevicePosture{DeviceID: d.ID, State: state, Reasons: []string{}, EvaluatedAt: now, ValidUntil: now.Add(validFor)}
	if state == types.PostureNoncompliant {
		p.Reasons = []string{"disk not encrypted"}
	}
	if _, err := e.repo.UpsertDevicePosture(context.Background(), p); err != nil {
		e.t.Fatal(err)
	}
}

// accessCfg stores forward-auth settings and restores the closed defaults afterwards.
func (e *apiEnv) accessCfg(trusted string, weak bool, ipHeader, certHeader string) {
	prefixes, err := db.ParseTrustedProxyList(trusted)
	if err != nil {
		e.t.Fatal(err)
	}
	set := func(s db.AccessProxySettings) {
		if err := e.repo.SaveAccessProxySettings(context.Background(), s, "test"); err != nil {
			e.t.Fatal(err)
		}
	}
	set(db.AccessProxySettings{TrustedProxies: prefixes, IPHeader: ipHeader, CertHeader: certHeader, AllowWeakIdentity: weak})
	e.t.Cleanup(func() { set(db.AccessProxySettings{IPHeader: db.IPHeaderXForwardedFor}) })
}

type fwd struct {
	peer   string
	xff    string
	token  string
	hdrs   map[string]string
	cHdr   string // X-Spire-Connector-Token
	noAuth bool
}

func (e *apiEnv) forward(f fwd) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, apiBase+"/access/forward-auth", nil)
	req.RemoteAddr = f.peer + ":4000"
	if f.peer == "" {
		req.RemoteAddr = testProxyAddr + ":4000"
	}
	if f.token != "" && !f.noAuth {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	if f.cHdr != "" {
		req.Header.Set(web.ConnectorTokenHeader, f.cHdr)
	}
	if f.xff != "" {
		req.Header.Set("X-Forwarded-For", f.xff)
	}
	for k, v := range f.hdrs {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func connectorSA(e *apiEnv, tags ...string) string {
	_, tok := e.mkSA(saSpec{role: types.RoleAuditor, tags: tags, scopes: []string{types.ScopePostureRead}})
	return tok
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, want int, what string) {
	t.Helper()
	if rec.Code != want {
		t.Errorf("%s: got %d, want %d (body %s)", what, rec.Code, want, rec.Body.String())
	}
}

func lookupData(t *testing.T, r apiResp) map[string]any {
	t.Helper()
	d, _ := r.json()["data"].(map[string]any)
	if d == nil {
		t.Fatalf("no data in %s", r.Body.String())
	}
	return d
}

// ---------------------------------------------------------------------------------------
// GET /devices/{id}/posture
// ---------------------------------------------------------------------------------------

func TestPostureAPI_DeviceEndpoint(t *testing.T) {
	e := newAPIEnv(t)
	tok := connectorSA(e)
	inTag := "pt-in-" + e.sfx
	scoped := connectorSA(e, inTag)
	noScope := func() string {
		_, t := e.mkSA(saSpec{role: types.RoleAuditor, scopes: []string{types.ScopeDevicesRead}})
		return t
	}()

	d := e.mkApproved(inTag)
	out := e.mkApproved("pt-out-" + e.sfx)

	// Never evaluated reads UNKNOWN, not an error and not COMPLIANT.
	r := e.call("GET", apiBase+"/devices/"+d.ID+"/posture", tok)
	wantStatus(t, r.ResponseRecorder, 200, "never evaluated")
	if m := lookupData(t, r); m["state"] != "UNKNOWN" || m["allowed"] != false {
		t.Errorf("never evaluated: %v", m)
	}

	e.setPosture(d, types.PostureCompliant, time.Hour)
	if m := lookupData(t, e.call("GET", apiBase+"/devices/"+d.ID+"/posture", tok)); m["state"] != "COMPLIANT" || m["allowed"] != true || m["stale"] != false {
		t.Errorf("compliant: %v", m)
	}

	// An expired COMPLIANT verdict must not read COMPLIANT.
	e.setPosture(d, types.PostureCompliant, -time.Minute)
	m := lookupData(t, e.call("GET", apiBase+"/devices/"+d.ID+"/posture", tok))
	if m["state"] != "UNKNOWN" || m["allowed"] != false || m["stale"] != true || m["stored_state"] != "COMPLIANT" {
		t.Errorf("stale: %v", m)
	}

	e.setPosture(out, types.PostureCompliant, time.Hour)
	wantStatus(t, e.call("GET", apiBase+"/devices/"+d.ID+"/posture", scoped).ResponseRecorder, 200, "scoped in-scope")
	wantStatus(t, e.call("GET", apiBase+"/devices/"+out.ID+"/posture", scoped).ResponseRecorder, 404, "scoped out-of-scope")
	wantStatus(t, e.call("GET", apiBase+"/devices/"+out.ID+"/posture", tok).ResponseRecorder, 200, "unscoped any device")
	wantStatus(t, e.call("GET", apiBase+"/devices/not-a-uuid/posture", tok).ResponseRecorder, 404, "bad id")
	wantStatus(t, e.call("GET", apiBase+"/devices/"+d.ID+"/posture", noScope).ResponseRecorder, 403, "missing posture:read")
	wantStatus(t, e.call("GET", apiBase+"/devices/"+d.ID+"/posture", "").ResponseRecorder, 401, "no credential")
}

// ---------------------------------------------------------------------------------------
// GET /posture/lookup
// ---------------------------------------------------------------------------------------

func TestPostureAPI_Lookup(t *testing.T) {
	e := newAPIEnv(t)
	tok := connectorSA(e)
	ip := e.freshIP()
	d := e.mkApproved()
	e.seenAt(d, ip)
	e.setPosture(d, types.PostureCompliant, time.Hour)

	r := e.call("GET", apiBase+"/posture/lookup?ip="+ip, tok)
	wantStatus(t, r.ResponseRecorder, 200, "ip lookup")
	m := lookupData(t, r)
	if m["allowed"] != true || m["state"] != "COMPLIANT" || m["device_id"] != d.ID || m["identity_strength"] != "weak" || m["matched_by"] != "ip" || m["hostname"] != d.Hostname {
		t.Errorf("ip lookup: %v", m)
	}

	// MAC and user are weak too.
	if err := e.repo.UpdateDeviceSeenFacts(context.Background(), d.ID, ip, "alice-"+e.sfx); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"user=ALICE-" + e.sfx, "user=alice-" + e.sfx} {
		if m := lookupData(t, e.call("GET", apiBase+"/posture/lookup?"+q, tok)); m["device_id"] != d.ID || m["identity_strength"] != "weak" || m["matched_by"] != "user" {
			t.Errorf("%s: %v", q, m)
		}
	}
	mac := fmt.Sprintf("02:ca:%02x:%02x:%02x:%02x", time.Now().UnixNano()&0xff, (time.Now().UnixNano()>>8)&0xff, (time.Now().UnixNano()>>16)&0xff, (time.Now().UnixNano()>>24)&0xff)
	if _, err := e.repo.ReplaceDeviceAttributes(context.Background(), d.ID, types.AttrSourceInventory, []types.DeviceAttribute{{Key: "net.primary_mac", Type: types.AttrString, Value: json.RawMessage(`"` + mac + `"`)}}); err != nil {
		t.Fatalf("set mac attribute: %v", err)
	} else if m := lookupData(t, e.call("GET", apiBase+"/posture/lookup?mac="+strings.ToUpper(strings.ReplaceAll(mac, ":", "-")), tok)); m["device_id"] != d.ID || m["identity_strength"] != "weak" || m["matched_by"] != "mac" {
		t.Errorf("mac lookup: %v", m)
	}

	// Noncompliant states are reported with their reasons.
	e.setPosture(d, types.PostureNoncompliant, time.Hour)
	m = lookupData(t, e.call("GET", apiBase+"/posture/lookup?ip="+ip, tok))
	if m["allowed"] != false || m["state"] != "NONCOMPLIANT" || fmt.Sprint(m["reasons"]) != "[disk not encrypted]" {
		t.Errorf("noncompliant: %v", m)
	}

	// Unknown device.
	unknown := lookupData(t, e.call("GET", apiBase+"/posture/lookup?ip=198.19.255.254", tok))
	if unknown["allowed"] != false || unknown["state"] != "UNKNOWN" || unknown["device_id"] != nil || fmt.Sprint(unknown["reasons"]) != "[unknown device]" {
		t.Errorf("unknown: %v", unknown)
	}

	// Two devices on one address: ambiguous, and neither id is revealed.
	d2 := e.mkApproved()
	e.seenAt(d2, ip)
	e.setPosture(d2, types.PostureCompliant, time.Hour)
	r = e.call("GET", apiBase+"/posture/lookup?ip="+ip, tok)
	m = lookupData(t, r)
	if m["allowed"] != false || m["state"] != "UNKNOWN" || m["device_id"] != nil || m["hostname"] != nil || fmt.Sprint(m["reasons"]) != "[ambiguous identity]" {
		t.Errorf("ambiguous: %v", m)
	}
	if strings.Contains(r.Body.String(), d.ID) || strings.Contains(r.Body.String(), d2.ID) {
		t.Errorf("ambiguous response leaks a device id: %s", r.Body.String())
	}

	// Bad input.
	for _, q := range []string{"", "ip=" + ip + "&user=x", "ip=", "ip=not-an-ip", "mac=zz", "bogus=1", "ip=" + ip + "&ip=" + ip, "ip=" + ip + "&bogus=1"} {
		wantStatus(t, e.call("GET", apiBase+"/posture/lookup?"+q, tok).ResponseRecorder, 400, "query "+q)
	}
	_, noScope := e.mkSA(saSpec{role: types.RoleAuditor, scopes: []string{types.ScopeDevicesRead}})
	wantStatus(t, e.call("GET", apiBase+"/posture/lookup?ip="+ip, noScope).ResponseRecorder, 403, "missing posture:read")
	wantStatus(t, e.call("GET", apiBase+"/posture/lookup?ip="+ip, "").ResponseRecorder, 401, "no credential")
}

// A tag-scoped connector must see an out-of-scope device exactly as it sees a missing one, and
// the scope is applied before ambiguity is judged.
func TestPostureAPI_Lookup_TagScope(t *testing.T) {
	e := newAPIEnv(t)
	team := "pl-team-" + e.sfx
	scoped := connectorSA(e, team)
	full := connectorSA(e)

	ip := e.freshIP()
	mine := e.mkApproved(team)
	other := e.mkApproved("pl-other-" + e.sfx)
	e.seenAt(mine, ip)
	e.setPosture(mine, types.PostureCompliant, time.Hour)
	otherIP := e.freshIP()
	e.seenAt(other, otherIP)
	e.setPosture(other, types.PostureCompliant, time.Hour)

	if m := lookupData(t, e.call("GET", apiBase+"/posture/lookup?ip="+ip, scoped)); m["device_id"] != mine.ID || m["allowed"] != true {
		t.Errorf("scoped, in scope: %v", m)
	}
	inv := e.call("GET", apiBase+"/posture/lookup?ip="+otherIP, scoped)
	missing := e.call("GET", apiBase+"/posture/lookup?ip=198.19.200.201", scoped)
	if inv.Code != missing.Code || strings.ReplaceAll(inv.Body.String(), "request_id", "") == "" {
		t.Fatalf("status differs: %d vs %d", inv.Code, missing.Code)
	}
	a, b := lookupData(t, inv), lookupData(t, missing)
	if fmt.Sprint(a) != fmt.Sprint(b) {
		t.Errorf("out-of-scope device is distinguishable from an unknown one:\n out-of-scope: %v\n unknown:      %v", a, b)
	}
	if strings.Contains(inv.Body.String(), other.ID) || strings.Contains(inv.Body.String(), other.Hostname) {
		t.Errorf("out-of-scope lookup leaks the device: %s", inv.Body.String())
	}
	if m := lookupData(t, e.call("GET", apiBase+"/posture/lookup?ip="+otherIP, full)); m["device_id"] != other.ID {
		t.Errorf("unscoped should see it: %v", m)
	}

	// Two devices share an address, only one is in scope: scoped sees one match, unscoped
	// sees ambiguity.
	shared := e.freshIP()
	e.seenAt(mine, shared)
	e.seenAt(other, shared)
	if m := lookupData(t, e.call("GET", apiBase+"/posture/lookup?ip="+shared, scoped)); m["device_id"] != mine.ID {
		t.Errorf("scope must be applied before ambiguity: %v", m)
	}
	if m := lookupData(t, e.call("GET", apiBase+"/posture/lookup?ip="+shared, full)); fmt.Sprint(m["reasons"]) != "[ambiguous identity]" {
		t.Errorf("unscoped should be ambiguous: %v", m)
	}
}

func TestPostureAPI_PATsHaveNoPostureScope(t *testing.T) {
	e := newAPIEnv(t)
	u, err := e.repo.CreateLocalAdminUser(context.Background(), types.CreateUserRequest{
		Username: e.uniq("pat"), Email: e.uniq("m") + "@example.test", Password: "correct-horse-battery", Role: types.RoleSuperAdmin})
	if err != nil {
		t.Fatal(err)
	}
	raw, hash, prefix, err := web.GeneratePAT()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.repo.CreatePersonalAccessToken(context.Background(), hash, prefix, "p", u.ID, types.RoleSuperAdmin, u.Username, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, e.call("GET", apiBase+"/posture/lookup?ip=198.19.1.1", raw).ResponseRecorder, 403, "PAT on lookup")
	wantStatus(t, e.forward(fwd{token: raw}), 403, "PAT on forward-auth")
}

// ---------------------------------------------------------------------------------------
// forward-auth: address identity
// ---------------------------------------------------------------------------------------

func TestForwardAuth_AddressIdentity(t *testing.T) {
	e := newAPIEnv(t)
	tok := connectorSA(e)
	ip := e.freshIP()
	d := e.mkApproved()
	e.seenAt(d, ip)
	e.setPosture(d, types.PostureCompliant, time.Hour)

	// Default settings are closed: nothing trusted, weak identity off.
	wantStatus(t, e.forward(fwd{token: tok, xff: ip}), 403, "default settings")

	// Trusted proxy but weak identity still off.
	e.accessCfg(testProxyAddr, false, db.IPHeaderXForwardedFor, "")
	wantStatus(t, e.forward(fwd{token: tok, xff: ip}), 403, "weak identity disabled")

	e.accessCfg(testProxyAddr, true, db.IPHeaderXForwardedFor, "")
	rec := e.forward(fwd{token: tok, xff: ip})
	wantStatus(t, rec, 200, "compliant device, trusted proxy, weak enabled")
	if rec.Header().Get("X-Spire-Device-Id") != d.ID || rec.Header().Get("X-Spire-Posture") != "COMPLIANT" || rec.Header().Get("X-Spire-Identity-Strength") != "weak" {
		t.Errorf("allow headers: %v", rec.Header())
	}

	// The same request from a peer that is NOT a trusted proxy is refused: it could have
	// written X-Forwarded-For itself.
	wantStatus(t, e.forward(fwd{token: tok, xff: ip, peer: "198.51.100.9"}), 403, "untrusted peer with spoofed X-Forwarded-For")

	// Entries a client prepended on the left are never used.
	wantStatus(t, e.forward(fwd{token: tok, xff: ip + ", 203.0.113.77"}), 403, "left-prepended spoof: rightmost untrusted entry is the client")
	// Our own proxy hops on the right are skipped.
	wantStatus(t, e.forward(fwd{token: tok, xff: ip + ", " + testProxyAddr}), 200, "trusted hop on the right is skipped")
	wantStatus(t, e.forward(fwd{token: tok, xff: "garbage"}), 403, "unparseable address")
	wantStatus(t, e.forward(fwd{token: tok, xff: ip + ", garbage"}), 403, "unparseable hop")
	wantStatus(t, e.forward(fwd{token: tok}), 403, "no address header")
	wantStatus(t, e.forward(fwd{token: tok, xff: testProxyAddr}), 403, "only trusted proxies listed")

	// X-Real-IP mode ignores X-Forwarded-For entirely.
	e.accessCfg(testProxyAddr, true, db.IPHeaderXRealIP, "")
	wantStatus(t, e.forward(fwd{token: tok, xff: ip}), 403, "real-ip mode ignores X-Forwarded-For")
	wantStatus(t, e.forward(fwd{token: tok, hdrs: map[string]string{"X-Real-Ip": ip}}), 200, "real-ip mode")
	wantStatus(t, e.forward(fwd{token: tok, xff: ip, hdrs: map[string]string{"X-Real-Ip": "203.0.113.5"}}), 403, "real-ip mode with another address in X-Forwarded-For")
	e.accessCfg(testProxyAddr, true, db.IPHeaderXForwardedFor, "")

	// Every state that is not COMPLIANT denies, with one generic body.
	var bodies []string
	for _, c := range []struct {
		name  string
		state types.PostureState
		valid time.Duration
	}{
		{"noncompliant", types.PostureNoncompliant, time.Hour},
		{"quarantined", types.PostureQuarantined, time.Hour},
		{"unknown", types.PostureUnknown, time.Hour},
		{"stale compliant", types.PostureCompliant, -time.Second},
	} {
		e.setPosture(d, c.state, c.valid)
		rec := e.forward(fwd{token: tok, xff: ip})
		wantStatus(t, rec, 403, c.name)
		bodies = append(bodies, rec.Body.String())
		if rec.Header().Get("X-Spire-Device-Id") != "" || rec.Header().Get("X-Spire-Posture") != "" {
			t.Errorf("%s: deny must not carry device headers: %v", c.name, rec.Header())
		}
	}
	rec = e.forward(fwd{token: tok, xff: "198.19.254.253"})
	bodies = append(bodies, rec.Body.String())
	for _, b := range bodies {
		if b != bodies[0] {
			t.Errorf("deny bodies differ (existence oracle): %q vs %q", b, bodies[0])
		}
	}
	// A device that has never been evaluated.
	d3 := e.mkApproved()
	ip3 := e.freshIP()
	e.seenAt(d3, ip3)
	wantStatus(t, e.forward(fwd{token: tok, xff: ip3}), 403, "no posture row")

	// Not-approved or lost devices never resolve.
	pending := e.mkDevice()
	ip4 := e.freshIP()
	e.seenAt(pending, ip4)
	e.setPosture(pending, types.PostureCompliant, time.Hour)
	wantStatus(t, e.forward(fwd{token: tok, xff: ip4}), 403, "unapproved device")

	// Two devices behind one address.
	dd := e.mkApproved()
	e.seenAt(dd, ip)
	e.setPosture(dd, types.PostureCompliant, time.Hour)
	e.setPosture(d, types.PostureCompliant, time.Hour)
	wantStatus(t, e.forward(fwd{token: tok, xff: ip}), 403, "ambiguous address")
}

func TestForwardAuth_Credentials(t *testing.T) {
	e := newAPIEnv(t)
	tok := connectorSA(e)
	e.accessCfg(testProxyAddr, true, db.IPHeaderXForwardedFor, "")
	ip := e.freshIP()
	d := e.mkApproved()
	e.seenAt(d, ip)
	e.setPosture(d, types.PostureCompliant, time.Hour)

	wantStatus(t, e.forward(fwd{noAuth: true, xff: ip}), 401, "no credential")
	wantStatus(t, e.forward(fwd{token: "spire_sa_0000000000000000_" + strings.Repeat("0", 64), xff: ip}), 401, "bad credential")
	_, noScope := e.mkSA(saSpec{role: types.RoleAuditor, scopes: []string{types.ScopeDevicesRead}})
	wantStatus(t, e.forward(fwd{token: noScope, xff: ip}), 403, "service account without posture:read")

	// The Traefik transport: token in X-Spire-Connector-Token.
	rec := e.forward(fwd{cHdr: tok, xff: ip})
	wantStatus(t, rec, 200, "connector token header")
	if strings.Contains(rec.Body.String(), tok) || strings.Contains(fmt.Sprint(rec.Header()), tok) {
		t.Errorf("response echoes the connector token")
	}
	// It replaces whatever Authorization the browser sent...
	wantStatus(t, e.forward(fwd{token: "attacker-supplied", cHdr: tok, xff: ip}), 200, "connector token wins over client Authorization")
	// ...and a bad connector token is a 401 even if Authorization is valid.
	wantStatus(t, e.forward(fwd{token: tok, cHdr: "spire_sa_bad", xff: ip}), 401, "bad connector token header")
}

// With SPIRE_TRUST_PROXY=true the router rewrites RemoteAddr from X-Real-IP. Forward-auth must
// still judge the real TCP peer, or any client could claim to be the trusted proxy.
func TestForwardAuth_PeerIsNotRewrittenByRealIPMiddleware(t *testing.T) {
	t.Setenv("SPIRE_TRUST_PROXY", "true")
	e := newAPIEnv(t)
	h, err := web.NewHandler(e.repo, nil, audit.NewForwarder(e.repo, ""))
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	r.Use(web.TrustedProxyRealIPMiddleware)
	h.RegisterRoutes(r, "admin", "adminpw")
	e.router = r

	tok := connectorSA(e)
	e.accessCfg(testProxyAddr, true, db.IPHeaderXForwardedFor, "")
	ip := e.freshIP()
	d := e.mkApproved()
	e.seenAt(d, ip)
	e.setPosture(d, types.PostureCompliant, time.Hour)

	// Attacker at 198.51.100.9 claims, via X-Real-IP, to be the trusted proxy.
	wantStatus(t, e.forward(fwd{token: tok, xff: ip, peer: "198.51.100.9", hdrs: map[string]string{"X-Real-Ip": testProxyAddr}}), 403, "client forging X-Real-IP to look like the proxy")
	wantStatus(t, e.forward(fwd{token: tok, xff: ip}), 200, "real proxy still works")
}

func TestForwardAuth_TagScopedConnector(t *testing.T) {
	e := newAPIEnv(t)
	team := "fa-team-" + e.sfx
	scoped := connectorSA(e, team)
	full := connectorSA(e)
	e.accessCfg(testProxyAddr, true, db.IPHeaderXForwardedFor, "")

	mine, other := e.mkApproved(team), e.mkApproved("fa-other-"+e.sfx)
	ipMine, ipOther := e.freshIP(), e.freshIP()
	e.seenAt(mine, ipMine)
	e.seenAt(other, ipOther)
	e.setPosture(mine, types.PostureCompliant, time.Hour)
	e.setPosture(other, types.PostureCompliant, time.Hour)

	wantStatus(t, e.forward(fwd{token: scoped, xff: ipMine}), 200, "scoped, in scope")
	r1 := e.forward(fwd{token: scoped, xff: ipOther})
	wantStatus(t, r1, 403, "scoped, out of scope")
	r2 := e.forward(fwd{token: scoped, xff: "198.19.254.1"})
	if r1.Body.String() != r2.Body.String() || r1.Code != r2.Code {
		t.Errorf("out-of-scope differs from unknown: %d %q vs %d %q", r1.Code, r1.Body.String(), r2.Code, r2.Body.String())
	}
	wantStatus(t, e.forward(fwd{token: full, xff: ipOther}), 200, "unscoped sees every device")
}

// ---------------------------------------------------------------------------------------
// forward-auth: certificate identity
// ---------------------------------------------------------------------------------------

type issued struct {
	der    []byte
	serial string
	fp     string
}

// issueFrom issues a browser certificate for user "alice", the kind forward-auth accepts.
func issueFrom(t *testing.T, ca *crypto.FileDeviceCA, deviceID string, validity time.Duration) issued {
	t.Helper()
	return issueFor(t, ca, deviceID, crypto.CertPurposeBrowser, "alice", validity)
}

// issueFor issues a certificate of the given purpose (and user, for a browser certificate).
func issueFor(t *testing.T, ca *crypto.FileDeviceCA, deviceID, purpose, user string, validity time.Duration) issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	ic, err := ca.IssueWithOptions(csr, crypto.IssueOptions{DeviceID: deviceID, Purpose: purpose, User: user, Validity: validity})
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pemDecode(ic.CertPEM)
	return issued{der: blk, serial: ic.Serial, fp: ic.FingerprintSHA256}
}

func newTestCA(t *testing.T) *crypto.FileDeviceCA {
	t.Helper()
	dir := t.TempDir()
	ca, err := crypto.NewFileDeviceCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func (e *apiEnv) register(d *types.Device, c issued) {
	if _, err := e.repo.StoreDeviceCertificateFor(context.Background(), d.ID, types.CertPurposeBrowser, "alice", c.serial, c.fp, time.Now().Add(-time.Minute), time.Now().Add(time.Hour)); err != nil {
		e.t.Fatal(err)
	}
}

func traefikCert(c issued) string { return url.QueryEscape(base64.StdEncoding.EncodeToString(c.der)) }
func nginxCert(c issued) string {
	return strings.ReplaceAll(url.QueryEscape(string(pemEncode(c.der))), "+", "%20")
}

func TestForwardAuth_CertificateIdentity(t *testing.T) {
	e := newAPIEnv(t)
	ca := newTestCA(t)
	e.repo.SetDeviceCA(ca)
	t.Cleanup(func() { e.repo.SetDeviceCA(nil) })
	tok := connectorSA(e)
	const hdr = "X-Forwarded-Tls-Client-Cert"

	d := e.mkApproved()
	e.setPosture(d, types.PostureCompliant, time.Hour)
	good := issueFrom(t, ca, d.ID, time.Hour)
	e.register(d, good)

	// Certificate headers are ignored unless an admin names one.
	e.accessCfg(testProxyAddr, false, db.IPHeaderXForwardedFor, "")
	wantStatus(t, e.forward(fwd{token: tok, hdrs: map[string]string{hdr: traefikCert(good)}}), 403, "certificate header not configured")

	e.accessCfg(testProxyAddr, false, db.IPHeaderXForwardedFor, hdr)
	rec := e.forward(fwd{token: tok, hdrs: map[string]string{hdr: traefikCert(good)}})
	wantStatus(t, rec, 200, "valid certificate, Traefik encoding")
	if rec.Header().Get("X-Spire-Identity-Strength") != "strong" || rec.Header().Get("X-Spire-Device-Id") != d.ID {
		t.Errorf("headers: %v", rec.Header())
	}
	wantStatus(t, e.forward(fwd{token: tok, hdrs: map[string]string{hdr: nginxCert(good)}}), 200, "valid certificate, nginx encoding")
	wantStatus(t, e.forward(fwd{token: tok, hdrs: map[string]string{hdr: base64.StdEncoding.EncodeToString(good.der)}}), 200, "valid certificate, plain base64 (Caddy)")

	// Only a trusted proxy can vouch for a certificate.
	wantStatus(t, e.forward(fwd{token: tok, peer: "198.51.100.9", hdrs: map[string]string{hdr: traefikCert(good)}}), 403, "certificate from an untrusted peer")

	// A failing certificate never falls back to the address identity, even when that would pass.
	e.accessCfg(testProxyAddr, true, db.IPHeaderXForwardedFor, hdr)
	ip := e.freshIP()
	ipDev := e.mkApproved()
	e.seenAt(ipDev, ip)
	e.setPosture(ipDev, types.PostureCompliant, time.Hour)
	wantStatus(t, e.forward(fwd{token: tok, xff: ip}), 200, "address identity alone works")
	wantStatus(t, e.forward(fwd{token: tok, xff: ip, hdrs: map[string]string{hdr: "garbage"}}), 403, "garbage certificate does not fall back to the address")

	for name, h := range map[string]string{
		"empty-ish":      "%20",
		"not base64":     "!!!!",
		"base64 not DER": base64.StdEncoding.EncodeToString([]byte("hello")),
		"oversized":      strings.Repeat("A", 20000),
	} {
		wantStatus(t, e.forward(fwd{token: tok, xff: ip, hdrs: map[string]string{hdr: h}}), 403, "bad certificate: "+name)
	}

	// Certificate from a different CA with the right device id.
	foreign := issueFrom(t, newTestCA(t), d.ID, time.Hour)
	e.register(d, foreign)
	wantStatus(t, e.forward(fwd{token: tok, xff: ip, hdrs: map[string]string{hdr: traefikCert(foreign)}}), 403, "certificate from another CA")

	// Expired certificate.
	short := issueFrom(t, ca, d.ID, time.Second)
	e.register(d, short)
	time.Sleep(1500 * time.Millisecond)
	wantStatus(t, e.forward(fwd{token: tok, xff: ip, hdrs: map[string]string{hdr: traefikCert(short)}}), 403, "expired certificate")

	// A genuine device-CA certificate nobody registered.
	unregistered := issueFrom(t, ca, d.ID, time.Hour)
	wantStatus(t, e.forward(fwd{token: tok, xff: ip, hdrs: map[string]string{hdr: traefikCert(unregistered)}}), 403, "certificate not in the database")

	// Revoked certificate.
	if _, err := e.repo.RevokeDeviceCertificates(context.Background(), d.ID); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, e.forward(fwd{token: tok, xff: ip, hdrs: map[string]string{hdr: traefikCert(good)}}), 403, "revoked certificate")

	// A certificate that names another device than the one registered for its serial.
	e2 := e.mkApproved()
	e.setPosture(e2, types.PostureCompliant, time.Hour)
	mismatch := issueFrom(t, ca, e2.ID, time.Hour)
	e.register(d, mismatch) // serial registered to d, SAN says e2
	wantStatus(t, e.forward(fwd{token: tok, xff: ip, hdrs: map[string]string{hdr: traefikCert(mismatch)}}), 403, "SAN device id differs from the registered device")

	// Valid certificate, device not compliant.
	nc := e.mkApproved()
	e.setPosture(nc, types.PostureQuarantined, time.Hour)
	ncCert := issueFrom(t, ca, nc.ID, time.Hour)
	e.register(nc, ncCert)
	wantStatus(t, e.forward(fwd{token: tok, xff: ip, hdrs: map[string]string{hdr: traefikCert(ncCert)}}), 403, "valid certificate, quarantined device")

	// No device CA loaded: any certificate is refused.
	e.repo.SetDeviceCA(nil)
	wantStatus(t, e.forward(fwd{token: tok, xff: ip, hdrs: map[string]string{hdr: traefikCert(good)}}), 403, "no device CA configured")
}

func TestForwardAuth_TwoCertificateHeadersDeny(t *testing.T) {
	e := newAPIEnv(t)
	ca := newTestCA(t)
	e.repo.SetDeviceCA(ca)
	t.Cleanup(func() { e.repo.SetDeviceCA(nil) })
	tok := connectorSA(e)
	e.accessCfg(testProxyAddr, false, db.IPHeaderXForwardedFor, "X-Forwarded-Tls-Client-Cert")
	d := e.mkApproved()
	e.setPosture(d, types.PostureCompliant, time.Hour)
	c := issueFrom(t, ca, d.ID, time.Hour)
	e.register(d, c)

	req := httptest.NewRequest(http.MethodGet, apiBase+"/access/forward-auth", nil)
	req.RemoteAddr = testProxyAddr + ":1"
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Add("X-Forwarded-Tls-Client-Cert", traefikCert(c))
	req.Header.Add("X-Forwarded-Tls-Client-Cert", traefikCert(c))
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	wantStatus(t, rec, 403, "two certificate headers")
}

// ---------------------------------------------------------------------------------------
// backend failures deny
// ---------------------------------------------------------------------------------------

// newBrokenEnv returns an environment on a private database whose tables the test can break
// without disturbing other tests.
func newBrokenEnv(t *testing.T) (*apiEnv, *pgxpool.Pool) {
	t.Helper()
	base := os.Getenv("SPIRE_TEST_DB_URL")
	if base == "" {
		t.Skip("SPIRE_TEST_DB_URL not set")
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Skipf("cannot connect: %v", err)
	}
	name := fmt.Sprintf("ca2_broken_%d", time.Now().UnixNano()%1e12)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close()
		t.Skipf("cannot create private database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		admin.Close()
	})
	u.Path = "/" + name
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := db.RunMigrations(ctx, pool, "../../migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	repo := db.NewRepository(pool)
	h, err := web.NewHandler(repo, nil, audit.NewForwarder(repo, ""))
	if err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	h.RegisterRoutes(r, "admin", "adminpw")
	return &apiEnv{t: t, pool: pool, repo: repo, router: r, sfx: fmt.Sprintf("%d", time.Now().UnixNano()%1e12)}, pool
}

func TestForwardAuth_BackendFailuresDeny(t *testing.T) {
	e, pool := newBrokenEnv(t)
	tok := connectorSA(e)
	e.accessCfg(testProxyAddr, true, db.IPHeaderXForwardedFor, "")
	ip := e.freshIP()
	d := e.mkApproved()
	e.seenAt(d, ip)
	e.setPosture(d, types.PostureCompliant, time.Hour)
	wantStatus(t, e.forward(fwd{token: tok, xff: ip}), 200, "baseline allow")

	ctx := context.Background()
	deny := func(what string) {
		t.Helper()
		rec := e.forward(fwd{token: tok, xff: ip})
		if rec.Code < 400 {
			t.Errorf("%s: backend failure must not allow, got %d", what, rec.Code)
		}
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: got %d, want 503", what, rec.Code)
		}
	}
	exec := func(q string) {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}

	exec(`ALTER TABLE device_posture RENAME TO device_posture_x`)
	deny("posture read fails")
	exec(`ALTER TABLE device_posture_x RENAME TO device_posture`)
	wantStatus(t, e.forward(fwd{token: tok, xff: ip}), 200, "recovered")

	exec(`ALTER TABLE system_settings RENAME TO system_settings_x`)
	deny("settings read fails")
	exec(`ALTER TABLE system_settings_x RENAME TO system_settings`)

	exec(`ALTER TABLE device_certificates RENAME TO device_certificates_x`)
	e.accessCfg(testProxyAddr, true, db.IPHeaderXForwardedFor, "")
	// address identity does not touch device_certificates, so this must still allow
	wantStatus(t, e.forward(fwd{token: tok, xff: ip}), 200, "unrelated table down")
	exec(`ALTER TABLE device_certificates_x RENAME TO device_certificates`)

	exec(`ALTER TABLE devices RENAME COLUMN last_seen_ip TO last_seen_ip_x`)
	deny("identity resolution fails")
	exec(`ALTER TABLE devices RENAME COLUMN last_seen_ip_x TO last_seen_ip`)

	// The lookup API surfaces the same failure as a 500, never as an allow.
	exec(`ALTER TABLE device_posture RENAME TO device_posture_x`)
	r := e.call("GET", apiBase+"/posture/lookup?ip="+ip, tok)
	if r.Code != 500 {
		t.Errorf("lookup with posture down: %d, want 500", r.Code)
	}
	exec(`ALTER TABLE device_posture_x RENAME TO device_posture`)
}

// ---------------------------------------------------------------------------------------
// settings page
// ---------------------------------------------------------------------------------------

func (e *apiEnv) formAdmin(method, path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	req.RemoteAddr = "192.0.2.20:4000"
	req.SetBasicAuth("admin", "adminpw")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func TestAccessProxySettingsPage(t *testing.T) {
	e := newAPIEnv(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_ = e.repo.SaveAccessProxySettings(ctx, db.AccessProxySettings{IPHeader: db.IPHeaderXForwardedFor}, "test")
	})

	rec := e.formAdmin("GET", "/admin/access-proxy", nil)
	wantStatus(t, rec, 200, "page renders")
	if !strings.Contains(rec.Body.String(), "Access proxy (forward-auth)") {
		t.Errorf("page content missing")
	}

	wantStatus(t, e.formAdmin("POST", "/admin/access-proxy", url.Values{"trusted_proxies": {"not-an-ip"}}), 400, "bad CIDR")
	wantStatus(t, e.formAdmin("POST", "/admin/access-proxy", url.Values{"trusted_proxies": {"0.0.0.0/0"}}), 400, "/0 trusts everything")
	wantStatus(t, e.formAdmin("POST", "/admin/access-proxy", url.Values{"trusted_proxies": {"::/0"}}), 400, "::/0 trusts everything")
	wantStatus(t, e.formAdmin("POST", "/admin/access-proxy", url.Values{"cert_header": {"bad header!"}}), 400, "bad header name")

	rec = e.formAdmin("POST", "/admin/access-proxy", url.Values{
		"trusted_proxies": {"10.1.2.3\n172.16.0.0/12, ::ffff:10.9.9.9"}, "ip_header": {"x-real-ip"},
		"cert_header": {"X-Forwarded-Tls-Client-Cert"}, "allow_weak_identity": {"on"}})
	wantStatus(t, rec, 303, "save")
	cfg, err := e.repo.GetAccessProxySettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AllowWeakIdentity || cfg.IPHeader != db.IPHeaderXRealIP || cfg.CertHeader != "X-Forwarded-Tls-Client-Cert" || len(cfg.TrustedProxies) != 3 {
		t.Errorf("saved settings: %+v", cfg)
	}
	for _, a := range []string{"10.1.2.3", "172.31.255.255", "10.9.9.9"} {
		if !cfg.IsTrustedProxy(netip.MustParseAddr(a)) {
			t.Errorf("%s should be trusted", a)
		}
	}
	if cfg.IsTrustedProxy(netip.MustParseAddr("172.32.0.1")) || cfg.IsTrustedProxy(netip.MustParseAddr("10.1.2.4")) {
		t.Errorf("trusted ranges too wide")
	}
	// The change is audited with before and after values.
	var n int
	if err := e.pool.QueryRow(ctx, `SELECT COUNT(*) FROM system_audit_events WHERE action = 'ACCESS_PROXY_SETTINGS_CHANGE' AND details::text LIKE '%allow_weak_identity_after%true%'`).Scan(&n); err != nil || n == 0 {
		t.Errorf("settings change not audited (n=%d err=%v)", n, err)
	}
}

// A tag-scoped SECURITY_ADMIN must not change fleet-wide access settings, and an AUDITOR or
// OPERATOR must not reach the page at all.
func TestAccessProxySettingsPage_Roles(t *testing.T) {
	e := newAPIEnv(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_ = e.repo.SaveAccessProxySettings(ctx, db.AccessProxySettings{IPHeader: db.IPHeaderXForwardedFor}, "test")
	})
	pat := func(role types.AdminRole, tags []string) string {
		u, err := e.repo.CreateLocalAdminUser(ctx, types.CreateUserRequest{Username: e.uniq("ap"), Email: e.uniq("m") + "@example.test", Password: "correct-horse-battery", Role: role, AllowedTags: tags})
		if err != nil {
			t.Fatal(err)
		}
		raw, hash, prefix, err := web.GeneratePAT()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.repo.CreatePersonalAccessToken(ctx, hash, prefix, "p", u.ID, role, u.Username, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		return raw
	}
	post := func(tok string) int {
		req := httptest.NewRequest("POST", "/admin/access-proxy", strings.NewReader(url.Values{"allow_weak_identity": {"on"}, "trusted_proxies": {"10.0.0.1"}}.Encode()))
		req.RemoteAddr = "192.0.2.21:1"
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		e.router.ServeHTTP(rec, req)
		return rec.Code
	}
	if c := post(pat(types.RoleSecurityAdmin, []string{"some-team"})); c != http.StatusForbidden {
		t.Errorf("tag-scoped SECURITY_ADMIN: %d, want 403", c)
	}
	if c := post(pat(types.RoleAuditor, nil)); c != http.StatusForbidden {
		t.Errorf("AUDITOR: %d, want 403", c)
	}
	if c := post(pat(types.RoleOperator, nil)); c != http.StatusForbidden {
		t.Errorf("OPERATOR: %d, want 403", c)
	}
	if cfg, _ := e.repo.GetAccessProxySettings(ctx); cfg.AllowWeakIdentity {
		t.Errorf("a forbidden request changed the settings")
	}
	if c := post(pat(types.RoleSecurityAdmin, nil)); c != http.StatusSeeOther {
		t.Errorf("unscoped SECURITY_ADMIN: %d, want 303", c)
	}
}

func TestParseTrustedProxyList(t *testing.T) {
	got, err := db.ParseTrustedProxyList("10.0.0.1, 192.168.0.0/16\n2001:db8::/32;::ffff:1.2.3.4")
	if err != nil || len(got) != 4 {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"10.0.0.256", "10.0.0.0/33", "host.example", "10.0.0.1/abc"} {
		if _, err := db.ParseTrustedProxyList(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	if got, err := db.ParseTrustedProxyList("  "); err != nil || len(got) != 0 {
		t.Errorf("blank list: %v %v", got, err)
	}
}

// ---------------------------------------------------------------------------------------
// latency of the hot path (forward-auth is called on every proxied request)
// ---------------------------------------------------------------------------------------

func TestForwardAuth_Latency(t *testing.T) {
	e := newAPIEnv(t)
	tok := connectorSA(e)
	e.accessCfg(testProxyAddr, true, db.IPHeaderXForwardedFor, "")
	ip := e.freshIP()
	d := e.mkApproved()
	e.seenAt(d, ip)
	e.setPosture(d, types.PostureCompliant, time.Hour)
	wantStatus(t, e.forward(fwd{token: tok, xff: ip}), 200, "warm up")
	const n = 200
	start := time.Now()
	for i := 0; i < n; i++ {
		if rec := e.forward(fwd{token: tok, xff: ip}); rec.Code != 200 {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	per := time.Since(start) / n
	t.Logf("forward-auth: %v per request (sequential, local Postgres)", per)
	if per > 50*time.Millisecond {
		t.Errorf("forward-auth too slow without a cache: %v per request", per)
	}
}

func pemDecode(b []byte) ([]byte, []byte) {
	blk, rest := pem.Decode(b)
	if blk == nil {
		return nil, rest
	}
	return blk.Bytes, rest
}

func pemEncode(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
