package web_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/spire-uem/spire-uem/internal/audit"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/radius"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/web"
)

const radiusAuthz = "/api/admin/v1/access/radius/authorize"

type radEnv struct {
	t      *testing.T
	pool   *pgxpool.Pool
	repo   *db.Repository
	router chi.Router
	sfx    string
	seq    int
}

func newRadEnv(t *testing.T) *radEnv {
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
	h.RegisterRoutes(r, "admin", "adminpw")
	e := &radEnv{t: t, pool: pool, repo: repo, router: r, sfx: fmt.Sprintf("%d", time.Now().UnixNano()%1e12)}
	// The settings row is a singleton shared by the whole test database: start and end clean.
	e.resetSettings()
	t.Cleanup(e.resetSettings)
	return e
}

func (e *radEnv) resetSettings() {
	_, _ = e.pool.Exec(context.Background(), `UPDATE radius_settings SET compliant_vlan='', quarantine_vlan='',
		remediation_vlan='', guest_vlan='', guest_enabled=FALSE, allow_weak_identity=FALSE WHERE id=1`)
}

func (e *radEnv) uniq(p string) string { e.seq++; return fmt.Sprintf("%s-%s-%d", p, e.sfx, e.seq) }

func (e *radEnv) exec(q string, args ...any) {
	e.t.Helper()
	if _, err := e.pool.Exec(context.Background(), q, args...); err != nil {
		e.t.Fatalf("exec: %v", err)
	}
}

func (e *radEnv) setSettings(s radius.Settings) {
	e.t.Helper()
	e.exec(`UPDATE radius_settings SET compliant_vlan=$1, quarantine_vlan=$2, remediation_vlan=$3,
		guest_vlan=$4, guest_enabled=$5, allow_weak_identity=$6 WHERE id=1`,
		s.CompliantVLAN, s.QuarantineVLAN, s.RemediationVLAN, s.GuestVLAN, s.GuestEnabled, s.AllowWeakIdentity)
}

// device creates an approved device with a unique MAC, a device-CA certificate (serial hex
// returned too) and the given posture.
type radDev struct {
	d      *types.Device
	mac    string
	serial string // decimal, as stored
	hex    string // as FreeRADIUS reports it
}

func (e *radEnv) device(state types.PostureState, tags ...string) radDev {
	e.t.Helper()
	ctx := context.Background()
	hw := e.uniq("hw")
	d, _, err := e.repo.GetOrCreateDevice(ctx, hw, hw)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, _, err := e.repo.ApproveDevice(ctx, d.ID); err != nil {
		e.t.Fatal(err)
	}
	if len(tags) > 0 {
		if d, err = e.repo.UpdateDeviceTags(ctx, d.ID, tags); err != nil {
			e.t.Fatal(err)
		}
	}
	n := rand.Int63n(1<<40) + 1<<20
	mac := fmt.Sprintf("02:%02x:%02x:%02x:%02x:%02x", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
	serialHex := fmt.Sprintf("%x", n)
	e.exec(`INSERT INTO device_attributes (device_id, key, value_type, value, source)
		VALUES ($1,'net.primary_mac','string',to_jsonb($2::text),'inventory')`, d.ID, mac)
	e.exec(`INSERT INTO device_certificates (device_id, serial, fingerprint_sha256, purpose, not_before, not_after)
		VALUES ($1,$2,$3,'network',NOW()-interval '1 hour',NOW()+interval '1 day')`, d.ID, fmt.Sprint(n), fmt.Sprintf("%064x", n))
	if state != "" {
		e.posture(d.ID, state, time.Hour)
	}
	return radDev{d: d, mac: mac, serial: fmt.Sprint(n), hex: serialHex}
}

func (e *radEnv) posture(id string, st types.PostureState, validFor time.Duration) {
	e.t.Helper()
	now := time.Now().UTC()
	if _, err := e.repo.UpsertDevicePosture(context.Background(), &types.DevicePosture{
		DeviceID: id, State: st, EvaluatedAt: now, ValidUntil: now.Add(validFor)}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *radEnv) sa(role types.AdminRole, tags []string, scopes ...string) string {
	e.t.Helper()
	raw, tid, hash, err := web.GenerateServiceAccountToken()
	if err != nil {
		e.t.Fatal(err)
	}
	if _, _, err := e.repo.CreateServiceAccount(context.Background(), &types.ServiceAccount{
		Name: e.uniq("rad"), Role: role, AllowedTags: tags, Scopes: scopes, Enabled: true, CreatedBy: "test"}, tid, hash, "t"); err != nil {
		e.t.Fatal(err)
	}
	return raw
}

func (e *radEnv) postureToken() string { return e.sa(types.RoleAuditor, nil, types.ScopePostureRead) }

// restBody builds a body exactly as FreeRADIUS 3.2 rlm_rest sends it.
func restBody(attrs map[string]string) string {
	m := map[string]any{}
	for k, v := range attrs {
		m[k] = map[string]any{"type": "string", "value": []string{v}}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func (e *radEnv) authz(token string, attrs map[string]string) *httptest.ResponseRecorder {
	return e.raw(token, restBody(attrs))
}

func (e *radEnv) raw(token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, radiusAuthz, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.10:4000"
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func (e *radEnv) basic(method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.20:4000"
	req.SetBasicAuth("admin", "adminpw")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func accepted(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("want accept (200), got %d %s", rec.Code, rec.Body)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("accept body: %v", err)
	}
	if m["control:Tmp-String-0"] != radius.AcceptMarker {
		t.Fatalf("accept without the marker: %v", m)
	}
	return m
}

func rejected(t *testing.T, name string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), radius.AcceptMarker) {
		t.Fatalf("%s: must not accept, got %d %s", name, rec.Code, rec.Body)
	}
}

// ---------------------------------------------------------------------------------------

func TestRadiusAuthorize_Auth_Matrix(t *testing.T) {
	e := newRadEnv(t)
	dev := e.device(types.PostureCompliant)
	attrs := map[string]string{"TLS-Client-Cert-Serial": dev.hex}
	if rec := e.authz("", attrs); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no credential: %d", rec.Code)
	}
	if rec := e.authz("spire_sa_deadbeefdeadbeef_"+strings.Repeat("0", 64), attrs); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", rec.Code)
	}
	// A session cookie alone is not a credential on this API.
	cookie, _, err := web.IssueSession(context.Background(), e.repo, "admin", false)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, radiusAuthz, strings.NewReader(restBody(attrs)))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("cookie only: %d", rec.Code)
	}
	// Right credential type, wrong scope: every other scope together is still refused.
	other := []string{}
	for _, s := range types.AllAPIScopes {
		if s != types.ScopePostureRead {
			other = append(other, s)
		}
	}
	rec = e.authz(e.sa(types.RoleSuperAdmin, nil, other...), attrs)
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), radius.AcceptMarker) {
		t.Fatalf("missing posture:read: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "insufficient_scope") {
		t.Fatalf("expected the scope error, got %s", rec.Body)
	}
	// With the scope it works.
	accepted(t, e.authz(e.postureToken(), attrs))
	// GET is not allowed.
	g := httptest.NewRequest(http.MethodGet, radiusAuthz, nil)
	g.Header.Set("Authorization", "Bearer "+e.postureToken())
	gr := httptest.NewRecorder()
	e.router.ServeHTTP(gr, g)
	if gr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", gr.Code)
	}
}

func TestRadiusAuthorize_CertificateIdentity_StrongAndMapped(t *testing.T) {
	e := newRadEnv(t)
	tok := e.postureToken()
	dev := e.device(types.PostureCompliant)

	m := accepted(t, e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": strings.ToUpper(dev.hex), "User-Name": "host/x"}))
	if _, ok := m["reply:Tunnel-Private-Group-Id:0"]; ok {
		t.Fatalf("no compliant VLAN configured, none expected: %v", m)
	}
	if m["control:Tmp-String-1"] != "strong" {
		t.Fatalf("identity strength: %v", m)
	}
	// Mapping.
	e.setSettings(radius.Settings{CompliantVLAN: "10", QuarantineVLAN: "666", RemediationVLAN: "20"})
	m = accepted(t, e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": dev.hex}))
	if m["reply:Tunnel-Private-Group-Id:0"] != "10" || m["reply:Tunnel-Type:0"] != "VLAN" || m["reply:Tunnel-Medium-Type:0"] != "IEEE-802" {
		t.Fatalf("compliant VLAN attrs: %v", m)
	}
	e.posture(dev.d.ID, types.PostureNoncompliant, time.Hour)
	m = accepted(t, e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": dev.hex}))
	if m["reply:Tunnel-Private-Group-Id:0"] != "20" {
		t.Fatalf("remediation VLAN: %v", m)
	}
	e.posture(dev.d.ID, types.PostureQuarantined, time.Hour)
	m = accepted(t, e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": dev.hex}))
	if m["reply:Tunnel-Private-Group-Id:0"] != "666" {
		t.Fatalf("quarantine VLAN: %v", m)
	}
	// Without those VLANs the same states are rejected.
	e.setSettings(radius.Settings{CompliantVLAN: "10"})
	rejected(t, "quarantined, no VLAN", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": dev.hex}))
	e.posture(dev.d.ID, types.PostureNoncompliant, time.Hour)
	rejected(t, "noncompliant, no VLAN", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": dev.hex}))
}

func TestRadiusAuthorize_FailClosed_UnknownStaleAndErrors(t *testing.T) {
	e := newRadEnv(t)
	tok := e.postureToken()
	e.setSettings(radius.Settings{CompliantVLAN: "10", QuarantineVLAN: "666", RemediationVLAN: "20"})

	never := e.device("") // no posture row
	rejected(t, "never evaluated", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": never.hex}))

	stale := e.device(types.PostureCompliant)
	e.posture(stale.d.ID, types.PostureCompliant, -time.Minute) // past valid_until
	rejected(t, "stale COMPLIANT", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": stale.hex}))

	unk := e.device(types.PostureUnknown)
	rejected(t, "explicit UNKNOWN", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": unk.hex}))

	// A lookup error must not turn into an accept: corrupt the stored verdict so reading it fails.
	bad := e.device(types.PostureCompliant)
	e.exec(`UPDATE device_posture SET reasons = '"not-an-array"'::jsonb WHERE device_id=$1`, bad.d.ID)
	rec := e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": bad.hex})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("posture read error must be a 5xx (rlm_rest: fail), got %d %s", rec.Code, rec.Body)
	}
	rejected(t, "posture read error", rec)
	// Leave no unreadable row behind in the shared test database.
	e.exec(`UPDATE device_posture SET reasons = '[]'::jsonb WHERE device_id=$1`, bad.d.ID)

	// Revoked and expired certificates, unparseable input, malformed bodies.
	rev := e.device(types.PostureCompliant)
	e.exec(`UPDATE device_certificates SET revoked_at = NOW() WHERE device_id=$1`, rev.d.ID)
	rejected(t, "revoked certificate", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": rev.hex}))
	exp := e.device(types.PostureCompliant)
	e.exec(`UPDATE device_certificates SET not_after = NOW() - interval '1 minute' WHERE device_id=$1`, exp.d.ID)
	rejected(t, "expired certificate", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": exp.hex}))
	rejected(t, "non-hex serial", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": "not-hex!"}))
	rejected(t, "unknown serial", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": "fffffffffffffff1"}))
	for name, body := range map[string]string{"empty": "", "not json": "x", "array": "[]", "no attrs": "{}",
		"conflicting": `{"TLS-Client-Cert-Serial":{"value":["` + stale.hex + `","` + unk.hex + `"]}}`} {
		rejected(t, name, e.raw(tok, body))
	}
	// Control: the healthy device is accepted, so the rejections above are about the input.
	ok := e.device(types.PostureCompliant)
	accepted(t, e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": ok.hex}))
}

func TestRadiusAuthorize_CertificateNeverFallsBackToMAC(t *testing.T) {
	e := newRadEnv(t)
	tok := e.postureToken()
	e.setSettings(radius.Settings{AllowWeakIdentity: true})
	good := e.device(types.PostureCompliant)
	// A presented certificate that names nobody is rejected even though the MAC alongside it
	// belongs to a compliant device.
	rejected(t, "unknown cert + good MAC", e.authz(tok, map[string]string{
		"TLS-Client-Cert-Serial": "fffffffffffffff2", "Calling-Station-Id": good.mac}))
	// Revoked cert of the same device + its own good MAC.
	e.exec(`UPDATE device_certificates SET revoked_at = NOW() WHERE device_id=$1`, good.d.ID)
	rejected(t, "revoked cert + own MAC", e.authz(tok, map[string]string{
		"TLS-Client-Cert-Serial": good.hex, "Calling-Station-Id": good.mac}))
	// Serial and fingerprint that name different devices.
	a, b := e.device(types.PostureCompliant), e.device(types.PostureCompliant)
	rejected(t, "serial/fingerprint disagree", e.authz(tok, map[string]string{
		"TLS-Client-Cert-Serial": a.hex, "TLS-Client-Cert-Fingerprint": fmt.Sprintf("%064s", b.hex)}))
	accepted(t, e.authz(tok, map[string]string{
		"TLS-Client-Cert-Serial": a.hex, "TLS-Client-Cert-Fingerprint": fmt.Sprintf("%064s", a.hex)}))
}

func TestRadiusAuthorize_WeakIdentity_OffByDefaultAndLabelled(t *testing.T) {
	e := newRadEnv(t)
	tok := e.postureToken()
	dev := e.device(types.PostureCompliant)
	mab := map[string]string{"User-Name": strings.ReplaceAll(dev.mac, ":", "-"), "Calling-Station-Id": strings.ToUpper(strings.ReplaceAll(dev.mac, ":", "-"))}

	rec := e.authz(tok, mab)
	rejected(t, "weak identity disabled", rec)
	if rec.Header().Get("X-Spire-Identity-Strength") != "weak" {
		t.Fatalf("a weak-identity answer must say so: %v", rec.Header())
	}

	e.setSettings(radius.Settings{AllowWeakIdentity: true, CompliantVLAN: "10"})
	rec = e.authz(tok, mab)
	m := accepted(t, rec)
	if m["control:Tmp-String-1"] != "weak" || rec.Header().Get("X-Spire-Identity-Strength") != "weak" {
		t.Fatalf("weak label missing: %v %v", m, rec.Header())
	}
	// MAC notations and a User-Name MAC that disagrees with Calling-Station-Id.
	accepted(t, e.authz(tok, map[string]string{"Calling-Station-Id": strings.ReplaceAll(dev.mac, ":", "")}))
	rejected(t, "User-Name MAC differs", e.authz(tok, map[string]string{"User-Name": "02-00-00-00-00-01", "Calling-Station-Id": dev.mac}))
	rejected(t, "no MAC at all", e.authz(tok, map[string]string{"User-Name": "alice"}))
	rejected(t, "garbage MAC", e.authz(tok, map[string]string{"Calling-Station-Id": "not-a-mac"}))
	rejected(t, "unknown MAC", e.authz(tok, map[string]string{"Calling-Station-Id": "02:de:ad:be:ef:01"}))
}

func TestRadiusAuthorize_AmbiguousMAC_Rejected(t *testing.T) {
	e := newRadEnv(t)
	tok := e.postureToken()
	e.setSettings(radius.Settings{AllowWeakIdentity: true, GuestVLAN: "30", GuestEnabled: true})
	a, b := e.device(types.PostureCompliant), e.device(types.PostureCompliant)
	e.exec(`UPDATE device_attributes SET value = to_jsonb($2::text) WHERE device_id=$1 AND key='net.primary_mac'`, b.d.ID, a.mac)
	// One is compliant and the other too: still ambiguous. Guest must not apply either.
	rec := e.authz(tok, map[string]string{"Calling-Station-Id": a.mac})
	rejected(t, "ambiguous MAC", rec)
	// Disambiguate: control accepts.
	e.exec(`UPDATE device_attributes SET value = to_jsonb($2::text) WHERE device_id=$1 AND key='net.primary_mac'`, b.d.ID, b.mac)
	accepted(t, e.authz(tok, map[string]string{"Calling-Station-Id": a.mac}))
}

func TestRadiusAuthorize_GuestVLAN_OnlyWhenEnabled_AndOnlyForUnknown(t *testing.T) {
	e := newRadEnv(t)
	tok := e.postureToken()
	unknownMAC := map[string]string{"Calling-Station-Id": "02:ca:fe:00:00:" + fmt.Sprintf("%02x", rand.Intn(256))}
	e.setSettings(radius.Settings{AllowWeakIdentity: true, GuestVLAN: "30"}) // configured, not enabled
	rejected(t, "guest configured but off", e.authz(tok, unknownMAC))

	e.setSettings(radius.Settings{AllowWeakIdentity: true, GuestVLAN: "30", GuestEnabled: true})
	m := accepted(t, e.authz(tok, unknownMAC))
	if m["reply:Tunnel-Private-Group-Id:0"] != "30" {
		t.Fatalf("guest VLAN: %v", m)
	}
	unk := e.device(types.PostureUnknown)
	m = accepted(t, e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": unk.hex}))
	if m["reply:Tunnel-Private-Group-Id:0"] != "30" {
		t.Fatalf("UNKNOWN posture -> guest: %v", m)
	}
	// Guest never covers: unknown certificate, malformed input, a NONCOMPLIANT/QUARANTINED device.
	rejected(t, "unknown certificate", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": "fffffffffffffff3"}))
	rejected(t, "bad body", e.raw(tok, "nope"))
	bad := e.device(types.PostureNoncompliant)
	rejected(t, "noncompliant -> not guest", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": bad.hex}))
	q := e.device(types.PostureQuarantined)
	rejected(t, "quarantined -> not guest", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": q.hex}))
	// Weak identity disabled beats guest.
	e.setSettings(radius.Settings{GuestVLAN: "30", GuestEnabled: true})
	rejected(t, "weak disabled, guest on", e.authz(tok, unknownMAC))
}

func TestRadiusAuthorize_TagScopedAccount_OutOfScopeLooksUnknown(t *testing.T) {
	e := newRadEnv(t)
	team := "team-" + e.sfx
	inScope := e.device(types.PostureCompliant, team)
	outScope := e.device(types.PostureCompliant, "other-"+e.sfx)
	scoped := e.sa(types.RoleAuditor, []string{team}, types.ScopePostureRead)
	unscoped := e.postureToken()

	accepted(t, e.authz(scoped, map[string]string{"TLS-Client-Cert-Serial": inScope.hex}))
	accepted(t, e.authz(unscoped, map[string]string{"TLS-Client-Cert-Serial": outScope.hex}))

	// The out-of-scope device and a device that does not exist get byte-identical answers.
	rOut := e.authz(scoped, map[string]string{"TLS-Client-Cert-Serial": outScope.hex})
	rNone := e.authz(scoped, map[string]string{"TLS-Client-Cert-Serial": "fffffffffffffff4"})
	rejected(t, "out of scope", rOut)
	if rOut.Code != rNone.Code || rOut.Body.String() != rNone.Body.String() ||
		rOut.Header().Get("X-Spire-Identity-Strength") != rNone.Header().Get("X-Spire-Identity-Strength") {
		t.Fatalf("existence oracle: out-of-scope %d %q vs unknown %d %q", rOut.Code, rOut.Body, rNone.Code, rNone.Body)
	}
	// Same for MAB, including with the guest VLAN on (both fall to the same verdict).
	e.setSettings(radius.Settings{AllowWeakIdentity: true})
	mOut := e.authz(scoped, map[string]string{"Calling-Station-Id": outScope.mac})
	mNone := e.authz(scoped, map[string]string{"Calling-Station-Id": "02:ba:ad:00:00:01"})
	rejected(t, "mab out of scope", mOut)
	if mOut.Code != mNone.Code || mOut.Body.String() != mNone.Body.String() {
		t.Fatalf("MAB existence oracle: %d %q vs %d %q", mOut.Code, mOut.Body, mNone.Code, mNone.Body)
	}
	e.setSettings(radius.Settings{AllowWeakIdentity: true, GuestVLAN: "30", GuestEnabled: true})
	gOut := e.authz(scoped, map[string]string{"Calling-Station-Id": outScope.mac})
	gNone := e.authz(scoped, map[string]string{"Calling-Station-Id": "02:ba:ad:00:00:02"})
	if gOut.Code != gNone.Code || gOut.Body.String() != gNone.Body.String() {
		t.Fatalf("guest-mode oracle: %d %q vs %d %q", gOut.Code, gOut.Body, gNone.Code, gNone.Body)
	}
	// A duplicate MAC outside the scope still makes the match ambiguous for the scoped caller.
	e.setSettings(radius.Settings{AllowWeakIdentity: true})
	dup := e.device(types.PostureCompliant, "other-"+e.sfx)
	e.exec(`UPDATE device_attributes SET value = to_jsonb($2::text) WHERE device_id=$1 AND key='net.primary_mac'`, dup.d.ID, inScope.mac)
	rejected(t, "duplicate hidden by scope", e.authz(scoped, map[string]string{"Calling-Station-Id": inScope.mac}))
}

func TestRadiusAuthorize_RecordsSessionOnlyForConfiguredNAS(t *testing.T) {
	e := newRadEnv(t)
	tok := e.postureToken()
	dev := e.device(types.PostureCompliant)
	nasIP := fmt.Sprintf("10.%d.%d.%d", 100+rand.Intn(100), rand.Intn(250), 1+rand.Intn(250))
	rec := e.basic("POST", "/admin/radius/nas", `{"name":"`+e.uniq("nas")+`","address":"`+nasIP+`","secret":"a-shared-secret","enabled":true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create NAS: %d %s", rec.Code, rec.Body)
	}
	var created struct {
		NAS struct{ ID string } `json:"nas_client"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	t.Cleanup(func() {
		_, _ = e.pool.Exec(context.Background(), `DELETE FROM radius_nas_clients WHERE id=$1`, created.NAS.ID)
	})

	accepted(t, e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": dev.hex, "NAS-IP-Address": "198.51.100.77"}))
	if n, _ := e.repo.RadiusStore().CountSessions(context.Background(), dev.d.ID); n != 0 {
		t.Fatalf("unconfigured NAS must not create session rows, got %d", n)
	}
	accepted(t, e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": dev.hex, "NAS-IP-Address": nasIP, "Calling-Station-Id": dev.mac}))
	if n, _ := e.repo.RadiusStore().CountSessions(context.Background(), dev.d.ID); n != 1 {
		t.Fatalf("configured NAS: want 1 session, got %d", n)
	}
	// Rejected requests record nothing.
	e.posture(dev.d.ID, types.PostureNoncompliant, time.Hour)
	e.exec(`DELETE FROM radius_sessions WHERE device_id=$1`, dev.d.ID)
	rejected(t, "noncompliant", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": dev.hex, "NAS-IP-Address": nasIP}))
	if n, _ := e.repo.RadiusStore().CountSessions(context.Background(), dev.d.ID); n != 0 {
		t.Fatalf("a rejected request must not record a session, got %d", n)
	}
}

// ---------------------------------------------------------------------------------------
// Admin page and settings
// ---------------------------------------------------------------------------------------

func (e *radEnv) user(role types.AdminRole, tags ...string) string {
	e.t.Helper()
	name := e.uniq("radu-" + strings.ToLower(string(role)))
	if _, err := e.repo.CreateLocalAdminUser(context.Background(), types.CreateUserRequest{
		Username: name, Email: name + "@x.test", Password: "Passw0rd-xyz-123", Role: role, AllowedTags: tags}); err != nil {
		e.t.Fatal(err)
	}
	return name
}

func (e *radEnv) as(user, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.30:4000"
	req.SetBasicAuth(user, "Passw0rd-xyz-123")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func TestRadiusAdmin_RBAC_AuditorReadsNeverWrites(t *testing.T) {
	e := newRadEnv(t)
	aud := e.user(types.RoleAuditor)
	op := e.user(types.RoleOperator)
	sec := e.user(types.RoleSecurityAdmin)
	scoped := e.user(types.RoleSecurityAdmin, "only-"+e.sfx)
	settings := `{"compliant_vlan":"10"}`
	nas := `{"name":"x","address":"10.1.2.3","secret":"longsecret1"}`
	for _, u := range []string{aud, op} {
		if rec := e.as(u, "GET", "/admin/radius", ""); rec.Code != http.StatusOK {
			t.Errorf("%s GET: %d", u, rec.Code)
		}
		for _, rt := range [][2]string{{"/admin/radius/settings", settings}, {"/admin/radius/nas", nas},
			{"/admin/radius/nas/" + "00000000-0000-0000-0000-000000000000", nas}, {"/admin/radius/nas/00000000-0000-0000-0000-000000000000/delete", ""}} {
			if rec := e.as(u, "POST", rt[0], rt[1]); rec.Code != http.StatusForbidden {
				t.Errorf("%s POST %s: %d, want 403", u, rt[0], rec.Code)
			}
		}
	}
	// A tag-scoped SECURITY_ADMIN may read but not change global access policy.
	if rec := e.as(scoped, "GET", "/admin/radius", ""); rec.Code != http.StatusOK {
		t.Errorf("scoped GET: %d", rec.Code)
	}
	for _, rt := range [][2]string{{"/admin/radius/settings", settings}, {"/admin/radius/nas", nas}} {
		if rec := e.as(scoped, "POST", rt[0], rt[1]); rec.Code != http.StatusForbidden {
			t.Errorf("scoped POST %s: %d, want 403", rt[0], rec.Code)
		}
	}
	if rec := e.as(sec, "POST", "/admin/radius/settings", settings); rec.Code != http.StatusOK {
		t.Errorf("security admin settings: %d %s", rec.Code, rec.Body)
	}
	if rec := e.authz(e.postureToken(), map[string]string{}); rec.Code == http.StatusOK {
		t.Errorf("sanity")
	}
	// Unauthenticated and cookie-without-CSRF.
	if rec := httptest.NewRecorder(); true {
		req := httptest.NewRequest("POST", "/admin/radius/settings", strings.NewReader(settings))
		e.router.ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Errorf("unauthenticated POST succeeded")
		}
	}
	cookie, _, _ := web.IssueSession(context.Background(), e.repo, "admin", false)
	req := httptest.NewRequest("POST", "/admin/radius/settings", strings.NewReader(settings))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("cookie POST without CSRF: %d", rec.Code)
	}
}

func TestRadiusAdmin_SettingsValidatedAndAudited(t *testing.T) {
	e := newRadEnv(t)
	for name, body := range map[string]string{
		"vlan 0": `{"compliant_vlan":"0"}`, "vlan 4095": `{"quarantine_vlan":"4095"}`,
		"vlan text": `{"remediation_vlan":"10; drop"}`, "xlat": `{"guest_vlan":"%{User-Name}"}`,
		"guest on without vlan": `{"guest_enabled":true}`,
	} {
		if rec := e.basic("POST", "/admin/radius/settings", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	rec := e.basic("POST", "/admin/radius/settings", `{"compliant_vlan":"10","guest_vlan":"30","guest_enabled":true,"allow_weak_identity":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rec.Code, rec.Body)
	}
	got := e.basic("GET", "/admin/radius", "")
	if !strings.Contains(got.Body.String(), `"guest_enabled":true`) || !strings.Contains(got.Body.String(), `"allow_weak_identity":true`) {
		t.Fatalf("settings not persisted: %s", got.Body)
	}
	seen := map[string]bool{}
	evs, _ := e.repo.ListSystemAuditEvents(context.Background(), 200)
	for _, ev := range evs {
		if ev.CreatedAt.After(time.Now().Add(-time.Minute)) {
			seen[ev.Action] = true
		}
	}
	for _, a := range []string{"RADIUS_SETTINGS_UPDATE", "RADIUS_GUEST_VLAN_CHANGE", "RADIUS_WEAK_IDENTITY_CHANGE"} {
		if !seen[a] {
			t.Errorf("audit event %s was not recorded", a)
		}
	}
}

func TestRadiusAdmin_NASSecretIsWriteOnlyAndSealed(t *testing.T) {
	e := newRadEnv(t)
	addr := fmt.Sprintf("10.%d.%d.%d", 100+rand.Intn(100), rand.Intn(250), 1+rand.Intn(250))
	const mySecret = "operator-chosen-secret-value"
	rec := e.basic("POST", "/admin/radius/nas", `{"name":"`+e.uniq("n")+`","address":"`+addr+`","secret":"`+mySecret+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), mySecret) || strings.Contains(rec.Body.String(), `"secret"`) {
		t.Fatalf("an admin-supplied secret must never be echoed: %s", rec.Body)
	}
	var out struct {
		NAS struct {
			ID        string
			HasSecret bool `json:"has_secret"`
		} `json:"nas_client"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	t.Cleanup(func() {
		_, _ = e.pool.Exec(context.Background(), `DELETE FROM radius_nas_clients WHERE id=$1`, out.NAS.ID)
	})
	if !out.NAS.HasSecret {
		t.Fatal("has_secret flag expected")
	}
	// Sealed at rest.
	var enc []byte
	if err := e.pool.QueryRow(context.Background(), `SELECT secret_enc FROM radius_nas_clients WHERE id=$1`, out.NAS.ID).Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if len(enc) == 0 || strings.Contains(string(enc), mySecret) {
		t.Fatalf("secret is not sealed: %q", enc)
	}
	// No GET (JSON or HTML) ever contains it.
	for _, accept := range []string{"application/json", "text/html"} {
		req := httptest.NewRequest("GET", "/admin/radius", nil)
		req.SetBasicAuth("admin", "adminpw")
		req.Header.Set("Accept", accept)
		w := httptest.NewRecorder()
		e.router.ServeHTTP(w, req)
		if w.Code != 200 || strings.Contains(w.Body.String(), mySecret) {
			t.Fatalf("GET %s: %d, secret leaked=%v", accept, w.Code, strings.Contains(w.Body.String(), mySecret))
		}
	}
	// Generated secret is returned exactly once.
	addr2 := fmt.Sprintf("10.%d.%d.%d", 100+rand.Intn(100), rand.Intn(250), 1+rand.Intn(250))
	rec = e.basic("POST", "/admin/radius/nas", `{"name":"`+e.uniq("g")+`","address":"`+addr2+`"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create generated: %d %s", rec.Code, rec.Body)
	}
	var gen struct {
		Secret string
		NAS    struct{ ID string } `json:"nas_client"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &gen)
	t.Cleanup(func() {
		_, _ = e.pool.Exec(context.Background(), `DELETE FROM radius_nas_clients WHERE id=$1`, gen.NAS.ID)
	})
	if len(gen.Secret) < 20 {
		t.Fatalf("generated secret expected once: %s", rec.Body)
	}
	if g := e.basic("GET", "/admin/radius", ""); strings.Contains(g.Body.String(), gen.Secret) {
		t.Fatal("generated secret leaked on a later GET")
	}
	// The audit event never carries the secret.
	evs, _ := e.repo.ListSystemAuditEvents(context.Background(), 100)
	for _, ev := range evs {
		if strings.HasPrefix(ev.Action, "RADIUS_") && (strings.Contains(string(ev.Details), mySecret) || strings.Contains(string(ev.Details), gen.Secret)) {
			t.Fatalf("secret in audit event %s", ev.Action)
		}
	}
}

func TestRadiusAdmin_NASAddressPolicy(t *testing.T) {
	e := newRadEnv(t)
	for name, addr := range map[string]string{"loopback": "127.0.0.1", "v6 loopback": "::1", "metadata": "169.254.169.254",
		"multicast": "224.0.0.1", "unspecified": "0.0.0.0", "hostname": "nas.example.com", "empty": "", "mapped loopback": "::ffff:127.0.0.1"} {
		rec := e.basic("POST", "/admin/radius/nas", `{"name":"`+e.uniq("bad")+`","address":"`+addr+`","secret":"longenough1"}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s (%q): %d %s", name, addr, rec.Code, rec.Body)
		}
	}
	if rec := e.basic("POST", "/admin/radius/nas", `{"name":"`+e.uniq("short")+`","address":"10.9.9.9","secret":"short"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("short secret: %d", rec.Code)
	}
	if rec := e.basic("POST", "/admin/radius/nas", `{"name":"`+e.uniq("port")+`","address":"10.9.9.9","coa_port":70000,"secret":"longenough1"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad port: %d", rec.Code)
	}
	// Duplicate address.
	addr := fmt.Sprintf("10.%d.%d.%d", 100+rand.Intn(100), rand.Intn(250), 1+rand.Intn(250))
	first := e.basic("POST", "/admin/radius/nas", `{"name":"`+e.uniq("a")+`","address":"`+addr+`","secret":"longenough1"}`)
	var f struct {
		NAS struct{ ID string } `json:"nas_client"`
	}
	_ = json.Unmarshal(first.Body.Bytes(), &f)
	t.Cleanup(func() {
		_, _ = e.pool.Exec(context.Background(), `DELETE FROM radius_nas_clients WHERE id=$1`, f.NAS.ID)
	})
	if rec := e.basic("POST", "/admin/radius/nas", `{"name":"`+e.uniq("b")+`","address":"`+addr+`","secret":"longenough1"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("duplicate address: %d", rec.Code)
	}
	// Update to a forbidden address is refused too.
	if rec := e.basic("POST", "/admin/radius/nas/"+f.NAS.ID, `{"name":"n","address":"127.0.0.1"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("update to loopback: %d", rec.Code)
	}
	if rec := e.basic("POST", "/admin/radius/nas/not-a-uuid", `{}`); rec.Code != http.StatusNotFound {
		t.Errorf("bad id: %d", rec.Code)
	}
}
