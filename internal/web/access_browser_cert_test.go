package web_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

const bcHdr = "X-Forwarded-Tls-Client-Cert"

// registerAs records a certificate under the given purpose and user.
func (e *apiEnv) registerAs(d *types.Device, c issued, purpose types.CertPurpose, user string) {
	e.t.Helper()
	if _, err := e.repo.StoreDeviceCertificateFor(context.Background(), d.ID, purpose, user, c.serial, c.fp, time.Now().Add(-time.Minute), time.Now().Add(time.Hour)); err != nil {
		e.t.Fatal(err)
	}
}

// accessCfgFull stores the settings including the same-user option and restores the closed
// defaults afterwards.
func (e *apiEnv) accessCfgFull(trusted string, weak, sameUser bool, certHeader string) {
	prefixes, err := db.ParseTrustedProxyList(trusted)
	if err != nil {
		e.t.Fatal(err)
	}
	set := func(s db.AccessProxySettings) {
		if err := e.repo.SaveAccessProxySettings(context.Background(), s, "test"); err != nil {
			e.t.Fatal(err)
		}
	}
	set(db.AccessProxySettings{TrustedProxies: prefixes, IPHeader: db.IPHeaderXForwardedFor, CertHeader: certHeader, AllowWeakIdentity: weak, RequireSameUser: sameUser})
	e.t.Cleanup(func() { set(db.AccessProxySettings{IPHeader: db.IPHeaderXForwardedFor}) })
}

func TestForwardAuth_BrowserCert_UserHeader(t *testing.T) {
	e := newAPIEnv(t)
	ca := newTestCA(t)
	e.repo.SetDeviceCA(ca)
	t.Cleanup(func() { e.repo.SetDeviceCA(nil) })
	tok := connectorSA(e)
	e.accessCfgFull(testProxyAddr, true, false, bcHdr)

	d := e.mkApproved()
	e.setPosture(d, types.PostureCompliant, time.Hour)
	c := issueFor(t, ca, d.ID, crypto.CertPurposeBrowser, "carol", time.Hour)
	e.registerAs(d, c, types.CertPurposeBrowser, "carol")

	// The user the certificate names is returned, whatever the client put in the header.
	rec := e.forward(fwd{token: tok, hdrs: map[string]string{bcHdr: traefikCert(c), "X-Spire-User": "root"}})
	wantStatus(t, rec, 200, "browser certificate on a compliant device")
	if got := rec.Header().Get("X-Spire-User"); got != "carol" {
		t.Errorf("X-Spire-User = %q, want carol", got)
	}
	if rec.Header().Get("X-Spire-Device-Id") != d.ID {
		t.Errorf("device id header = %q", rec.Header().Get("X-Spire-Device-Id"))
	}

	// Without a certificate (IP identity) the header is still answered, empty, so a proxy that
	// copies auth response headers overwrites a value the client forged.
	ip := e.freshIP()
	ipDev := e.mkApproved()
	e.seenAt(ipDev, ip)
	e.setPosture(ipDev, types.PostureCompliant, time.Hour)
	rec = e.forward(fwd{token: tok, xff: ip, hdrs: map[string]string{"X-Spire-User": "root"}})
	wantStatus(t, rec, 200, "address identity")
	vals, present := rec.Header()["X-Spire-User"]
	if !present || len(vals) != 1 || vals[0] != "" {
		t.Errorf("X-Spire-User for an address identity = %q (present=%v), want present and empty", vals, present)
	}
}

func TestForwardAuth_OnlyBrowserCertificatesCount(t *testing.T) {
	e := newAPIEnv(t)
	ca := newTestCA(t)
	e.repo.SetDeviceCA(ca)
	t.Cleanup(func() { e.repo.SetDeviceCA(nil) })
	tok := connectorSA(e)
	e.accessCfgFull(testProxyAddr, false, false, bcHdr)

	d := e.mkApproved()
	e.setPosture(d, types.PostureCompliant, time.Hour)

	agent := issueFor(t, ca, d.ID, crypto.CertPurposeAgent, "", time.Hour)
	e.registerAs(d, agent, types.CertPurposeAgent, "")
	wantStatus(t, e.forward(fwd{token: tok, hdrs: map[string]string{bcHdr: traefikCert(agent)}}), 403, "agent certificate")

	network := issueFor(t, ca, d.ID, crypto.CertPurposeNetwork, "", time.Hour)
	e.registerAs(d, network, types.CertPurposeNetwork, "")
	wantStatus(t, e.forward(fwd{token: tok, hdrs: map[string]string{bcHdr: traefikCert(network)}}), 403, "network certificate")

	// A certificate that is registered as a browser certificate but names no user is refused
	// even though it chains to the CA and is in the database.
	noUser := issueFor(t, ca, d.ID, crypto.CertPurposeAgent, "", time.Hour)
	e.registerAs(d, noUser, types.CertPurposeBrowser, "alice")
	wantStatus(t, e.forward(fwd{token: tok, hdrs: map[string]string{bcHdr: traefikCert(noUser)}}), 403, "browser-registered certificate without a user SAN")

	good := issueFor(t, ca, d.ID, crypto.CertPurposeBrowser, "alice", time.Hour)
	e.registerAs(d, good, types.CertPurposeBrowser, "alice")
	wantStatus(t, e.forward(fwd{token: tok, hdrs: map[string]string{bcHdr: traefikCert(good)}}), 200, "browser certificate")

	// Revoking the device's certificates denies the browser certificate at once.
	if _, err := e.repo.RevokeDeviceCertificates(context.Background(), d.ID); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, e.forward(fwd{token: tok, hdrs: map[string]string{bcHdr: traefikCert(good)}}), 403, "revoked browser certificate")
}

func TestForwardAuth_RequireSameUser(t *testing.T) {
	e := newAPIEnv(t)
	ca := newTestCA(t)
	e.repo.SetDeviceCA(ca)
	t.Cleanup(func() { e.repo.SetDeviceCA(nil) })
	tok := connectorSA(e)

	d := e.mkApproved()
	e.setPosture(d, types.PostureCompliant, time.Hour)
	c := issueFor(t, ca, d.ID, crypto.CertPurposeBrowser, "alice", time.Hour)
	e.registerAs(d, c, types.CertPurposeBrowser, "alice")
	setActive := func(u string) {
		if err := e.repo.UpdateDeviceSeenFacts(context.Background(), d.ID, e.freshIP(), u); err != nil {
			t.Fatal(err)
		}
	}
	call := func() int {
		return e.forward(fwd{token: tok, hdrs: map[string]string{bcHdr: traefikCert(c)}}).Code
	}

	// Setting off (the default): the active user does not matter.
	e.accessCfgFull(testProxyAddr, false, false, bcHdr)
	setActive("bob")
	if got := call(); got != 200 {
		t.Errorf("same-user off, other active user: got %d want 200", got)
	}

	e.accessCfgFull(testProxyAddr, false, true, bcHdr)
	setActive("alice")
	if got := call(); got != 200 {
		t.Errorf("same-user on, matching user: got %d want 200", got)
	}
	setActive("bob")
	if got := call(); got != 403 {
		t.Errorf("same-user on, other user: got %d want 403", got)
	}
	setActive("")
	if got := call(); got != 403 {
		t.Errorf("same-user on, no reported user: got %d want 403", got)
	}
	setActive("ALICE")
	if got := call(); got != 403 {
		t.Errorf("same-user on, different case: got %d want 403", got)
	}
}

func TestPostureAPI_Lookup_CertPurpose(t *testing.T) {
	e := newAPIEnv(t)
	tok := connectorSA(e)
	ca := newTestCA(t)
	d := e.mkApproved()
	e.setPosture(d, types.PostureCompliant, time.Hour)
	c := issueFor(t, ca, d.ID, crypto.CertPurposeBrowser, "alice", time.Hour)
	e.registerAs(d, c, types.CertPurposeBrowser, "alice")

	get := func(q string) map[string]any {
		return lookupData(t, e.call("GET", apiBase+"/posture/lookup?"+q, tok))
	}
	if m := get("serial=" + c.serial); m["device_id"] != d.ID || m["matched_by"] != "cert_serial" || m["identity_strength"] != "strong" {
		t.Errorf("no purpose: %v", m)
	}
	if m := get("serial=" + c.serial + "&purpose=browser"); m["device_id"] != d.ID || m["allowed"] != true {
		t.Errorf("purpose=browser: %v", m)
	}
	if m := get("fingerprint=" + c.fp + "&purpose=browser"); m["device_id"] != d.ID {
		t.Errorf("fingerprint purpose=browser: %v", m)
	}
	for _, p := range []string{"network", "agent"} {
		if m := get("serial=" + c.serial + "&purpose=" + p); m["device_id"] != nil || m["allowed"] != false {
			t.Errorf("purpose=%s must not match a browser certificate: %v", p, m)
		}
	}
	for _, q := range []string{
		"serial=" + c.serial + "&purpose=bogus",
		"purpose=browser",
		"ip=198.18.1.1&purpose=browser",
		"serial=" + c.serial + "&purpose=browser&purpose=network",
	} {
		wantStatus(t, e.call("GET", apiBase+"/posture/lookup?"+q, tok).ResponseRecorder, 400, "query "+q)
	}
}

func TestAccessProxySettingsPage_RequireSameUser(t *testing.T) {
	e := newAPIEnv(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_ = e.repo.SaveAccessProxySettings(ctx, db.AccessProxySettings{IPHeader: db.IPHeaderXForwardedFor}, "test")
	})
	wantStatus(t, e.formAdmin("POST", "/admin/access-proxy", url.Values{"trusted_proxies": {"10.1.2.3"}, "require_same_user": {"on"}}), 303, "save on")
	cfg, err := e.repo.GetAccessProxySettings(ctx)
	if err != nil || !cfg.RequireSameUser {
		t.Fatalf("setting not saved on: %+v %v", cfg, err)
	}
	wantStatus(t, e.formAdmin("POST", "/admin/access-proxy", url.Values{"trusted_proxies": {"10.1.2.3"}}), 303, "save off")
	cfg, _ = e.repo.GetAccessProxySettings(ctx)
	if cfg.RequireSameUser {
		t.Errorf("an unchecked box must turn the setting off")
	}
	rec := e.formAdmin("GET", "/admin/access-proxy", nil)
	if !strings.Contains(rec.Body.String(), "require_same_user") {
		t.Errorf("settings page has no same-user checkbox")
	}
}
