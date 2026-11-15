package web

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

func formReq(values url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/admin/policies", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()
	return req
}

func TestBuildFirewallRulesetPayload_LinesAndValidation(t *testing.T) {
	// Valid line-oriented rules.
	req := formReq(url.Values{
		"fw_default_inbound":   {"drop"},
		"fw_allow_established": {"on"},
		"fw_allow_loopback":    {"on"},
		"fw_allow_icmp":        {"on"},
		"fw_rules":             {"tcp 22 10.0.0.0/8 # ssh from mgmt\nudp 51820\ntcp 8000-8010"},
	})
	raw, err := buildFirewallRulesetPayload(req)
	if err != nil {
		t.Fatalf("expected valid firewall payload, got %v", err)
	}
	var p types.FirewallRulesetPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.DefaultInbound != "drop" || !p.AllowEstablished || !p.AllowLoopback || !p.AllowICMP {
		t.Errorf("flags not parsed: %+v", p)
	}
	if len(p.InboundRules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(p.InboundRules))
	}

	// Invalid CIDR rejected server-side.
	bad := formReq(url.Values{"fw_default_inbound": {"drop"}, "fw_rules": {"tcp 22 999.1.1.1/8"}})
	if _, err := buildFirewallRulesetPayload(bad); err == nil {
		t.Error("expected invalid CIDR to be rejected")
	}

	// Invalid default rejected.
	bad2 := formReq(url.Values{"fw_default_inbound": {"allow"}})
	if _, err := buildFirewallRulesetPayload(bad2); err == nil {
		t.Error("expected invalid default_inbound to be rejected")
	}

	// JSON array form accepted.
	jreq := formReq(url.Values{
		"fw_default_inbound": {"drop"},
		"fw_rules":           {`[{"proto":"tcp","port":443},{"proto":"udp","port":53,"source_cidr":"192.168.0.0/16"}]`},
	})
	if _, err := buildFirewallRulesetPayload(jreq); err != nil {
		t.Errorf("expected JSON-array rules to parse, got %v", err)
	}
}

func TestBuildLocalAccountPolicyPayload(t *testing.T) {
	req := formReq(url.Values{
		"la_minlen":          {"14"},
		"la_minclass":        {"3"},
		"la_faillock_deny":   {"5"},
		"la_faillock_unlock": {"900"},
		"la_pass_max_days":   {"365"},
		"la_sudo_groups":     {"sudo, admins"},
		"la_sudo_users":      {"ops"},
	})
	raw, err := buildLocalAccountPolicyPayload(req)
	if err != nil {
		t.Fatalf("expected valid, got %v", err)
	}
	var p types.LocalAccountPolicyPayload
	_ = json.Unmarshal(raw, &p)
	if p.PwqualityMinLen != 14 || p.FaillockDeny != 5 || p.PassMaxDays != 365 {
		t.Errorf("fields not parsed: %+v", p)
	}
	if p.Sudoers == nil || len(p.Sudoers.Groups) != 2 || len(p.Sudoers.Users) != 1 {
		t.Errorf("sudoers not parsed: %+v", p.Sudoers)
	}

	// Empty policy rejected.
	if _, err := buildLocalAccountPolicyPayload(formReq(url.Values{})); err == nil {
		t.Error("expected empty local-account policy to be rejected")
	}
	// Out-of-range rejected.
	if _, err := buildLocalAccountPolicyPayload(formReq(url.Values{"la_minclass": {"9"}})); err == nil {
		t.Error("expected minclass=9 to be rejected")
	}
	// Bad sudoers principal rejected.
	if _, err := buildLocalAccountPolicyPayload(formReq(url.Values{"la_sudo_groups": {"bad!group"}})); err == nil {
		t.Error("expected invalid group name to be rejected")
	}
}

func testCAPEM(t *testing.T) string {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "Web Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestBuildTrustedCACertificatesPayload(t *testing.T) {
	caPEM := testCAPEM(t)

	// Single cert form.
	req := formReq(url.Values{"ca_name": {"corp-root"}, "ca_pem": {caPEM}})
	raw, err := buildTrustedCACertificatesPayload(req)
	if err != nil {
		t.Fatalf("expected valid single cert, got %v", err)
	}
	var p types.TrustedCACertificatesPayload
	_ = json.Unmarshal(raw, &p)
	if len(p.Certificates) != 1 || p.Certificates[0].Name != "corp-root" {
		t.Errorf("single cert not parsed: %+v", p)
	}

	// JSON array form.
	arr, _ := json.Marshal([]types.TrustedCACertificate{{Name: "root", PEM: caPEM}})
	jreq := formReq(url.Values{"ca_certs": {string(arr)}})
	if _, err := buildTrustedCACertificatesPayload(jreq); err != nil {
		t.Errorf("expected JSON array certs to parse, got %v", err)
	}

	// Garbage PEM rejected.
	if _, err := buildTrustedCACertificatesPayload(formReq(url.Values{"ca_name": {"x"}, "ca_pem": {"nope"}})); err == nil {
		t.Error("expected garbage PEM to be rejected")
	}
	// Missing fields rejected.
	if _, err := buildTrustedCACertificatesPayload(formReq(url.Values{})); err == nil {
		t.Error("expected missing cert fields to be rejected")
	}
}
