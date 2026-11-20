package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

// A NETWORK_PROFILE with client_cert_source "device" that also carries a pasted certificate or
// key, uses a method other than EAP-TLS, or names an unknown source is refused with 400 on
// every create path, before anything reaches the repository (the handler has none, so
// reaching it would panic).
func TestCreatePolicy_DeviceCertSourceRefusedOnRawPaths(t *testing.T) {
	bad := map[string]string{
		"pasted cert":   `{"kind":"wired_8021x","wired_8021x":{"eap":"tls","client_cert_source":"device","client_cert":"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----"}}`,
		"pasted key":    `{"kind":"wired_8021x","wired_8021x":{"eap":"tls","client_cert_source":"device","client_key":"-----BEGIN PRIVATE KEY-----"}}`,
		"peap":          `{"kind":"wired_8021x","wired_8021x":{"eap":"peap-mschapv2","identity":"u","client_cert_source":"device"}}`,
		"unknown":       `{"kind":"wired_8021x","wired_8021x":{"eap":"tls","client_cert_source":"yes"}}`,
		"wifi key":      `{"kind":"wifi","wifi":{"ssid":"c","security":"wpa2-enterprise","eap":"tls","client_cert_source":"device","client_key":"k"}}`,
		"wifi personal": `{"kind":"wifi","wifi":{"ssid":"c","security":"wpa2-personal","psk":"longenough","client_cert_source":"device"}}`,
	}
	admin := &types.AdminUser{Role: types.RoleSecurityAdmin}
	for name, payload := range bad {
		for _, path := range []string{"json", "form-payload-field"} {
			h := &Handler{}
			var req *http.Request
			if path == "json" {
				body := `{"name":"n","policy_type":"NETWORK_PROFILE","payload":` + payload + `,"target_tags":["x"]}`
				req = httptest.NewRequest(http.MethodPost, "/admin/policies", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				form := url.Values{"name": {"n"}, "policy_type": {"NETWORK_PROFILE"}, "payload": {payload}, "target_tags": {"x"}}
				req = httptest.NewRequest(http.MethodPost, "/admin/policies", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			rec := httptest.NewRecorder()
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Errorf("%s/%s: handler stored or sealed the payload instead of refusing: %v", name, path, p)
					}
				}()
				_ = admin
				h.CreatePolicy(rec, req)
			}()
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s/%s: got %d, want 400 (%s)", name, path, rec.Code, rec.Body.String())
			}
		}
	}
}

// The admin form drops whatever the hidden paste fields still hold when the certificate is
// issued by SpireUEM, and refuses an unknown source value.
func TestBuildNetworkProfilePayload_DeviceSource(t *testing.T) {
	post := func(vals url.Values) (*http.Request, error) {
		r := httptest.NewRequest(http.MethodPost, "/admin/policies", strings.NewReader(vals.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r, r.ParseForm()
	}
	r, err := post(url.Values{
		"np_kind": {"wired_8021x"}, "np_wired_eap": {"tls"}, "np_wired_client_cert_source": {"device"},
		"np_wired_client_cert": {"leftover"}, "np_wired_client_key": {"leftover"}, "np_wired_password": {"leftover"},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := buildNetworkProfilePayload(r)
	if err != nil {
		t.Fatalf("device source from the form: %v", err)
	}
	if strings.Contains(string(raw), "leftover") || !strings.Contains(string(raw), `"client_cert_source":"device"`) {
		t.Fatalf("payload = %s", raw)
	}

	r, _ = post(url.Values{"np_kind": {"wired_8021x"}, "np_wired_eap": {"peap-mschapv2"}, "np_wired_identity": {"u"},
		"np_wired_password": {"pw"}, "np_wired_client_cert_source": {"device"}})
	if _, err := buildNetworkProfilePayload(r); err == nil {
		t.Fatal("device source with PEAP accepted")
	}
	r, _ = post(url.Values{"np_kind": {"wired_8021x"}, "np_wired_eap": {"tls"}, "np_wired_client_cert_source": {"magic"}})
	if _, err := buildNetworkProfilePayload(r); err == nil {
		t.Fatal("unknown source accepted")
	}
}
