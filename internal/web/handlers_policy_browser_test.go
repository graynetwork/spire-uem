package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

func TestBuildBrowserPolicyPayload(t *testing.T) {
	raw, err := buildBrowserPolicyPayload(formReq(url.Values{
		"bp_chromium": {`{"HomepageLocation":"https://a.example.com"}`},
		"bp_firefox":  {`{"DisableTelemetry":true}`},
	}))
	if err != nil {
		t.Fatalf("valid form refused: %v", err)
	}
	var p types.BrowserPolicyPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Chromium) != 1 || len(p.Firefox) != 1 {
		t.Errorf("payload = %+v", p)
	}
	for name, form := range map[string]url.Values{
		"both empty":    {},
		"not json":      {"bp_chromium": {"HomepageLocation=x"}},
		"array":         {"bp_firefox": {`[1]`}},
		"reserved key":  {"bp_chromium": {`{"AutoSelectCertificateForUrls":[]}`}},
		"bad key shape": {"bp_chromium": {`{"../etc":1}`}},
	} {
		if _, err := buildBrowserPolicyPayload(formReq(form)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// A raw JSON payload is validated the same way, and refused before reaching the repository.
func TestCreatePolicy_BrowserPolicyRawPayloadValidated(t *testing.T) {
	h := &Handler{}
	for _, body := range []string{
		`{"name":"bp","policy_type":"BROWSER_POLICY","payload":{}}`,
		`{"name":"bp","policy_type":"BROWSER_POLICY","payload":{"chromium":{"HomepageLocation":"x"},"edge":{}}}`,
		`{"name":"bp","policy_type":"BROWSER_POLICY","payload":{"firefox":{"Preferences":{"security.default_personal_cert":{"Value":"Ask Every Time"}}}}}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/admin/policies", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("invalid payload reached the repository: %v (%s)", p, body)
				}
			}()
			h.CreatePolicy(rec, req)
		}()
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d want 400 (%s)", body, rec.Code, rec.Body.String())
		}
	}
}
