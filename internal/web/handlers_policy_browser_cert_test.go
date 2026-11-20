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

func TestBuildBrowserCertificatePayload(t *testing.T) {
	raw, err := buildBrowserCertificatePayload(formReq(url.Values{
		"bc_urls":     {"https://apps.example.com\n[*.]corp.example.com, https://apps.example.com"},
		"bc_browsers": {"chromium"},
	}))
	if err != nil {
		t.Fatalf("valid form refused: %v", err)
	}
	var p types.BrowserCertificatePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.AutoSelectURLs) != 2 || len(p.Browsers) != 1 || p.Browsers[0] != "chromium" {
		t.Errorf("payload = %+v", p)
	}

	for name, form := range map[string]url.Values{
		"no urls":         {"bc_browsers": {"chromium"}},
		"wildcard":        {"bc_urls": {"*"}},
		"plain http":      {"bc_urls": {"http://a.example.com"}},
		"unknown browser": {"bc_urls": {"https://a.example.com"}, "bc_browsers": {"lynx"}},
	} {
		if _, err := buildBrowserCertificatePayload(formReq(form)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	// Firefox only needs no URL list.
	if _, err := buildBrowserCertificatePayload(formReq(url.Values{"bc_browsers": {"firefox"}})); err != nil {
		t.Errorf("firefox-only policy refused: %v", err)
	}
}

func TestValidateBrowserCertificateJSON_RejectsUnknownFields(t *testing.T) {
	if _, err := validateBrowserCertificateJSON(json.RawMessage(`{"auto_select_urls":["https://a.example.com"],"extra":1}`)); err == nil {
		t.Error("unknown field accepted")
	}
	if _, err := validateBrowserCertificateJSON(json.RawMessage(`not json`)); err == nil {
		t.Error("garbage accepted")
	}
}

// A raw JSON payload goes through the same validation as the admin form: an invalid one is
// refused with 400 before anything is stored (the handler has no repository).
func TestCreatePolicy_BrowserCertificateRawPayloadValidated(t *testing.T) {
	h := &Handler{}
	for _, body := range []string{
		`{"name":"bc","policy_type":"BROWSER_CERTIFICATE","payload":{"auto_select_urls":["*"]}}`,
		`{"name":"bc","policy_type":"BROWSER_CERTIFICATE","payload":{"auto_select_urls":["https://a.example.com"],"browsers":["lynx"]}}`,
		`{"name":"bc","policy_type":"BROWSER_CERTIFICATE","payload":{}}`,
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
