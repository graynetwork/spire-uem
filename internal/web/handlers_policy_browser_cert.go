package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/types"
)

// buildBrowserCertificatePayload parses the BROWSER_CERTIFICATE admin form.
//
// Form fields: bc_urls (one URL pattern per line or comma-separated) and bc_browsers
// ("both", "chromium" or "firefox"; blank means both).
func buildBrowserCertificatePayload(r *http.Request) (json.RawMessage, error) {
	payload := types.BrowserCertificatePayload{
		AutoSelectURLs: pbSplitList(r.FormValue("bc_urls")),
	}
	switch strings.ToLower(strings.TrimSpace(r.FormValue("bc_browsers"))) {
	case "", "both":
	case types.BrowserFamilyChromium:
		payload.Browsers = []string{types.BrowserFamilyChromium}
	case types.BrowserFamilyFirefox:
		payload.Browsers = []string{types.BrowserFamilyFirefox}
	default:
		return nil, fmt.Errorf("bc_browsers must be both, chromium or firefox")
	}
	return validateBrowserCertificateJSON(mustMarshalJSON(payload))
}

// validateBrowserCertificateJSON checks a BROWSER_CERTIFICATE payload and returns it in
// canonical form. It is used for both the admin form and a raw JSON payload, so the two
// paths accept the same set of payloads.
func validateBrowserCertificateJSON(raw json.RawMessage) (json.RawMessage, error) {
	var payload types.BrowserCertificatePayload
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		return nil, fmt.Errorf("invalid BROWSER_CERTIFICATE payload: %w", err)
	}
	if err := engine.ValidateBrowserCertificatePayload(payload); err != nil {
		return nil, fmt.Errorf("browser certificate policy invalid: %w", err)
	}
	// Canonical form: trimmed and de-duplicated.
	seen := map[string]bool{}
	var urls []string
	for _, u := range payload.AutoSelectURLs {
		if u = strings.TrimSpace(u); !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	payload.AutoSelectURLs = urls
	return json.Marshal(payload)
}

func mustMarshalJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}
