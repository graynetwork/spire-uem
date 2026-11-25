package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/types"
)

// buildBrowserPolicyPayload parses the BROWSER_POLICY admin form: two JSON objects, one
// of Chromium-family policies and one of Firefox policies. Either may be empty.
func buildBrowserPolicyPayload(r *http.Request) (json.RawMessage, error) {
	var payload types.BrowserPolicyPayload
	for _, f := range []struct {
		field string
		dst   *map[string]json.RawMessage
	}{
		{"bp_chromium", &payload.Chromium},
		{"bp_firefox", &payload.Firefox},
	} {
		raw := strings.TrimSpace(r.FormValue(f.field))
		if raw == "" {
			continue
		}
		if err := json.Unmarshal([]byte(raw), f.dst); err != nil || *f.dst == nil {
			return nil, fmt.Errorf("%s must be a JSON object of policy names and values", f.field)
		}
	}
	return validateBrowserPolicyJSON(mustMarshalJSON(payload))
}

// validateBrowserPolicyJSON checks a BROWSER_POLICY payload and returns it in canonical
// form. Both the admin form and a raw JSON payload go through it.
func validateBrowserPolicyJSON(raw json.RawMessage) (json.RawMessage, error) {
	var payload types.BrowserPolicyPayload
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		return nil, fmt.Errorf("invalid BROWSER_POLICY payload: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("invalid BROWSER_POLICY payload: trailing data")
	}
	if err := engine.ValidateBrowserPolicyPayload(payload); err != nil {
		return nil, fmt.Errorf("browser policy invalid: %w", err)
	}
	return json.Marshal(payload)
}
