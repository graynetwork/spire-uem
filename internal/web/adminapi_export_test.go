package web

import "encoding/json"

// SanitizePolicyPayloadForTest exposes the policy redaction to the external test package.
func SanitizePolicyPayloadForTest(raw string) (json.RawMessage, bool) {
	return sanitizePolicyPayload(json.RawMessage(raw))
}
