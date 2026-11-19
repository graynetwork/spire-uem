package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A panic inside a handler becomes the standard 500 error object, without leaking the
// panic value, and a client-supplied X-Request-Id is not trusted.
func TestAPIv1_PanicBecomesStandard500(t *testing.T) {
	h := apiBaseMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("secret internal detail: db password hunter2")
	}))
	req := httptest.NewRequest("GET", "/api/admin/v1/x", nil)
	req.Header.Set("X-Request-Id", "attacker\nlog-injection")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 500 {
		t.Fatalf("status %d", rec.Code)
	}
	var m map[string]map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	e := m["error"]
	if e["code"] != "internal_error" || e["request_id"] == "" || e["request_id"] != rec.Header().Get("X-Request-Id") {
		t.Errorf("bad 500 shape: %v hdr=%q", e, rec.Header().Get("X-Request-Id"))
	}
	if strings.Contains(rec.Body.String(), "hunter2") || strings.Contains(rec.Header().Get("X-Request-Id"), "attacker") {
		t.Errorf("panic detail or client request id leaked: %s", rec.Body.String())
	}
}

func TestServiceAccountTokenFormatAndEntropy(t *testing.T) {
	raw, id, hash, err := GenerateServiceAccountToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, "spire_sa_"+id+"_") {
		t.Fatalf("format: %s", raw)
	}
	secret := strings.TrimPrefix(raw, "spire_sa_"+id+"_")
	if len(secret) != 64 || !isHex(secret, 64) { // 32 bytes = 256 bits
		t.Fatalf("secret must be 64 hex chars (256 bits), got %d", len(secret))
	}
	if hash != sha256Hex(secret) || hash == secret {
		t.Fatalf("stored value must be the SHA-256 of the secret")
	}
	raw2, _, _, _ := GenerateServiceAccountToken()
	if raw == raw2 {
		t.Fatal("tokens must be unique")
	}
}
