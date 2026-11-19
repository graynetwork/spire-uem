package web

import (
	_ "embed"
	"net/http"
)

//go:embed adminapi_openapi.json
var adminAPISpec []byte

// apiOpenAPI serves the embedded OpenAPI 3.1 document. It is public: the spec describes the
// API surface only and contains no deployment data.
func (h *Handler) apiOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(adminAPISpec)
}
