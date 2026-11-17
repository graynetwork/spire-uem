package ipc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/spire-uem/spire-uem/internal/ipc"
)

func TestCampaignDefer_ForwardsWithBearer(t *testing.T) {
	t.Setenv("SPIRE_SEAT0_UID", "1000")

	// Stub control plane that asserts the bearer token and campaign id, and returns a
	// deferral decision.
	var gotAuth, gotBody string
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"deferred": true, "deferrals_used": 1, "deferrals_left": 2})
	}))
	defer cp.Close()

	// Token file the agent reads.
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("dev-token-abc"), 0600); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(dir, "agent.sock")
	srv := ipc.NewServer(sockPath, cp.URL, tokenPath, "hw", "host", nil, nil, nil)

	// Drive the handler through the peer-cred middleware as an authorized root caller.
	handler := srv.PeerCredMiddlewareForTest(http.HandlerFunc(srv.HandleCampaignDeferForTest))
	req := httptest.NewRequest(http.MethodPost, "http://unix/v1/campaign/defer", strings.NewReader(`{"campaign_id":"camp-1"}`))
	req = req.WithContext(ipc.WithPeerCred(req.Context(), &syscall.Ucred{Uid: 0}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if gotAuth != "Bearer dev-token-abc" {
		t.Errorf("expected bearer token forwarded, got %q", gotAuth)
	}
	if !strings.Contains(gotBody, "camp-1") {
		t.Errorf("expected campaign id forwarded, got %q", gotBody)
	}
	var resp ipc.CampaignDeferResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !resp.Deferred || resp.DeferralsLeft != 2 {
		t.Errorf("unexpected response: %+v", resp)
	}
}

func TestCampaignDefer_RejectsNonSeat0(t *testing.T) {
	t.Setenv("SPIRE_SEAT0_UID", "1000")
	srv := ipc.NewServer("/tmp/x.sock", "http://localhost:1", "", "hw", "host", nil, nil, nil)
	handler := srv.PeerCredMiddlewareForTest(http.HandlerFunc(srv.HandleCampaignDeferForTest))
	req := httptest.NewRequest(http.MethodPost, "http://unix/v1/campaign/defer", strings.NewReader(`{"campaign_id":"camp-1"}`))
	req = req.WithContext(ipc.WithPeerCred(req.Context(), &syscall.Ucred{Uid: 1001})) // not seat0
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a non-seat0 caller must be rejected, got %d", rec.Code)
	}
}

func TestCampaignDefer_MethodGuard(t *testing.T) {
	t.Setenv("SPIRE_SEAT0_UID", "1000")
	srv := ipc.NewServer("/tmp/x.sock", "http://localhost:1", "", "hw", "host", nil, nil, nil)
	handler := srv.PeerCredMiddlewareForTest(http.HandlerFunc(srv.HandleCampaignDeferForTest))
	req := httptest.NewRequest(http.MethodGet, "http://unix/v1/campaign/defer", nil)
	req = req.WithContext(ipc.WithPeerCred(req.Context(), &syscall.Ucred{Uid: 0}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET should be 405, got %d", rec.Code)
	}
}
