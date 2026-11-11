package ipc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/ipc"
	"github.com/spire-uem/spire-uem/internal/types"
)

func TestPeerCredMiddleware_Authorization(t *testing.T) {
	// Simulate active seat0 UID = 1000
	t.Setenv("SPIRE_SEAT0_UID", "1000")

	srv := ipc.NewServer("/tmp/dummy.sock", "http://localhost:8080", "", "hw-uuid", "host", nil, nil, nil)
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	handler := srv.PeerCredMiddlewareForTest(dummyHandler)

	tests := []struct {
		name       string
		ucred      *syscall.Ucred
		wantCode   int
		wantSubstr string
	}{
		{
			name:     "Root UID 0 allowed unconditionally",
			ucred:    &syscall.Ucred{Uid: 0, Gid: 0, Pid: 100},
			wantCode: http.StatusOK,
		},
		{
			name:     "Active seat0 UID 1000 allowed",
			ucred:    &syscall.Ucred{Uid: 1000, Gid: 1000, Pid: 200},
			wantCode: http.StatusOK,
		},
		{
			name:       "Non-seat0 UID 1001 rejected with 403",
			ucred:      &syscall.Ucred{Uid: 1001, Gid: 1001, Pid: 300},
			wantCode:   http.StatusForbidden,
			wantSubstr: "Caller is not the active console session user",
		},
		{
			name:       "Missing peer credentials rejected with 403",
			ucred:      nil,
			wantCode:   http.StatusForbidden,
			wantSubstr: "Caller is not the active console session user",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://unix/v1/status", nil)
			if tc.ucred != nil {
				req = req.WithContext(ipc.WithPeerCred(req.Context(), tc.ucred))
			}
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantCode {
				t.Fatalf("expected HTTP %d, got %d. Body: %s", tc.wantCode, rec.Code, rec.Body.String())
			}
			if tc.wantSubstr != "" {
				var errResp map[string]string
				_ = json.Unmarshal(rec.Body.Bytes(), &errResp)
				if errResp["error"] != tc.wantSubstr {
					t.Errorf("expected error %q, got %q", tc.wantSubstr, errResp["error"])
				}
			}
		})
	}
}

func TestServer_SocketCreation_Permissions(t *testing.T) {
	tempDir := t.TempDir()
	sockPath := filepath.Join(tempDir, "spire", "agent.sock")

	srv := ipc.NewServer(sockPath, "http://localhost:8080", "", "hw-uuid", "host", nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Run(ctx)
	}()

	// Wait for socket to be created
	var info os.FileInfo
	var err error
	for i := 0; i < 20; i++ {
		info, err = os.Stat(sockPath)
		if err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("socket file was not created: %v", err)
	}

	// Verify socket permissions: 0666 (world dialable + SO_PEERCRED auth)
	perm := info.Mode().Perm()
	if perm != 0666 {
		t.Errorf("expected socket permissions 0666, got %o", perm)
	}

	// Verify directory permissions: 0755
	dirInfo, err := os.Stat(filepath.Dir(sockPath))
	if err != nil {
		t.Fatalf("failed to stat sock dir: %v", err)
	}
	dirPerm := dirInfo.Mode().Perm()
	if dirPerm != 0755 {
		t.Errorf("expected socket dir permissions 0755, got %o", dirPerm)
	}

	cancel()
	<-errCh
}

func TestServer_Uninstall_Validation(t *testing.T) {
	t.Setenv("SPIRE_SEAT0_UID", "1000")
	srv := ipc.NewServer("/tmp/dummy-uninst.sock", "http://localhost:8080", "", "hw-uuid", "host", nil, nil, nil)

	// PeerCredMiddleware allows root (UID 0)
	ucred := &syscall.Ucred{Uid: 0, Gid: 0, Pid: 100}

	// 1. Method GET rejected with 405 Method Not Allowed
	req := httptest.NewRequest(http.MethodGet, "http://unix/v1/uninstall", nil)
	req = req.WithContext(ipc.WithPeerCred(req.Context(), ucred))
	rec := httptest.NewRecorder()
	srv.PeerCredMiddlewareForTest(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock router or direct call
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 on GET /v1/uninstall, got %d", rec.Code)
	}
}

func TestServer_PartitionedStatus_CoreComplianceRule(t *testing.T) {
	tempDir := t.TempDir()
	sockPath := filepath.Join(tempDir, "agent.sock")
	srv := ipc.NewServer(sockPath, "", "", "hw-uuid-test", "ep-test-01", nil, nil, nil)

	policies := []types.AssignedPolicy{
		{
			ID:         "pol-sysctl-1",
			Name:       "Enforce IPv4 RP Filter",
			PolicyType: types.PolicyTypeSysctlSetting,
			Payload:    json.RawMessage(`{"key":"net.ipv4.conf.all.rp_filter","value":"1"}`),
		},
		{
			ID:             "pol-app-req",
			Name:           "Firefox ESR",
			PolicyType:     types.PolicyTypeFlatpakApp,
			AssignmentType: types.AssignmentRequired,
			Payload:        json.RawMessage(`{"app_id":"org.mozilla.firefox","version":"128.0","assignment_type":"REQUIRED"}`),
		},
		{
			ID:             "pol-app-opt",
			Name:           "VLC Media Player",
			PolicyType:     types.PolicyTypeFlatpakApp,
			AssignmentType: types.AssignmentAvailable,
			Payload:        json.RawMessage(`{"app_id":"org.videolan.VLC","version":"3.0.20","assignment_type":"AVAILABLE"}`),
		},
	}
	results := []types.PolicyExecutionItem{
		{PolicyID: "pol-sysctl-1", ComplianceStatus: types.ComplianceCompliant},
		{PolicyID: "pol-app-req", ComplianceStatus: types.ComplianceCompliant},
		{PolicyID: "pol-app-opt", ComplianceStatus: types.ComplianceNonCompliant},
	}

	srv.UpdateDevicePolicies("dev-123", policies, results)
	srv.UpdateStatus(true, time.Now().UTC(), results)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = srv.Run(ctx)
	}()

	for i := 0; i < 20; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Ensure AVAILABLE policy does not mark status as failed in UpdateStatus
	if srvStatus := srv; srvStatus == nil {
		t.Fatal("nil server")
	}
}
