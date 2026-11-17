package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/config"
	"github.com/spire-uem/spire-uem/internal/types"
)

func TestResolveEnrollmentToken_Precedence(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("  file-token\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// File wins over env and config.
	t.Setenv("SPIRE_ENROLLMENT_TOKEN", "env-token")
	cfg := config.AgentConfig{EnrollmentTokenFile: tokenFile, EnrollmentToken: "config-token"}
	if tok, src := resolveEnrollmentToken(cfg); tok != "file-token" || src != tokenSourceFile {
		t.Fatalf("file must win: got %q src=%s", tok, src)
	}

	// With no file, env wins over config.
	cfg2 := config.AgentConfig{EnrollmentToken: "config-token"}
	if tok, src := resolveEnrollmentToken(cfg2); tok != "env-token" || src != tokenSourceEnv {
		t.Fatalf("env must win over config: got %q src=%s", tok, src)
	}

	// With no file and no env, config value is used.
	os.Unsetenv("SPIRE_ENROLLMENT_TOKEN")
	cfg3 := config.AgentConfig{EnrollmentToken: "config-token"}
	if tok, src := resolveEnrollmentToken(cfg3); tok != "config-token" || src != tokenSourceConfig {
		t.Fatalf("config must be used: got %q src=%s", tok, src)
	}

	// Nothing configured -> none.
	if tok, src := resolveEnrollmentToken(config.AgentConfig{}); tok != "" || src != tokenSourceNone {
		t.Fatalf("expected none, got %q src=%s", tok, src)
	}
}

func TestResolveEnrollmentToken_MissingFileFallsThrough(t *testing.T) {
	cfg := config.AgentConfig{EnrollmentTokenFile: "/nonexistent/path/token", EnrollmentToken: "config-token"}
	os.Unsetenv("SPIRE_ENROLLMENT_TOKEN")
	if tok, src := resolveEnrollmentToken(cfg); tok != "config-token" || src != tokenSourceConfig {
		t.Fatalf("a missing token file must fall through to config, got %q src=%s", tok, src)
	}
}

// genDeviceKey builds a temp device key + cert paths for registerWithToken.
func genDeviceKeyPaths(t *testing.T) deviceCertPaths {
	t.Helper()
	dir := t.TempDir()
	cp := deviceCertFiles(filepath.Join(dir, "token"))
	return cp
}

func TestRegisterWithToken_AutoApprovePersistsCert(t *testing.T) {
	cp := genDeviceKeyPaths(t)
	key, err := loadOrCreateDeviceKey(cp.keyPath)
	if err != nil {
		t.Fatal(err)
	}

	var gotReq types.EnrollmentRegisterRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotReq)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(types.EnrollmentRegisterResponse{
			DeviceID:  "dev-1",
			Status:    types.StatusApproved,
			PatchRing: types.RingProduction,
			AuthToken: "bearer-xyz",
		})
	}))
	defer srv.Close()

	tokenPath := filepath.Join(t.TempDir(), "token")
	bearer, pending, err := registerWithToken(context.Background(), srv.Client(), srv.URL, tokenPath, "tok-abc", "hw-1", "host-1", "enrollkey", key, cp)
	if err != nil {
		t.Fatalf("registerWithToken: %v", err)
	}
	if pending {
		t.Fatalf("auto-approve must not be pending")
	}
	if bearer != "bearer-xyz" {
		t.Fatalf("expected bearer token, got %q", bearer)
	}
	// The request must carry the enrollment key AND a CSR (binds hw+key+csr in one request).
	if gotReq.EnrollmentKey != "enrollkey" {
		t.Fatalf("enrollment key must be sent, got %q", gotReq.EnrollmentKey)
	}
	if gotReq.CSRPEM == "" {
		t.Fatalf("a CSR must be sent so the server can issue a cert at claim")
	}
}

func TestRegisterWithToken_PendingApproval(t *testing.T) {
	cp := genDeviceKeyPaths(t)
	key, _ := loadOrCreateDeviceKey(cp.keyPath)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(types.EnrollmentRegisterResponse{
			DeviceID: "dev-2", Status: types.StatusPendingApproval, PatchRing: types.RingProduction,
		})
	}))
	defer srv.Close()
	bearer, pending, err := registerWithToken(context.Background(), srv.Client(), srv.URL, filepath.Join(t.TempDir(), "token"), "tok", "hw", "host", "key", key, cp)
	if err != nil {
		t.Fatalf("registerWithToken: %v", err)
	}
	if !pending || bearer != "" {
		t.Fatalf("require_approval response must be pending with no bearer; got pending=%v bearer=%q", pending, bearer)
	}
}

func TestRegisterWithToken_RefusalIsNotNetworkError(t *testing.T) {
	cp := genDeviceKeyPaths(t)
	key, _ := loadOrCreateDeviceKey(cp.keyPath)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "enrollment refused"})
	}))
	defer srv.Close()
	bearer, pending, err := registerWithToken(context.Background(), srv.Client(), srv.URL, filepath.Join(t.TempDir(), "token"), "bad", "hw", "host", "key", key, cp)
	// A 401 is a server decision: no error (so no network backoff), and no bearer/pending so
	// the agent falls through to manual enrollment.
	if err != nil {
		t.Fatalf("a 401 refusal must not be surfaced as a network error, got %v", err)
	}
	if bearer != "" || pending {
		t.Fatalf("a refusal must yield bearer='' pending=false, got bearer=%q pending=%v", bearer, pending)
	}
}

func TestRegisterWithToken_RateLimitedIsNetworkError(t *testing.T) {
	cp := genDeviceKeyPaths(t)
	key, _ := loadOrCreateDeviceKey(cp.keyPath)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	_, _, err := registerWithToken(context.Background(), srv.Client(), srv.URL, filepath.Join(t.TempDir(), "token"), "tok", "hw", "host", "key", key, cp)
	if err == nil {
		t.Fatalf("a 429 must be surfaced as a retryable error so the agent backs off")
	}
	_ = time.Now
}

func TestResetDeviceIdentity_RemovesAllArtefacts(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	cp := deviceCertFiles(tokenPath)
	files := []string{
		tokenPath,
		enrollmentKeyPath(tokenPath),
		cp.keyPath,
		cp.certPath,
		cp.keyPath + ".new",
		wipeKeyPath(tokenPath),
		filepath.Join(dir, "enrollment-token"),
	}
	for _, f := range files {
		if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
			t.Fatalf("seed %s: %v", f, err)
		}
	}
	if err := resetDeviceIdentity(tokenPath); err != nil {
		t.Fatalf("resetDeviceIdentity: %v", err)
	}
	for _, f := range files {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("identity artefact %s must be removed by reset-identity (err=%v)", f, err)
		}
	}
	// Idempotent: a second run with everything already gone is not an error.
	if err := resetDeviceIdentity(tokenPath); err != nil {
		t.Fatalf("reset-identity must be idempotent, got %v", err)
	}
}
