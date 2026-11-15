package engine_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/types"
)

// debServer serves the given bytes at /dist/<name>, requiring the bearer token.
func debServer(t *testing.T, body []byte, wantToken string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wantToken != "" && r.Header.Get("Authorization") != "Bearer "+wantToken {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.debian.binary-package")
		_, _ = w.Write(body)
	}))
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func directive(version, url, sum string, size int64) *types.AgentUpdateDirective {
	return &types.AgentUpdateDirective{
		Action:        types.UpdateActionUpdate,
		TargetVersion: version,
		Artifact:      &types.AgentArtifact{Version: version, URL: url, SHA256: sum, Size: size},
	}
}

func TestApplyDirective_SuccessVerifiesThenInstalls(t *testing.T) {
	body := []byte("fake .deb package contents")
	srv := debServer(t, body, "tok-123")
	defer srv.Close()

	var installedPath string
	var installedBytes []byte
	installer := func(ctx context.Context, debPath string) error {
		installedPath = debPath
		b, _ := os.ReadFile(debPath)
		installedBytes = b
		return nil
	}

	u := engine.NewSelfUpdater(srv.Client(), srv.URL, "0.1.0", installer)
	engine.SetUpdaterStatePath(u, filepath.Join(t.TempDir(), "state.json"))

	d := directive("0.2.0", "/dist/spire-agent_0.2.0_amd64.deb", sha256hex(body), int64(len(body)))
	res := u.ApplyDirective(context.Background(), d, "tok-123")

	if res == nil || res.Status != types.AgentUpdateSuccess {
		t.Fatalf("expected SUCCESS, got %+v", res)
	}
	if installedPath == "" {
		t.Fatal("installer was never called")
	}
	if string(installedBytes) != string(body) {
		t.Fatalf("installer received wrong bytes: %q", installedBytes)
	}
	if _, err := os.Stat(installedPath); !os.IsNotExist(err) {
		t.Errorf("temp .deb should be cleaned up after install, still at %s", installedPath)
	}
}

func TestApplyDirective_SHA256MismatchDoesNotInstall(t *testing.T) {
	body := []byte("real contents")
	srv := debServer(t, body, "")
	defer srv.Close()

	called := false
	installer := func(ctx context.Context, debPath string) error { called = true; return nil }

	u := engine.NewSelfUpdater(srv.Client(), srv.URL, "0.1.0", installer)
	engine.SetUpdaterStatePath(u, filepath.Join(t.TempDir(), "state.json"))

	// Wrong sha256.
	d := directive("0.2.0", "/dist/x.deb", sha256hex([]byte("different")), int64(len(body)))
	res := u.ApplyDirective(context.Background(), d, "")

	if res == nil || res.Status != types.AgentUpdateFailed {
		t.Fatalf("expected FAILED, got %+v", res)
	}
	if called {
		t.Fatal("installer MUST NOT run when sha256 does not match")
	}
}

func TestApplyDirective_SizeMismatchDoesNotInstall(t *testing.T) {
	body := []byte("twelve bytes")
	srv := debServer(t, body, "")
	defer srv.Close()

	called := false
	installer := func(ctx context.Context, debPath string) error { called = true; return nil }

	u := engine.NewSelfUpdater(srv.Client(), srv.URL, "0.1.0", installer)
	engine.SetUpdaterStatePath(u, filepath.Join(t.TempDir(), "state.json"))

	// Declared size wrong (too large), correct sha256 — size check must still catch it.
	d := directive("0.2.0", "/dist/x.deb", sha256hex(body), int64(len(body)+100))
	res := u.ApplyDirective(context.Background(), d, "")

	if res == nil || res.Status != types.AgentUpdateFailed {
		t.Fatalf("expected FAILED on size mismatch, got %+v", res)
	}
	if called {
		t.Fatal("installer MUST NOT run when size does not match")
	}
}

func TestApplyDirective_NoopOnNoneAction(t *testing.T) {
	u := engine.NewSelfUpdater(http.DefaultClient, "http://unused", "0.1.0", func(ctx context.Context, p string) error {
		t.Fatal("installer should not be called for a none directive")
		return nil
	})
	engine.SetUpdaterStatePath(u, filepath.Join(t.TempDir(), "state.json"))

	if res := u.ApplyDirective(context.Background(), nil, ""); res != nil {
		t.Errorf("nil directive should yield nil result, got %+v", res)
	}
	if res := u.ApplyDirective(context.Background(), &types.AgentUpdateDirective{Action: types.UpdateActionNone}, ""); res != nil {
		t.Errorf("none action should yield nil result, got %+v", res)
	}
}

func TestApplyDirective_FailureBacksOff(t *testing.T) {
	body := []byte("contents")
	srv := debServer(t, body, "")
	defer srv.Close()

	calls := 0
	installer := func(ctx context.Context, debPath string) error { calls++; return nil }

	statePath := filepath.Join(t.TempDir(), "state.json")
	u := engine.NewSelfUpdater(srv.Client(), srv.URL, "0.1.0", installer)
	engine.SetUpdaterStatePath(u, statePath)

	// First attempt fails verification (bad sha), recording a FAILED state.
	bad := directive("0.2.0", "/dist/x.deb", sha256hex([]byte("other")), int64(len(body)))
	if res := u.ApplyDirective(context.Background(), bad, ""); res == nil || res.Status != types.AgentUpdateFailed {
		t.Fatalf("expected first attempt FAILED, got %+v", res)
	}

	// A fresh updater pointed at the same state file + same target must back off (no retry).
	u2 := engine.NewSelfUpdater(srv.Client(), srv.URL, "0.1.0", installer)
	engine.SetUpdaterStatePath(u2, statePath)
	if res := u2.ApplyDirective(context.Background(), bad, ""); res != nil {
		t.Errorf("second attempt within backoff window should be skipped (nil), got %+v", res)
	}
	if calls != 0 {
		t.Errorf("installer should never have run on a verify failure, calls=%d", calls)
	}
}

func TestConsumePendingUpdateResult(t *testing.T) {
	body := []byte("ok")
	srv := debServer(t, body, "")
	defer srv.Close()

	statePath := filepath.Join(t.TempDir(), "state.json")
	installer := func(ctx context.Context, debPath string) error { return nil }
	u := engine.NewSelfUpdater(srv.Client(), srv.URL, "0.1.0", installer)
	engine.SetUpdaterStatePath(u, statePath)

	d := directive("0.2.0", "/dist/x.deb", sha256hex(body), int64(len(body)))
	if res := u.ApplyDirective(context.Background(), d, ""); res == nil || res.Status != types.AgentUpdateSuccess {
		t.Fatalf("expected SUCCESS, got %+v", res)
	}

	// The persisted result is consumable exactly once (survives an agent restart).
	got := engine.ConsumePendingUpdateResult(statePath)
	if got == nil || got.Status != types.AgentUpdateSuccess || got.TargetVersion != "0.2.0" {
		t.Fatalf("expected consumable SUCCESS result, got %+v", got)
	}
	if again := engine.ConsumePendingUpdateResult(statePath); again != nil {
		t.Errorf("result should be consumed only once, got %+v", again)
	}
}

// An absolute artifact URL must be refused before any request is made, so the device token is
// never sent to another host.
func TestApplyDirective_RejectsAbsoluteArtifactURL(t *testing.T) {
	hit := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer other.Close()
	installer := func(ctx context.Context, p string) error { t.Fatal("installer must not run"); return nil }
	u := engine.NewSelfUpdater(other.Client(), "http://127.0.0.1:1", "0.1.0", installer)
	engine.SetUpdaterStatePath(u, filepath.Join(t.TempDir(), "state.json"))
	for _, url := range []string{other.URL + "/x.deb", "//evil.example/x.deb"} {
		res := u.ApplyDirective(context.Background(), directive("0.2.0", url, "00", 1), "tok")
		if res == nil || res.Status != types.AgentUpdateFailed {
			t.Errorf("%s: expected failure, got %+v", url, res)
		}
		engine.SetUpdaterStatePath(u, filepath.Join(t.TempDir(), "state.json"))
	}
	if hit {
		t.Fatal("agent contacted a host other than its server")
	}
}
