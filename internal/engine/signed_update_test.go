package engine_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/release"
	"github.com/spire-uem/spire-uem/internal/types"
)

// signedDebServer serves the .deb at /dist/<name> and the manifest at /dist/<name>.manifest.json.
func signedDebServer(t *testing.T, deb []byte, debName string, manifest []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/dist/" + debName:
			_, _ = w.Write(deb)
		case "/dist/" + debName + ".manifest.json":
			if manifest == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(manifest)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func signManifest(t *testing.T, priv ed25519.PrivateKey, deb []byte, version string, expires time.Time) []byte {
	t.Helper()
	sum := sha256.Sum256(deb)
	p := release.Payload{
		Version:      version,
		Package:      "spire-agent",
		Architecture: "amd64",
		SHA256:       hex.EncodeToString(sum[:]),
		Size:         int64(len(deb)),
		IssuedAt:     time.Now().Add(-time.Hour),
		ExpiresAt:    expires,
	}
	m, err := release.Sign(priv, p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := release.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func signedDirective(debName, sum string, size int64) *types.AgentUpdateDirective {
	return &types.AgentUpdateDirective{
		Action:        types.UpdateActionUpdate,
		TargetVersion: "0.2.0",
		Artifact: &types.AgentArtifact{
			Version:     "0.2.0",
			URL:         "/dist/" + debName,
			SHA256:      sum,
			Size:        size,
			ManifestURL: "/dist/" + debName + ".manifest.json",
		},
	}
}

func newSignedUpdater(t *testing.T, srv *httptest.Server, trust map[string]ed25519.PublicKey, requireSigned bool, installer engine.Installer) *engine.SelfUpdater {
	t.Helper()
	u := engine.NewSelfUpdater(srv.Client(), srv.URL, "0.1.0", installer)
	engine.SetUpdaterStatePath(u, filepath.Join(t.TempDir(), "state.json"))
	engine.SetSignatureVerification(u, trust, requireSigned, "")
	return u
}

func TestSignedUpdate_SuccessVerifiesManifestThenInstalls(t *testing.T) {
	pub, priv, _ := release.GenerateKey()
	deb := []byte("new agent 0.2.0 package bytes")
	name := "spire-agent_0.2.0_amd64.deb"
	manifest := signManifest(t, priv, deb, "0.2.0", time.Now().Add(24*time.Hour))
	srv := signedDebServer(t, deb, name, manifest)
	defer srv.Close()

	installed := false
	u := newSignedUpdater(t, srv, map[string]ed25519.PublicKey{release.KeyID(pub): pub}, true,
		func(ctx context.Context, p string) error { installed = true; return nil })

	sum := sha256.Sum256(deb)
	d := signedDirective(name, hex.EncodeToString(sum[:]), int64(len(deb)))
	res := u.ApplyDirective(context.Background(), d, "")
	if res == nil || res.Status != types.AgentUpdateSuccess {
		t.Fatalf("expected SUCCESS, got %+v", res)
	}
	if !installed {
		t.Fatal("installer never ran on a valid signed update")
	}
}

func TestSignedUpdate_ServerSizeDisagreesWithManifest(t *testing.T) {
	pub, priv, _ := release.GenerateKey()
	deb := []byte("agent bytes xyz")
	name := "spire-agent_0.2.0_amd64.deb"
	manifest := signManifest(t, priv, deb, "0.2.0", time.Now().Add(24*time.Hour))
	srv := signedDebServer(t, deb, name, manifest)
	defer srv.Close()

	installed := false
	u := newSignedUpdater(t, srv, map[string]ed25519.PublicKey{release.KeyID(pub): pub}, true,
		func(ctx context.Context, p string) error { installed = true; return nil })

	sum := sha256.Sum256(deb)
	// Server advertises a size that disagrees with the signed manifest → refuse.
	d := signedDirective(name, hex.EncodeToString(sum[:]), int64(len(deb)+5))
	res := u.ApplyDirective(context.Background(), d, "")
	if res == nil || res.Status != types.AgentUpdateFailed {
		t.Fatalf("expected FAILED on server/manifest size disagreement, got %+v", res)
	}
	if installed {
		t.Fatal("installer must not run when the server disagrees with the signed manifest")
	}
}

func TestSignedUpdate_UnknownKeyRefused(t *testing.T) {
	_, priv, _ := release.GenerateKey()
	otherPub, _, _ := release.GenerateKey()
	deb := []byte("agent bytes abc")
	name := "spire-agent_0.2.0_amd64.deb"
	manifest := signManifest(t, priv, deb, "0.2.0", time.Now().Add(24*time.Hour))
	srv := signedDebServer(t, deb, name, manifest)
	defer srv.Close()

	installed := false
	// Trust a DIFFERENT key only → manifest's key_id is unknown.
	u := newSignedUpdater(t, srv, map[string]ed25519.PublicKey{release.KeyID(otherPub): otherPub}, true,
		func(ctx context.Context, p string) error { installed = true; return nil })

	sum := sha256.Sum256(deb)
	d := signedDirective(name, hex.EncodeToString(sum[:]), int64(len(deb)))
	res := u.ApplyDirective(context.Background(), d, "")
	if res == nil || res.Status != types.AgentUpdateFailed {
		t.Fatalf("expected FAILED for unknown key, got %+v", res)
	}
	if installed {
		t.Fatal("installer must not run for an unknown signing key")
	}
}

func TestSignedUpdate_ExpiredManifestRefused(t *testing.T) {
	pub, priv, _ := release.GenerateKey()
	deb := []byte("agent bytes exp")
	name := "spire-agent_0.2.0_amd64.deb"
	manifest := signManifest(t, priv, deb, "0.2.0", time.Now().Add(-time.Minute)) // already expired
	srv := signedDebServer(t, deb, name, manifest)
	defer srv.Close()

	u := newSignedUpdater(t, srv, map[string]ed25519.PublicKey{release.KeyID(pub): pub}, true,
		func(ctx context.Context, p string) error { t.Fatal("installer must not run for expired manifest"); return nil })

	sum := sha256.Sum256(deb)
	d := signedDirective(name, hex.EncodeToString(sum[:]), int64(len(deb)))
	if res := u.ApplyDirective(context.Background(), d, ""); res == nil || res.Status != types.AgentUpdateFailed {
		t.Fatalf("expected FAILED for expired manifest, got %+v", res)
	}
}

func TestSignedUpdate_DowngradeRefused(t *testing.T) {
	pub, priv, _ := release.GenerateKey()
	deb := []byte("older agent")
	name := "spire-agent_0.0.9_amd64.deb"
	manifest := signManifest(t, priv, deb, "0.0.9", time.Now().Add(24*time.Hour))
	srv := signedDebServer(t, deb, name, manifest)
	defer srv.Close()

	// Running 0.1.0; directive target 0.0.9 < running → no-downgrade refusal.
	u := engine.NewSelfUpdater(srv.Client(), srv.URL, "0.1.0",
		func(ctx context.Context, p string) error { t.Fatal("installer must not run for a downgrade"); return nil })
	engine.SetUpdaterStatePath(u, filepath.Join(t.TempDir(), "state.json"))
	engine.SetSignatureVerification(u, map[string]ed25519.PublicKey{release.KeyID(pub): pub}, true, "")

	sum := sha256.Sum256(deb)
	d := &types.AgentUpdateDirective{
		Action:        types.UpdateActionUpdate,
		TargetVersion: "0.0.9",
		Artifact:      &types.AgentArtifact{Version: "0.0.9", URL: "/dist/" + name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(deb)), ManifestURL: "/dist/" + name + ".manifest.json"},
	}
	if res := u.ApplyDirective(context.Background(), d, ""); res == nil || res.Status != types.AgentUpdateFailed {
		t.Fatalf("expected FAILED for downgrade, got %+v", res)
	}
}

func TestSignedUpdate_RequireSignedButNoManifest(t *testing.T) {
	deb := []byte("agent bytes nomanifest")
	name := "spire-agent_0.2.0_amd64.deb"
	srv := signedDebServer(t, deb, name, nil) // no manifest served
	defer srv.Close()

	installed := false
	// require_signed=true but the directive has no ManifestURL.
	u := engine.NewSelfUpdater(srv.Client(), srv.URL, "0.1.0",
		func(ctx context.Context, p string) error { installed = true; return nil })
	engine.SetUpdaterStatePath(u, filepath.Join(t.TempDir(), "state.json"))
	engine.SetSignatureVerification(u, map[string]ed25519.PublicKey{}, true, "")

	sum := sha256.Sum256(deb)
	d := &types.AgentUpdateDirective{
		Action:        types.UpdateActionUpdate,
		TargetVersion: "0.2.0",
		Artifact:      &types.AgentArtifact{Version: "0.2.0", URL: "/dist/" + name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(deb))}, // no ManifestURL
	}
	res := u.ApplyDirective(context.Background(), d, "")
	if res == nil || res.Status != types.AgentUpdateFailed {
		t.Fatalf("expected FAILED when require_signed and no manifest, got %+v", res)
	}
	if installed {
		t.Fatal("installer must not run when signed updates are required and none is available")
	}
}

func TestSignedUpdate_RequireSignedFalseUnsignedFallback(t *testing.T) {
	deb := []byte("legacy unsigned agent bytes")
	name := "spire-agent_0.2.0_amd64.deb"
	srv := signedDebServer(t, deb, name, nil) // no manifest
	defer srv.Close()

	installed := false
	// require_signed=false and no manifest → legacy size+sha path, install with warning.
	u := engine.NewSelfUpdater(srv.Client(), srv.URL, "0.1.0",
		func(ctx context.Context, p string) error { installed = true; return nil })
	engine.SetUpdaterStatePath(u, filepath.Join(t.TempDir(), "state.json"))
	engine.SetSignatureVerification(u, map[string]ed25519.PublicKey{}, false, "")

	sum := sha256.Sum256(deb)
	d := &types.AgentUpdateDirective{
		Action:        types.UpdateActionUpdate,
		TargetVersion: "0.2.0",
		Artifact:      &types.AgentArtifact{Version: "0.2.0", URL: "/dist/" + name, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(deb))},
	}
	res := u.ApplyDirective(context.Background(), d, "")
	if res == nil || res.Status != types.AgentUpdateSuccess {
		t.Fatalf("expected SUCCESS via unsigned fallback, got %+v", res)
	}
	if !installed {
		t.Fatal("installer should run on the unsigned fallback path when require_signed is off")
	}
}

func TestSignedUpdate_TamperedBytesRefused(t *testing.T) {
	pub, priv, _ := release.GenerateKey()
	realDeb := []byte("the signed bytes")
	name := "spire-agent_0.2.0_amd64.deb"
	manifest := signManifest(t, priv, realDeb, "0.2.0", time.Now().Add(24*time.Hour))
	// Server actually serves DIFFERENT bytes than the manifest was signed over.
	tampered := []byte("tampered-by-compromised-server!!")
	srv := signedDebServer(t, tampered, name, manifest)
	defer srv.Close()

	installed := false
	u := newSignedUpdater(t, srv, map[string]ed25519.PublicKey{release.KeyID(pub): pub}, true,
		func(ctx context.Context, p string) error { installed = true; return nil })

	// Directive advertises the signed sha/size (as a compromised server would, to look
	// consistent), but the bytes served don't match → refuse.
	sum := sha256.Sum256(realDeb)
	d := signedDirective(name, hex.EncodeToString(sum[:]), int64(len(realDeb)))
	res := u.ApplyDirective(context.Background(), d, "")
	if res == nil || res.Status != types.AgentUpdateFailed {
		t.Fatalf("expected FAILED when served bytes != signed manifest, got %+v", res)
	}
	if installed {
		t.Fatal("installer must not run when the downloaded bytes do not match the signed manifest")
	}
}
