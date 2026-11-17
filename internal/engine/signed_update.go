package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/release"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/version"
)

// signatureConfig holds the agent's release-signing trust state. It is built from the keys
// shipped INSIDE the agent package (never fetched from the server) plus the
// require_signed_updates setting.
type signatureConfig struct {
	trust         map[string]ed25519.PublicKey
	requireSigned bool
	// keysDir is recorded only for diagnostics.
	keysDir string
}

// SetSignatureVerification configures a SelfUpdater's release-signature trust. trust maps
// key_id -> pinned public key (release.LoadTrustAnchors output); requireSigned refuses any
// update without a valid manifest. Called from the agent with the package-shipped keys.
func SetSignatureVerification(u *SelfUpdater, trust map[string]ed25519.PublicKey, requireSigned bool, keysDir string) {
	u.sig = &signatureConfig{trust: trust, requireSigned: requireSigned, keysDir: keysDir}
}

// verifySignedUpdate enforces the full pre-install verification order against the downloaded
// .deb and the directive, returning the verified semantics or an error. It is the security
// core of requirement 4. Order (any failure refuses the install):
//
//  1. manifest signature valid under a pinned key; key_id known; not expired/not-yet-valid;
//  2. package and arch in the manifest match the expected package/arch;
//  3. manifest version equals the directive target and is strictly greater than running
//     (no-downgrade);
//  4. the downloaded bytes' sha256 and size equal the SIGNED manifest values;
//  5. the server-advertised sha/size must equal the manifest too, else refuse (a server that
//     disagrees with the signed manifest is treated as hostile).
//
// When require_signed is false and no manifest is available, it returns (nil, nil): the
// caller then falls back to the legacy size+sha256 check and logs a loud per-update warning.
func (u *SelfUpdater) verifySignedUpdate(ctx context.Context, debPath string, d *types.AgentUpdateDirective, token string) (*release.Payload, error) {
	a := d.Artifact
	target := strings.TrimSpace(d.TargetVersion)
	if target == "" {
		target = strings.TrimSpace(a.Version)
	}

	hasManifestURL := a != nil && strings.TrimSpace(a.ManifestURL) != ""
	requireSigned := u.sig != nil && u.sig.requireSigned

	if !hasManifestURL {
		if requireSigned {
			return nil, fmt.Errorf("require_signed_updates is on but the server advertised no signed manifest for %s", target)
		}
		// Unsigned transition path: caller does the legacy check and logs the warning.
		return nil, nil
	}

	// Fetch the detached manifest from the server (same host, same bearer token).
	manifestBytes, err := u.downloadBytes(ctx, a.ManifestURL, token, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	m, err := release.ParseManifest(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	trust := map[string]ed25519.PublicKey{}
	if u.sig != nil {
		trust = u.sig.trust
	}
	payload, err := release.VerifyManifest(m, trust, u.now())
	if err != nil {
		// 1. signature / key_id / expiry failures surface here.
		return nil, fmt.Errorf("manifest verification: %w", err)
	}

	// 2. package + arch must match what this agent is.
	if payload.Package != "" && payload.Package != expectedPackageName {
		return nil, fmt.Errorf("manifest package %q != expected %q", payload.Package, expectedPackageName)
	}
	if payload.Architecture != "" && payload.Architecture != expectedArch {
		return nil, fmt.Errorf("manifest arch %q != expected %q", payload.Architecture, expectedArch)
	}

	// 3. version == directive target, and strictly greater than running (no downgrade).
	if payload.Version != target {
		return nil, fmt.Errorf("manifest version %q != directive target %q", payload.Version, target)
	}
	if !version.IsDev(u.currentVer) && version.Compare(payload.Version, u.currentVer) <= 0 {
		return nil, fmt.Errorf("refusing downgrade/equal: manifest version %q not greater than running %q", payload.Version, u.currentVer)
	}

	// 4. downloaded bytes' sha256 + size equal the SIGNED values.
	sum, size, err := hashAndSize(debPath)
	if err != nil {
		return nil, err
	}
	if size != payload.Size {
		return nil, fmt.Errorf("downloaded size %d != signed manifest size %d", size, payload.Size)
	}
	if sum != payload.SHA256 {
		return nil, fmt.Errorf("downloaded sha256 %s != signed manifest sha256 %s", sum, payload.SHA256)
	}

	// 5. the server-advertised sha/size must agree with the SIGNED manifest.
	if a.Size > 0 && a.Size != payload.Size {
		return nil, fmt.Errorf("server-advertised size %d disagrees with signed manifest %d", a.Size, payload.Size)
	}
	if adv := strings.ToLower(strings.TrimSpace(a.SHA256)); adv != "" && adv != payload.SHA256 {
		return nil, fmt.Errorf("server-advertised sha256 %s disagrees with signed manifest %s", adv, payload.SHA256)
	}

	return payload, nil
}

// expectedPackageName / expectedArch are what a signed manifest must claim for THIS agent.
// They match the Makefile `deb` target output (spire-agent_<v>_amd64.deb).
const (
	expectedPackageName = "spire-agent"
	expectedArch        = "amd64"
)

// downloadBytes fetches a small server resource (the manifest) over the same connection,
// enforcing a byte cap and the server-path-only rule used for the .deb.
func (u *SelfUpdater) downloadBytes(ctx context.Context, path, token string, cap int64) ([]byte, error) {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return nil, fmt.Errorf("manifest URL must be a path on the server, got %q", path)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.serverURL+path, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, cap))
}

// hashAndSize returns the lowercase-hex SHA-256 and byte size of a file.
func hashAndSize(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// logUnsignedWarning emits the loud per-update warning required when an unsigned update is
// installed because require_signed_updates is off.
func logUnsignedWarning(target string) {
	log.Printf("[spired] SECURITY WARNING: installing UNSIGNED agent update to %s because require_signed_updates is OFF. "+
		"This update's integrity rests only on the control plane, which also serves the bytes. "+
		"Set require_signed_updates=true once all agents understand signed manifests. (see ADMIN_RUNBOOK unsigned-to-signed transition)", target)
}

// updateDeadlineDefault is how long the new agent has to confirm healthy before the
// independent rollback trigger reinstalls the previous package.
const updateDeadlineDefault = 10 * time.Minute
