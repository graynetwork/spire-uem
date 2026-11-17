package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// DefaultUpdateStatePath records the last self-update attempt so the agent can report the
// result on the next check-in and back off after a failure instead of hot-looping.
const DefaultUpdateStatePath = "/etc/spire/update-state.json"

// updateFailureBackoff is the minimum interval between attempts at the SAME target version
// after a failure, so a persistently-failing target does not re-download every cycle.
const updateFailureBackoff = 30 * time.Minute

// rolledBackBackoff blocks reinstalling a target that was rolled back, so a version that
// cannot confirm healthy is not reinstalled every check-in.
const rolledBackBackoff = 24 * time.Hour

// maxArtifactBytes caps the .deb download size defensively (256 MiB); the server-declared
// Size is also enforced exactly.
const maxArtifactBytes = 256 << 20

// Installer installs a downloaded .deb and returns an error on failure. It is injected so
// tests exercise verify-then-install without touching dpkg or systemd. The production
// implementation (SystemdRunInstaller) detaches the install via systemd-run so the agent
// does not kill itself when dpkg restarts spired.service.
type Installer func(ctx context.Context, debPath string) error

// SelfUpdater performs verified agent self-updates driven by the server's check-in directive.
type SelfUpdater struct {
	client      *http.Client
	serverURL   string
	currentVer  string
	installer   Installer
	downloadDir string
	statePath   string
	now         func() time.Time
	// sig carries the pinned release trust anchors and require_signed flag. Nil means
	// signature verification is not configured (legacy behaviour: size+sha only).
	sig *signatureConfig
	// rollback stages the previous package and arms an independent rollback trigger before
	// install. Nil disables rollback staging (used by tests that only exercise verification).
	rollback *Rollbacker
}

// SetRollbacker attaches a Rollbacker so a successful install is preceded by staging the
// previous package and arming an independent rollback trigger.
func SetRollbacker(u *SelfUpdater, rb *Rollbacker) { u.rollback = rb }

// NewSelfUpdater builds a SelfUpdater. A nil installer defaults to SystemdRunInstaller.
func NewSelfUpdater(client *http.Client, serverURL, currentVersion string, installer Installer) *SelfUpdater {
	if installer == nil {
		installer = SystemdRunInstaller
	}
	return &SelfUpdater{
		client:      client,
		serverURL:   strings.TrimRight(serverURL, "/"),
		currentVer:  currentVersion,
		installer:   installer,
		downloadDir: os.TempDir(),
		statePath:   DefaultUpdateStatePath,
		now:         time.Now,
	}
}

// SetUpdaterStatePath points a SelfUpdater at a specific state file and uses that file's
// directory as the download scratch dir. Intended for tests, so the updater never writes to
// /etc/spire or /tmp of the host under test.
func SetUpdaterStatePath(u *SelfUpdater, path string) {
	u.statePath = path
	u.downloadDir = filepath.Dir(path)
}

// updateState is the small on-disk record of the last attempt.
type updateState struct {
	TargetVersion string    `json:"target_version"`
	Status        string    `json:"status"`
	Message       string    `json:"message"`
	AttemptedAt   time.Time `json:"attempted_at"`
	Reported      bool      `json:"reported"`
}

// ApplyDirective downloads, verifies and installs the target artifact described by d. It
// returns an AgentUpdateResult to report on the next check-in, or nil when there is nothing
// to do (no directive, action none, already at/above target, or backing off after a recent
// failure of the same target). It verifies size AND sha256 BEFORE installing.
func (u *SelfUpdater) ApplyDirective(ctx context.Context, d *types.AgentUpdateDirective, token string) *types.AgentUpdateResult {
	if d == nil || d.Action != types.UpdateActionUpdate || d.Artifact == nil {
		return nil
	}
	target := strings.TrimSpace(d.TargetVersion)
	if target == "" {
		target = strings.TrimSpace(d.Artifact.Version)
	}
	if target == "" {
		return nil
	}

	// Back off if we recently failed this exact target, to avoid a hot download/install loop.
	if st, err := u.loadState(); err == nil && st != nil && st.TargetVersion == target {
		age := u.now().Sub(st.AttemptedAt)
		if st.Status == types.AgentUpdateFailed && age < updateFailureBackoff {
			return nil
		}
		if st.Status == types.AgentUpdateRolledBack && age < rolledBackBackoff {
			return nil
		}
	}

	result := &types.AgentUpdateResult{
		FromVersion:   u.currentVer,
		TargetVersion: target,
	}

	debPath, err := u.download(ctx, d.Artifact, token)
	if debPath != "" {
		defer os.Remove(debPath)
	}
	if err != nil {
		return u.finish(result, types.AgentUpdateFailed, "download: "+err.Error())
	}

	// Independent signature verification (requirement 4). When a signed manifest is present
	// it is the authority; when it is absent and require_signed is off, fall back to the
	// legacy size+sha256 check with a loud warning.
	signed, err := u.verifySignedUpdate(ctx, debPath, d, token)
	if err != nil {
		return u.finish(result, types.AgentUpdateFailed, "verify: "+err.Error())
	}
	if signed == nil {
		// Unsigned transition path: verify size+sha against the server descriptor only.
		if err := verifyArtifact(debPath, d.Artifact); err != nil {
			return u.finish(result, types.AgentUpdateFailed, "verify: "+err.Error())
		}
		logUnsignedWarning(target)
	}
	// (When signed != nil, verifySignedUpdate already checked the bytes against the SIGNED
	// size+sha256, which is strictly stronger than verifyArtifact.)

	// Stage the previous package and arm the independent rollback trigger BEFORE install, so
	// a new agent that never confirms healthy is reverted without needing the new binary.
	rollbackNote := ""
	if u.rollback != nil {
		if _, armErr := u.rollback.StageAndArm(ctx, u.currentVer, target); armErr != nil {
			if !errors.Is(armErr, ErrNoPreviousPackage) {
				return u.finish(result, types.AgentUpdateFailed, "rollback arm: "+armErr.Error())
			}
			// The running version's package is not on disk (e.g. installed by the bootstrap,
			// which deletes its download). Install anyway; later updates will have rollback.
			log.Printf("[spired] warning: no package for running version %s; installing %s WITHOUT automatic rollback", u.currentVer, target)
			rollbackNote = " (no automatic rollback: previous package unavailable)"
		}
		// Keep the package being installed so the NEXT update can roll back to it.
		if err := u.rollback.KeepInstalled(debPath, target); err != nil {
			log.Printf("[spired] warning: could not keep installed package for future rollback: %v", err)
		}
	}

	if err := u.installer(ctx, debPath); err != nil {
		return u.finish(result, types.AgentUpdateFailed, "install: "+err.Error())
	}

	return u.finish(result, types.AgentUpdateSuccess, fmt.Sprintf("installed %s%s", target, rollbackNote))
}

// download fetches the artifact over the same server connection using the device bearer
// token, enforcing the server-declared Size exactly and a hard byte cap.
func (u *SelfUpdater) download(ctx context.Context, a *types.AgentArtifact, token string) (string, error) {
	// Only accept a path on the configured server. An absolute URL would send the download,
	// and the device's bearer token, to whatever host the directive named.
	if !strings.HasPrefix(a.URL, "/") || strings.HasPrefix(a.URL, "//") {
		return "", fmt.Errorf("artifact URL must be a path on the server, got %q", a.URL)
	}
	url := u.serverURL + a.URL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(u.downloadDir, "spire-agent-*.deb")
	if err != nil {
		return "", err
	}
	limit := a.Size
	if limit <= 0 || limit > maxArtifactBytes {
		limit = maxArtifactBytes
	}
	// Read one extra byte so an oversized body (larger than the declared Size) is detected.
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, limit+1))
	closeErr := tmp.Close()
	if err != nil {
		return tmp.Name(), err
	}
	if closeErr != nil {
		return tmp.Name(), closeErr
	}
	if a.Size > 0 && n != a.Size {
		return tmp.Name(), fmt.Errorf("size mismatch: got %d bytes, expected %d", n, a.Size)
	}
	return tmp.Name(), nil
}

// verifyArtifact re-checks the file size and its SHA-256 against the server descriptor.
func verifyArtifact(path string, a *types.AgentArtifact) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if a.Size > 0 && info.Size() != a.Size {
		return fmt.Errorf("size mismatch: file is %d bytes, expected %d", info.Size(), a.Size)
	}
	want := strings.ToLower(strings.TrimSpace(a.SHA256))
	if want == "" {
		return fmt.Errorf("server descriptor carries no sha256")
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		return fmt.Errorf("sha256 mismatch: got %s, expected %s", got, want)
	}
	return nil
}

func (u *SelfUpdater) finish(res *types.AgentUpdateResult, status, msg string) *types.AgentUpdateResult {
	res.Status = status
	res.Message = msg
	_ = u.saveState(&updateState{
		TargetVersion: res.TargetVersion,
		Status:        status,
		Message:       msg,
		AttemptedAt:   u.now().UTC(),
		Reported:      false,
	})
	return res
}

// SystemdRunInstaller installs the .deb in a transient systemd unit so the install (which
// restarts spired.service via the package's postinstall) runs in a process that is NOT a
// child of spired. If spired killed itself mid-dpkg the install would be left half-applied;
// detaching to systemd-run avoids that. Falls back to a detached `dpkg -i` via setsid when
// systemd-run is unavailable (e.g. no systemd).
func SystemdRunInstaller(ctx context.Context, debPath string) error {
	abs, err := filepath.Abs(debPath)
	if err != nil {
		abs = debPath
	}
	if _, err := exec.LookPath("systemd-run"); err == nil {
		// --collect reaps the unit after exit; the unit runs dpkg -i then lets systemd
		// restart spired.service (Restart=always) rather than this process restarting itself.
		cmd := exec.CommandContext(ctx, "systemd-run",
			"--unit=spire-agent-update",
			"--collect",
			"--property=Type=oneshot",
			"/usr/bin/dpkg", "-i", abs,
		)
		out, runErr := cmd.CombinedOutput()
		if runErr != nil {
			return fmt.Errorf("systemd-run dpkg: %v: %s", runErr, strings.TrimSpace(string(out)))
		}
		return nil
	}

	// No systemd: detach dpkg with setsid so it survives this process restarting.
	if _, err := exec.LookPath("setsid"); err == nil {
		cmd := exec.Command("setsid", "dpkg", "-i", abs)
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("setsid dpkg: %w", err)
		}
		_ = cmd.Process.Release()
		return nil
	}
	return fmt.Errorf("no systemd-run or setsid available to detach the install")
}

// ConsumePendingUpdateResult returns an unreported update result from a prior cycle (so a
// result survives an agent restart caused by the install itself) and marks it reported.
func ConsumePendingUpdateResult(statePath string) *types.AgentUpdateResult {
	u := &SelfUpdater{statePath: statePath, now: time.Now}
	st, err := u.loadState()
	if err != nil || st == nil || st.Reported || st.Status == "" {
		return nil
	}
	st.Reported = true
	_ = u.saveState(st)
	return &types.AgentUpdateResult{
		TargetVersion: st.TargetVersion,
		Status:        st.Status,
		Message:       st.Message,
	}
}
