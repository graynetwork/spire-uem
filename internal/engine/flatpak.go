package engine

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/config"
	"github.com/spire-uem/spire-uem/internal/types"
)

var validFlatpakAppIDRe = regexp.MustCompile(`^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_-]+){2,}$`)
var validFlatpakRemoteRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
var validBundleSHA256Re = regexp.MustCompile(`^[a-f0-9]{64}$`)

// DefaultBundleCacheDir is the endpoint cache directory for downloaded .flatpak single-file bundles.
const DefaultBundleCacheDir = "/var/cache/spire/bundles"

// GetInstalledFlatpaks runs `flatpak list --app --columns=application`
// and returns the list of installed Flatpak application IDs.
func GetInstalledFlatpaks(ctx context.Context) ([]string, map[string]bool) {
	installedMap := make(map[string]bool)
	var list []string

	if _, err := exec.LookPath("flatpak"); err != nil {
		return list, installedMap
	}

	cmd := exec.CommandContext(ctx, "flatpak", "list", "--app", "--columns=application")
	out, err := cmd.Output()
	if err != nil {
		return list, installedMap
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		appID := strings.TrimSpace(scanner.Text())
		if appID != "" && appID != "Application ID" && !installedMap[appID] {
			installedMap[appID] = true
			list = append(list, appID)
		}
	}
	return list, installedMap
}

// ReconcileFlatpakApp evaluates and enforces a FLATPAK_APP policy against real host Flatpak CLI.
// Fails closed if the `flatpak` binary is missing or installation fails.
func ReconcileFlatpakApp(ctx context.Context, policy types.AssignedPolicy, installedFlatpaks map[string]bool) types.PolicyExecutionItem {
	var payload types.FlatpakAppPayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid FLATPAK_APP payload: %v", err),
		}
	}

	appID := strings.TrimSpace(payload.AppID)
	if !validFlatpakAppIDRe.MatchString(appID) {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid flatpak app_id: %q", appID),
		}
	}

	state := strings.ToLower(strings.TrimSpace(payload.State))
	if state == "" {
		state = "present"
	}
	if state != "present" && state != "absent" {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid flatpak state %q (must be 'present' or 'absent')", state),
		}
	}

	remote := strings.TrimSpace(payload.Remote)
	if remote == "" {
		remote = "flathub"
	}
	if !validFlatpakRemoteRe.MatchString(remote) {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid flatpak remote: %q", remote),
		}
	}

	if _, err := exec.LookPath("flatpak"); err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     "flatpak executable not found in PATH",
		}
	}

	isInstalled := installedFlatpaks != nil && installedFlatpaks[appID]

	if state == "present" {
		expectedCmd := fmt.Sprintf("flatpak install -y --system %s %s", remote, appID)
		if isInstalled {
			SyncFlatpakDesktopExports(appID)
			out, _ := json.Marshal(map[string]any{
				"app_id":     appID,
				"remote":     remote,
				"state":      "present",
				"action":     "none (already installed)",
				"checked_at": time.Now().UTC().Format(time.RFC3339),
			})
			return types.PolicyExecutionItem{
				PolicyID:         policy.ID,
				ComplianceStatus: types.ComplianceCompliant,
				ExecutionOutput:  out,
			}
		}

		if payload.AutoInstall != nil && !*payload.AutoInstall {
			assignType := ResolveAssignmentType(policy.AssignmentType, policy.Payload)
			if assignType == types.AssignmentAvailable {
				out, _ := json.Marshal(map[string]any{
					"app_id":          appID,
					"assignment_type": "AVAILABLE",
					"installed":       false,
					"checked_at":      time.Now().UTC().Format(time.RFC3339),
				})
				return types.PolicyExecutionItem{
					PolicyID:         policy.ID,
					ComplianceStatus: types.ComplianceCompliant,
					ExecutionOutput:  out,
				}
			}
			out, _ := json.Marshal(map[string]any{
				"app_id":          appID,
				"assignment_type": "REQUIRED",
				"installed":       false,
				"checked_at":      time.Now().UTC().Format(time.RFC3339),
			})
			return types.PolicyExecutionItem{
				PolicyID:         policy.ID,
				ComplianceStatus: types.ComplianceNonCompliant,
				ErrorMessage:     "Action Required: Install",
				ExecutionOutput:  out,
			}
		}

		cmd := exec.CommandContext(ctx, "flatpak", "install", "-y", "--system", remote, appID)
		cmdOut, err := cmd.CombinedOutput()
		if err != nil {
			out, _ := json.Marshal(map[string]any{
				"command": expectedCmd,
				"output":  strings.TrimSpace(string(cmdOut)),
			})
			return types.PolicyExecutionItem{
				PolicyID:         policy.ID,
				ComplianceStatus: types.ComplianceFailed,
				ErrorMessage:     fmt.Sprintf("flatpak install failed: %v", err),
				ExecutionOutput:  out,
			}
		}

		if installedFlatpaks != nil {
			installedFlatpaks[appID] = true
		}
		SyncFlatpakDesktopExports(appID)
		out, _ := json.Marshal(map[string]any{
			"app_id":     appID,
			"remote":     remote,
			"state":      "present",
			"command":    expectedCmd,
			"output":     strings.TrimSpace(string(cmdOut)),
			"checked_at": time.Now().UTC().Format(time.RFC3339),
		})
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceCompliant,
			ExecutionOutput:  out,
		}
	}

	// state == "absent"
	expectedCmd := fmt.Sprintf("flatpak uninstall -y --system %s", appID)
	if !isInstalled {
		RemoveFlatpakDesktopExports(appID)
		out, _ := json.Marshal(map[string]any{
			"app_id":     appID,
			"state":      "absent",
			"action":     "none (already absent)",
			"checked_at": time.Now().UTC().Format(time.RFC3339),
		})
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceCompliant,
			ExecutionOutput:  out,
		}
	}

	cmd := exec.CommandContext(ctx, "flatpak", "uninstall", "-y", "--system", appID)
	cmdOut, err := cmd.CombinedOutput()
	if err != nil {
		out, _ := json.Marshal(map[string]any{
			"command": expectedCmd,
			"output":  strings.TrimSpace(string(cmdOut)),
		})
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("flatpak uninstall failed: %v", err),
			ExecutionOutput:  out,
		}
	}

	if installedFlatpaks != nil {
		delete(installedFlatpaks, appID)
	}
	RemoveFlatpakDesktopExports(appID)
	out, _ := json.Marshal(map[string]any{
		"app_id":     appID,
		"state":      "absent",
		"command":    expectedCmd,
		"output":     strings.TrimSpace(string(cmdOut)),
		"checked_at": time.Now().UTC().Format(time.RFC3339),
	})
	return types.PolicyExecutionItem{
		PolicyID:         policy.ID,
		ComplianceStatus: types.ComplianceCompliant,
		ExecutionOutput:  out,
	}
}

// ReconcileFlatpakBundle evaluates and enforces a FLATPAK_BUNDLE custom single-file bundle policy.
// Streams the bundle to /var/cache/spire/bundles/<sha256>.flatpak.tmp, verifies SHA-256 digest (failing closed on mismatch),
// atomically renames to /var/cache/spire/bundles/<sha256>.flatpak, and executes:
// `flatpak install --system --noninteractive --reinstall -y /var/cache/spire/bundles/<sha256>.flatpak`.
func ReconcileFlatpakBundle(
	ctx context.Context,
	policy types.AssignedPolicy,
	installedFlatpaks map[string]bool,
	httpClient *http.Client,
	serverURL string,
	authToken string,
) types.PolicyExecutionItem {
	var payload types.FlatpakBundlePayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid FLATPAK_BUNDLE payload: %v", err),
		}
	}

	appID := strings.TrimSpace(payload.AppID)
	if !validFlatpakAppIDRe.MatchString(appID) {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid flatpak bundle app_id: %q", appID),
		}
	}

	expectedSHA := strings.ToLower(strings.TrimSpace(payload.SHA256))
	if !validBundleSHA256Re.MatchString(expectedSHA) {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid flatpak bundle sha256: %q", expectedSHA),
		}
	}

	if _, err := exec.LookPath("flatpak"); err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     "flatpak executable not found in PATH",
		}
	}

	cacheDir := DefaultBundleCacheDir
	if envDir := strings.TrimSpace(os.Getenv("SPIRE_BUNDLE_CACHE_DIR")); envDir != "" {
		cacheDir = envDir
	}
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("failed to create bundle cache directory %s: %v", cacheDir, err),
		}
	}

	finalBundlePath := filepath.Join(cacheDir, expectedSHA+".flatpak")
	tmpBundlePath := filepath.Join(cacheDir, expectedSHA+".flatpak.tmp")

	// Check if the application is currently installed via `flatpak info <app_id>`
	infoCmd := exec.CommandContext(ctx, "flatpak", "info", appID)
	isInstalled := infoCmd.Run() == nil
	if installedFlatpaks != nil && isInstalled {
		installedFlatpaks[appID] = true
	}

	// Check if cached archive for this SHA-256 already exists and is verified
	_, cachedErr := os.Stat(finalBundlePath)
	hashMatchesInstalled := isInstalled && cachedErr == nil

	if hashMatchesInstalled {
		SyncFlatpakDesktopExports(appID)
		out, _ := json.Marshal(map[string]any{
			"app_id":      appID,
			"bundle_name": payload.BundleName,
			"sha256":      expectedSHA,
			"installed":   true,
			"action":      "none (bundle already installed and verified)",
			"checked_at":  time.Now().UTC().Format(time.RFC3339),
		})
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceCompliant,
			ExecutionOutput:  out,
		}
	}

	// Respect AutoInstall=false when not yet installed
	if !payload.AutoInstall && !isInstalled {
		assignType := ResolveAssignmentType(policy.AssignmentType, policy.Payload)
		if assignType == types.AssignmentAvailable {
			out, _ := json.Marshal(map[string]any{
				"app_id":          appID,
				"bundle_name":     payload.BundleName,
				"sha256":          expectedSHA,
				"assignment_type": "AVAILABLE",
				"installed":       false,
				"checked_at":      time.Now().UTC().Format(time.RFC3339),
			})
			return types.PolicyExecutionItem{
				PolicyID:         policy.ID,
				ComplianceStatus: types.ComplianceCompliant,
				ExecutionOutput:  out,
			}
		}
		out, _ := json.Marshal(map[string]any{
			"app_id":          appID,
			"bundle_name":     payload.BundleName,
			"sha256":          expectedSHA,
			"assignment_type": "REQUIRED",
			"installed":       false,
			"checked_at":      time.Now().UTC().Format(time.RFC3339),
		})
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceNonCompliant,
			ErrorMessage:     "Action Required: Install",
			ExecutionOutput:  out,
		}
	}

	// Resolve server URL and Bearer token if not explicitly passed
	if strings.TrimSpace(serverURL) == "" || strings.TrimSpace(authToken) == "" {
		cfg := config.Load("/etc/spire/config.yaml")
		if strings.TrimSpace(serverURL) == "" {
			serverURL = cfg.Agent.ServerURL
		}
		if strings.TrimSpace(authToken) == "" {
			if rawTok, err := os.ReadFile(cfg.Agent.TokenPath); err == nil {
				authToken = strings.TrimSpace(string(rawTok))
			}
		}
	}

	downloadURL := strings.TrimSpace(payload.DownloadURL)
	if downloadURL == "" {
		downloadURL = "/api/v1/desktop/bundles/" + expectedSHA
	}
	if strings.HasPrefix(downloadURL, "/") {
		downloadURL = strings.TrimRight(serverURL, "/") + downloadURL
	}

	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Minute}
	}

	// 1. Stream bundle from download_url directly to /var/cache/spire/bundles/<sha256>.flatpak.tmp
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("build bundle download request failed: %v", err),
		}
	}
	if strings.TrimSpace(authToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(authToken))
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("bundle download request failed: %v", err),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		bodySnippet, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("bundle download returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(bodySnippet))),
		}
	}

	_ = os.Remove(tmpBundlePath)
	tmpFile, err := os.OpenFile(tmpBundlePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("create temp bundle file %s failed: %v", tmpBundlePath, err),
		}
	}

	hasher := sha256.New()
	tee := io.TeeReader(resp.Body, hasher)
	writtenBytes, copyErr := io.Copy(tmpFile, tee)
	if copyErr != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpBundlePath)
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("stream bundle to %s failed: %v", tmpBundlePath, copyErr),
		}
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpBundlePath)
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("fsync temp bundle %s failed: %v", tmpBundlePath, err),
		}
	}
	_ = tmpFile.Close()

	// 2. Verify downloaded SHA-256 digest against payload.SHA256. Fail closed if mismatch.
	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if actualSHA != expectedSHA {
		_ = os.Remove(tmpBundlePath)
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("bundle SHA-256 mismatch (fail closed): expected %s, got %s", expectedSHA, actualSHA),
		}
	}

	// 3. Atomically rename to /var/cache/spire/bundles/<sha256>.flatpak
	if err := os.Rename(tmpBundlePath, finalBundlePath); err != nil {
		_ = os.Remove(tmpBundlePath)
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("atomic rename %s -> %s failed: %v", tmpBundlePath, finalBundlePath, err),
		}
	}

	// 4. Execute installation:
	// `flatpak install --system --noninteractive --reinstall -y /var/cache/spire/bundles/<sha256>.flatpak`
	expectedCmd := fmt.Sprintf("flatpak install --system --noninteractive --reinstall -y %s", finalBundlePath)
	installCmd := exec.CommandContext(ctx, "flatpak", "install", "--system", "--noninteractive", "--reinstall", "-y", finalBundlePath)
	cmdOut, err := installCmd.CombinedOutput()
	if err != nil {
		out, _ := json.Marshal(map[string]any{
			"command": expectedCmd,
			"sha256":  actualSHA,
			"output":  strings.TrimSpace(string(cmdOut)),
		})
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("flatpak bundle install failed: %v (%s)", err, strings.TrimSpace(string(cmdOut))),
			ExecutionOutput:  out,
		}
	}

	if installedFlatpaks != nil {
		installedFlatpaks[appID] = true
	}
	SyncFlatpakDesktopExports(appID)

	out, _ := json.Marshal(map[string]any{
		"app_id":      appID,
		"bundle_name": payload.BundleName,
		"sha256":      actualSHA,
		"size_bytes":  writtenBytes,
		"cache_path":  finalBundlePath,
		"installed":   true,
		"command":     expectedCmd,
		"output":      strings.TrimSpace(string(cmdOut)),
		"checked_at":  time.Now().UTC().Format(time.RFC3339),
	})
	return types.PolicyExecutionItem{
		PolicyID:         policy.ID,
		ComplianceStatus: types.ComplianceCompliant,
		ExecutionOutput:  out,
	}
}

// UninstallAndCleanFlatpakBundle uninstalls a custom Flatpak bundle app and removes its cached .flatpak archive.
func UninstallAndCleanFlatpakBundle(ctx context.Context, appID, sha256Hex string) string {
	appID = strings.TrimSpace(appID)
	sha256Hex = strings.ToLower(strings.TrimSpace(sha256Hex))
	var cmdOutput string

	if validFlatpakAppIDRe.MatchString(appID) {
		if _, err := exec.LookPath("flatpak"); err == nil {
			out, _ := exec.CommandContext(ctx, "flatpak", "uninstall", "--system", "--noninteractive", "-y", appID).CombinedOutput()
			cmdOutput = strings.TrimSpace(string(out))
		}
		RemoveFlatpakDesktopExports(appID)
	}

	cacheDir := DefaultBundleCacheDir
	if envDir := strings.TrimSpace(os.Getenv("SPIRE_BUNDLE_CACHE_DIR")); envDir != "" {
		cacheDir = envDir
	}
	if validBundleSHA256Re.MatchString(sha256Hex) {
		_ = os.Remove(filepath.Join(cacheDir, sha256Hex+".flatpak"))
		_ = os.Remove(filepath.Join(cacheDir, sha256Hex+".flatpak.tmp"))
	}

	return cmdOutput
}

// SyncFlatpakDesktopExports links Flatpak exported .desktop files and icons into /usr/local/share
// so that active desktop sessions (like GNOME/KDE) immediately display application icons without requiring a relogin.
func SyncFlatpakDesktopExports(appID string) {
	flatpakExportsAppDir := "/var/lib/flatpak/exports/share/applications"
	localAppDir := "/usr/local/share/applications"
	_ = os.MkdirAll(localAppDir, 0755)

	if entries, err := os.ReadDir(flatpakExportsAppDir); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), appID) && strings.HasSuffix(e.Name(), ".desktop") {
				src := filepath.Join(flatpakExportsAppDir, e.Name())
				dst := filepath.Join(localAppDir, e.Name())
				_ = os.Remove(dst)
				_ = os.Symlink(src, dst)
			}
		}
	}

	flatpakIconsBase := "/var/lib/flatpak/exports/share/icons/hicolor"
	localIconsBase := "/usr/local/share/icons/hicolor"
	if _, err := os.Stat(flatpakIconsBase); err == nil {
		_ = filepath.Walk(flatpakIconsBase, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			baseName := info.Name()
			if strings.HasPrefix(baseName, appID) {
				rel, rErr := filepath.Rel(flatpakIconsBase, path)
				if rErr == nil {
					targetDst := filepath.Join(localIconsBase, rel)
					_ = os.MkdirAll(filepath.Dir(targetDst), 0755)
					_ = os.Remove(targetDst)
					_ = os.Symlink(path, targetDst)
				}
			}
			return nil
		})
	}

	// Also symlink command line launcher if appropriate (e.g. 'code' for com.visualstudio.code)
	if appID == "com.visualstudio.code" {
		codePath := "/usr/local/bin/code"
		if _, err := os.Stat(codePath); os.IsNotExist(err) {
			_ = os.WriteFile(codePath, []byte("#!/bin/sh\nexec flatpak run com.visualstudio.code \"$@\"\n"), 0755)
		}
	}

	if updateDesktop, err := exec.LookPath("update-desktop-database"); err == nil {
		_ = exec.Command(updateDesktop, localAppDir).Run()
	}
	if updateIcon, err := exec.LookPath("gtk-update-icon-cache"); err == nil {
		_ = exec.Command(updateIcon, "-f", "-t", localIconsBase).Run()
	}
}

// RemoveFlatpakDesktopExports removes desktop entries and icons created by SyncFlatpakDesktopExports.
func RemoveFlatpakDesktopExports(appID string) {
	localAppDir := "/usr/local/share/applications"
	if entries, err := os.ReadDir(localAppDir); err == nil {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), appID) && strings.HasSuffix(e.Name(), ".desktop") {
				_ = os.Remove(filepath.Join(localAppDir, e.Name()))
			}
		}
	}

	localIconsBase := "/usr/local/share/icons/hicolor"
	if _, err := os.Stat(localIconsBase); err == nil {
		_ = filepath.Walk(localIconsBase, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if strings.HasPrefix(info.Name(), appID) {
				_ = os.Remove(path)
			}
			return nil
		})
	}

	if appID == "com.visualstudio.code" {
		_ = os.Remove("/usr/local/bin/code")
	}

	if updateDesktop, err := exec.LookPath("update-desktop-database"); err == nil {
		_ = exec.Command(updateDesktop, localAppDir).Run()
	}
	if updateIcon, err := exec.LookPath("gtk-update-icon-cache"); err == nil {
		_ = exec.Command(updateIcon, "-f", "-t", localIconsBase).Run()
	}
}
