package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/config"
	"github.com/spire-uem/spire-uem/internal/types"
)

const (
	dconfProfilePath = "/etc/dconf/profile/user"
	dconfLocalDir    = "/etc/dconf/db/local.d"
	dconfLocksDir    = "/etc/dconf/db/local.d/locks"
)

var (
	safePolicyIDRe       = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	safeWallpaperNameRe  = regexp.MustCompile(`^[a-zA-Z0-9._-]+\.(png|jpg|jpeg|webp|svg)$`)
	validWallpaperHashRe = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

// EnsureCorporateBackgroundAsset ensures that the corporate wallpaper file exists.
// If missing, it writes a placeholder 1x1 corporate background PNG (#0b0f19)
// and ensures directory permissions are 0755.
func EnsureCorporateBackgroundAsset(destPath string) error {
	if destPath == "" {
		destPath = "/usr/share/backgrounds/corporate/thegraylan-wallpaper.png"
	}
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if fi, err := os.Stat(destPath); err == nil && fi.Size() > 0 {
		return nil
	}
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 0x0b, G: 0x0f, B: 0x19, A: 0xff})
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return fmt.Errorf("encode placeholder wallpaper: %w", err)
	}
	return atomicWriteFile(destPath, buf.Bytes(), 0644)
}

// EnsureDconfProfile ensures /etc/dconf/profile/user exists with user-db:user and system-db:local entries.
// Returns true if the profile file was created or updated.
func EnsureDconfProfile() (bool, error) {
	if err := os.MkdirAll(filepath.Dir(dconfProfilePath), 0755); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(dconfProfilePath), err)
	}

	const profileContent = "user-db:user\nsystem-db:local\n"
	existing, err := os.ReadFile(dconfProfilePath)
	if err == nil {
		text := string(existing)
		if strings.Contains(text, "user-db:user") && strings.Contains(text, "system-db:local") {
			return false, nil
		}
	}

	if err := atomicWriteFile(dconfProfilePath, []byte(profileContent), 0644); err != nil {
		return false, fmt.Errorf("write %s: %w", dconfProfilePath, err)
	}
	return true, nil
}

// ReconcileDconfSetting verifies that /etc/dconf/db/local.d/10-spire-<policy_id> (and lock file)
// exist and match expected contents. If missing or drifted, it re-writes the keyfiles and returns drifted=true.
func ReconcileDconfSetting(ctx context.Context, policy types.AssignedPolicy) (types.PolicyExecutionItem, bool) {
	_ = ctx
	if _, lookErr := exec.LookPath("dconf"); lookErr != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("dconf executable not found in PATH: %v", lookErr),
		}, false
	}

	var payload types.DconfSettingPayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid DCONF_SETTING payload: %v", err),
		}, false
	}

	assetDrifted, err := reconcileDconfAsset(ctx, payload)
	if err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("reconcile dconf asset: %v", err),
		}, false
	}

	profileChanged, err := EnsureDconfProfile()
	if err != nil {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("ensure dconf profile: %v", err),
		}, false
	}

	policyID := strings.TrimSpace(policy.ID)
	if policyID == "" || !safePolicyIDRe.MatchString(policyID) {
		return types.PolicyExecutionItem{
			PolicyID:         policy.ID,
			ComplianceStatus: types.ComplianceFailed,
			ErrorMessage:     fmt.Sprintf("invalid policy_id for dconf file naming: %q", policyID),
		}, false
	}

	// Ensure required directories exist with mode 0755
	for _, dir := range []string{"/etc/dconf/profile", dconfLocalDir, dconfLocksDir, "/usr/share/backgrounds/corporate"} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return types.PolicyExecutionItem{
				PolicyID:         policy.ID,
				ComplianceStatus: types.ComplianceFailed,
				ErrorMessage:     fmt.Sprintf("mkdir %s: %v", dir, err),
			}, false
		}
	}

	// Ensure corporate background asset if referenced
	needsCorporateAsset := strings.Contains(payload.Value, "thegraylan-wallpaper.png")
	if !needsCorporateAsset {
		for _, kvs := range payload.Sections {
			for _, v := range kvs {
				if strings.Contains(v, "thegraylan-wallpaper.png") {
					needsCorporateAsset = true
					break
				}
			}
			if needsCorporateAsset {
				break
			}
		}
	}
	if needsCorporateAsset {
		if err := EnsureCorporateBackgroundAsset("/usr/share/backgrounds/corporate/thegraylan-wallpaper.png"); err != nil {
			return types.PolicyExecutionItem{
				PolicyID:         policy.ID,
				ComplianceStatus: types.ComplianceFailed,
				ErrorMessage:     fmt.Sprintf("ensure corporate background: %v", err),
			}, false
		}
	}

	fileName := fmt.Sprintf("10-spire-%s", policyID)
	if payload.FileName != "" && safePolicyIDRe.MatchString(payload.FileName) {
		fileName = payload.FileName
	}
	ruleFilePath := filepath.Join(dconfLocalDir, fileName)
	lockFilePath := filepath.Join(dconfLocksDir, fileName)

	var ruleBuilder strings.Builder
	var lockBuilder strings.Builder

	schemaSection := strings.ReplaceAll(strings.Trim(strings.TrimSpace(payload.SchemaPath), "/"), ".", "/")
	key := strings.TrimSpace(payload.Key)
	val := strings.TrimSpace(payload.Value)

	if len(payload.Sections) > 0 {
		sections := make([]string, 0, len(payload.Sections))
		for sec := range payload.Sections {
			sections = append(sections, sec)
		}
		sort.Strings(sections)

		for _, sec := range sections {
			secClean := strings.ReplaceAll(strings.Trim(strings.TrimSpace(sec), "/"), ".", "/")
			fmt.Fprintf(&ruleBuilder, "[%s]\n", secClean)
			kvs := payload.Sections[sec]
			keys := make([]string, 0, len(kvs))
			for k := range kvs {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				kc := strings.TrimSpace(k)
				vc := strings.TrimSpace(kvs[k])
				fmt.Fprintf(&ruleBuilder, "%s=%s\n", kc, vc)
				if len(payload.Locks) == 0 {
					fmt.Fprintf(&lockBuilder, "/%s/%s\n", secClean, kc)
				}
			}
		}
	} else {
		if schemaSection == "" || key == "" {
			return types.PolicyExecutionItem{
				PolicyID:         policy.ID,
				ComplianceStatus: types.ComplianceFailed,
				ErrorMessage:     "schema_path and key are required for DCONF_SETTING",
			}, false
		}

		fmt.Fprintf(&ruleBuilder, "[%s]\n%s=%s\n", schemaSection, key, val)
		if len(payload.Locks) == 0 {
			fmt.Fprintf(&lockBuilder, "/%s/%s\n", schemaSection, key)
		}

		if len(payload.ExtraSettings) > 0 {
			extraKeys := make([]string, 0, len(payload.ExtraSettings))
			for ek := range payload.ExtraSettings {
				extraKeys = append(extraKeys, ek)
			}
			sort.Strings(extraKeys)
			for _, extraKey := range extraKeys {
				ek := strings.TrimSpace(extraKey)
				ev := strings.TrimSpace(payload.ExtraSettings[extraKey])
				if ek != "" {
					fmt.Fprintf(&ruleBuilder, "%s=%s\n", ek, ev)
					if len(payload.Locks) == 0 {
						fmt.Fprintf(&lockBuilder, "/%s/%s\n", schemaSection, ek)
					}
				}
			}
		}
	}

	if len(payload.Locks) > 0 {
		lockBuilder.Reset()
		for _, l := range payload.Locks {
			cleanLock := strings.TrimSpace(l)
			if cleanLock != "" {
				if !strings.HasPrefix(cleanLock, "/") {
					cleanLock = "/" + cleanLock
				}
				fmt.Fprintf(&lockBuilder, "%s\n", cleanLock)
			}
		}
	}

	expectedRule := ruleBuilder.String()
	expectedLock := lockBuilder.String()

	drifted := profileChanged || assetDrifted

	existingRule, err := os.ReadFile(ruleFilePath)
	if err != nil || string(existingRule) != expectedRule {
		drifted = true
		if err := atomicWriteFile(ruleFilePath, []byte(expectedRule), 0644); err != nil {
			return types.PolicyExecutionItem{
				PolicyID:         policy.ID,
				ComplianceStatus: types.ComplianceFailed,
				ErrorMessage:     fmt.Sprintf("atomic write %s: %v", ruleFilePath, err),
			}, false
		}
	}

	shouldLock := payload.Locked || len(payload.Locks) > 0
	if shouldLock && expectedLock != "" {
		existingLock, err := os.ReadFile(lockFilePath)
		if err != nil || string(existingLock) != expectedLock {
			drifted = true
			if err := atomicWriteFile(lockFilePath, []byte(expectedLock), 0644); err != nil {
				return types.PolicyExecutionItem{
					PolicyID:         policy.ID,
					ComplianceStatus: types.ComplianceFailed,
					ErrorMessage:     fmt.Sprintf("atomic write %s: %v", lockFilePath, err),
				}, false
			}
		}
	} else {
		if _, err := os.Stat(lockFilePath); err == nil {
			drifted = true
			_ = os.Remove(lockFilePath)
		}
	}

	execMeta, _ := json.Marshal(map[string]any{
		"profile_file":    dconfProfilePath,
		"rules_file":      ruleFilePath,
		"locks_file":      lockFilePath,
		"schema_path":     schemaSection,
		"key":             key,
		"value":           val,
		"asset_dest_path": payload.AssetDestPath,
		"asset_sha256":    payload.AssetSHA256,
		"locked":          payload.Locked,
		"drifted":         drifted,
		"checked_at":      time.Now().UTC().Format(time.RFC3339),
	})

	return types.PolicyExecutionItem{
		PolicyID:         policy.ID,
		ComplianceStatus: types.ComplianceCompliant,
		ExecutionOutput:  execMeta,
	}, drifted
}

func reconcileDconfAsset(ctx context.Context, payload types.DconfSettingPayload) (bool, error) {
	assetURL := strings.TrimSpace(payload.AssetURL)
	destPath := strings.TrimSpace(payload.AssetDestPath)
	expectedSHA := strings.ToLower(strings.TrimSpace(payload.AssetSHA256))
	if assetURL == "" || destPath == "" {
		return false, nil
	}

	cleanDest := filepath.Clean(destPath)
	allowedPrefix := "/usr/share/backgrounds/"
	allowedLocalPrefix := "/usr/local/share/backgrounds/"
	customDir := strings.TrimSpace(os.Getenv("SPIRE_WALLPAPER_DIR"))
	validDir := strings.HasPrefix(cleanDest, allowedPrefix) || strings.HasPrefix(cleanDest, allowedLocalPrefix)
	if customDir != "" && strings.HasPrefix(cleanDest, filepath.Clean(customDir)+string(os.PathSeparator)) {
		validDir = true
	}
	if !validDir || !safeWallpaperNameRe.MatchString(filepath.Base(cleanDest)) {
		return false, fmt.Errorf("invalid asset_dest_path %q: must be an image file under /usr/share/backgrounds/", destPath)
	}
	if expectedSHA != "" && !validWallpaperHashRe.MatchString(expectedSHA) {
		return false, fmt.Errorf("invalid asset_sha256 %q", expectedSHA)
	}

	// Check if existing file already matches SHA-256
	if existingBytes, err := os.ReadFile(cleanDest); err == nil {
		if expectedSHA == "" {
			return false, nil
		}
		sum := sha256.Sum256(existingBytes)
		if hex.EncodeToString(sum[:]) == expectedSHA {
			return false, nil
		}
	}

	cfg := config.Load("/etc/spire/config.yaml")
	serverURL := strings.TrimSpace(cfg.Agent.ServerURL)
	var authToken string
	if rawTok, err := os.ReadFile(cfg.Agent.TokenPath); err == nil {
		authToken = strings.TrimSpace(string(rawTok))
	}

	downloadURL := assetURL
	if strings.HasPrefix(downloadURL, "/") {
		downloadURL = strings.TrimRight(serverURL, "/") + downloadURL
	}

	if err := os.MkdirAll(filepath.Dir(cleanDest), 0755); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(cleanDest), err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return false, fmt.Errorf("create asset request: %w", err)
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("download wallpaper asset %s: %w", downloadURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("download wallpaper asset %s returned HTTP %d", downloadURL, resp.StatusCode)
	}

	tmpPath := cleanDest + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return false, fmt.Errorf("open temp wallpaper %s: %w", tmpPath, err)
	}

	hasher := sha256.New()
	_, copyErr := io.Copy(f, io.TeeReader(io.LimitReader(resp.Body, 25<<20), hasher))
	_ = f.Sync()
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("stream wallpaper asset: %w", copyErr)
	}
	if closeErr != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("close temp wallpaper: %w", closeErr)
	}

	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if expectedSHA != "" && actualSHA != expectedSHA {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("wallpaper SHA-256 mismatch: expected %s, got %s", expectedSHA, actualSHA)
	}

	_ = os.Chmod(tmpPath, 0644)
	if err := os.Rename(tmpPath, cleanDest); err != nil {
		_ = os.Remove(tmpPath)
		return false, fmt.Errorf("rename wallpaper to %s: %w", cleanDest, err)
	}
	return true, nil
}

// EnforceDconfSetting writes a policy's declarative settings and returns the PolicyExecutionItem.
func EnforceDconfSetting(ctx context.Context, policy types.AssignedPolicy) types.PolicyExecutionItem {
	item, _ := ReconcileDconfSetting(ctx, policy)
	return item
}

// RunDconfUpdate compiles the /etc/dconf/db/local database once after all dconf policies have been written.
func RunDconfUpdate(ctx context.Context) (string, error) {
	if _, lookErr := exec.LookPath("dconf"); lookErr != nil {
		return "", fmt.Errorf("dconf executable not found in PATH: %w", lookErr)
	}
	cmd := exec.CommandContext(ctx, "dconf", "update")
	out, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(out))
	if err != nil {
		return outStr, fmt.Errorf("dconf update failed: %w (output: %s)", err, outStr)
	}
	return outStr, nil
}
