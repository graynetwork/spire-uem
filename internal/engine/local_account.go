package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// LOCAL_ACCOUNT_POLICY engine: configures password quality (pam_pwquality), account lockout
// (pam_faillock), password max age (login.defs PASS_MAX_DAYS), and a managed sudoers drop-in.
//
// Debian 12 way, used deliberately instead of blind sed on /etc/pam.d:
//   - pam_pwquality reads /etc/security/pwquality.conf and /etc/security/pwquality.conf.d/*.conf
//   - pam_faillock reads /etc/security/faillock.conf
//   - the common-auth/common-password PAM stacks are managed by pam-auth-update, NOT edited here
//   - PASS_MAX_DAYS lives in /etc/login.defs (no drop-in dir), managed via a delimited marker block
//   - sudo grants go in /etc/sudoers.d/90-spire, validated with `visudo -cf` before install, mode 0440

var (
	// laRoot is the filesystem root the engine writes under. "" means the real root ("/").
	// Tests set it to a temp dir so nothing touches the real host.
	laRoot = ""
	// findVisudoBin locates the visudo binary. Overridden in tests.
	findVisudoBin = FindVisudoBinary
	// runVisudoCheck validates a sudoers file at path with `visudo -cf <path>`. Overridden in tests.
	runVisudoCheck = defaultRunVisudoCheck

	validUnixNameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]*\$?$`)
)

const (
	pwqualityConfRel = "etc/security/pwquality.conf.d/90-spire.conf"
	faillockConfRel  = "etc/security/faillock.conf"
	loginDefsRel     = "etc/login.defs"
	sudoersDropRel   = "etc/sudoers.d/90-spire"

	loginDefsBegin = "# BEGIN SpireUEM LOCAL_ACCOUNT_POLICY"
	loginDefsEnd   = "# END SpireUEM LOCAL_ACCOUNT_POLICY"
)

// FindVisudoBinary locates visudo in PATH or standard system directories.
func FindVisudoBinary() (string, error) {
	for _, p := range []string{"/usr/sbin/visudo", "/sbin/visudo", "/usr/bin/visudo"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("visudo executable not found in standard directories")
}

// defaultRunVisudoCheck runs `visudo -cf <path>` to validate sudoers syntax.
func defaultRunVisudoCheck(ctx context.Context, path string) (string, error) {
	bin, err := findVisudoBin()
	if err != nil {
		return "", err
	}
	out, runErr := exec.CommandContext(ctx, bin, "-cf", path).CombinedOutput()
	return string(out), runErr
}

// laPath joins laRoot with a relative path.
func laPath(rel string) string {
	if laRoot == "" {
		return "/" + rel
	}
	return filepath.Join(laRoot, rel)
}

// validateLocalAccountPayload validates a LOCAL_ACCOUNT_POLICY payload at the trust boundary.
// Shared with the server so invalid input is rejected before storage.
func validateLocalAccountPayload(p types.LocalAccountPolicyPayload) error {
	if p.PwqualityMinLen < 0 || p.PwqualityMinLen > 255 {
		return fmt.Errorf("pwquality_minlen %d out of range 0-255", p.PwqualityMinLen)
	}
	if p.PwqualityMinClass < 0 || p.PwqualityMinClass > 4 {
		return fmt.Errorf("pwquality_minclass %d out of range 0-4", p.PwqualityMinClass)
	}
	if p.FaillockDeny < 0 || p.FaillockDeny > 1000 {
		return fmt.Errorf("faillock_deny %d out of range 0-1000", p.FaillockDeny)
	}
	if p.FaillockUnlockTime < 0 || p.FaillockUnlockTime > 31536000 {
		return fmt.Errorf("faillock_unlock_time %d out of range 0-31536000", p.FaillockUnlockTime)
	}
	if p.PassMaxDays < 0 || p.PassMaxDays > 99999 {
		return fmt.Errorf("pass_max_days %d out of range 0-99999", p.PassMaxDays)
	}
	if p.Sudoers != nil {
		for _, g := range p.Sudoers.Groups {
			if !validUnixNameRe.MatchString(strings.TrimSpace(g)) {
				return fmt.Errorf("invalid sudoers group name %q", g)
			}
		}
		for _, u := range p.Sudoers.Users {
			if !validUnixNameRe.MatchString(strings.TrimSpace(u)) {
				return fmt.Errorf("invalid sudoers user name %q", u)
			}
		}
	}
	return nil
}

// RenderPwqualityConf renders the pwquality drop-in. Returns "" when no pwquality fields are set.
func RenderPwqualityConf(p types.LocalAccountPolicyPayload) string {
	if p.PwqualityMinLen == 0 && p.PwqualityMinClass == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("# Managed by SpireUEM - LOCAL_ACCOUNT_POLICY (pam_pwquality)\n")
	if p.PwqualityMinLen > 0 {
		sb.WriteString(fmt.Sprintf("minlen = %d\n", p.PwqualityMinLen))
	}
	if p.PwqualityMinClass > 0 {
		sb.WriteString(fmt.Sprintf("minclass = %d\n", p.PwqualityMinClass))
	}
	return sb.String()
}

// RenderFaillockConf renders the faillock drop-in. Returns "" when no lockout fields are set.
func RenderFaillockConf(p types.LocalAccountPolicyPayload) string {
	if p.FaillockDeny == 0 && p.FaillockUnlockTime == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("# Managed by SpireUEM - LOCAL_ACCOUNT_POLICY (pam_faillock)\n")
	if p.FaillockDeny > 0 {
		sb.WriteString(fmt.Sprintf("deny = %d\n", p.FaillockDeny))
	}
	if p.FaillockUnlockTime > 0 {
		sb.WriteString(fmt.Sprintf("unlock_time = %d\n", p.FaillockUnlockTime))
	}
	return sb.String()
}

// RenderSudoers renders the /etc/sudoers.d/90-spire drop-in content. Returns "" when no grants set.
func RenderSudoers(s *types.LocalAccountSudoersPayload) string {
	if s == nil || (len(s.Groups) == 0 && len(s.Users) == 0) {
		return ""
	}
	tag := ""
	if s.NoPasswd {
		tag = "NOPASSWD:"
	}
	var sb strings.Builder
	sb.WriteString("# Managed by SpireUEM - LOCAL_ACCOUNT_POLICY sudoers drop-in. Do not edit by hand.\n")

	groups := append([]string(nil), s.Groups...)
	sort.Strings(groups)
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if tag != "" {
			sb.WriteString(fmt.Sprintf("%%%s ALL=(ALL:ALL) %s ALL\n", g, tag))
		} else {
			sb.WriteString(fmt.Sprintf("%%%s ALL=(ALL:ALL) ALL\n", g))
		}
	}
	users := append([]string(nil), s.Users...)
	sort.Strings(users)
	for _, u := range users {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if tag != "" {
			sb.WriteString(fmt.Sprintf("%s ALL=(ALL:ALL) %s ALL\n", u, tag))
		} else {
			sb.WriteString(fmt.Sprintf("%s ALL=(ALL:ALL) ALL\n", u))
		}
	}
	return sb.String()
}

// upsertLoginDefsMaxDays rewrites the SpireUEM-delimited block in /etc/login.defs to set (or clear)
// PASS_MAX_DAYS, preserving all other content. maxDays == 0 removes the managed block entirely.
func upsertLoginDefsMaxDays(path string, maxDays int) error {
	var existing []string
	if data, err := os.ReadFile(path); err == nil {
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		inBlock := false
		for sc.Scan() {
			line := sc.Text()
			if strings.TrimSpace(line) == loginDefsBegin {
				inBlock = true
				continue
			}
			if strings.TrimSpace(line) == loginDefsEnd {
				inBlock = false
				continue
			}
			if inBlock {
				continue
			}
			existing = append(existing, line)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}

	// Trim trailing blank lines left after block removal.
	for len(existing) > 0 && strings.TrimSpace(existing[len(existing)-1]) == "" {
		existing = existing[:len(existing)-1]
	}

	out := strings.Join(existing, "\n")
	if out != "" {
		out += "\n"
	}
	if maxDays > 0 {
		out += loginDefsBegin + "\n"
		out += fmt.Sprintf("PASS_MAX_DAYS\t%d\n", maxDays)
		out += loginDefsEnd + "\n"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return atomicWriteFile(path, []byte(out), 0644)
}

// EnforceLocalAccountPolicy applies a LOCAL_ACCOUNT_POLICY and verifies the written files.
func EnforceLocalAccountPolicy(ctx context.Context, policy types.AssignedPolicy) types.PolicyExecutionItem {
	var payload types.LocalAccountPolicyPayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return failItem(policy.ID, fmt.Sprintf("invalid LOCAL_ACCOUNT_POLICY payload: %v", err), nil)
	}
	if err := validateLocalAccountPayload(payload); err != nil {
		return failItem(policy.ID, err.Error(), nil)
	}

	details := map[string]any{
		"policy_id": policy.ID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"written":   []string{},
	}
	written := []string{}

	writeOrRemove := func(rel, content string, mode os.FileMode) error {
		path := laPath(rel)
		if content == "" {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove %s: %w", path, err)
			}
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
		}
		if err := atomicWriteFile(path, []byte(content), mode); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		written = append(written, path)
		return nil
	}

	// 1. pam_pwquality drop-in.
	if err := writeOrRemove(pwqualityConfRel, RenderPwqualityConf(payload), 0644); err != nil {
		return failItem(policy.ID, err.Error(), details)
	}

	// 2. pam_faillock drop-in.
	if err := writeOrRemove(faillockConfRel, RenderFaillockConf(payload), 0644); err != nil {
		return failItem(policy.ID, err.Error(), details)
	}

	// 3. PASS_MAX_DAYS in login.defs (managed marker block).
	if err := upsertLoginDefsMaxDays(laPath(loginDefsRel), payload.PassMaxDays); err != nil {
		return failItem(policy.ID, err.Error(), details)
	}
	if payload.PassMaxDays > 0 {
		written = append(written, laPath(loginDefsRel))
	}

	// 4. Managed sudoers drop-in: write to a temp file, validate with visudo -cf, then install 0440.
	sudoersContent := RenderSudoers(payload.Sudoers)
	sudoersPath := laPath(sudoersDropRel)
	if sudoersContent == "" {
		if err := os.Remove(sudoersPath); err != nil && !os.IsNotExist(err) {
			return failItem(policy.ID, fmt.Sprintf("remove sudoers %s: %v", sudoersPath, err), details)
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(sudoersPath), 0755); err != nil {
			return failItem(policy.ID, fmt.Sprintf("mkdir %s: %v", filepath.Dir(sudoersPath), err), details)
		}
		tmp := sudoersPath + ".spire-validate"
		if err := atomicWriteFile(tmp, []byte(sudoersContent), 0440); err != nil {
			return failItem(policy.ID, fmt.Sprintf("stage sudoers temp: %v", err), details)
		}
		out, verr := runVisudoCheck(ctx, tmp)
		if verr != nil {
			details["visudo_output"] = strings.TrimSpace(out)
			_ = os.Remove(tmp)
			return failItem(policy.ID, fmt.Sprintf("visudo -cf rejected sudoers drop-in: %v", verr), details)
		}
		if err := os.Rename(tmp, sudoersPath); err != nil {
			_ = os.Remove(tmp)
			return failItem(policy.ID, fmt.Sprintf("install sudoers drop-in: %v", err), details)
		}
		if err := os.Chmod(sudoersPath, 0440); err != nil {
			return failItem(policy.ID, fmt.Sprintf("chmod sudoers 0440: %v", err), details)
		}
		written = append(written, sudoersPath)
	}

	details["written"] = written
	details["verified"] = true
	return types.PolicyExecutionItem{
		PolicyID:         policy.ID,
		ComplianceStatus: types.ComplianceCompliant,
		ExecutionOutput:  mustJSON(details),
	}
}

// RemoveLocalAccountPolicy removes everything the LOCAL_ACCOUNT_POLICY engine created. Used on revoke.
func RemoveLocalAccountPolicy(ctx context.Context) error {
	_ = ctx
	for _, rel := range []string{pwqualityConfRel, faillockConfRel, sudoersDropRel} {
		path := laPath(rel)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
	}
	// Strip the managed login.defs block (maxDays == 0 removes it, preserving the rest of the file).
	if _, err := os.Stat(laPath(loginDefsRel)); err == nil {
		if err := upsertLoginDefsMaxDays(laPath(loginDefsRel), 0); err != nil {
			return err
		}
	}
	return nil
}

// ValidateLocalAccountPolicyPayload is the exported trust-boundary validator, used by the server to
// reject out-of-range values and invalid sudoers principal names before storage.
func ValidateLocalAccountPolicyPayload(p types.LocalAccountPolicyPayload) error {
	return validateLocalAccountPayload(p)
}
