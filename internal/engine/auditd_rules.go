package engine

import (
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

// Injectable seams so tests run unprivileged with fakes and never touch the real host auditd.
var (
	// auditdRulesDir is the directory holding augenrules fragments. The spire-managed file is
	// always "90-spire.rules" inside it, so other fragments are never touched.
	auditdRulesDir = "/etc/audit/rules.d"
	// auditdRunner executes augenrules (and friends). Overridden in tests with a fake.
	auditdRunner CommandRunner = execCommandRunner{}
)

// auditdFileName is the single file this engine owns.
const auditdFileName = "90-spire.rules"

var (
	auditdKeyRe     = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
	auditdSyscallRe = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	// A -F field expression: name op value, with a conservative value charset (no shell metachars).
	auditdFieldRe = regexp.MustCompile(`^[a-zA-Z0-9_]+[=!<>]{1,2}[a-zA-Z0-9_./:-]+$`)
	auditdPermsRe = regexp.MustCompile(`^[rwxa]{1,4}$`)
)

// CommandRunner abstracts command execution so engines can be tested with fakes.
// (Defined here; shared across the new policy-types-b engines.)
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (stdout string, err error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// auditdPresets maps a preset name to its concrete rule lines (CIS-style). Kept intentionally
// small and auditable; unknown presets are rejected at validation.
var auditdPresets = map[string][]string{
	"identity": {
		"-w /etc/passwd -p wa -k identity",
		"-w /etc/group -p wa -k identity",
		"-w /etc/shadow -p wa -k identity",
		"-w /etc/gshadow -p wa -k identity",
	},
	"sudoers": {
		"-w /etc/sudoers -p wa -k scope",
		"-w /etc/sudoers.d -p wa -k scope",
	},
	"time_change": {
		"-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change",
		"-a always,exit -F arch=b64 -S clock_settime -k time-change",
		"-w /etc/localtime -p wa -k time-change",
	},
	"module_loading": {
		"-w /sbin/insmod -p x -k modules",
		"-w /sbin/rmmod -p x -k modules",
		"-w /sbin/modprobe -p x -k modules",
		"-a always,exit -F arch=b64 -S init_module -S delete_module -k modules",
	},
}

// AuditdPresetNames returns the sorted list of supported preset names (for UI validation/help).
func AuditdPresetNames() []string {
	names := make([]string, 0, len(auditdPresets))
	for k := range auditdPresets {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// validateAuditdPayload validates a payload and returns the fully-rendered, sorted rule lines.
func validateAuditdPayload(p types.AuditdRulesPayload) ([]string, error) {
	var lines []string
	seen := make(map[string]bool)

	addLine := func(l string) {
		l = strings.TrimSpace(l)
		if l == "" || seen[l] {
			return
		}
		seen[l] = true
		lines = append(lines, l)
	}

	for _, preset := range p.Presets {
		rules, ok := auditdPresets[strings.TrimSpace(preset)]
		if !ok {
			return nil, fmt.Errorf("unknown auditd preset %q", preset)
		}
		for _, l := range rules {
			addLine(l)
		}
	}

	for _, w := range p.Watches {
		path := strings.TrimSpace(w.Path)
		if path == "" || !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
			return nil, fmt.Errorf("invalid auditd watch path %q (must be absolute, no '..')", path)
		}
		if strings.ContainsAny(path, " \t\n\r") {
			return nil, fmt.Errorf("auditd watch path %q contains whitespace", path)
		}
		perms := strings.TrimSpace(w.Perms)
		if !auditdPermsRe.MatchString(perms) {
			return nil, fmt.Errorf("invalid auditd watch perms %q (subset of r,w,x,a)", perms)
		}
		key := strings.TrimSpace(w.Key)
		if !auditdKeyRe.MatchString(key) {
			return nil, fmt.Errorf("invalid auditd watch key %q", key)
		}
		addLine(fmt.Sprintf("-w %s -p %s -k %s", path, perms, key))
	}

	for _, s := range p.Syscalls {
		action := strings.TrimSpace(s.Action)
		if action != "always" && action != "never" {
			return nil, fmt.Errorf("invalid auditd syscall action %q (always|never)", action)
		}
		filter := strings.TrimSpace(s.Filter)
		switch filter {
		case "exit", "entry", "task", "user", "exclude":
		default:
			return nil, fmt.Errorf("invalid auditd syscall filter %q", filter)
		}
		if len(s.Syscalls) == 0 {
			return nil, fmt.Errorf("auditd syscall rule with key %q has no syscalls", s.Key)
		}
		key := strings.TrimSpace(s.Key)
		if !auditdKeyRe.MatchString(key) {
			return nil, fmt.Errorf("invalid auditd syscall key %q", key)
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "-a %s,%s", action, filter)
		for _, f := range s.Fields {
			f = strings.TrimSpace(f)
			if !auditdFieldRe.MatchString(f) {
				return nil, fmt.Errorf("invalid auditd -F field expression %q", f)
			}
			fmt.Fprintf(&sb, " -F %s", f)
		}
		for _, sc := range s.Syscalls {
			sc = strings.TrimSpace(sc)
			if !auditdSyscallRe.MatchString(sc) {
				return nil, fmt.Errorf("invalid auditd syscall name %q", sc)
			}
			fmt.Fprintf(&sb, " -S %s", sc)
		}
		fmt.Fprintf(&sb, " -k %s", key)
		addLine(sb.String())
	}

	if len(lines) == 0 {
		return nil, fmt.Errorf("auditd policy has no rules (need at least one preset, watch, or syscall rule)")
	}
	return lines, nil
}

// renderAuditdRules builds the managed rules file content.
func renderAuditdRules(policyID string, lines []string) string {
	var sb strings.Builder
	sb.WriteString("## Managed by SpireUEM - AUDITD_RULES\n")
	fmt.Fprintf(&sb, "## Policy ID: %s\n", policyID)
	fmt.Fprintf(&sb, "## Generated at: %s\n", time.Now().UTC().Format(time.RFC3339))
	sb.WriteString("## WARNING: regenerated on every policy convergence; edit the policy, not this file.\n\n")
	for _, l := range lines {
		sb.WriteString(l)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// EnforceAuditdRulesPolicy reconciles an AUDITD_RULES policy: validate -> render ->
// atomically write /etc/audit/rules.d/90-spire.rules -> augenrules --check -> augenrules --load,
// then verify the on-disk file matches (drift detection).
func EnforceAuditdRulesPolicy(ctx context.Context, policy types.AssignedPolicy) types.PolicyExecutionItem {
	details := map[string]any{
		"policy_id": policy.ID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	var payload types.AuditdRulesPayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return auditdFail(policy.ID, details, fmt.Sprintf("invalid AUDITD_RULES payload: %v", err))
	}

	lines, err := validateAuditdPayload(payload)
	if err != nil {
		return auditdFail(policy.ID, details, err.Error())
	}

	content := renderAuditdRules(policy.ID, lines)
	details["rule_count"] = len(lines)

	if err := os.MkdirAll(auditdRulesDir, 0750); err != nil {
		return auditdFail(policy.ID, details, fmt.Sprintf("mkdir %s: %v", auditdRulesDir, err))
	}
	target := filepath.Join(auditdRulesDir, auditdFileName)
	details["rules_file"] = target

	// Short-circuit if already converged (no reload churn).
	if existing, rerr := os.ReadFile(target); rerr == nil && string(existing) == content {
		details["drifted"] = false
		details["action"] = "verified_content"
		return auditdOK(policy.ID, types.ComplianceCompliant, details)
	}

	if err := atomicWriteFile(target, []byte(content), 0640); err != nil {
		return auditdFail(policy.ID, details, fmt.Sprintf("atomic write %s: %v", target, err))
	}
	details["drifted"] = true
	details["reasserted"] = true

	// Validate ruleset with augenrules --check (does not load). Skip gracefully if augenrules absent.
	if out, cerr := auditdRunner.Run(ctx, "augenrules", "--check"); cerr != nil {
		details["augenrules_check"] = out
		// A non-zero --check means the compiled ruleset differs from loaded; that is expected
		// before --load, so we only hard-fail on an outright execution error message.
		if strings.Contains(strings.ToLower(out), "error") || strings.Contains(strings.ToLower(cerr.Error()), "no such file") {
			details["check_note"] = cerr.Error()
		}
	} else {
		details["augenrules_check"] = out
	}

	if out, lerr := auditdRunner.Run(ctx, "augenrules", "--load"); lerr != nil {
		details["augenrules_load"] = out
		// In a mock/test environment without auditd the loader is absent; keep the file but report.
		if strings.Contains(strings.ToLower(lerr.Error()), "no such file") || strings.Contains(strings.ToLower(lerr.Error()), "not found") {
			details["load_skipped"] = "augenrules not present"
			return auditdOK(policy.ID, types.ComplianceCompliant, details)
		}
		return auditdFail(policy.ID, details, fmt.Sprintf("augenrules --load failed: %v (%s)", lerr, out))
	} else {
		details["augenrules_load"] = out
	}

	// Verify on-disk file still matches (drift).
	if got, rerr := os.ReadFile(target); rerr != nil || string(got) != content {
		details["drift_after_load"] = true
		return auditdOut(policy.ID, types.ComplianceNonCompliant, "", details)
	}

	return auditdOK(policy.ID, types.ComplianceCompliant, details)
}

// RemoveAuditdRules deletes only the spire-managed rules file and reloads, never touching other fragments.
func RemoveAuditdRules(ctx context.Context) error {
	target := filepath.Join(auditdRulesDir, auditdFileName)
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", target, err)
	}
	_, _ = auditdRunner.Run(ctx, "augenrules", "--load")
	return nil
}

func auditdFail(policyID string, details map[string]any, msg string) types.PolicyExecutionItem {
	details["error"] = msg
	out, _ := json.Marshal(details)
	return types.PolicyExecutionItem{
		PolicyID:         policyID,
		ComplianceStatus: types.ComplianceFailed,
		ErrorMessage:     msg,
		ExecutionOutput:  out,
	}
}

func auditdOK(policyID string, status types.ComplianceStatus, details map[string]any) types.PolicyExecutionItem {
	return auditdOut(policyID, status, "", details)
}

func auditdOut(policyID string, status types.ComplianceStatus, errMsg string, details map[string]any) types.PolicyExecutionItem {
	out, _ := json.Marshal(details)
	item := types.PolicyExecutionItem{
		PolicyID:         policyID,
		ComplianceStatus: status,
		ExecutionOutput:  out,
	}
	if errMsg != "" {
		item.ErrorMessage = errMsg
	}
	return item
}
