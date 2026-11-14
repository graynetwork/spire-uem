package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

// fakeRunner records invocations and returns scripted output per command name.
type fakeRunner struct {
	calls   [][]string
	outputs map[string]string
	errs    map[string]error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{outputs: map[string]string{}, errs: map[string]error{}}
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	key := name
	if len(args) > 0 {
		key = name + " " + args[0]
	}
	f.calls = append(f.calls, append([]string{name}, args...))
	return f.outputs[key], f.errs[key]
}

func (f *fakeRunner) called(sub string) bool {
	for _, c := range f.calls {
		if strings.Contains(strings.Join(c, " "), sub) {
			return true
		}
	}
	return false
}

func withAuditdFakes(t *testing.T) (dir string, fr *fakeRunner, restore func()) {
	t.Helper()
	tmp := t.TempDir()
	origDir := auditdRulesDir
	origRunner := auditdRunner
	auditdRulesDir = filepath.Join(tmp, "rules.d")
	fr = newFakeRunner()
	auditdRunner = fr
	return auditdRulesDir, fr, func() {
		auditdRulesDir = origDir
		auditdRunner = origRunner
	}
}

func TestValidateAuditdPayload(t *testing.T) {
	// valid preset + watch + syscall
	lines, err := validateAuditdPayload(types.AuditdRulesPayload{
		Presets: []string{"identity", "time_change"},
		Watches: []types.AuditdWatchRule{{Path: "/etc/ssh/sshd_config", Perms: "wa", Key: "sshd"}},
		Syscalls: []types.AuditdSyscallRule{
			{Action: "always", Filter: "exit", Syscalls: []string{"execve"}, Fields: []string{"arch=b64"}, Key: "exec"},
		},
	})
	if err != nil {
		t.Fatalf("expected valid payload, got %v", err)
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "-w /etc/passwd -p wa -k identity") {
		t.Errorf("missing identity preset expansion: %s", joined)
	}
	if !strings.Contains(joined, "-a always,exit -F arch=b64 -S execve -k exec") {
		t.Errorf("syscall rule not rendered as expected: %s", joined)
	}

	bad := []types.AuditdRulesPayload{
		{Presets: []string{"nonexistent"}},
		{Watches: []types.AuditdWatchRule{{Path: "relative/path", Perms: "wa", Key: "k"}}},
		{Watches: []types.AuditdWatchRule{{Path: "/etc/x", Perms: "zz", Key: "k"}}},
		{Watches: []types.AuditdWatchRule{{Path: "/etc/x", Perms: "wa", Key: "bad key!"}}},
		{Syscalls: []types.AuditdSyscallRule{{Action: "bogus", Filter: "exit", Syscalls: []string{"execve"}, Key: "k"}}},
		{Syscalls: []types.AuditdSyscallRule{{Action: "always", Filter: "exit", Syscalls: []string{"rm -rf"}, Key: "k"}}},
		{Syscalls: []types.AuditdSyscallRule{{Action: "always", Filter: "exit", Syscalls: []string{"execve"}, Fields: []string{"arch; rm"}, Key: "k"}}},
		{}, // empty
	}
	for i, p := range bad {
		if _, err := validateAuditdPayload(p); err == nil {
			t.Errorf("case %d: expected validation error, got nil", i)
		}
	}
}

func TestAuditdPathTraversalRejected(t *testing.T) {
	_, err := validateAuditdPayload(types.AuditdRulesPayload{
		Watches: []types.AuditdWatchRule{{Path: "/etc/../etc/shadow", Perms: "wa", Key: "k"}},
	})
	if err == nil {
		t.Fatal("expected '..' path to be rejected")
	}
}

func TestEnforceAuditdRulesApplyVerifyDriftRemove(t *testing.T) {
	dir, fr, restore := withAuditdFakes(t)
	defer restore()
	ctx := context.Background()

	payload, _ := json.Marshal(types.AuditdRulesPayload{
		Presets: []string{"identity"},
		Watches: []types.AuditdWatchRule{{Path: "/etc/ssh/sshd_config", Perms: "wa", Key: "sshd"}},
	})
	pol := types.AssignedPolicy{ID: "aud1", PolicyType: types.PolicyTypeAuditdRules, Payload: payload}

	// First apply
	item := EnforceAuditdRulesPolicy(ctx, pol)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("apply: expected COMPLIANT, got %s (err %s)", item.ComplianceStatus, item.ErrorMessage)
	}
	target := filepath.Join(dir, auditdFileName)
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("rules file not created: %v", err)
	}
	if info.Mode().Perm() != 0640 {
		t.Errorf("expected 0640, got %v", info.Mode().Perm())
	}
	if !fr.called("augenrules --load") {
		t.Error("expected augenrules --load to be called on apply")
	}

	// Second apply = converged, no reload churn
	frCallsBefore := len(fr.calls)
	item = EnforceAuditdRulesPolicy(ctx, pol)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("reapply: expected COMPLIANT, got %s", item.ComplianceStatus)
	}
	var det map[string]any
	_ = json.Unmarshal(item.ExecutionOutput, &det)
	if det["drifted"] != false {
		t.Errorf("reapply should be verified_content (drifted=false), got %v", det["drifted"])
	}
	if len(fr.calls) != frCallsBefore {
		t.Error("converged reapply should not invoke augenrules again")
	}

	// Drift: corrupt the file, reapply reasserts
	if err := os.WriteFile(target, []byte("# tampered\n"), 0640); err != nil {
		t.Fatal(err)
	}
	item = EnforceAuditdRulesPolicy(ctx, pol)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("drift reassert: expected COMPLIANT, got %s", item.ComplianceStatus)
	}
	data, _ := os.ReadFile(target)
	if strings.Contains(string(data), "tampered") {
		t.Error("drifted file was not reasserted")
	}

	// Remove
	if err := RemoveAuditdRules(ctx); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("expected rules file removed, stat err=%v", err)
	}
}

func TestEnforceAuditdRulesLoaderAbsent(t *testing.T) {
	_, fr, restore := withAuditdFakes(t)
	defer restore()
	fr.errs["augenrules --load"] = &execNotFound{}
	ctx := context.Background()

	payload, _ := json.Marshal(types.AuditdRulesPayload{Presets: []string{"sudoers"}})
	pol := types.AssignedPolicy{ID: "aud2", PolicyType: types.PolicyTypeAuditdRules, Payload: payload}
	item := EnforceAuditdRulesPolicy(ctx, pol)
	// Loader absent should still write the file and report COMPLIANT with a skip note.
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("expected COMPLIANT when augenrules absent, got %s (%s)", item.ComplianceStatus, item.ErrorMessage)
	}
}

// execNotFound mimics an exec "no such file" error.
type execNotFound struct{}

func (*execNotFound) Error() string {
	return "exec: \"augenrules\": executable file not found in $PATH"
}
