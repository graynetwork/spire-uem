package engine

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// newTestRunner builds a runner writing to a temp dir with a fake active-user lookup.
func newTestRunner(t *testing.T, activeUser func() (string, string, error)) *ScriptRunner {
	t.Helper()
	sr := NewScriptRunner(t.TempDir())
	if activeUser != nil {
		sr.activeUser = activeUser
	}
	return sr
}

func bashDirective(content string, params map[string]string) types.ScriptDirective {
	return types.ScriptDirective{
		RunID:       "run-1",
		Interpreter: types.InterpreterBash,
		RunAs:       types.RunAsRoot,
		Content:     content,
		SHA256:      types.ComputeScriptSHA256(content),
		TimeoutSecs: 10,
		MaxOutput:   64 * 1024,
		Params:      params,
	}
}

func TestRunScript_SHA256MismatchRefused(t *testing.T) {
	sr := newTestRunner(t, nil)
	d := bashDirective("echo should-not-run", nil)
	d.SHA256 = "deadbeef" // tampered
	out := sr.RunScript(context.Background(), d)
	if out.Status != types.ScriptRunFailed || !strings.Contains(out.Stderr, "sha256 mismatch") {
		t.Fatalf("tampered content must be refused; got status=%s stderr=%q", out.Status, out.Stderr)
	}
	if strings.Contains(out.Stdout, "should-not-run") {
		t.Fatal("script ran despite sha256 mismatch")
	}
}

func TestRunScript_InterpreterAllowlist(t *testing.T) {
	sr := newTestRunner(t, nil)
	d := bashDirective("echo hi", nil)
	d.Interpreter = "perl" // not allowed
	out := sr.RunScript(context.Background(), d)
	if out.Status != types.ScriptRunFailed || !strings.Contains(out.Stderr, "allowlist") {
		t.Fatalf("disallowed interpreter must be refused; got %s %q", out.Status, out.Stderr)
	}
}

func TestRunScript_ParamsAreEnvOnlyAndLiteral(t *testing.T) {
	sr := newTestRunner(t, nil)
	// The script echoes the raw env var. If the value were interpolated into a shell command
	// line, the $(...) and backticks would execute; as an env var they must stay literal.
	content := `printf '%s' "$SPIRE_PARAM_PAYLOAD"`
	injection := "$(touch /tmp/pwned); `id`; ; rm -rf /"
	out := sr.RunScript(context.Background(), bashDirective(content, map[string]string{"PAYLOAD": injection}))
	if out.Status != types.ScriptRunCompleted {
		t.Fatalf("status=%s stderr=%q", out.Status, out.Stderr)
	}
	if out.Stdout != injection {
		t.Fatalf("param value was not passed literally.\n got: %q\nwant: %q", out.Stdout, injection)
	}
}

func TestRunScript_ParamNotOnArgv(t *testing.T) {
	sr := newTestRunner(t, nil)
	// The script's argv must be just the script path; parameters must not appear as arguments.
	content := `printf 'argc=%s' "$#"`
	out := sr.RunScript(context.Background(), bashDirective(content, map[string]string{"FOO": "bar", "BAZ": "qux"}))
	if out.Status != types.ScriptRunCompleted || out.Stdout != "argc=0" {
		t.Fatalf("parameters leaked onto argv: stdout=%q status=%s", out.Stdout, out.Status)
	}
}

func TestRunScript_TimeoutKillsProcessGroup(t *testing.T) {
	sr := newTestRunner(t, nil)
	// A child sleep in a subshell: the whole process group must be killed on timeout.
	content := "sleep 30 & sleep 30; echo done"
	d := bashDirective(content, nil)
	d.TimeoutSecs = 1
	start := time.Now()
	out := sr.RunScript(context.Background(), d)
	if out.Status != types.ScriptRunTimedOut {
		t.Fatalf("status=%s, want TIMED_OUT (stderr=%q)", out.Status, out.Stderr)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("timeout did not fire promptly: %v", elapsed)
	}
	if strings.Contains(out.Stdout, "done") {
		t.Fatal("script completed despite timeout")
	}
}

func TestRunScript_OutputCap(t *testing.T) {
	sr := newTestRunner(t, nil)
	content := `head -c 100000 /dev/zero | tr '\0' 'A'` // 100 KB of 'A'
	d := bashDirective(content, nil)
	d.MaxOutput = 1024
	out := sr.RunScript(context.Background(), d)
	if len(out.Stdout) > 1024+len("\n[TRUNCATED]") {
		t.Fatalf("stdout not capped: %d bytes", len(out.Stdout))
	}
	if !strings.Contains(out.Stdout, "[TRUNCATED]") {
		t.Fatal("expected truncation notice")
	}
}

func TestRunScript_ActiveUserNoSession(t *testing.T) {
	sr := newTestRunner(t, func() (string, string, error) {
		return "", "", errors.New("no session")
	})
	d := bashDirective("echo hi", nil)
	d.RunAs = types.RunAsActiveUser
	out := sr.RunScript(context.Background(), d)
	if out.Status != types.ScriptRunFailed || !strings.Contains(out.Stderr, "no active graphical session") {
		t.Fatalf("active_user with no session must fail clearly; got %s %q", out.Status, out.Stderr)
	}
}

func TestRunScript_ExitCodeMapping(t *testing.T) {
	sr := newTestRunner(t, nil)
	out := sr.RunScript(context.Background(), bashDirective("exit 3", nil))
	if out.Status != types.ScriptRunFailed || out.ExitCode != 3 {
		t.Fatalf("non-zero exit: status=%s exit=%d", out.Status, out.ExitCode)
	}
	ok := sr.RunScript(context.Background(), bashDirective("exit 0", nil))
	if ok.Status != types.ScriptRunCompleted || ok.ExitCode != 0 {
		t.Fatalf("zero exit: status=%s exit=%d", ok.Status, ok.ExitCode)
	}
}

// ----- SCRIPT_POLICY -----

func stepFor(content string) *types.ScriptPolicyStep {
	return &types.ScriptPolicyStep{
		Interpreter: types.InterpreterBash, RunAs: types.RunAsRoot,
		Content: content, SHA256: types.ComputeScriptSHA256(content),
		TimeoutSecs: 10, MaxOutput: 65536,
	}
}

func policyWith(t *testing.T, dir types.ScriptPolicyDirective) types.AssignedPolicy {
	t.Helper()
	b, _ := json.Marshal(dir)
	return types.AssignedPolicy{ID: "pol-1", PolicyType: types.PolicyTypeScriptPolicy, Payload: b}
}

func TestScriptPolicy_DetectCompliant(t *testing.T) {
	sr := newTestRunner(t, nil)
	pol := policyWith(t, types.ScriptPolicyDirective{Detect: stepFor("exit 0")})
	item := EnforceScriptPolicy(context.Background(), sr, pol)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("detect exit 0 should be compliant, got %s (%s)", item.ComplianceStatus, item.ErrorMessage)
	}
}

func TestScriptPolicy_RemediateThenCompliant(t *testing.T) {
	sr := newTestRunner(t, nil)
	// detect fails until a marker file exists; remediate creates it; second detect passes.
	marker := t.TempDir() + "/ok"
	detect := stepFor("test -f " + marker)
	remediate := stepFor("touch " + marker)
	pol := policyWith(t, types.ScriptPolicyDirective{Detect: detect, Remediate: remediate})
	item := EnforceScriptPolicy(context.Background(), sr, pol)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("remediation should make it compliant, got %s (%s)", item.ComplianceStatus, item.ErrorMessage)
	}
}

func TestScriptPolicy_NonCompliantNoRemediate(t *testing.T) {
	sr := newTestRunner(t, nil)
	pol := policyWith(t, types.ScriptPolicyDirective{Detect: stepFor("exit 1")})
	item := EnforceScriptPolicy(context.Background(), sr, pol)
	if item.ComplianceStatus != types.ComplianceNonCompliant {
		t.Fatalf("detect fail with no remediate should be NON_COMPLIANT, got %s", item.ComplianceStatus)
	}
}

func TestScriptPolicy_StillNonCompliantAfterRemediate(t *testing.T) {
	sr := newTestRunner(t, nil)
	pol := policyWith(t, types.ScriptPolicyDirective{Detect: stepFor("exit 1"), Remediate: stepFor("exit 0")})
	item := EnforceScriptPolicy(context.Background(), sr, pol)
	if item.ComplianceStatus != types.ComplianceNonCompliant {
		t.Fatalf("still-failing detect after remediate should be NON_COMPLIANT, got %s", item.ComplianceStatus)
	}
}

func TestScriptPolicy_MissingVersionFailsSafe(t *testing.T) {
	sr := newTestRunner(t, nil)
	pol := policyWith(t, types.ScriptPolicyDirective{Missing: "detect: version gone"})
	item := EnforceScriptPolicy(context.Background(), sr, pol)
	if item.ComplianceStatus != types.ComplianceFailed {
		t.Fatalf("missing version must be FAILED, got %s", item.ComplianceStatus)
	}
}

func TestScriptPolicy_RemoveStep(t *testing.T) {
	sr := newTestRunner(t, nil)
	marker := t.TempDir() + "/removed"
	pol := policyWith(t, types.ScriptPolicyDirective{Detect: stepFor("exit 0"), Remove: stepFor("touch " + marker)})
	item := RunScriptPolicyRemove(context.Background(), sr, pol)
	if item.ComplianceStatus != types.ComplianceRevoked {
		t.Fatalf("remove should report REVOKED, got %s", item.ComplianceStatus)
	}
	out := sr.RunScript(context.Background(), bashDirective("test -f "+marker, nil))
	if out.ExitCode != 0 {
		t.Fatal("remove step did not run (marker missing)")
	}
}

func TestScriptPolicy_RemoveNoStepIsSafe(t *testing.T) {
	sr := newTestRunner(t, nil)
	pol := policyWith(t, types.ScriptPolicyDirective{Detect: stepFor("exit 0")})
	item := RunScriptPolicyRemove(context.Background(), sr, pol)
	if item.ComplianceStatus != types.ComplianceRevoked {
		t.Fatalf("remove with no step should still report REVOKED, got %s", item.ComplianceStatus)
	}
}
