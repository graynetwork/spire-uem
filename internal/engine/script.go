package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spire-uem/spire-uem/internal/inventory"
	"github.com/spire-uem/spire-uem/internal/types"
)

// DefaultScriptWorkDir is the root-owned 0700 directory script files are written into on the
// endpoint. Each script is a 0700 file created here, run directly by the interpreter, and
// removed afterwards. Overridable in tests via NewScriptRunner.
const DefaultScriptWorkDir = "/run/spire/scripts"

// activeSessionDetails is a package var so tests can stub the seat0 user lookup. Production
// reads loginctl via the inventory package (same source the lost-device actions use).
var activeSessionDetails = inventory.GetActiveSessionDetails

// ScriptRunner executes verified script directives on the endpoint. All of its system
// touch-points (work dir, interpreter path resolution, active-user lookup) are injectable so
// the security behaviour is tested with fakes and no real root execution.
type ScriptRunner struct {
	WorkDir string
	// interpreterPath resolves an allowed interpreter to its absolute binary. Defaults to the
	// fixed allowlist in types.InterpreterPath; tests point it at a harness binary.
	interpreterPath func(types.ScriptInterpreter) (string, bool)
	// activeUser returns (username, uid, err) for the seat0 graphical user.
	activeUser func() (string, string, error)
	// now is injectable for deterministic duration assertions.
	now func() time.Time
}

// NewScriptRunner returns a runner writing to workDir (DefaultScriptWorkDir when empty).
func NewScriptRunner(workDir string) *ScriptRunner {
	if workDir == "" {
		workDir = DefaultScriptWorkDir
	}
	return &ScriptRunner{
		WorkDir:         workDir,
		interpreterPath: types.InterpreterPath,
		activeUser:      activeSessionDetails,
		now:             time.Now,
	}
}

// scriptRunOutcome is the engine-internal result of one execution.
type scriptRunOutcome struct {
	Status     types.ScriptRunStatus
	ExitCode   int
	Stdout     string
	Stderr     string
	DurationMS int64
}

// RunScript executes a script directive: it verifies the content sha256, resolves the fixed
// interpreter path, writes the content to a fresh 0700 file in the 0700 work dir, runs the
// interpreter directly on that path (never `sh -c`), passes parameters ONLY as
// SPIRE_PARAM_<NAME> environment variables, enforces the timeout by killing the whole process
// group, caps combined output, and removes the file afterwards.
func (sr *ScriptRunner) RunScript(ctx context.Context, d types.ScriptDirective) scriptRunOutcome {
	return sr.run(ctx, scriptSpec{
		interpreter: d.Interpreter,
		runAs:       d.RunAs,
		content:     d.Content,
		sha256:      d.SHA256,
		timeoutSecs: d.TimeoutSecs,
		maxOutput:   d.MaxOutput,
		params:      d.Params,
		namePrefix:  "run",
	})
}

// RunSensor executes a sensor's script (no parameters) and returns the trimmed stdout plus
// exit info for the caller to type-parse.
func (sr *ScriptRunner) RunSensor(ctx context.Context, d types.SensorDirective) scriptRunOutcome {
	return sr.run(ctx, scriptSpec{
		interpreter: d.Interpreter,
		runAs:       d.RunAs,
		content:     d.Content,
		sha256:      d.SHA256,
		timeoutSecs: d.TimeoutSecs,
		maxOutput:   d.MaxOutput,
		namePrefix:  "sensor",
	})
}

// RunStep executes one SCRIPT_POLICY step and returns its outcome.
func (sr *ScriptRunner) RunStep(ctx context.Context, step types.ScriptPolicyStep, params map[string]string) scriptRunOutcome {
	return sr.run(ctx, scriptSpec{
		interpreter: step.Interpreter,
		runAs:       step.RunAs,
		content:     step.Content,
		sha256:      step.SHA256,
		timeoutSecs: step.TimeoutSecs,
		maxOutput:   step.MaxOutput,
		params:      params,
		namePrefix:  "policy",
	})
}

type scriptSpec struct {
	interpreter types.ScriptInterpreter
	runAs       types.ScriptRunAs
	content     string
	sha256      string
	timeoutSecs int
	maxOutput   int
	params      map[string]string
	namePrefix  string
}

func (sr *ScriptRunner) run(ctx context.Context, spec scriptSpec) scriptRunOutcome {
	fail := func(msg string) scriptRunOutcome {
		return scriptRunOutcome{Status: types.ScriptRunFailed, ExitCode: 1, Stderr: msg}
	}

	// 1. Verify the content hash before touching disk. A mismatch means the directive was
	//    tampered with in transit — refuse to run it.
	if types.ComputeScriptSHA256(spec.content) != strings.ToLower(strings.TrimSpace(spec.sha256)) {
		return fail("sha256 mismatch: refusing to run script")
	}

	// 2. Resolve the interpreter against the fixed allowlist. The interpreter NAME is never
	//    placed on a command line; only its resolved absolute path is exec'd.
	interpPath, ok := sr.interpreterPath(spec.interpreter)
	if !ok {
		return fail(fmt.Sprintf("interpreter %q is not in the allowlist", spec.interpreter))
	}

	// 3. Caps.
	timeout := time.Duration(spec.timeoutSecs) * time.Second
	if timeout <= 0 {
		timeout = types.ScriptDefaultTimeoutSeconds * time.Second
	}
	if timeout > types.ScriptMaxTimeoutSeconds*time.Second {
		timeout = types.ScriptMaxTimeoutSeconds * time.Second
	}
	maxOut := spec.maxOutput
	if maxOut <= 0 {
		maxOut = types.ScriptDefaultMaxOutputBytes
	}
	if maxOut > types.ScriptMaxOutputBytesCeiling {
		maxOut = types.ScriptMaxOutputBytesCeiling
	}

	// 4. Write the script to a fresh 0700 file inside the 0700 root-owned work dir.
	if err := os.MkdirAll(sr.WorkDir, 0o700); err != nil {
		return fail("prepare work dir: " + err.Error())
	}
	_ = os.Chmod(sr.WorkDir, 0o700)
	f, err := os.CreateTemp(sr.WorkDir, spec.namePrefix+"-*.script")
	if err != nil {
		return fail("create script file: " + err.Error())
	}
	scriptPath := f.Name()
	defer func() { _ = os.Remove(scriptPath) }()
	if err := f.Chmod(0o700); err != nil {
		_ = f.Close()
		return fail("chmod script file: " + err.Error())
	}
	if _, err := f.WriteString(spec.content); err != nil {
		_ = f.Close()
		return fail("write script file: " + err.Error())
	}
	if err := f.Close(); err != nil {
		return fail("close script file: " + err.Error())
	}

	// 5. Build argv: interpreter path + script file path. No shell, no parameter text.
	var name string
	var args []string
	if spec.runAs == types.RunAsActiveUser {
		user, _, uerr := sr.activeUser()
		if uerr != nil || strings.TrimSpace(user) == "" {
			return scriptRunOutcome{
				Status:   types.ScriptRunFailed,
				ExitCode: 1,
				Stderr:   "run_as active_user: no active graphical session on this device",
			}
		}
		// runuser -u <user> -- <interp> <script>; runuser is exec'd directly, not via a shell,
		// and the user name comes from loginctl, not from any script parameter.
		name = "runuser"
		args = []string{"-u", user, "--", interpPath, scriptPath}
	} else {
		name = interpPath
		args = []string{scriptPath}
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, name, args...)

	// 6. Parameters ONLY as environment variables. A minimal, fixed base env plus the typed
	//    SPIRE_PARAM_<NAME> values. Values are assigned verbatim, so shell metacharacters in a
	//    value never reach a shell and stay literal.
	env := []string{
		"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
		"SPIRE_MANAGED=1",
	}
	for k, v := range spec.params {
		if !types.ValidScriptParamName(k) {
			continue // defensive: server already validated names
		}
		env = append(env, "SPIRE_PARAM_"+k+"="+v)
	}
	cmd.Env = env

	// 7. Own process group so a timeout kills children too, not just the interpreter.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// On context cancel (timeout), kill the ENTIRE process group, not just the interpreter:
	// a backgrounded child that inherited the stdout pipe would otherwise keep the pipe open
	// and block the readers past the deadline. WaitDelay bounds how long we wait for the pipes
	// to drain after the kill before giving up on them.
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = 3 * time.Second

	start := sr.now()
	outcome := runBounded(cmd, maxOut)
	outcome.DurationMS = sr.now().Sub(start).Milliseconds()

	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		outcome.Status = types.ScriptRunTimedOut
		if outcome.ExitCode == 0 {
			outcome.ExitCode = -1
		}
	}
	return outcome
}

// runBounded starts cmd, reads stdout/stderr through a byte cap, kills the whole process group
// on completion/timeout, and returns status + exit code + capped output.
func runBounded(cmd *exec.Cmd, maxOut int) scriptRunOutcome {
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return scriptRunOutcome{Status: types.ScriptRunFailed, ExitCode: 1, Stderr: "stdout pipe: " + err.Error()}
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return scriptRunOutcome{Status: types.ScriptRunFailed, ExitCode: 1, Stderr: "stderr pipe: " + err.Error()}
	}
	if err := cmd.Start(); err != nil {
		return scriptRunOutcome{Status: types.ScriptRunFailed, ExitCode: 1, Stderr: "start: " + err.Error()}
	}

	// Ensure the whole process group is reaped on return (covers timeout kills and leftover
	// children of a finished parent).
	pgid := cmd.Process.Pid
	defer func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) }()

	var stdoutB, stderrB []byte
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); stdoutB = readCapped(stdoutPipe, maxOut) }()
	go func() { defer wg.Done(); stderrB = readCapped(stderrPipe, maxOut) }()
	wg.Wait()
	waitErr := cmd.Wait()

	outcome := scriptRunOutcome{Status: types.ScriptRunCompleted, Stdout: string(stdoutB), Stderr: string(stderrB)}
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			outcome.ExitCode = exitErr.ExitCode()
			if outcome.ExitCode != 0 {
				outcome.Status = types.ScriptRunFailed
			}
		} else {
			outcome.Status = types.ScriptRunFailed
			outcome.ExitCode = 1
			if outcome.Stderr == "" {
				outcome.Stderr = waitErr.Error()
			}
		}
	}
	return outcome
}

// readCapped reads up to maxOut bytes, appending a truncation notice if the source had more.
func readCapped(rc io.Reader, maxOut int) []byte {
	lr := io.LimitReader(rc, int64(maxOut)+1)
	b, _ := io.ReadAll(lr)
	if len(b) > maxOut {
		b = append(b[:maxOut], []byte("\n[TRUNCATED]")...)
	}
	// Drain the rest so the writer never blocks on a full pipe.
	_, _ = io.Copy(io.Discard, rc)
	return b
}

// scriptOutcomeToResult converts an engine outcome into the on-wire run result for a run id.
func scriptOutcomeToResult(runID string, o scriptRunOutcome) types.ScriptRunResult {
	return types.ScriptRunResult{
		RunID:      runID,
		Status:     o.Status,
		ExitCode:   o.ExitCode,
		Stdout:     o.Stdout,
		Stderr:     o.Stderr,
		DurationMS: o.DurationMS,
	}
}

// ScriptOutcome is the exported, wire-friendly outcome of a sensor or ad-hoc run (the internal
// scriptRunOutcome is unexported so callers outside the package use this).
type ScriptOutcome struct {
	Status     types.ScriptRunStatus
	ExitCode   int
	Stdout     string
	Stderr     string
	DurationMS int64
}

// RunScriptResult runs a script directive and returns its on-wire result (RunID populated).
func (sr *ScriptRunner) RunScriptResult(ctx context.Context, d types.ScriptDirective) types.ScriptRunResult {
	return scriptOutcomeToResult(d.RunID, sr.RunScript(ctx, d))
}

// RunSensorResult runs a sensor directive and returns its exported outcome.
func (sr *ScriptRunner) RunSensorResult(ctx context.Context, d types.SensorDirective) ScriptOutcome {
	o := sr.RunSensor(ctx, d)
	return ScriptOutcome{Status: o.Status, ExitCode: o.ExitCode, Stdout: o.Stdout, Stderr: o.Stderr, DurationMS: o.DurationMS}
}
