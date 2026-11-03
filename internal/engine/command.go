package engine

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

const maxCommandOutputBytes = 64 * 1024 // 64KB cap

// ExecuteDiagnosticCommand runs an ad-hoc diagnostic command with a strict timeout (default 30s)
// and captures stdout and stderr truncated to 64KB.
func ExecuteDiagnosticCommand(parentCtx context.Context, cmdDTO types.CommandDTO, timeout time.Duration) types.CommandReportRequest {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", cmdDTO.Command)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()

	stdoutStr := truncateOutput(stdoutBuf.Bytes(), maxCommandOutputBytes)
	stderrStr := truncateOutput(stderrBuf.Bytes(), maxCommandOutputBytes)

	status := "COMPLETED"
	exitCode := 0

	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			status = "TIMED_OUT"
			exitCode = -1
		} else {
			status = "FAILED"
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = 1
			}
		}
	}

	return types.CommandReportRequest{
		CommandID: cmdDTO.ID,
		Status:    status,
		ExitCode:  exitCode,
		Stdout:    stdoutStr,
		Stderr:    stderrStr,
	}
}

func truncateOutput(b []byte, maxBytes int) string {
	if len(b) <= maxBytes {
		return string(b)
	}
	return string(b[:maxBytes]) + "\n...[truncated at 64KB]"
}
