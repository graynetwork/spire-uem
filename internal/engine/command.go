package engine

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"sync"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

const (
	maxCommandOutputBytes = 64 * 1024 // 64KB hard cap
	truncationNotice      = "\n[TRUNCATED: Output exceeded 64KB limit]"
)

// ExecuteDiagnosticCommand runs an ad-hoc diagnostic command with a strict timeout (default 30s)
// and reads stdout and stderr using io.LimitReader to strictly bound memory allocations.
func ExecuteDiagnosticCommand(parentCtx context.Context, cmdDTO types.CommandDTO, timeout time.Duration) types.CommandReportRequest {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(parentCtx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", cmdDTO.Command)

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return types.CommandReportRequest{
			CommandID: cmdDTO.ID,
			Status:    "FAILED",
			ExitCode:  1,
			Stderr:    "Failed to create stdout pipe: " + err.Error(),
		}
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return types.CommandReportRequest{
			CommandID: cmdDTO.ID,
			Status:    "FAILED",
			ExitCode:  1,
			Stderr:    "Failed to create stderr pipe: " + err.Error(),
		}
	}

	if err := cmd.Start(); err != nil {
		return types.CommandReportRequest{
			CommandID: cmdDTO.ID,
			Status:    "FAILED",
			ExitCode:  1,
			Stderr:    "Failed to start command: " + err.Error(),
		}
	}

	var stdoutBytes, stderrBytes []byte
	var stdoutTruncated, stderrTruncated bool
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		lr := io.LimitReader(stdoutPipe, maxCommandOutputBytes+1)
		b, _ := io.ReadAll(lr)
		if len(b) > maxCommandOutputBytes {
			stdoutBytes = b[:maxCommandOutputBytes]
			stdoutTruncated = true
		} else {
			stdoutBytes = b
		}
		// Drain remaining output so the process does not block on write
		_, _ = io.Copy(io.Discard, stdoutPipe)
	}()

	go func() {
		defer wg.Done()
		lr := io.LimitReader(stderrPipe, maxCommandOutputBytes+1)
		b, _ := io.ReadAll(lr)
		if len(b) > maxCommandOutputBytes {
			stderrBytes = b[:maxCommandOutputBytes]
			stderrTruncated = true
		} else {
			stderrBytes = b
		}
		// Drain remaining output so the process does not block on write
		_, _ = io.Copy(io.Discard, stderrPipe)
	}()

	wg.Wait()
	waitErr := cmd.Wait()

	stdoutStr := string(stdoutBytes)
	if stdoutTruncated {
		stdoutStr += truncationNotice
	}

	stderrStr := string(stderrBytes)
	if stderrTruncated {
		stderrStr += truncationNotice
	}

	status := "COMPLETED"
	exitCode := 0

	if waitErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			status = "TIMED_OUT"
			exitCode = -1
		} else {
			status = "FAILED"
			var exitErr *exec.ExitError
			if errors.As(waitErr, &exitErr) {
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
