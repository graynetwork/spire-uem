package engine_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/types"
)

func TestExecuteDiagnosticCommand_Truncation(t *testing.T) {
	ctx := context.Background()

	// 1. Command producing 2MB of 'A' characters
	cmdDTO := types.CommandDTO{
		ID:      "test-trunc-cmd-1",
		Command: "head -c 2097152 /dev/zero | tr '\\0' 'A'",
	}

	report := engine.ExecuteDiagnosticCommand(ctx, cmdDTO, 5*time.Second)

	if report.Status != "COMPLETED" {
		t.Fatalf("expected status COMPLETED, got %s (stderr: %s)", report.Status, report.Stderr)
	}

	const expectedLimit = 64 * 1024
	const notice = "\n[TRUNCATED: Output exceeded 64KB limit]"

	if !strings.HasSuffix(report.Stdout, notice) {
		t.Fatalf("expected stdout to have truncation notice suffix, got tail: %q", report.Stdout[max(0, len(report.Stdout)-50):])
	}

	contentBeforeNotice := strings.TrimSuffix(report.Stdout, notice)
	if len(contentBeforeNotice) != expectedLimit {
		t.Fatalf("expected truncated content to be exactly %d bytes, got %d bytes", expectedLimit, len(contentBeforeNotice))
	}
}

func TestExecuteDiagnosticCommand_SmallOutput(t *testing.T) {
	ctx := context.Background()

	cmdDTO := types.CommandDTO{
		ID:      "test-small-cmd-1",
		Command: "echo 'hello world'",
	}

	report := engine.ExecuteDiagnosticCommand(ctx, cmdDTO, 5*time.Second)

	if report.Status != "COMPLETED" {
		t.Fatalf("expected status COMPLETED, got %s", report.Status)
	}
	if strings.Contains(report.Stdout, "[TRUNCATED") {
		t.Errorf("expected small output not to contain truncation notice, got: %s", report.Stdout)
	}
	if strings.TrimSpace(report.Stdout) != "hello world" {
		t.Errorf("expected 'hello world', got: %q", report.Stdout)
	}
}
