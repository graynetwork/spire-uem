package engine_test

import (
	"context"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/types"
)

func TestHandleRemoteAssistRequest_NoActiveSession(t *testing.T) {
	ctx := context.Background()
	t.Setenv("SPIRE_REMOTE_ASSIST_DECISION", "")

	req := types.RemoteAssistRequestPayload{
		SessionID:  "test-session-no-user",
		AdminActor: "secops-admin",
	}

	resp := engine.HandleRemoteAssistRequest(ctx, req)
	if resp.Status != "NO_ACTIVE_USER_SESSION" && resp.Status != "REJECTED_BY_USER" && resp.Status != "CONSENT_UNAVAILABLE" {
		t.Fatalf("expected NO_ACTIVE_USER_SESSION, REJECTED_BY_USER, or CONSENT_UNAVAILABLE when no session is present, got %s", resp.Status)
	}
	if resp.Credentials != "" {
		t.Fatalf("expected empty credentials when remote assist is unapproved, got: %s", resp.Credentials)
	}
}

func TestHandleRemoteAssistRequest_ExplicitDeny(t *testing.T) {
	ctx := context.Background()
	t.Setenv("SPIRE_REMOTE_ASSIST_DECISION", "DENY")

	req := types.RemoteAssistRequestPayload{
		SessionID:  "test-session-deny",
		AdminActor: "secops-admin",
	}

	resp := engine.HandleRemoteAssistRequest(ctx, req)
	if resp.Status != "REJECTED_BY_USER" {
		t.Fatalf("expected REJECTED_BY_USER when explicitly denied, got %s", resp.Status)
	}
	if resp.Credentials != "" {
		t.Fatalf("expected empty credentials when explicitly denied, got: %s", resp.Credentials)
	}
}

func TestHandleRemoteAssistRequest_ExplicitApprove(t *testing.T) {
	ctx := context.Background()
	t.Setenv("SPIRE_REMOTE_ASSIST_DECISION", "APPROVE")

	req := types.RemoteAssistRequestPayload{
		SessionID:  "test-session-approve",
		AdminActor: "secops-admin",
	}

	resp := engine.HandleRemoteAssistRequest(ctx, req)
	if resp.Status != "APPROVED" {
		t.Fatalf("expected APPROVED when explicitly approved, got %s", resp.Status)
	}
	if !strings.HasPrefix(resp.Credentials, "rdp://") {
		t.Fatalf("expected credentials to start with rdp://, got: %s", resp.Credentials)
	}
}
