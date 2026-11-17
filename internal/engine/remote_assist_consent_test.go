package engine

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

// withConsentFakes replaces the session lookup, prompt and notifier for one test.
func withConsentFakes(t *testing.T, decision consentDecision) (prompted *bool, notified *string) {
	t.Helper()
	t.Setenv("SPIRE_REMOTE_ASSIST_DECISION", "")
	if _, err := os.Stat("/etc/spire/remote-assist-decision"); err == nil {
		t.Skip("host has /etc/spire/remote-assist-decision; override would bypass the prompt")
	}
	oldLookup, oldPrompt, oldNotify := activeSessionLookup, consentPrompter, consentNotifier
	t.Cleanup(func() { activeSessionLookup, consentPrompter, consentNotifier = oldLookup, oldPrompt, oldNotify })

	p, n := false, ""
	activeSessionLookup = func() (string, string, error) { return "alice", "1000", nil }
	consentPrompter = func(_ context.Context, user, uid, text string) consentDecision {
		p = true
		if user != "alice" || uid != "1000" || !strings.Contains(text, "secops-admin") {
			t.Errorf("prompt got user=%q uid=%q text=%q", user, uid, text)
		}
		return decision
	}
	consentNotifier = func(_ context.Context, _ string, _ string, body string) { n = body }
	return &p, &n
}

func raRequest() types.RemoteAssistRequestPayload {
	return types.RemoteAssistRequestPayload{SessionID: "s1", AdminActor: "secops-admin"}
}

func TestRemoteAssistConsent_ExplicitYesApproves(t *testing.T) {
	prompted, _ := withConsentFakes(t, consentApproved)
	resp := HandleRemoteAssistRequest(context.Background(), raRequest())
	if !*prompted || resp.Status != "APPROVED" || !strings.HasPrefix(resp.Credentials, "rdp://") {
		t.Fatalf("explicit Yes should approve after prompting, got %+v (prompted=%v)", resp, *prompted)
	}
}

func TestRemoteAssistConsent_NoOrTimeoutRejects(t *testing.T) {
	prompted, _ := withConsentFakes(t, consentRejected)
	resp := HandleRemoteAssistRequest(context.Background(), raRequest())
	if !*prompted || resp.Status != "REJECTED_BY_USER" || resp.Credentials != "" {
		t.Fatalf("No/timeout must reject without credentials, got %+v", resp)
	}
}

// A missing dialog must never approve. Before this fix, a successful notify-send
// counted as consent.
func TestRemoteAssistConsent_UnavailableFailsClosed(t *testing.T) {
	_, notified := withConsentFakes(t, consentUnavailable)
	resp := HandleRemoteAssistRequest(context.Background(), raRequest())
	if resp.Status != "CONSENT_UNAVAILABLE" || resp.Credentials != "" {
		t.Fatalf("unavailable consent must fail closed, got %+v", resp)
	}
	if !strings.Contains(*notified, "refused") {
		t.Fatalf("user should be told the request was refused, got %q", *notified)
	}
}

func TestZenityConsentPrompt_MissingZenityIsUnavailable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if got := zenityConsentPrompt(context.Background(), "alice", "1000", "x"); got != consentUnavailable {
		t.Fatalf("missing zenity must be consentUnavailable, got %v", got)
	}
}

func fakeBin(t *testing.T, dir, name, script string) {
	t.Helper()
	if err := os.WriteFile(dir+"/"+name, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestZenityConsentPrompt_ExitCodes(t *testing.T) {
	cases := map[string]consentDecision{
		"exit 0": consentApproved,
		"exit 1": consentRejected, // user clicked No
		"exit 5": consentRejected, // dialog timed out
	}
	for script, want := range cases {
		dir := t.TempDir()
		fakeBin(t, dir, "zenity", script)
		fakeBin(t, dir, "notify-send", "exit 0")
		t.Setenv("PATH", dir)
		if got := zenityConsentPrompt(context.Background(), "alice", "1000", "x"); got != want {
			t.Errorf("zenity %q: got %v, want %v", script, got, want)
		}
	}
}

func TestZenityConsentPrompt_NotifySendAloneNeverApproves(t *testing.T) {
	dir := t.TempDir()
	fakeBin(t, dir, "notify-send", "exit 0")
	t.Setenv("PATH", dir)
	if got := zenityConsentPrompt(context.Background(), "alice", "1000", "x"); got != consentUnavailable {
		t.Fatalf("notify-send without zenity must not approve, got %v", got)
	}
}
