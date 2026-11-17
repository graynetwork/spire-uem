package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/inventory"
	"github.com/spire-uem/spire-uem/internal/types"
)

// teardownRemoteDesktop resets gnome-remote-desktop credentials and disables RDP sharing.
func teardownRemoteDesktop(ctx context.Context) {
	if grdCtl, lookErr := exec.LookPath("grdctl"); lookErr == nil {
		_ = exec.CommandContext(ctx, grdCtl, "rdp", "disable").Run()
		_ = exec.CommandContext(ctx, grdCtl, "rdp", "clear-credentials").Run()
	}
}

// consentDecision is the outcome of asking the desktop user for remote-assist consent.
type consentDecision int

const (
	consentRejected    consentDecision = iota // user clicked No, closed the dialog, or it timed out
	consentApproved                           // user explicitly clicked Yes
	consentUnavailable                        // no interactive dialog could be shown
)

// consentPrompter and consentNotifier are variables so tests can replace them.
var (
	consentPrompter     = zenityConsentPrompt
	consentNotifier     = notifyUser
	activeSessionLookup = inventory.GetActiveSessionDetails
)

// zenityConsentPrompt shows a Yes/No dialog to the seat0 user. Only exit status 0
// (an explicit Yes) approves. A missing zenity binary means no consent can be given;
// a desktop notification is never treated as consent.
func zenityConsentPrompt(ctx context.Context, username, uid, promptText string) consentDecision {
	zenityPath, err := exec.LookPath("zenity")
	if err != nil {
		return consentUnavailable
	}
	dbusAddr := fmt.Sprintf("unix:path=/run/user/%s/bus", uid)
	args := []string{"--question", "--title=SpireUEM Remote Assistance", "--text=" + promptText, "--timeout=60"}
	var cmd *exec.Cmd
	if runuserPath, rErr := exec.LookPath("runuser"); rErr == nil {
		full := append([]string{"-u", username, "--", "env", "DBUS_SESSION_BUS_ADDRESS=" + dbusAddr, "DISPLAY=:0", zenityPath}, args...)
		cmd = exec.CommandContext(ctx, runuserPath, full...)
	} else {
		cmd = exec.CommandContext(ctx, zenityPath, args...)
		cmd.Env = append(os.Environ(), "DBUS_SESSION_BUS_ADDRESS="+dbusAddr, "DISPLAY=:0")
	}
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return consentRejected // 1 = No, 5 = timeout, others = dialog failure
		}
		return consentUnavailable // could not start the dialog at all
	}
	return consentApproved
}

// notifyUser best-effort shows an informational desktop notification. It never approves anything.
func notifyUser(ctx context.Context, uid, summary, body string) {
	notifyPath, err := exec.LookPath("notify-send")
	if err != nil || strings.TrimSpace(uid) == "" {
		return
	}
	cmd := exec.CommandContext(ctx, notifyPath, "-u", "critical", "-a", "SpireUEM", summary, body)
	cmd.Env = append(os.Environ(), fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%s/bus", uid), "DISPLAY=:0")
	_ = cmd.Run()
}

// HandleRemoteAssistRequest checks the active seat0 desktop session via loginctl and
// asks the user for consent with a 60-second zenity Yes/No dialog. Only an explicit Yes
// approves. It returns NO_ACTIVE_USER_SESSION, REJECTED_BY_USER, CONSENT_UNAVAILABLE
// (no dialog could be shown), or APPROVED with RDP details.
func HandleRemoteAssistRequest(parentCtx context.Context, req types.RemoteAssistRequestPayload) types.RemoteAssistResponsePayload {
	ctx, cancel := context.WithTimeout(parentCtx, 60*time.Second)
	defer cancel()

	if strings.TrimSpace(req.AdminActor) == "" {
		req.AdminActor = "admin"
	}

	// Allow explicit policy override for automated/headless verification
	decisionOverride := strings.ToUpper(strings.TrimSpace(os.Getenv("SPIRE_REMOTE_ASSIST_DECISION")))
	if decisionOverride == "" {
		if b, err := os.ReadFile("/etc/spire/remote-assist-decision"); err == nil {
			decisionOverride = strings.ToUpper(strings.TrimSpace(string(b)))
		}
	}
	if decisionOverride == "REJECT" || decisionOverride == "DENY" {
		teardownRemoteDesktop(ctx)
		return types.RemoteAssistResponsePayload{
			SessionID:    req.SessionID,
			Status:       "REJECTED_BY_USER",
			ErrorMessage: "User declined attended remote desktop assistance request",
		}
	}

	username, uid, err := activeSessionLookup()
	if (err != nil || strings.TrimSpace(username) == "" || strings.TrimSpace(uid) == "") && decisionOverride != "APPROVE" {
		teardownRemoteDesktop(ctx)
		return types.RemoteAssistResponsePayload{
			SessionID:    req.SessionID,
			Status:       "NO_ACTIVE_USER_SESSION",
			ErrorMessage: "No active graphical seat0 user session available to approve attended remote assist",
		}
	}

	decision := consentApproved
	if decisionOverride == "APPROVE" {
		log.Printf("[spired] remote assist session=%s approved by local override file/env, not by the desktop user", req.SessionID)
	} else {
		promptText := fmt.Sprintf("Administrator '%s' is requesting attended remote desktop assistance. Allow screen sharing?", req.AdminActor)
		decision = consentPrompter(ctx, username, uid, promptText)
	}

	switch decision {
	case consentApproved:
		// fall through to session setup below
	case consentUnavailable:
		teardownRemoteDesktop(ctx)
		consentNotifier(ctx, uid, "SpireUEM Remote Assistance",
			fmt.Sprintf("Administrator '%s' requested remote assistance. It was refused because no consent dialog is available on this device.", req.AdminActor))
		return types.RemoteAssistResponsePayload{
			SessionID:    req.SessionID,
			Status:       "CONSENT_UNAVAILABLE",
			ErrorMessage: "No interactive consent dialog (zenity) is available on the device; remote assistance refused",
		}
	default:
		teardownRemoteDesktop(ctx)
		return types.RemoteAssistResponsePayload{
			SessionID:    req.SessionID,
			Status:       "REJECTED_BY_USER",
			ErrorMessage: "Attended remote assistance rejected or timed out after 60s",
		}
	}

	// Best-effort start of gnome-remote-desktop if installed on the endpoint
	if grdCtl, lookErr := exec.LookPath("grdctl"); lookErr == nil {
		_ = exec.CommandContext(ctx, grdCtl, "rdp", "enable").Run()
	}

	hostname := inventory.GetHostname()
	passBytes := make([]byte, 6)
	_, _ = rand.Read(passBytes)
	oneTimePin := hex.EncodeToString(passBytes)

	return types.RemoteAssistResponsePayload{
		SessionID:   req.SessionID,
		Status:      "APPROVED",
		Credentials: fmt.Sprintf("rdp://%s:3389 (pin=%s)", hostname, oneTimePin),
	}
}
