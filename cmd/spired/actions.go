package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/types"
)

// IsActionDirective reports whether a queued command is a structured lost-device action
// rather than an ad-hoc shell command.
func IsActionDirective(command string) bool {
	return strings.HasPrefix(command, types.ActionDirectivePrefix)
}

// inventoryRefreshFlagPath is a one-shot marker: its presence forces a full inventory report
// on the next check-in. It sits next to the inventory cadence state so both share a dir.
func inventoryRefreshFlagPath() string {
	return filepath.Join(filepath.Dir(inventoryLastPath()), "inventory-refresh.flag")
}

func inventoryLastPath() string {
	// Mirror inventory.DefaultInventoryStatePath so the flag lives beside the cadence file.
	return "/var/lib/spire/inventory-last.json"
}

// armInventoryRefresh writes the one-shot force marker so the next check-in sends inventory.
func armInventoryRefresh() {
	path := inventoryRefreshFlagPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		log.Printf("[spired] failed to prepare inventory refresh dir: %v", err)
		return
	}
	if err := os.WriteFile(path, []byte("1"), 0600); err != nil {
		log.Printf("[spired] failed to arm inventory refresh: %v", err)
	}
}

// consumeInventoryRefresh reports whether a refresh was armed and clears the marker, so a
// forced report happens exactly once per request.
func consumeInventoryRefresh() bool {
	path := inventoryRefreshFlagPath()
	if _, err := os.Stat(path); err != nil {
		return false
	}
	_ = os.Remove(path)
	return true
}

// parseActionDirective extracts the JSON directive from a prefixed command string.
func parseActionDirective(command string) (types.ActionDirective, error) {
	var d types.ActionDirective
	raw := strings.TrimPrefix(command, types.ActionDirectivePrefix)
	err := json.Unmarshal([]byte(raw), &d)
	return d, err
}

// wipeKeyPath is where the agent pins the server's Ed25519 wipe-signing public key, next to
// the token so it shares the token directory's 0700 protection.
func wipeKeyPath(tokenPath string) string {
	return filepath.Join(filepath.Dir(tokenPath), "wipe-signing.pub")
}

// pinWipeKey persists the server's wipe-signing public key the first time it is seen. It is
// written once and never silently overwritten with a different key — a changed key is logged
// and ignored, so a compromised server cannot re-pin a key it controls. Returns the pinned
// key (existing or newly written).
func pinWipeKey(tokenPath, serverKey string) string {
	serverKey = strings.TrimSpace(serverKey)
	path := wipeKeyPath(tokenPath)
	existing := ""
	if b, err := os.ReadFile(path); err == nil {
		existing = strings.TrimSpace(string(b))
	}
	if existing != "" {
		if serverKey != "" && serverKey != existing {
			log.Printf("[spired] WARNING: server presented a wipe-signing key different from the pinned one; keeping the pinned key")
		}
		return existing
	}
	if serverKey == "" {
		return ""
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		log.Printf("[spired] failed to prepare wipe key dir: %v", err)
		return serverKey
	}
	if err := os.WriteFile(path, []byte(serverKey+"\n"), 0600); err != nil {
		log.Printf("[spired] failed to pin wipe-signing key: %v", err)
	} else {
		log.Printf("[spired] pinned server wipe-signing public key to %s", path)
	}
	return serverKey
}

// readPinnedWipeKey returns the pinned wipe-signing public key, or "".
func readPinnedWipeKey(tokenPath string) string {
	b, err := os.ReadFile(wipeKeyPath(tokenPath))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// escrowedVolumeMap re-discovers LUKS volumes and keeps only those this agent previously
// escrowed (recorded in the local escrow state), keyed by volume UUID. This is the set the
// wipe engine intersects with the signed order.
func escrowedVolumeMap(ctx context.Context) map[string]engine.DiscoveredLUKSVolume {
	out := map[string]engine.DiscoveredLUKSVolume{}
	vols, err := engine.DiscoverLUKSVolumes(ctx)
	if err != nil {
		return out
	}
	escrowed := engine.LoadEscrowedVolumeState()
	for _, v := range vols {
		if escrowed[v.VolumeUUID] {
			out[v.VolumeUUID] = v
		}
	}
	return out
}

// dispatchActionDirective executes one structured action and reports its action-specific
// result to the server. The command-report (QUEUED->done) still flows through the normal
// command path in the caller.
func dispatchActionDirective(
	ctx context.Context,
	client *http.Client,
	serverURL, token, tokenPath, hwUUID, kekPEM string,
	d types.ActionDirective,
) {
	actEngine := engine.NewDeviceActionEngine()

	switch d.Kind {
	case types.ActionLock:
		detail, err := actEngine.LockSessions(ctx, d.Message)
		reportAction(ctx, client, serverURL, token, types.ActionReportRequest{
			Kind: d.Kind, ActorID: d.ActorID, Status: statusWord(err, "APPLIED"), Detail: detailOrErr(detail, err),
		})

	case types.ActionLostApply:
		detail, err := actEngine.ApplyLost(ctx, d.Message)
		reportAction(ctx, client, serverURL, token, types.ActionReportRequest{
			Kind: d.Kind, ActorID: d.ActorID, Status: statusWord(err, "APPLIED"), Detail: detailOrErr(detail, err),
		})

	case types.ActionLostRevert:
		detail, err := actEngine.RevertLost(ctx)
		reportAction(ctx, client, serverURL, token, types.ActionReportRequest{
			Kind: d.Kind, ActorID: d.ActorID, Status: statusWord(err, "REVERTED"), Detail: detailOrErr(detail, err),
		})

	case types.ActionWipe:
		pinned := readPinnedWipeKey(tokenPath)
		we := &engine.WipeEngine{
			EscrowedVolumes: func() map[string]engine.DiscoveredLUKSVolume { return escrowedVolumeMap(ctx) },
		}
		res := we.PerformWipe(ctx, pinned, hwUUID, d)
		reportAction(ctx, client, serverURL, token, types.ActionReportRequest{
			Kind: d.Kind, ActorID: res.RequestID, Status: res.Status, Detail: res.Detail,
		})

	case types.ActionLUKSRotate:
		rotator := &engine.LUKSRotator{}
		var kekPub, perr = db.ParseRSAPublicKeyPEM(kekPEM)
		if perr != nil {
			reportAction(ctx, client, serverURL, token, types.ActionReportRequest{
				Kind: d.Kind, VolumeUUID: d.VolumeUUID, Status: "FAILED",
				Detail: "server KEK public key unavailable: " + perr.Error(),
			})
			return
		}
		res := rotator.Rotate(ctx, d.DevicePath, d.VolumeUUID, d.KeySlot, kekPub)
		reportAction(ctx, client, serverURL, token, types.ActionReportRequest{
			Kind: d.Kind, VolumeUUID: res.VolumeUUID, Status: res.Status, Detail: res.Detail,
			NewEncryptedDEK: res.EncryptedDEK, NewEncryptedRecoveryKey: res.EncryptedRecoveryKey,
			NewNonce: res.Nonce, NewKeySlot: res.NewKeySlot,
		})

	default:
		log.Printf("[spired] unknown action directive kind=%q; ignoring", d.Kind)
	}
}

func statusWord(err error, ok string) string {
	if err != nil {
		return "FAILED"
	}
	return ok
}

func detailOrErr(detail string, err error) string {
	if err != nil {
		if detail != "" {
			return detail + "; error: " + err.Error()
		}
		return err.Error()
	}
	return detail
}

// reportAction POSTs an action-specific result to /api/v1/desktop/actions/report.
func reportAction(ctx context.Context, client *http.Client, serverURL, token string, report types.ActionReportRequest) {
	payload, _ := json.Marshal(report)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/desktop/actions/report", bytes.NewReader(payload))
	if err != nil {
		log.Printf("[spired] build action report failed: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[spired] action report (%s) failed: %v", report.Kind, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[spired] action report (%s) HTTP %d: %s", report.Kind, resp.StatusCode, strings.TrimSpace(string(body)))
		return
	}
	log.Printf("[spired] action report (%s) status=%s delivered", report.Kind, report.Status)
}
