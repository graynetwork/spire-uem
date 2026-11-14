package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/types"
)

// WipeDisableEnv, when set to "1", hard-refuses any crypto-erase. Documented for labs so a
// test/lab endpoint can never be wiped even by a fully valid signed order.
const WipeDisableEnv = "SPIRE_AGENT_DISABLE_WIPE"

// WipeResult reports the outcome of a crypto-erase attempt.
type WipeResult struct {
	RequestID   string
	Status      string // COMPLETED | FAILED
	Detail      string
	ErasedSlots int
	PoweredOff  bool
}

// WipeEngine performs an irreversible LUKS crypto-erase. Runner and PowerOff are injected so
// tests never call real cryptsetup or power the machine off. EscrowedVolumes is the set of
// volume UUIDs THIS agent reported as escrowed (from its local escrow state); only the
// intersection of the signed order's volumes and this set is ever targeted.
type WipeEngine struct {
	Runner          CommandRunner
	PowerOff        func(ctx context.Context) error
	EscrowedVolumes func() map[string]DiscoveredLUKSVolume
	Now             func() time.Time
}

// PerformWipe verifies and executes a signed wipe order. It:
//  1. refuses if SPIRE_AGENT_DISABLE_WIPE=1,
//  2. verifies the Ed25519 signature against the pinned public key,
//  3. refuses an expired order or one whose hardware UUID does not match this device,
//  4. erases every LUKS keyslot (luksErase) of each volume that is BOTH named in the order
//     AND reported as escrowed by this agent — never the agent's own guess,
//  5. powers the machine off.
//
// pinnedPubKeyBase64 is the key the agent pinned at enrollment. hwUUID is this device's
// hardware UUID.
func (e *WipeEngine) PerformWipe(ctx context.Context, pinnedPubKeyBase64, hwUUID string, d types.ActionDirective) WipeResult {
	res := WipeResult{Status: string(types.WipeFailed)}

	if strings.TrimSpace(os.Getenv(WipeDisableEnv)) == "1" {
		res.Detail = WipeDisableEnv + "=1: crypto-erase refused on this endpoint"
		return res
	}
	if strings.TrimSpace(pinnedPubKeyBase64) == "" {
		res.Detail = "no pinned wipe-signing key; refusing unsigned-trust wipe"
		return res
	}
	if len(d.SignedOrder) == 0 || len(d.OrderSignature) == 0 {
		res.Detail = "wipe directive missing signed order or signature"
		return res
	}
	if err := crypto.VerifyWipeOrder(pinnedPubKeyBase64, d.SignedOrder, d.OrderSignature); err != nil {
		res.Detail = "signature verification failed: " + err.Error()
		return res
	}

	var order types.WipeOrder
	if err := json.Unmarshal(d.SignedOrder, &order); err != nil {
		res.Detail = "signed order is not valid JSON: " + err.Error()
		return res
	}
	res.RequestID = order.RequestID

	now := time.Now().UTC()
	if e.Now != nil {
		now = e.Now()
	}
	if !order.ExpiresAt.IsZero() && now.After(order.ExpiresAt) {
		res.Detail = fmt.Sprintf("wipe order expired at %s", order.ExpiresAt.Format(time.RFC3339))
		return res
	}
	if strings.TrimSpace(order.HardwareUUID) != "" && strings.TrimSpace(hwUUID) != "" &&
		!strings.EqualFold(order.HardwareUUID, hwUUID) {
		res.Detail = "wipe order hardware_uuid does not match this device"
		return res
	}

	// Only target volumes the agent itself reported as escrowed. This is the guardrail: the
	// server names volumes, but the agent independently confirms each against its own escrow
	// record before erasing. Never erase the agent's guess.
	escrowed := map[string]DiscoveredLUKSVolume{}
	if e.EscrowedVolumes != nil {
		escrowed = e.EscrowedVolumes()
	}
	ordered := map[string]bool{}
	for _, v := range order.VolumeUUIDs {
		ordered[strings.TrimSpace(v)] = true
	}

	targets := make([]DiscoveredLUKSVolume, 0)
	for uuid, vol := range escrowed {
		if ordered[uuid] {
			targets = append(targets, vol)
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].VolumeUUID < targets[j].VolumeUUID })

	if len(targets) == 0 {
		res.Detail = "no volume is both named in the order and locally escrowed; nothing erased"
		return res
	}

	runner := e.Runner
	if runner == nil {
		runner = execRunner
	}

	var erased []string
	for _, vol := range targets {
		// luksErase wipes ALL keyslots, rendering the data unrecoverable (crypto-erase).
		out, err := runner(ctx, "cryptsetup", "luksErase", "--batch-mode", vol.DevicePath)
		if err != nil {
			res.Detail = fmt.Sprintf("cryptsetup luksErase %s failed: %v (%s)", vol.DevicePath, err, strings.TrimSpace(out))
			return res
		}
		erased = append(erased, vol.VolumeUUID)
		res.ErasedSlots++
	}

	res.Status = string(types.WipeCompleted)
	res.Detail = fmt.Sprintf("crypto-erased %d volume(s): %s", len(erased), strings.Join(erased, ", "))

	// Power off after the keys are gone. A power-off failure does not un-erase the keys, so
	// the wipe is still COMPLETED; the power-off outcome is appended to the detail.
	powerOff := e.PowerOff
	if powerOff == nil {
		powerOff = func(ctx context.Context) error {
			_, err := runner(ctx, "systemctl", "poweroff")
			return err
		}
	}
	if err := powerOff(ctx); err != nil {
		res.Detail += fmt.Sprintf("; power-off failed: %v", err)
	} else {
		res.PoweredOff = true
		res.Detail += "; powered off"
	}
	return res
}
