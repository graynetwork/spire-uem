package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// Injectable seams so tests run unprivileged with a fake usbguard and temp dirs.
var (
	usbguardRulesDir               = "/etc/usbguard"
	usbguardRunner   CommandRunner = execCommandRunner{}
)

const usbguardRulesFile = "rules.conf"

var (
	usbHexIDRe  = regexp.MustCompile(`^[0-9a-f]{4}$`)
	usbSerialRe = regexp.MustCompile(`^[0-9A-Za-z._:-]{1,64}$`)
	usbClassRe  = regexp.MustCompile(`^[0-9a-f]{2}$`)
)

// usbguardRulesPath returns the managed usbguard rules file path.
func usbguardRulesPath() string {
	return filepath.Join(usbguardRulesDir, usbguardRulesFile)
}

// validateUSBPayload validates an allow-list payload and the mode.
func validateUSBPayload(p types.USBDeviceControlPayload) error {
	switch p.Mode {
	case types.USBModeAllowAll, types.USBModeBlockNew:
	default:
		return fmt.Errorf("invalid usb mode %q (allow_all|block_new)", p.Mode)
	}
	for i, e := range p.AllowList {
		if e.VendorID != "" && !usbHexIDRe.MatchString(strings.ToLower(e.VendorID)) {
			return fmt.Errorf("allow_list[%d]: invalid vendor_id %q (want 4 hex digits)", i, e.VendorID)
		}
		if e.ProductID != "" {
			if e.VendorID == "" {
				return fmt.Errorf("allow_list[%d]: product_id requires vendor_id", i)
			}
			if !usbHexIDRe.MatchString(strings.ToLower(e.ProductID)) {
				return fmt.Errorf("allow_list[%d]: invalid product_id %q (want 4 hex digits)", i, e.ProductID)
			}
		}
		if e.Serial != "" && !usbSerialRe.MatchString(e.Serial) {
			return fmt.Errorf("allow_list[%d]: invalid serial %q", i, e.Serial)
		}
		if e.DeviceClass != "" && !usbClassRe.MatchString(strings.ToLower(e.DeviceClass)) {
			return fmt.Errorf("allow_list[%d]: invalid device_class %q (want 2 hex digits)", i, e.DeviceClass)
		}
		if e.VendorID == "" && e.DeviceClass == "" {
			return fmt.Errorf("allow_list[%d]: entry must specify at least vendor_id or device_class", i)
		}
	}
	return nil
}

// renderUSBRules builds the usbguard rules.conf content.
//
// In block_new mode, a base policy of the currently-connected devices is prepended (so nothing
// already plugged in is cut off at first apply), then explicit allow-list entries, then — if
// AllowHID is set — a blanket allow for HID (class 03) so admins cannot lock out keyboards/mice,
// then an implicit "block" for everything else. In allow_all mode a single allow rule is emitted.
func renderUSBRules(policyID string, p types.USBDeviceControlPayload, baselineRules []string) string {
	var sb strings.Builder
	sb.WriteString("# Managed by SpireUEM - USB_DEVICE_CONTROL\n")
	fmt.Fprintf(&sb, "# Policy ID: %s\n", policyID)
	fmt.Fprintf(&sb, "# Mode: %s\n", p.Mode)
	fmt.Fprintf(&sb, "# Generated at: %s\n\n", time.Now().UTC().Format(time.RFC3339))

	if p.Mode == types.USBModeAllowAll {
		sb.WriteString("allow\n")
		return sb.String()
	}

	// block_new: grandfather currently-connected devices captured at first apply.
	if len(baselineRules) > 0 {
		sb.WriteString("# --- devices present at first apply (grandfathered) ---\n")
		for _, r := range baselineRules {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}
			sb.WriteString(r)
			sb.WriteByte('\n')
		}
		sb.WriteByte('\n')
	}

	if p.AllowHID {
		sb.WriteString("# HID (keyboards/mice) always allowed to prevent admin lockout\n")
		sb.WriteString("allow with-interface one-of { 03:*:* }\n\n")
	}

	if len(p.AllowList) > 0 {
		sb.WriteString("# --- explicit allow-list ---\n")
		for _, e := range p.AllowList {
			sb.WriteString(renderUSBAllowEntry(e))
			sb.WriteByte('\n')
		}
		sb.WriteByte('\n')
	}

	// Implicit deny: usbguard's ImplicitPolicyTarget is "block", but we make the posture explicit.
	sb.WriteString("# everything not matched above is blocked by the implicit policy\n")
	return sb.String()
}

func renderUSBAllowEntry(e types.USBAllowEntry) string {
	var sb strings.Builder
	sb.WriteString("allow")
	if e.VendorID != "" {
		id := strings.ToLower(e.VendorID) + ":"
		if e.ProductID != "" {
			id += strings.ToLower(e.ProductID)
		} else {
			id += "*"
		}
		fmt.Fprintf(&sb, " id %s", id)
	}
	if e.DeviceClass != "" {
		fmt.Fprintf(&sb, " with-interface one-of { %s:*:* }", strings.ToLower(e.DeviceClass))
	}
	if e.Serial != "" {
		fmt.Fprintf(&sb, " serial %q", e.Serial)
	}
	if e.Comment != "" {
		fmt.Fprintf(&sb, " # %s", sanitizeComment(e.Comment))
	}
	return sb.String()
}

func sanitizeComment(c string) string {
	c = strings.ReplaceAll(c, "\n", " ")
	c = strings.ReplaceAll(c, "\r", " ")
	if len(c) > 120 {
		c = c[:120]
	}
	return c
}

// ReconcileUSBDeviceControl enforces a USB_DEVICE_CONTROL policy with usbguard.
func ReconcileUSBDeviceControl(ctx context.Context, policy types.AssignedPolicy) types.PolicyExecutionItem {
	details := map[string]any{
		"policy_id": policy.ID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	var payload types.USBDeviceControlPayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return usbFail(policy.ID, details, fmt.Sprintf("invalid USB_DEVICE_CONTROL payload: %v", err))
	}
	if err := validateUSBPayload(payload); err != nil {
		return usbFail(policy.ID, details, err.Error())
	}
	details["mode"] = string(payload.Mode)
	details["allow_hid"] = payload.AllowHID

	if err := os.MkdirAll(usbguardRulesDir, 0750); err != nil {
		return usbFail(policy.ID, details, fmt.Sprintf("mkdir %s: %v", usbguardRulesDir, err))
	}
	target := usbguardRulesPath()
	details["rules_file"] = target

	// Grandfather currently-connected devices only on first apply (no managed file yet) in block_new.
	var baseline []string
	_, statErr := os.Stat(target)
	firstApply := os.IsNotExist(statErr)
	if payload.Mode == types.USBModeBlockNew && firstApply {
		if out, gerr := usbguardRunner.Run(ctx, "usbguard", "generate-policy"); gerr == nil && out != "" {
			baseline = strings.Split(out, "\n")
			details["grandfathered_devices"] = len(baseline)
		} else if gerr != nil {
			details["generate_policy_note"] = "usbguard generate-policy unavailable; no devices grandfathered"
		}
	}

	content := renderUSBRules(policy.ID, payload, baseline)

	// Converged? (Only compare when not first apply, since baseline is captured once.)
	if existing, rerr := os.ReadFile(target); rerr == nil {
		if string(existing) == content {
			details["drifted"] = false
			details["action"] = "verified_content"
			if serr := ensureUsbguardEnabled(ctx, details); serr != "" {
				details["service_note"] = serr
			}
			return usbOK(policy.ID, types.ComplianceCompliant, details)
		}
		// Re-render preserving the existing grandfathered block so a later convergence is stable.
		if payload.Mode == types.USBModeBlockNew {
			if gf := extractGrandfathered(string(existing)); len(gf) > 0 {
				content = renderUSBRules(policy.ID, payload, gf)
				if string(existing) == content {
					details["drifted"] = false
					details["action"] = "verified_content"
					if serr := ensureUsbguardEnabled(ctx, details); serr != "" {
						details["service_note"] = serr
					}
					return usbOK(policy.ID, types.ComplianceCompliant, details)
				}
			}
		}
	}

	if err := atomicWriteFile(target, []byte(content), 0600); err != nil {
		return usbFail(policy.ID, details, fmt.Sprintf("atomic write %s: %v", target, err))
	}
	details["drifted"] = true
	details["reasserted"] = true

	// Validate the written ruleset if usbguard is present.
	if out, verr := usbguardRunner.Run(ctx, "usbguard", "read-rules", target); verr != nil {
		details["read_rules"] = out
		if !strings.Contains(strings.ToLower(verr.Error()), "no such file") && !strings.Contains(strings.ToLower(verr.Error()), "not found") {
			details["validate_note"] = verr.Error()
		}
	} else {
		details["read_rules"] = "ok"
	}

	if serr := ensureUsbguardEnabled(ctx, details); serr != "" {
		details["service_note"] = serr
	}

	return usbOK(policy.ID, types.ComplianceCompliant, details)
}

// extractGrandfathered pulls the grandfathered device rule lines out of an existing managed file
// so repeated convergence does not re-run generate-policy or churn the file.
func extractGrandfathered(content string) []string {
	const startMark = "# --- devices present at first apply (grandfathered) ---"
	lines := strings.Split(content, "\n")
	var out []string
	in := false
	for _, l := range lines {
		if strings.TrimSpace(l) == startMark {
			in = true
			continue
		}
		if in {
			if strings.HasPrefix(strings.TrimSpace(l), "#") || strings.TrimSpace(l) == "" {
				break
			}
			out = append(out, l)
		}
	}
	return out
}

// ensureUsbguardEnabled makes a best-effort attempt to enable+start usbguard. Returns a note string
// on failure (never fatal — in tests/containers systemctl is absent).
func ensureUsbguardEnabled(ctx context.Context, details map[string]any) string {
	out, err := usbguardRunner.Run(ctx, "systemctl", "enable", "--now", "usbguard")
	if err != nil {
		return fmt.Sprintf("could not enable usbguard service: %v (%s)", err, out)
	}
	details["service"] = "enabled"
	return ""
}

// RemoveUSBDeviceControl removes the spire-managed usbguard rules file on revoke.
func RemoveUSBDeviceControl(ctx context.Context) error {
	_ = ctx
	target := usbguardRulesPath()
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", target, err)
	}
	return nil
}

func usbFail(policyID string, details map[string]any, msg string) types.PolicyExecutionItem {
	details["error"] = msg
	out, _ := json.Marshal(details)
	return types.PolicyExecutionItem{
		PolicyID:         policyID,
		ComplianceStatus: types.ComplianceFailed,
		ErrorMessage:     msg,
		ExecutionOutput:  out,
	}
}

func usbOK(policyID string, status types.ComplianceStatus, details map[string]any) types.PolicyExecutionItem {
	out, _ := json.Marshal(details)
	return types.PolicyExecutionItem{
		PolicyID:         policyID,
		ComplianceStatus: status,
		ExecutionOutput:  out,
	}
}
