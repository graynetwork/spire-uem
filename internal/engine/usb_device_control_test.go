package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

func withUSBFakes(t *testing.T) (dir string, fr *fakeRunner, restore func()) {
	t.Helper()
	tmp := t.TempDir()
	origDir := usbguardRulesDir
	origRunner := usbguardRunner
	usbguardRulesDir = filepath.Join(tmp, "usbguard")
	fr = newFakeRunner()
	usbguardRunner = fr
	return usbguardRulesDir, fr, func() {
		usbguardRulesDir = origDir
		usbguardRunner = origRunner
	}
}

func TestValidateUSBPayload(t *testing.T) {
	ok := []types.USBDeviceControlPayload{
		{Mode: types.USBModeAllowAll},
		{Mode: types.USBModeBlockNew, AllowHID: true},
		{Mode: types.USBModeBlockNew, AllowList: []types.USBAllowEntry{{VendorID: "046d", ProductID: "c52b"}}},
		{Mode: types.USBModeBlockNew, AllowList: []types.USBAllowEntry{{DeviceClass: "03"}}},
		{Mode: types.USBModeBlockNew, AllowList: []types.USBAllowEntry{{VendorID: "0781", Serial: "ABC-123"}}},
	}
	for i, p := range ok {
		if err := validateUSBPayload(p); err != nil {
			t.Errorf("ok case %d: unexpected error %v", i, err)
		}
	}
	bad := []types.USBDeviceControlPayload{
		{Mode: "weird"},
		{Mode: types.USBModeBlockNew, AllowList: []types.USBAllowEntry{{VendorID: "ZZZZ"}}},
		{Mode: types.USBModeBlockNew, AllowList: []types.USBAllowEntry{{ProductID: "c52b"}}}, // product without vendor
		{Mode: types.USBModeBlockNew, AllowList: []types.USBAllowEntry{{VendorID: "046d", ProductID: "xyz"}}},
		{Mode: types.USBModeBlockNew, AllowList: []types.USBAllowEntry{{DeviceClass: "999"}}},
		{Mode: types.USBModeBlockNew, AllowList: []types.USBAllowEntry{{Serial: "has space"}}},
		{Mode: types.USBModeBlockNew, AllowList: []types.USBAllowEntry{{}}}, // empty entry
	}
	for i, p := range bad {
		if err := validateUSBPayload(p); err == nil {
			t.Errorf("bad case %d: expected error, got nil", i)
		}
	}
}

func TestUSBAllowAllRender(t *testing.T) {
	c := renderUSBRules("p1", types.USBDeviceControlPayload{Mode: types.USBModeAllowAll}, nil)
	if !strings.Contains(c, "\nallow\n") {
		t.Errorf("allow_all should emit a single allow rule: %q", c)
	}
}

func TestUSBBlockNewHIDAndAllowList(t *testing.T) {
	c := renderUSBRules("p1", types.USBDeviceControlPayload{
		Mode:      types.USBModeBlockNew,
		AllowHID:  true,
		AllowList: []types.USBAllowEntry{{VendorID: "046d", ProductID: "c52b", Comment: "logitech receiver"}},
	}, []string{"allow id 1d6b:0002 # root hub"})
	if !strings.Contains(c, "grandfathered") {
		t.Error("expected grandfathered section")
	}
	if !strings.Contains(c, "allow id 1d6b:0002") {
		t.Error("expected baseline device preserved")
	}
	if !strings.Contains(c, "03:*:*") {
		t.Error("expected HID allow when AllowHID=true")
	}
	if !strings.Contains(c, "allow id 046d:c52b") {
		t.Error("expected allow-list entry")
	}
	if !strings.Contains(c, "# logitech receiver") {
		t.Error("expected comment preserved")
	}
}

func TestUSBBlockNewNoHIDWarnPathStillRenders(t *testing.T) {
	c := renderUSBRules("p1", types.USBDeviceControlPayload{Mode: types.USBModeBlockNew, AllowHID: false}, nil)
	if strings.Contains(c, "03:*:*") {
		t.Error("HID allow should be absent when AllowHID=false")
	}
}

func TestReconcileUSBApplyGrandfatherDriftRemove(t *testing.T) {
	dir, fr, restore := withUSBFakes(t)
	defer restore()
	ctx := context.Background()
	// usbguard generate-policy returns current devices on first apply
	fr.outputs["usbguard generate-policy"] = "allow id 1d6b:0002\nallow id 8087:0024"

	payload, _ := json.Marshal(types.USBDeviceControlPayload{
		Mode:      types.USBModeBlockNew,
		AllowHID:  true,
		AllowList: []types.USBAllowEntry{{VendorID: "046d", ProductID: "c52b"}},
	})
	pol := types.AssignedPolicy{ID: "usb1", PolicyType: types.PolicyTypeUSBDeviceControl, Payload: payload}

	item := ReconcileUSBDeviceControl(ctx, pol)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("apply: expected COMPLIANT, got %s (%s)", item.ComplianceStatus, item.ErrorMessage)
	}
	target := usbguardRulesPath()
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("rules.conf not created: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600, got %v", info.Mode().Perm())
	}
	data, _ := os.ReadFile(target)
	if !strings.Contains(string(data), "1d6b:0002") {
		t.Error("expected grandfathered device in file")
	}
	if !fr.called("usbguard generate-policy") {
		t.Error("expected generate-policy called on first apply")
	}
	_ = dir

	// Second apply converges and preserves grandfathered block without re-running generate-policy
	fr.calls = nil
	item = ReconcileUSBDeviceControl(ctx, pol)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("reapply: expected COMPLIANT, got %s", item.ComplianceStatus)
	}
	if fr.called("generate-policy") {
		t.Error("generate-policy should NOT run on a converged reapply")
	}
	var det map[string]any
	_ = json.Unmarshal(item.ExecutionOutput, &det)
	if det["drifted"] != false {
		t.Errorf("expected drifted=false on converged reapply, got %v", det["drifted"])
	}

	// Remove
	if err := RemoveUSBDeviceControl(ctx); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("expected rules.conf removed, got %v", err)
	}
}

func TestExtractGrandfathered(t *testing.T) {
	content := renderUSBRules("p1", types.USBDeviceControlPayload{Mode: types.USBModeBlockNew, AllowHID: true},
		[]string{"allow id aaaa:bbbb", "allow id cccc:dddd"})
	gf := extractGrandfathered(content)
	if len(gf) != 2 || !strings.Contains(gf[0], "aaaa:bbbb") {
		t.Errorf("extractGrandfathered mismatch: %v", gf)
	}
}
