package engine_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/types"
)

func TestEnrollLUKSKeySlot1_MissingKeyFile(t *testing.T) {
	ctx := context.Background()
	// Test that EnrollLUKSKeySlot1 fails closed when /etc/spire/luks-master.key does not exist
	err := engine.EnrollLUKSKeySlot1(ctx, "/dev/null", "TEST-KEY-12345678901234567890123456789012345678")
	if err == nil {
		t.Errorf("expected EnrollLUKSKeySlot1 to fail closed when keyfile is missing, got nil error")
	}
}

func TestRunDconfUpdate(t *testing.T) {
	ctx := context.Background()
	out, err := engine.RunDconfUpdate(ctx)
	// On this system or container, if dconf is missing or not writable, it returns an error
	t.Logf("RunDconfUpdate result: out=%q err=%v", out, err)
}

func TestEvaluateDeviceCompliance_PartitioningAndCoreRule(t *testing.T) {
	policies := []types.AssignedPolicy{
		{
			ID:         "pol-sysctl-1",
			Name:       "CIS Network Hardening",
			PolicyType: types.PolicyTypeSysctlSetting,
			Payload:    json.RawMessage(`{"net.ipv4.conf.all.rp_filter":"1"}`),
		},
		{
			ID:         "pol-dconf-1",
			Name:       "GNOME Idle Lock",
			PolicyType: types.PolicyTypeDconfSetting,
			Payload:    json.RawMessage(`{"schema_path":"org/gnome/desktop/session","key":"idle-delay","value":"uint32 300","locked":true}`),
		},
		{
			ID:         "pol-apt-1",
			Name:       "Zero-Touch Unattended Upgrades",
			PolicyType: types.PolicyTypeAptConfig,
			Payload:    json.RawMessage(`{"file_name":"52spire","content":"Unattended-Upgrade::Automatic-Reboot \"false\";"}`),
		},
		{
			ID:             "pol-app-req-1",
			Name:           "Corporate Browser (Firefox)",
			PolicyType:     types.PolicyTypeFlatpakApp,
			AssignmentType: types.AssignmentRequired,
			Payload:        json.RawMessage(`{"app_id":"org.mozilla.firefox","state":"present","assignment_type":"REQUIRED"}`),
		},
		{
			ID:             "pol-app-avail-1",
			Name:           "VLC Media Player",
			PolicyType:     types.PolicyTypeFlatpakApp,
			AssignmentType: types.AssignmentAvailable,
			Payload:        json.RawMessage(`{"app_id":"org.videolan.VLC","state":"present","assignment_type":"AVAILABLE"}`),
		},
	}

	results := []types.PolicyExecutionItem{
		{PolicyID: "pol-sysctl-1", ComplianceStatus: types.ComplianceCompliant},
		{PolicyID: "pol-dconf-1", ComplianceStatus: types.ComplianceCompliant},
		{PolicyID: "pol-apt-1", ComplianceStatus: types.ComplianceCompliant},
	}

	catalog := []types.SelfServiceCatalogItem{
		{
			PolicyID:       "pol-app-avail-2",
			Name:           "LibreOffice Suite",
			Description:    "Optional office suite",
			PolicyType:     types.PolicyTypeFlatpakApp,
			AssignmentType: types.AssignmentAvailable,
			Payload:        json.RawMessage(`{"app_id":"org.libreoffice.LibreOffice","state":"present"}`),
			Installed:      false,
		},
	}

	// Case 1: Mandatory app (org.mozilla.firefox) is NOT installed -> IsCompliant MUST be false
	installedPkgs := map[string]bool{"ca-certificates": true}
	installedFlatpaks := map[string]bool{} // firefox not installed yet

	status1 := engine.EvaluateDeviceCompliance("dev-1", policies, results, catalog, installedPkgs, installedFlatpaks)
	if status1.IsCompliant {
		t.Fatalf("expected IsCompliant=false when REQUIRED application is not installed")
	}
	if len(status1.SecurityPolicies) != 3 {
		t.Fatalf("expected 3 SecurityPolicies, got %d", len(status1.SecurityPolicies))
	}
	if len(status1.MandatoryApps) != 1 {
		t.Fatalf("expected 1 MandatoryApps item, got %d", len(status1.MandatoryApps))
	}
	if status1.MandatoryApps[0].IsCompliant || status1.MandatoryApps[0].Installed {
		t.Fatalf("expected MandatoryApps[0] to have Installed=false and IsCompliant=false")
	}
	if len(status1.AvailableCatalog) != 2 {
		t.Fatalf("expected 2 AvailableCatalog items, got %d", len(status1.AvailableCatalog))
	}

	// Case 2: Mandatory app (org.mozilla.firefox) IS installed, while both AVAILABLE catalog apps remain uninstalled -> IsCompliant MUST be true
	installedFlatpaks["org.mozilla.firefox"] = true
	status2 := engine.EvaluateDeviceCompliance("dev-1", policies, results, catalog, installedPkgs, installedFlatpaks)
	if !status2.IsCompliant {
		t.Fatalf("expected IsCompliant=true when all security policies and REQUIRED apps are compliant, even with AVAILABLE apps uninstalled")
	}
	if !status2.MandatoryApps[0].IsCompliant || !status2.MandatoryApps[0].Installed {
		t.Fatalf("expected MandatoryApps[0] to have Installed=true and IsCompliant=true")
	}
	for _, catItem := range status2.AvailableCatalog {
		if catItem.Installed {
			t.Errorf("expected available catalog item %s to show Installed=false", catItem.Name)
		}
	}
}
