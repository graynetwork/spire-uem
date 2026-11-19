package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

// A policy flagged SecretsWithheld must be reported NON_COMPLIANT and must NOT write a
// keyfile or touch an existing one — the agent treats it as a skipped item.
func TestEnforceNetworkProfile_WithheldSkipsWithoutWriting(t *testing.T) {
	dir, fr, restore := withNMFakes(t)
	defer restore()
	ctx := context.Background()
	_ = fr

	payload, _ := json.Marshal(types.NetworkProfilePayload{
		Kind:        types.NetworkProfileWifi,
		Autoconnect: true,
		Wifi: &types.WifiProfile{
			SSID:     "CorpWifi",
			Security: types.WifiWPA2Personal,
			PSK:      types.SecretEnvelope{}, // stripped by the server
		},
	})
	pol := types.AssignedPolicy{
		ID:              "wifiW",
		PolicyType:      types.PolicyTypeNetworkProfile,
		Payload:         payload,
		SecretsWithheld: true,
		WithheldReason:  "device attestation untrusted; sealed secrets withheld",
	}

	item := EnforceNetworkProfilePolicy(ctx, pol)
	if item.ComplianceStatus != types.ComplianceNonCompliant {
		t.Fatalf("expected NON_COMPLIANT for a withheld policy, got %s", item.ComplianceStatus)
	}
	if item.ErrorMessage == "" {
		t.Fatal("expected an error message explaining the withhold")
	}
	// No keyfile should have been written.
	if _, err := os.Stat(filepath.Join(dir, "spire-wifiW.nmconnection")); !os.IsNotExist(err) {
		t.Fatalf("withheld policy must not write a keyfile (stat err=%v)", err)
	}
}

// A withhold must not remove an already-working keyfile: the existing file is left intact.
func TestEnforceNetworkProfile_WithheldLeavesExistingKeyfile(t *testing.T) {
	dir, _, restore := withNMFakes(t)
	defer restore()
	ctx := context.Background()

	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	existing := filepath.Join(dir, "spire-wifiE.nmconnection")
	const original = "[connection]\nid=spire-wifiE\n"
	if err := os.WriteFile(existing, []byte(original), 0600); err != nil {
		t.Fatalf("seed keyfile: %v", err)
	}

	payload, _ := json.Marshal(types.NetworkProfilePayload{
		Kind: types.NetworkProfileWifi,
		Wifi: &types.WifiProfile{SSID: "CorpWifi", Security: types.WifiWPA2Personal},
	})
	pol := types.AssignedPolicy{
		ID: "wifiE", PolicyType: types.PolicyTypeNetworkProfile, Payload: payload, SecretsWithheld: true,
	}

	if item := EnforceNetworkProfilePolicy(ctx, pol); item.ComplianceStatus != types.ComplianceNonCompliant {
		t.Fatalf("expected NON_COMPLIANT, got %s", item.ComplianceStatus)
	}
	got, err := os.ReadFile(existing)
	if err != nil {
		t.Fatalf("existing keyfile was removed or unreadable: %v", err)
	}
	if string(got) != original {
		t.Fatalf("existing keyfile was modified:\n%s", got)
	}
}
