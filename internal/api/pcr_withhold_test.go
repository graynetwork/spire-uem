package api

import (
	"encoding/json"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

func sealed() types.SecretEnvelope {
	return types.SecretEnvelope{Ciphertext: "c", EncryptedDEK: "d", Nonce: "n"}
}

func wifiPolicy(t *testing.T, psk types.SecretEnvelope) types.AssignedPolicy {
	t.Helper()
	payload, _ := json.Marshal(types.NetworkProfilePayload{
		Kind: types.NetworkProfileWifi,
		Wifi: &types.WifiProfile{SSID: "Corp", Security: types.WifiWPA2Personal, PSK: psk},
	})
	return types.AssignedPolicy{ID: "wifi1", PolicyType: types.PolicyTypeNetworkProfile, Payload: payload}
}

func TestPolicyCarriesSealedSecret(t *testing.T) {
	cases := []struct {
		name string
		p    types.NetworkProfilePayload
		want bool
	}{
		{"wifi sealed psk", types.NetworkProfilePayload{Wifi: &types.WifiProfile{PSK: sealed()}}, true},
		{"wifi no secret", types.NetworkProfilePayload{Wifi: &types.WifiProfile{}}, false},
		{"wired sealed password", types.NetworkProfilePayload{Wired: &types.WiredDot1xProfile{Password: sealed()}}, true},
		{"wireguard sealed peer psk", types.NetworkProfilePayload{WireGuard: &types.WireGuardProfile{PeerPSKs: map[string]types.SecretEnvelope{"0": sealed()}}}, true},
		{"wireguard no psk", types.NetworkProfilePayload{WireGuard: &types.WireGuardProfile{}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.p
			if got := policyCarriesSealedSecret(&p); got != tc.want {
				t.Fatalf("policyCarriesSealedSecret=%v want %v", got, tc.want)
			}
		})
	}
}

func TestWithholdPolicySecrets(t *testing.T) {
	h := &Handler{}
	pols := []types.AssignedPolicy{wifiPolicy(t, sealed())}

	h.withholdPolicySecrets(pols, "untrusted")

	if !pols[0].SecretsWithheld {
		t.Fatal("expected SecretsWithheld=true on the carrying policy")
	}
	if pols[0].WithheldReason == "" {
		t.Fatal("expected a WithheldReason")
	}
	var out types.NetworkProfilePayload
	if err := json.Unmarshal(pols[0].Payload, &out); err != nil {
		t.Fatalf("payload no longer parses: %v", err)
	}
	// The sealed envelope must be stripped — no ciphertext and no plaintext leaked.
	if out.Wifi.PSK.IsSealed() || out.Wifi.PSK.Plaintext != "" {
		t.Fatalf("sealed PSK was not stripped: %+v", out.Wifi.PSK)
	}
}

func TestWithholdSkipsNonCarryingPolicy(t *testing.T) {
	h := &Handler{}
	// A NETWORK_PROFILE with no sealed secret must NOT be flagged withheld.
	pols := []types.AssignedPolicy{wifiPolicy(t, types.SecretEnvelope{})}
	h.withholdPolicySecrets(pols, "untrusted")
	if pols[0].SecretsWithheld {
		t.Fatal("a profile with no sealed secret must not be flagged withheld")
	}
}
