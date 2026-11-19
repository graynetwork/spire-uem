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

func TestPolicyCarriesSecret(t *testing.T) {
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
		{"wifi sealed eap-tls client key only", types.NetworkProfilePayload{Wifi: &types.WifiProfile{ClientKey: sealed()}}, true},
		{"wired sealed eap-tls client key only", types.NetworkProfilePayload{Wired: &types.WiredDot1xProfile{ClientKey: sealed()}}, true},
		{"wired legacy plaintext client key", types.NetworkProfilePayload{Wired: &types.WiredDot1xProfile{ClientKey: types.SecretEnvelope{Plaintext: "-----BEGIN PRIVATE KEY-----"}}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.p
			if got := policyCarriesSecret(&p); got != tc.want {
				t.Fatalf("policyCarriesSecret=%v want %v", got, tc.want)
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

// An EAP-TLS profile whose only secret is the client key must be withheld from an untrusted
// device, both when the key is sealed and when it is a legacy plaintext key stored before keys
// were sealed at rest. Neither ciphertext nor plaintext may remain in the delivered payload.
func TestWithholdStripsEAPTLSClientKey(t *testing.T) {
	keys := map[string]types.SecretEnvelope{
		"sealed": sealed(),
		"legacy": {Plaintext: "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"},
	}
	for name, key := range keys {
		t.Run(name, func(t *testing.T) {
			wifi, _ := json.Marshal(types.NetworkProfilePayload{
				Kind: types.NetworkProfileWifi,
				Wifi: &types.WifiProfile{SSID: "Corp", ClientKey: key},
			})
			wired, _ := json.Marshal(types.NetworkProfilePayload{
				Wired: &types.WiredDot1xProfile{ClientKey: key},
			})
			pols := []types.AssignedPolicy{
				{ID: "wifi", PolicyType: types.PolicyTypeNetworkProfile, Payload: wifi},
				{ID: "wired", PolicyType: types.PolicyTypeNetworkProfile, Payload: wired},
			}
			(&Handler{}).withholdPolicySecrets(pols, "untrusted")
			for _, pol := range pols {
				if !pol.SecretsWithheld {
					t.Fatalf("%s: client-key-only profile not flagged SecretsWithheld", pol.ID)
				}
				var out types.NetworkProfilePayload
				if err := json.Unmarshal(pol.Payload, &out); err != nil {
					t.Fatalf("%s: payload no longer parses: %v", pol.ID, err)
				}
				var got types.SecretEnvelope
				if out.Wifi != nil {
					got = out.Wifi.ClientKey
				} else {
					got = out.Wired.ClientKey
				}
				if got.HasValue() {
					t.Fatalf("%s: client key was delivered to an untrusted device: %+v", pol.ID, got)
				}
			}
		})
	}
}
