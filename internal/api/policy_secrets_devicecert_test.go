package api

import (
	"encoding/json"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

// A profile that uses the device-issued certificate carries no secret, so attestation
// withholding never touches it, whatever the device's trust. This is intended: the key stays
// on the endpoint, and RADIUS checks posture when the device connects.
func TestWithholdDoesNotTouchDeviceCertProfiles(t *testing.T) {
	wired, _ := json.Marshal(types.NetworkProfilePayload{
		Kind:  types.NetworkProfileWiredDot1x,
		Wired: &types.WiredDot1xProfile{EAP: types.EAPTLS, ClientCertSource: types.ClientCertSourceDevice},
	})
	wifi, _ := json.Marshal(types.NetworkProfilePayload{
		Kind: types.NetworkProfileWifi,
		Wifi: &types.WifiProfile{SSID: "Corp", Security: types.WifiWPA2Enterprise, EAP: types.EAPTLS, ClientCertSource: types.ClientCertSourceDevice},
	})
	var p types.NetworkProfilePayload
	_ = json.Unmarshal(wired, &p)
	if policyCarriesSecret(&p) {
		t.Fatal("a device-certificate profile reported as carrying a secret")
	}

	pols := []types.AssignedPolicy{
		{ID: "wired", PolicyType: types.PolicyTypeNetworkProfile, Payload: wired},
		{ID: "wifi", PolicyType: types.PolicyTypeNetworkProfile, Payload: wifi},
	}
	(&Handler{}).withholdPolicySecrets(pols, "untrusted")
	for _, pol := range pols {
		if pol.SecretsWithheld {
			t.Fatalf("%s: a profile with no secret was withheld", pol.ID)
		}
	}
	var out types.NetworkProfilePayload
	_ = json.Unmarshal(pols[0].Payload, &out)
	if out.Wired == nil || out.Wired.ClientCertSource != types.ClientCertSourceDevice {
		t.Fatalf("the payload was altered: %s", pols[0].Payload)
	}

	// The same profile with an extra pasted key would be a secret-carrying one (and the
	// server refuses to store that combination, see the validation tests).
	var mixed types.NetworkProfilePayload
	_ = json.Unmarshal(wired, &mixed)
	mixed.Wired.ClientKey = sealed()
	if !policyCarriesSecret(&mixed) {
		t.Fatal("a profile with a sealed key must still count as carrying a secret")
	}
}
