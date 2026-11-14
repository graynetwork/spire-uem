package api

import (
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

func TestEvaluateAttestation_FailsClosed(t *testing.T) {
	h := &Handler{}
	fresh := &types.DeviceTPMAttestation{ChallengeNonce: "abcd", UpdatedAt: time.Now(), AKPublicPEM: "x", EKPublicPEM: "y"}

	cases := map[string]struct {
		staged *types.DeviceTPMAttestation
		req    types.AttestationVerifyRequest
		env    string
	}{
		"no TPM":                      {fresh, types.AttestationVerifyRequest{Nonce: "absent-tpm"}, ""},
		"no outstanding challenge":    {nil, types.AttestationVerifyRequest{Nonce: "abcd"}, ""},
		"challenge already consumed":  {&types.DeviceTPMAttestation{UpdatedAt: time.Now()}, types.AttestationVerifyRequest{Nonce: "abcd"}, ""},
		"empty nonce no longer skips": {fresh, types.AttestationVerifyRequest{Nonce: ""}, ""},
		"nonce mismatch":              {fresh, types.AttestationVerifyRequest{Nonce: "ffff"}, ""},
		"expired challenge":           {&types.DeviceTPMAttestation{ChallengeNonce: "abcd", UpdatedAt: time.Now().Add(-time.Hour)}, types.AttestationVerifyRequest{Nonce: "abcd"}, ""},
		"simulated without opt-in":    {fresh, types.AttestationVerifyRequest{Nonce: "abcd", Simulated: true}, ""},
		"hardware without EK cert":    {fresh, types.AttestationVerifyRequest{Nonce: "abcd"}, ""},
		"client secure-boot flag alone": {fresh, types.AttestationVerifyRequest{Nonce: "abcd", SecureBootEnabled: true,
			PCRValues: map[string]string{"7": "11"}}, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("SPIRE_SIMULATE_TPM2", c.env)
			t.Setenv("SPIRE_ALLOW_UNATTESTED_DEVICES", "")
			t.Setenv("SPIRE_ALLOW_SIMULATED_TPM", "")
			status, sb, _, reason := h.evaluateAttestation(c.staged, &c.req)
			if status == types.AttestationAttested || sb {
				t.Fatalf("expected non-attested result, got status=%s secureBoot=%v", status, sb)
			}
			if reason == "" {
				t.Fatal("expected a reason for the failure")
			}
		})
	}
}
