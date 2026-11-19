package api

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// nowUTC is the time source for trust evaluation (indirection kept trivial for tests that
// call crypto.EvaluateTrust with an explicit clock).
func nowUTC() time.Time { return time.Now().UTC() }

// policyCarriesSealedSecret reports whether a NETWORK_PROFILE payload contains at least one
// sealed SecretEnvelope. Only such policies are affected by attestation enforcement; a
// profile with no secrets (e.g. EAP-TLS with inline certs only, or an open network) is
// delivered unchanged even to an untrusted device.
func policyCarriesSealedSecret(p *types.NetworkProfilePayload) bool {
	if p == nil {
		return false
	}
	if p.Wifi != nil && (p.Wifi.PSK.IsSealed() || p.Wifi.Password.IsSealed()) {
		return true
	}
	if p.Wired != nil && p.Wired.Password.IsSealed() {
		return true
	}
	if p.WireGuard != nil {
		for _, env := range p.WireGuard.PeerPSKs {
			if env.IsSealed() {
				return true
			}
		}
	}
	return false
}

// gatePolicySecrets decides, per attestation enforcement mode, whether a device may receive
// unsealed NETWORK_PROFILE secrets, then either unseals them or marks the carrying policies
// as withheld. It returns the trust evaluation so the caller can alert under warn mode.
//
//   - off     : always unseal (pre-baseline behaviour).
//   - warn    : always unseal, but return trusted=false so the caller can alert.
//   - enforce : trusted devices get unsealed secrets; untrusted devices get the sealed
//               secrets stripped and the policy flagged SecretsWithheld.
//
// A device is trusted per the crypto.EvaluateTrust decision table (latest result + exception
// + max age). A no-TPM device has no result and, without an exception, is untrusted.
func (h *Handler) gatePolicySecrets(ctx context.Context, dev *types.Device, policies []types.AssignedPolicy) types.TrustEvaluation {
	mode, err := h.repo.AttestationEnforcementMode(ctx)
	if err != nil {
		// Fail closed: if the setting cannot be read we cannot tell whether enforcement is on,
		// so treat it as enforce. A withheld profile is reported non-compliant and the agent
		// keeps any working keyfile, so this never disconnects a device that already has one.
		log.Printf("[api] warning: read attestation enforcement mode failed: %v; treating as enforce", err)
		mode = types.EnforcementEnforce
	}
	if mode == types.EnforcementOff {
		h.unsealPolicyPayloadSecrets(policies)
		return types.TrustEvaluation{Trusted: true, Reason: "enforcement off"}
	}

	maxAge, _ := h.repo.AttestationMaxAge(ctx)
	latest, _ := h.repo.GetLatestAttestationResult(ctx, dev.ID)
	exc, _ := h.repo.GetActiveBaselineException(ctx, dev.ID)
	trust := crypto.EvaluateTrust(latest, exc, maxAge, nowUTC())

	if mode == types.EnforcementWarn || trust.Trusted {
		// warn still delivers secrets; enforce delivers to trusted devices.
		h.unsealPolicyPayloadSecrets(policies)
		return trust
	}

	// enforce + untrusted: withhold sealed secrets from the carrying policies.
	h.withholdPolicySecrets(policies, "device attestation untrusted ("+trust.Reason+"); sealed secrets withheld under enforce mode")
	log.Printf("[api] attestation enforce: withholding sealed secrets from untrusted device=%s (%s)", dev.ID, trust.Reason)
	return trust
}

// withholdPolicySecrets strips sealed SecretEnvelope fields from each NETWORK_PROFILE policy
// that carries one, replacing them with empty envelopes, and flags the policy SecretsWithheld
// so the agent skips it rather than writing a blank credential. Policies without sealed
// secrets are left untouched.
func (h *Handler) withholdPolicySecrets(policies []types.AssignedPolicy, reason string) {
	for i := range policies {
		if policies[i].PolicyType != types.PolicyTypeNetworkProfile {
			continue
		}
		var p types.NetworkProfilePayload
		if err := json.Unmarshal(policies[i].Payload, &p); err != nil {
			log.Printf("[api] withhold: parse NETWORK_PROFILE payload for policy=%s failed: %v", policies[i].ID, err)
			continue
		}
		if !policyCarriesSealedSecret(&p) {
			continue
		}
		if p.Wifi != nil {
			p.Wifi.PSK = types.SecretEnvelope{}
			p.Wifi.Password = types.SecretEnvelope{}
		}
		if p.Wired != nil {
			p.Wired.Password = types.SecretEnvelope{}
		}
		if p.WireGuard != nil {
			for idx := range p.WireGuard.PeerPSKs {
				p.WireGuard.PeerPSKs[idx] = types.SecretEnvelope{}
			}
		}
		if rebuilt, err := json.Marshal(p); err == nil {
			policies[i].Payload = rebuilt
		}
		policies[i].SecretsWithheld = true
		policies[i].WithheldReason = reason
	}
}

// unsealPolicyPayloadSecrets rewrites each NETWORK_PROFILE policy payload in place, replacing the
// sealed SecretEnvelope fields with their plaintext (in the transient Plaintext field) so the agent
// can write the NetworkManager keyfile. Only the agent receives this, over the deployment's
// TLS-terminating proxy; the stored payload and the admin UI never hold plaintext.
//
// A policy whose secrets cannot be unsealed is left with empty plaintext and logged; the agent then
// reports the keyfile as non-compliant rather than writing a broken credential.
func (h *Handler) unsealPolicyPayloadSecrets(policies []types.AssignedPolicy) {
	priv := h.repo.KEKPrivateKey()
	for i := range policies {
		if policies[i].PolicyType != types.PolicyTypeNetworkProfile {
			continue
		}
		var p types.NetworkProfilePayload
		if err := json.Unmarshal(policies[i].Payload, &p); err != nil {
			log.Printf("[api] unseal: parse NETWORK_PROFILE payload for policy=%s failed: %v", policies[i].ID, err)
			continue
		}
		open := func(env types.SecretEnvelope) types.SecretEnvelope {
			if !env.IsSealed() {
				return env
			}
			pt, err := db.OpenSecret(priv, env)
			if err != nil {
				log.Printf("[api] unseal: open secret for policy=%s failed: %v", policies[i].ID, err)
				return types.SecretEnvelope{}
			}
			return types.SecretEnvelope{Plaintext: pt}
		}

		if p.Wifi != nil {
			p.Wifi.PSK = open(p.Wifi.PSK)
			p.Wifi.ClientKey = open(p.Wifi.ClientKey)
			p.Wifi.Password = open(p.Wifi.Password)
		}
		if p.Wired != nil {
			p.Wired.ClientKey = open(p.Wired.ClientKey)
			p.Wired.Password = open(p.Wired.Password)
		}
		if p.WireGuard != nil {
			for idx, env := range p.WireGuard.PeerPSKs {
				p.WireGuard.PeerPSKs[idx] = open(env)
			}
		}

		if rebuilt, err := json.Marshal(p); err == nil {
			policies[i].Payload = rebuilt
		} else {
			log.Printf("[api] unseal: re-marshal NETWORK_PROFILE payload for policy=%s failed: %v", policies[i].ID, err)
		}
	}
}
