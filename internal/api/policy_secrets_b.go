package api

import (
	"encoding/json"
	"log"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

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
