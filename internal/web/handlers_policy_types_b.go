package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/types"
)

// buildNetworkProfilePayload parses the NETWORK_PROFILE admin form into a payload. Secrets are
// placed in SecretEnvelope.Plaintext here; CreatePolicy seals them with the KEK before persisting.
func buildNetworkProfilePayload(r *http.Request) (json.RawMessage, error) {
	kind := types.NetworkProfileKind(strings.TrimSpace(r.FormValue("np_kind")))
	autoconnect := pbFormBool(r, "np_autoconnect")
	payload := types.NetworkProfilePayload{Kind: kind, Autoconnect: autoconnect}

	switch kind {
	case types.NetworkProfileWifi:
		sec := types.WifiSecurity(strings.TrimSpace(r.FormValue("np_wifi_security")))
		w := &types.WifiProfile{
			SSID:     strings.TrimSpace(r.FormValue("np_wifi_ssid")),
			Hidden:   pbFormBool(r, "np_wifi_hidden"),
			Security: sec,
		}
		switch sec {
		case types.WifiWPA2Personal, types.WifiWPA3Personal:
			w.PSK = types.SecretEnvelope{Plaintext: r.FormValue("np_wifi_psk")}
		case types.WifiWPA2Enterprise, types.WifiWPA3Enterprise:
			w.EAP = types.EAPMethod(strings.TrimSpace(r.FormValue("np_wifi_eap")))
			w.Identity = strings.TrimSpace(r.FormValue("np_wifi_identity"))
			w.CACert = r.FormValue("np_wifi_ca_cert")
			w.ClientCert = r.FormValue("np_wifi_client_cert")
			w.ClientKey = types.SecretEnvelope{Plaintext: r.FormValue("np_wifi_client_key")}
			w.Password = types.SecretEnvelope{Plaintext: r.FormValue("np_wifi_password")}
		default:
			return nil, fmt.Errorf("invalid wifi security %q", sec)
		}
		payload.Wifi = w

	case types.NetworkProfileWiredDot1x:
		payload.Wired = &types.WiredDot1xProfile{
			EAP:        types.EAPMethod(strings.TrimSpace(r.FormValue("np_wired_eap"))),
			Identity:   strings.TrimSpace(r.FormValue("np_wired_identity")),
			CACert:     r.FormValue("np_wired_ca_cert"),
			ClientCert: r.FormValue("np_wired_client_cert"),
			ClientKey:  types.SecretEnvelope{Plaintext: r.FormValue("np_wired_client_key")},
			Password:   types.SecretEnvelope{Plaintext: r.FormValue("np_wired_password")},
		}

	case types.NetworkProfileWireGuard:
		wg := &types.WireGuardProfile{
			Address: pbSplitList(r.FormValue("np_wg_address")),
			DNS:     pbSplitList(r.FormValue("np_wg_dns")),
		}
		// Single-peer form (the common case); multiple peers can be supplied via raw JSON override.
		peerPub := strings.TrimSpace(r.FormValue("np_wg_peer_public_key"))
		if peerPub != "" {
			peer := types.WireGuardPeer{
				PublicKey:  peerPub,
				Endpoint:   strings.TrimSpace(r.FormValue("np_wg_peer_endpoint")),
				AllowedIPs: pbSplitList(r.FormValue("np_wg_peer_allowed_ips")),
			}
			wg.Peers = append(wg.Peers, peer)
			if psk := r.FormValue("np_wg_peer_psk"); psk != "" {
				wg.PeerPSKs = map[string]types.SecretEnvelope{"0": {Plaintext: psk}}
			}
		}
		payload.WireGuard = wg

	default:
		return nil, fmt.Errorf("invalid network profile kind %q", kind)
	}

	if err := engine.ValidateNetworkProfilePayload(payload); err != nil {
		return nil, err
	}
	return json.Marshal(payload)
}

// buildUSBDeviceControlPayload parses the USB_DEVICE_CONTROL admin form.
func buildUSBDeviceControlPayload(r *http.Request) (json.RawMessage, error) {
	mode := types.USBMode(strings.TrimSpace(r.FormValue("usb_mode")))
	payload := types.USBDeviceControlPayload{
		Mode:     mode,
		AllowHID: formBoolDefault(r, "usb_allow_hid", true),
	}
	// allow-list from a textarea: one entry per line, "vendor:product[,serial][,class:XX] # comment"
	raw := strings.TrimSpace(r.FormValue("usb_allow_list"))
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entry, err := parseUSBAllowLine(line)
		if err != nil {
			return nil, err
		}
		payload.AllowList = append(payload.AllowList, entry)
	}
	if err := engine.ValidateUSBDeviceControlPayload(payload); err != nil {
		return nil, err
	}
	return json.Marshal(payload)
}

func parseUSBAllowLine(line string) (types.USBAllowEntry, error) {
	var e types.USBAllowEntry
	if idx := strings.Index(line, "#"); idx >= 0 {
		e.Comment = strings.TrimSpace(line[idx+1:])
		line = strings.TrimSpace(line[:idx])
	}
	for _, tok := range strings.Split(line, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		switch {
		case strings.HasPrefix(tok, "class:"):
			e.DeviceClass = strings.TrimPrefix(tok, "class:")
		case strings.HasPrefix(tok, "serial:"):
			e.Serial = strings.TrimPrefix(tok, "serial:")
		case strings.Contains(tok, ":"):
			parts := strings.SplitN(tok, ":", 2)
			e.VendorID = parts[0]
			if len(parts) == 2 {
				e.ProductID = parts[1]
			}
		default:
			return e, fmt.Errorf("unrecognized usb allow-list token %q", tok)
		}
	}
	return e, nil
}

// buildAuditdRulesPayload parses the AUDITD_RULES admin form.
func buildAuditdRulesPayload(r *http.Request) (json.RawMessage, error) {
	payload := types.AuditdRulesPayload{
		Presets: pbSplitList(r.FormValue("auditd_presets")),
	}
	// watches: "path perms key" per line
	for _, line := range strings.Split(strings.TrimSpace(r.FormValue("auditd_watches")), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			return nil, fmt.Errorf("auditd watch line %q must be: <path> <perms> <key>", line)
		}
		payload.Watches = append(payload.Watches, types.AuditdWatchRule{Path: f[0], Perms: f[1], Key: f[2]})
	}
	// syscalls: "action,filter syscall[,syscall...] key" per line
	for _, line := range strings.Split(strings.TrimSpace(r.FormValue("auditd_syscalls")), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			return nil, fmt.Errorf("auditd syscall line %q must be: <action,filter> <syscall[,syscall]> <key>", line)
		}
		af := strings.SplitN(f[0], ",", 2)
		if len(af) != 2 {
			return nil, fmt.Errorf("auditd syscall line %q: first token must be action,filter", line)
		}
		payload.Syscalls = append(payload.Syscalls, types.AuditdSyscallRule{
			Action:   af[0],
			Filter:   af[1],
			Syscalls: splitListComma(f[1]),
			Key:      f[len(f)-1],
		})
	}
	if len(payload.Presets) == 0 && len(payload.Watches) == 0 && len(payload.Syscalls) == 0 {
		return nil, fmt.Errorf("AUDITD_RULES requires at least one preset, watch, or syscall rule")
	}
	if err := engine.ValidateAuditdRulesPayload(payload); err != nil {
		return nil, err
	}
	return json.Marshal(payload)
}

// sealPolicyPayloadSecrets seals plaintext secrets in a payload with the server KEK before persist.
// Only NETWORK_PROFILE carries secrets; all other types pass through unchanged.
func (h *Handler) sealPolicyPayloadSecrets(policyType types.PolicyType, payload json.RawMessage) (json.RawMessage, error) {
	if policyType != types.PolicyTypeNetworkProfile {
		return payload, nil
	}
	var p types.NetworkProfilePayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, fmt.Errorf("parse NETWORK_PROFILE payload for sealing: %w", err)
	}
	pub := &h.repo.KEKPrivateKey().PublicKey
	seal := func(env types.SecretEnvelope) (types.SecretEnvelope, error) {
		if env.Plaintext == "" {
			// Preserve an already-sealed envelope (e.g. raw-JSON re-submit) unchanged.
			return env, nil
		}
		return db.SealSecret(pub, env.Plaintext)
	}

	var err error
	if p.Wifi != nil {
		if p.Wifi.PSK, err = seal(p.Wifi.PSK); err != nil {
			return nil, err
		}
		if p.Wifi.ClientKey, err = seal(p.Wifi.ClientKey); err != nil {
			return nil, err
		}
		if p.Wifi.Password, err = seal(p.Wifi.Password); err != nil {
			return nil, err
		}
	}
	if p.Wired != nil {
		if p.Wired.ClientKey, err = seal(p.Wired.ClientKey); err != nil {
			return nil, err
		}
		if p.Wired.Password, err = seal(p.Wired.Password); err != nil {
			return nil, err
		}
	}
	if p.WireGuard != nil && len(p.WireGuard.PeerPSKs) > 0 {
		for idx, env := range p.WireGuard.PeerPSKs {
			if p.WireGuard.PeerPSKs[idx], err = seal(env); err != nil {
				return nil, err
			}
		}
	}
	return json.Marshal(p)
}

// --- small form helpers (local to this file to avoid touching shared handlers.go) ---

func pbFormBool(r *http.Request, key string) bool {
	v := strings.ToLower(strings.TrimSpace(r.FormValue(key)))
	return v == "true" || v == "1" || v == "on"
}

func formBoolDefault(r *http.Request, key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(r.FormValue(key)))
	if v == "" {
		return def
	}
	return v == "true" || v == "1" || v == "on"
}

func pbSplitList(s string) []string {
	var out []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == ';' || r == ' ' }) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitListComma(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}
