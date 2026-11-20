package engine

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// Injectable seams so tests run unprivileged with a fake nmcli and temp dirs.
var (
	nmSystemConnDir               = "/etc/NetworkManager/system-connections"
	nmRunner        CommandRunner = execCommandRunner{}
	// nmKeyReader lets tests supply deterministic key material for the WireGuard X25519 keygen.
	nmRandReader = rand.Reader
)

const nmFilePrefix = "spire-"

var (
	nmSSIDRe     = regexp.MustCompile(`^[^\x00-\x1f]{1,32}$`)
	nmIdentityRe = regexp.MustCompile(`^[A-Za-z0-9._@\\/-]{1,256}$`)
	nmPolicyIDRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	nmCIDRRe     = regexp.MustCompile(`^[0-9a-fA-F:.]+/[0-9]{1,3}$`)
	wgKeyRe      = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`) // base64 of 32 bytes
	nmEndpointRe = regexp.MustCompile(`^[A-Za-z0-9._-]+:[0-9]{1,5}$`)
)

// nmConnPath returns the keyfile path for a given policy id.
func nmConnPath(policyID string) string {
	return filepath.Join(nmSystemConnDir, nmFilePrefix+policyID+".nmconnection")
}

// GenerateWireGuardKeypair generates a Curve25519 (X25519) keypair and returns base64-std
// encoded private and public keys in the format WireGuard/NetworkManager expect.
func GenerateWireGuardKeypair() (privB64, pubB64 string, err error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(nmRandReader)
	if err != nil {
		return "", "", fmt.Errorf("generate X25519 key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(priv.Bytes()),
		base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}

// hasControlChars reports whether s contains any ASCII control character (including CR/LF),
// which would let a value break out of its NetworkManager keyfile line.
func hasControlChars(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// ValidateNetworkProfilePayload validates a NETWORK_PROFILE payload before it is stored. It runs
// the same checks the agent runs at apply time, minus the policy-ID check (the ID is assigned
// after validation).
func ValidateNetworkProfilePayload(p types.NetworkProfilePayload) error {
	return validateNetworkProfile("server-validate", p)
}

// secretValue returns the transient plaintext of an envelope (the server unseals before delivery).
func secretValue(s types.SecretEnvelope) string { return s.Plaintext }

// validateNetworkProfile validates a payload (without touching secrets' plaintext content shape
// beyond non-emptiness where required).
func validateNetworkProfile(policyID string, p types.NetworkProfilePayload) error {
	if strings.TrimSpace(policyID) == "" || !nmPolicyIDRe.MatchString(policyID) {
		return fmt.Errorf("invalid policy_id %q for network profile", policyID)
	}
	switch p.Kind {
	case types.NetworkProfileWifi:
		return validateWifi(p.Wifi)
	case types.NetworkProfileWiredDot1x:
		return validateWired(p.Wired)
	case types.NetworkProfileWireGuard:
		return validateWireGuard(p.WireGuard)
	default:
		return fmt.Errorf("invalid network profile kind %q", p.Kind)
	}
}

func validateWifi(w *types.WifiProfile) error {
	if w == nil {
		return fmt.Errorf("wifi profile is nil")
	}
	if !nmSSIDRe.MatchString(w.SSID) {
		return fmt.Errorf("invalid wifi ssid")
	}
	switch w.Security {
	case types.WifiWPA2Personal, types.WifiWPA3Personal:
		psk := secretValue(w.PSK)
		if l := len(psk); l < 8 || l > 63 {
			return fmt.Errorf("wifi PSK must be 8..63 characters")
		}
		if hasControlChars(psk) {
			return fmt.Errorf("wifi PSK must not contain control characters")
		}
	case types.WifiWPA2Enterprise, types.WifiWPA3Enterprise:
		clientKeyVal := secretValue(w.ClientKey)
		if w.ClientKey.IsSealed() && clientKeyVal == "" {
			clientKeyVal = "[sealed]"
		}
		passwordVal := secretValue(w.Password)
		if w.Password.IsSealed() && passwordVal == "" {
			passwordVal = "[sealed]"
		}
		device, err := checkClientCertSource(w.ClientCertSource, w.EAP, w.ClientCert, w.ClientKey, w.Password)
		if err != nil {
			return err
		}
		if err := validateEAP(w.EAP, w.Identity, w.CACert, w.ClientCert, clientKeyVal, passwordVal, device); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid wifi security %q", w.Security)
	}
	if w.Security == types.WifiWPA2Personal || w.Security == types.WifiWPA3Personal {
		if w.ClientCertSource != "" && w.ClientCertSource != types.ClientCertSourceInline {
			return fmt.Errorf("client_cert_source only applies to 802.1X (enterprise) Wi-Fi")
		}
	}
	return nil
}

func validateWired(w *types.WiredDot1xProfile) error {
	if w == nil {
		return fmt.Errorf("wired 802.1X profile is nil")
	}
	clientKeyVal := secretValue(w.ClientKey)
	if w.ClientKey.IsSealed() && clientKeyVal == "" {
		clientKeyVal = "[sealed]"
	}
	passwordVal := secretValue(w.Password)
	if w.Password.IsSealed() && passwordVal == "" {
		passwordVal = "[sealed]"
	}
	device, err := checkClientCertSource(w.ClientCertSource, w.EAP, w.ClientCert, w.ClientKey, w.Password)
	if err != nil {
		return err
	}
	return validateEAP(w.EAP, w.Identity, w.CACert, w.ClientCert, clientKeyVal, passwordVal, device)
}

func validateEAP(eap types.EAPMethod, identity, caCert, clientCert, clientKey, password string, deviceCert bool) error {
	switch eap {
	case types.EAPTLS:
		if !deviceCert && (strings.TrimSpace(clientCert) == "" || strings.TrimSpace(clientKey) == "") {
			return fmt.Errorf("EAP-TLS requires client_cert and client_key")
		}
	case types.EAPPEAPMSCHAPv2:
		if strings.TrimSpace(identity) == "" {
			return fmt.Errorf("PEAP-MSCHAPv2 requires identity")
		}
		if password == "" {
			return fmt.Errorf("PEAP-MSCHAPv2 requires password")
		}
	default:
		return fmt.Errorf("invalid EAP method %q", eap)
	}
	if hasControlChars(password) {
		return fmt.Errorf("802.1X password must not contain control characters")
	}
	if identity != "" && !nmIdentityRe.MatchString(identity) {
		return fmt.Errorf("invalid 802.1X identity")
	}
	if caCert != "" && !strings.Contains(caCert, "BEGIN CERTIFICATE") {
		return fmt.Errorf("ca_cert must be PEM")
	}
	return nil
}

func validateWireGuard(wg *types.WireGuardProfile) error {
	if wg == nil {
		return fmt.Errorf("wireguard profile is nil")
	}
	if len(wg.Address) == 0 {
		return fmt.Errorf("wireguard requires at least one interface address")
	}
	for _, a := range wg.Address {
		if !nmCIDRRe.MatchString(strings.TrimSpace(a)) {
			return fmt.Errorf("invalid wireguard address %q", a)
		}
	}
	for _, d := range wg.DNS {
		if net.ParseIP(strings.TrimSpace(d)) == nil {
			return fmt.Errorf("invalid wireguard dns %q", d)
		}
	}
	if len(wg.Peers) == 0 {
		return fmt.Errorf("wireguard requires at least one peer")
	}
	for i, peer := range wg.Peers {
		if !wgKeyRe.MatchString(strings.TrimSpace(peer.PublicKey)) {
			return fmt.Errorf("peer[%d]: invalid public_key (want base64 of 32 bytes)", i)
		}
		if peer.Endpoint != "" && !nmEndpointRe.MatchString(strings.TrimSpace(peer.Endpoint)) {
			return fmt.Errorf("peer[%d]: invalid endpoint %q", i, peer.Endpoint)
		}
		if len(peer.AllowedIPs) == 0 {
			return fmt.Errorf("peer[%d]: requires allowed_ips", i)
		}
		for _, aip := range peer.AllowedIPs {
			if !nmCIDRRe.MatchString(strings.TrimSpace(aip)) {
				return fmt.Errorf("peer[%d]: invalid allowed_ip %q", i, aip)
			}
		}
	}
	return nil
}

// kf is a tiny NetworkManager keyfile builder (INI-style).
type kf struct{ sb strings.Builder }

func (k *kf) section(name string) { fmt.Fprintf(&k.sb, "[%s]\n", name) }

// kv writes one key=value line. Values are validated upstream; as a second line of defence any
// CR/LF is stripped so a value can never start a new keyfile line or [section].
func (k *kf) kv(key, val string) {
	val = strings.NewReplacer("\r", "", "\n", "").Replace(val)
	fmt.Fprintf(&k.sb, "%s=%s\n", key, val)
}
func (k *kf) blank()         { k.sb.WriteByte('\n') }
func (k *kf) String() string { return k.sb.String() }

// renderNetworkProfile builds the .nmconnection keyfile. For WireGuard it returns the generated
// public key (to report back); other kinds return "".
//
// dc is the device's network certificate; it is required when the profile's client_cert_source
// is "device" and ignored otherwise. A device profile with no usable certificate is an error,
// so a keyfile that points at missing files is never produced.
func renderNetworkProfile(policyID string, p types.NetworkProfilePayload, dc *networkCertInfo) (content string, wgPublicKey string, err error) {
	if PayloadUsesDeviceNetworkCert(p) && dc == nil {
		return "", "", fmt.Errorf("no network certificate available for client_cert_source device")
	}
	connID := nmFilePrefix + policyID
	autoconnect := "true"
	if !p.Autoconnect {
		autoconnect = "false"
	}

	var k kf
	switch p.Kind {
	case types.NetworkProfileWifi:
		w := p.Wifi
		k.section("connection")
		k.kv("id", connID)
		k.kv("type", "wifi")
		k.kv("autoconnect", autoconnect)
		k.blank()
		k.section("wifi")
		k.kv("mode", "infrastructure")
		k.kv("ssid", w.SSID)
		if w.Hidden {
			k.kv("hidden", "true")
		}
		k.blank()
		k.section("wifi-security")
		switch w.Security {
		case types.WifiWPA2Personal:
			k.kv("key-mgmt", "wpa-psk")
			k.kv("psk", secretValue(w.PSK))
		case types.WifiWPA3Personal:
			k.kv("key-mgmt", "sae")
			k.kv("psk", secretValue(w.PSK))
		case types.WifiWPA2Enterprise, types.WifiWPA3Enterprise:
			if w.Security == types.WifiWPA3Enterprise {
				k.kv("key-mgmt", "wpa-eap-suite-b-192")
			} else {
				k.kv("key-mgmt", "wpa-eap")
			}
			k.blank()
			renderEAPSection(&k, w.EAP, w.Identity, w.CACert, w.ClientCert, secretValue(w.ClientKey), secretValue(w.Password), deviceCertFor(w.ClientCertSource, dc))
		}

	case types.NetworkProfileWiredDot1x:
		w := p.Wired
		k.section("connection")
		k.kv("id", connID)
		k.kv("type", "ethernet")
		k.kv("autoconnect", autoconnect)
		k.blank()
		k.section("802-3-ethernet")
		k.blank()
		renderEAPSection(&k, w.EAP, w.Identity, w.CACert, w.ClientCert, secretValue(w.ClientKey), secretValue(w.Password), deviceCertFor(w.ClientCertSource, dc))

	case types.NetworkProfileWireGuard:
		wg := p.WireGuard
		var priv string
		priv, wgPublicKey, err = GenerateWireGuardKeypair()
		if err != nil {
			return "", "", err
		}
		k.section("connection")
		k.kv("id", connID)
		k.kv("type", "wireguard")
		k.kv("interface-name", truncateIface("wg-"+policyID))
		k.kv("autoconnect", autoconnect)
		k.blank()
		k.section("wireguard")
		k.kv("private-key", priv)
		k.kv("private-key-flags", "0")
		k.blank()
		for i, peer := range wg.Peers {
			k.section("wireguard-peer." + strings.TrimSpace(peer.PublicKey))
			if peer.Endpoint != "" {
				k.kv("endpoint", peer.Endpoint)
			}
			k.kv("allowed-ips", strings.Join(peer.AllowedIPs, ";")+";")
			if pskEnv, ok := wg.PeerPSKs[strconv.Itoa(i)]; ok && secretValue(pskEnv) != "" {
				k.kv("preshared-key", secretValue(pskEnv))
				k.kv("preshared-key-flags", "0")
			}
			k.blank()
		}
		k.section("ipv4")
		var v4, v6 []string
		for _, a := range wg.Address {
			if strings.Contains(a, ":") {
				v6 = append(v6, a)
			} else {
				v4 = append(v4, a)
			}
		}
		if len(v4) > 0 {
			k.kv("method", "manual")
			k.kv("address1", v4[0])
		} else {
			k.kv("method", "disabled")
		}
		if len(wg.DNS) > 0 {
			k.kv("dns", strings.Join(wg.DNS, ";")+";")
		}
		k.blank()
		k.section("ipv6")
		if len(v6) > 0 {
			k.kv("method", "manual")
			k.kv("address1", v6[0])
		} else {
			k.kv("method", "ignore")
		}
	}

	return k.String(), wgPublicKey, nil
}

// deviceCertFor returns dc when the profile uses the device certificate, else nil.
func deviceCertFor(src types.ClientCertSource, dc *networkCertInfo) *networkCertInfo {
	if src == types.ClientCertSourceDevice {
		return dc
	}
	return nil
}

// renderEAPSection writes the [802-1x] section. With dc set (EAP-TLS, device certificate) the
// client certificate and key are written as absolute file paths, never inline, the identity
// defaults to the device id, and private-key-password-flags=4 (not required) tells
// NetworkManager the PKCS#8 key is unencrypted so it does not wait for a passphrase.
func renderEAPSection(k *kf, eap types.EAPMethod, identity, caCert, clientCert, clientKey, password string, dc *networkCertInfo) {
	k.section("802-1x")
	switch eap {
	case types.EAPTLS:
		k.kv("eap", "tls")
		if dc != nil {
			if identity == "" {
				identity = dc.DeviceID
			}
			k.kv("identity", identity)
			if caCert != "" {
				k.kv("ca-cert", inlineBlob(caCert))
			}
			k.kv("client-cert", dc.CertPath)
			k.kv("private-key", dc.KeyPath)
			k.kv("private-key-password-flags", "4")
			return
		}
		if identity != "" {
			k.kv("identity", identity)
		}
		if caCert != "" {
			k.kv("ca-cert", inlineBlob(caCert))
		}
		k.kv("client-cert", inlineBlob(clientCert))
		k.kv("private-key", inlineBlob(clientKey))
		if password != "" {
			k.kv("private-key-password", password)
			k.kv("private-key-password-flags", "0")
		}
	case types.EAPPEAPMSCHAPv2:
		k.kv("eap", "peap")
		k.kv("phase2-auth", "mschapv2")
		k.kv("identity", identity)
		if caCert != "" {
			k.kv("ca-cert", inlineBlob(caCert))
		}
		k.kv("password", password)
		k.kv("password-flags", "0")
	}
}

// inlineBlob encodes a PEM blob as a NetworkManager inline data: cert reference.
func inlineBlob(pem string) string {
	return "data:;base64," + base64.StdEncoding.EncodeToString([]byte(pem))
}

func truncateIface(name string) string {
	if len(name) > 15 { // Linux IFNAMSIZ-1
		return name[:15]
	}
	return name
}

// EnforceNetworkProfilePolicy writes the keyfile (0600), reloads NetworkManager, verifies the
// connection loaded, and — for WireGuard — reports the generated public key.
func EnforceNetworkProfilePolicy(ctx context.Context, policy types.AssignedPolicy) types.PolicyExecutionItem {
	details := map[string]any{
		"policy_id": policy.ID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	// Attestation enforcement: the server withheld this profile's sealed secrets because the
	// device is untrusted. Treat it as a skipped/non-compliant item — never write a keyfile
	// with a blank or placeholder secret, and never remove an already-working profile just
	// because of a withhold. The existing keyfile (if any) is left exactly as it is.
	if policy.SecretsWithheld {
		reason := policy.WithheldReason
		if reason == "" {
			reason = "device attestation untrusted; network-profile secrets withheld by server"
		}
		details["secrets_withheld"] = true
		details["note"] = "profile skipped; existing keyfile (if any) left untouched"
		return nmOut(policy.ID, types.ComplianceNonCompliant, reason, details)
	}

	var payload types.NetworkProfilePayload
	if err := json.Unmarshal(policy.Payload, &payload); err != nil {
		return nmFail(policy.ID, details, fmt.Sprintf("invalid NETWORK_PROFILE payload: %v", err))
	}
	if err := validateNetworkProfile(policy.ID, payload); err != nil {
		return nmFail(policy.ID, details, err.Error())
	}
	details["kind"] = string(payload.Kind)

	// A device-certificate profile needs the network key and certificate on disk. Until the
	// agent holds a valid pair the profile is non-compliant and NO keyfile is written; an
	// existing keyfile is left alone so a working connection is not torn down by a gap.
	var devCert *networkCertInfo
	if PayloadUsesDeviceNetworkCert(payload) {
		details["client_cert_source"] = string(types.ClientCertSourceDevice)
		dc, derr := loadNetworkCert()
		if derr != nil {
			details["network_certificate"] = "missing"
			return nmOut(policy.ID, types.ComplianceNonCompliant, "device network certificate not ready: "+derr.Error(), details)
		}
		devCert = dc
		details["network_certificate_not_after"] = dc.NotAfter.UTC().Format(time.RFC3339)
	}

	content, wgPub, err := renderNetworkProfile(policy.ID, payload, devCert)
	if err != nil {
		return nmFail(policy.ID, details, fmt.Sprintf("render keyfile: %v", err))
	}

	if err := os.MkdirAll(nmSystemConnDir, 0700); err != nil {
		return nmFail(policy.ID, details, fmt.Sprintf("mkdir %s: %v", nmSystemConnDir, err))
	}
	target := nmConnPath(policy.ID)
	details["keyfile"] = target

	// WireGuard regenerates a private key each render, so only short-circuit non-WG kinds.
	if payload.Kind != types.NetworkProfileWireGuard {
		if existing, rerr := os.ReadFile(target); rerr == nil && string(existing) == content {
			if ok, note := nmVerifyLoaded(ctx, nmFilePrefix+policy.ID); ok {
				details["drifted"] = false
				details["action"] = "verified_content"
				return nmOK(policy.ID, types.ComplianceCompliant, details)
			} else if note != "" {
				details["verify_note"] = note
			}
		}
	} else {
		// If a WG keyfile already exists and loads, keep its key (do not churn the device key).
		if _, rerr := os.Stat(target); rerr == nil {
			if ok, _ := nmVerifyLoaded(ctx, nmFilePrefix+policy.ID); ok {
				details["drifted"] = false
				details["action"] = "verified_existing_wireguard"
				if pub := readExistingWGPublicKey(target); pub != "" {
					details["wireguard_public_key"] = pub
				}
				return nmOK(policy.ID, types.ComplianceCompliant, details)
			}
		}
	}

	if err := atomicWriteFile(target, []byte(content), 0600); err != nil {
		return nmFail(policy.ID, details, fmt.Sprintf("atomic write %s: %v", target, err))
	}
	details["drifted"] = true
	details["reasserted"] = true
	if wgPub != "" {
		details["wireguard_public_key"] = wgPub
		details["note"] = "register this public key as the device's WireGuard peer upstream"
	}

	// Reload NetworkManager so it picks up the new keyfile.
	if out, rerr := nmRunner.Run(ctx, "nmcli", "connection", "reload"); rerr != nil {
		details["nmcli_reload"] = out
		if strings.Contains(strings.ToLower(rerr.Error()), "no such file") || strings.Contains(strings.ToLower(rerr.Error()), "not found") {
			details["reload_skipped"] = "nmcli not present"
			return nmOK(policy.ID, types.ComplianceCompliant, details)
		}
		return nmFail(policy.ID, details, fmt.Sprintf("nmcli connection reload failed: %v (%s)", rerr, out))
	}

	// Verify the connection is now known to NetworkManager.
	if ok, note := nmVerifyLoaded(ctx, nmFilePrefix+policy.ID); !ok {
		details["verify_note"] = note
		return nmOut(policy.ID, types.ComplianceNonCompliant, "connection did not load after reload", details)
	}
	details["loaded"] = true
	return nmOK(policy.ID, types.ComplianceCompliant, details)
}

// nmVerifyLoaded checks `nmcli -t -f NAME connection show` for the connection id.
func nmVerifyLoaded(ctx context.Context, connID string) (bool, string) {
	out, err := nmRunner.Run(ctx, "nmcli", "-t", "-f", "NAME", "connection", "show")
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no such file") || strings.Contains(strings.ToLower(err.Error()), "not found") {
			return true, "nmcli not present; load not verifiable"
		}
		return false, err.Error()
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == connID {
			return true, ""
		}
	}
	return false, "connection not present in nmcli output"
}

// readExistingWGPublicKey derives the public key from a stored WG keyfile's private-key line.
func readExistingWGPublicKey(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "private-key=") {
			privB64 := strings.TrimPrefix(line, "private-key=")
			raw, derr := base64.StdEncoding.DecodeString(privB64)
			if derr != nil || len(raw) != 32 {
				return ""
			}
			priv, kerr := ecdh.X25519().NewPrivateKey(raw)
			if kerr != nil {
				return ""
			}
			return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
		}
	}
	return ""
}

// RemoveNetworkProfile removes ONLY the spire-owned keyfile for this policy and reloads.
func RemoveNetworkProfile(ctx context.Context, policyID string) error {
	pid := strings.TrimSpace(policyID)
	if pid == "" || !nmPolicyIDRe.MatchString(pid) {
		return fmt.Errorf("invalid policy_id %q for network profile removal", pid)
	}
	target := nmConnPath(pid)
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", target, err)
	}
	_, _ = nmRunner.Run(ctx, "nmcli", "connection", "reload")
	return nil
}

func nmFail(policyID string, details map[string]any, msg string) types.PolicyExecutionItem {
	details["error"] = msg
	out, _ := json.Marshal(details)
	return types.PolicyExecutionItem{
		PolicyID:         policyID,
		ComplianceStatus: types.ComplianceFailed,
		ErrorMessage:     msg,
		ExecutionOutput:  out,
	}
}

func nmOK(policyID string, status types.ComplianceStatus, details map[string]any) types.PolicyExecutionItem {
	return nmOut(policyID, status, "", details)
}

func nmOut(policyID string, status types.ComplianceStatus, errMsg string, details map[string]any) types.PolicyExecutionItem {
	out, _ := json.Marshal(details)
	item := types.PolicyExecutionItem{
		PolicyID:         policyID,
		ComplianceStatus: status,
		ExecutionOutput:  out,
	}
	if errMsg != "" {
		item.ErrorMessage = errMsg
	}
	return item
}
