package engine

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

func withNMFakes(t *testing.T) (dir string, fr *fakeRunner, restore func()) {
	t.Helper()
	tmp := t.TempDir()
	origDir := nmSystemConnDir
	origRunner := nmRunner
	nmSystemConnDir = filepath.Join(tmp, "system-connections")
	fr = newFakeRunner()
	nmRunner = fr
	return nmSystemConnDir, fr, func() {
		nmSystemConnDir = origDir
		nmRunner = origRunner
	}
}

func TestGenerateWireGuardKeypairRoundTrip(t *testing.T) {
	priv, pub, err := GenerateWireGuardKeypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if !wgKeyRe.MatchString(priv) || !wgKeyRe.MatchString(pub) {
		t.Fatalf("keys not valid base64-32: priv=%q pub=%q", priv, pub)
	}
	// Independently derive the public key from the private key and confirm it matches.
	raw, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(raw) != 32 {
		t.Fatalf("priv decode: %v len=%d", err, len(raw))
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatalf("rebuild priv: %v", err)
	}
	derivedPub := base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
	if derivedPub != pub {
		t.Fatalf("derived pub %q != reported pub %q", derivedPub, pub)
	}
}

func TestNetworkProfileValidation(t *testing.T) {
	bad := []types.NetworkProfilePayload{
		{Kind: "bogus"},
		{Kind: types.NetworkProfileWifi, Wifi: &types.WifiProfile{SSID: "", Security: types.WifiWPA2Personal}},
		{Kind: types.NetworkProfileWifi, Wifi: &types.WifiProfile{SSID: "net", Security: types.WifiWPA2Personal, PSK: types.SecretEnvelope{Plaintext: "short"}}},
		{Kind: types.NetworkProfileWifi, Wifi: &types.WifiProfile{SSID: "net", Security: types.WifiWPA2Enterprise, EAP: types.EAPPEAPMSCHAPv2, Identity: "", Password: types.SecretEnvelope{Plaintext: "x"}}},
		{Kind: types.NetworkProfileWireGuard, WireGuard: &types.WireGuardProfile{Address: []string{"10.0.0.1/32"}}}, // no peers
		{Kind: types.NetworkProfileWireGuard, WireGuard: &types.WireGuardProfile{Address: []string{"bad"}, Peers: []types.WireGuardPeer{{PublicKey: strings.Repeat("A", 42) + "=", AllowedIPs: []string{"0.0.0.0/0"}}}}},
	}
	for i, p := range bad {
		if err := validateNetworkProfile("pol1", p); err == nil {
			t.Errorf("bad case %d: expected error, got nil", i)
		}
	}

	_, wgPub, _ := GenerateWireGuardKeypair()
	good := types.NetworkProfilePayload{
		Kind: types.NetworkProfileWireGuard,
		WireGuard: &types.WireGuardProfile{
			Address: []string{"10.0.0.5/32"},
			DNS:     []string{"10.0.0.1"},
			Peers:   []types.WireGuardPeer{{PublicKey: wgPub, Endpoint: "vpn.example.com:51820", AllowedIPs: []string{"0.0.0.0/0"}}},
		},
	}
	if err := validateNetworkProfile("pol1", good); err != nil {
		t.Errorf("valid wireguard rejected: %v", err)
	}
}

func TestEnforceWifiPersonalWritesKeyfileAndReloads(t *testing.T) {
	dir, fr, restore := withNMFakes(t)
	defer restore()
	ctx := context.Background()
	// nmcli connection show must list the connection for verify to pass.
	fr.outputs["nmcli -t"] = "spire-wifi1"

	payload, _ := json.Marshal(types.NetworkProfilePayload{
		Kind:        types.NetworkProfileWifi,
		Autoconnect: true,
		Wifi: &types.WifiProfile{
			SSID:     "CorpWifi",
			Security: types.WifiWPA3Personal,
			PSK:      types.SecretEnvelope{Plaintext: "supersecret123"},
		},
	})
	pol := types.AssignedPolicy{ID: "wifi1", PolicyType: types.PolicyTypeNetworkProfile, Payload: payload}

	item := EnforceNetworkProfilePolicy(ctx, pol)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("apply: expected COMPLIANT, got %s (%s)", item.ComplianceStatus, item.ErrorMessage)
	}
	target := filepath.Join(dir, "spire-wifi1.nmconnection")
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("keyfile not created: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("expected 0600, got %v", info.Mode().Perm())
	}
	data, _ := os.ReadFile(target)
	s := string(data)
	if !strings.Contains(s, "key-mgmt=sae") {
		t.Error("expected WPA3 sae key-mgmt")
	}
	if !strings.Contains(s, "psk=supersecret123") {
		t.Error("expected psk written to keyfile")
	}
	if !fr.called("nmcli connection reload") {
		t.Error("expected nmcli connection reload")
	}
}

func TestEnforceWiredEnterpriseEAPTLS(t *testing.T) {
	dir, fr, restore := withNMFakes(t)
	defer restore()
	ctx := context.Background()
	fr.outputs["nmcli -t"] = "spire-wired1"

	payload, _ := json.Marshal(types.NetworkProfilePayload{
		Kind: types.NetworkProfileWiredDot1x,
		Wired: &types.WiredDot1xProfile{
			EAP:        types.EAPTLS,
			Identity:   "host/workstation",
			CACert:     "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
			ClientCert: "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----",
			ClientKey:  "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----",
		},
	})
	pol := types.AssignedPolicy{ID: "wired1", PolicyType: types.PolicyTypeNetworkProfile, Payload: payload}
	item := EnforceNetworkProfilePolicy(ctx, pol)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("apply: expected COMPLIANT, got %s (%s)", item.ComplianceStatus, item.ErrorMessage)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "spire-wired1.nmconnection"))
	s := string(data)
	if !strings.Contains(s, "eap=tls") {
		t.Error("expected eap=tls")
	}
	if !strings.Contains(s, "data:;base64,") {
		t.Error("expected inline cert blob encoding")
	}
}

func TestEnforceWireGuardReportsPublicKeyAndPersistsPrivate(t *testing.T) {
	dir, fr, restore := withNMFakes(t)
	defer restore()
	ctx := context.Background()
	fr.outputs["nmcli -t"] = "spire-wg1"

	_, peerPub, _ := GenerateWireGuardKeypair()
	payload, _ := json.Marshal(types.NetworkProfilePayload{
		Kind:        types.NetworkProfileWireGuard,
		Autoconnect: true,
		WireGuard: &types.WireGuardProfile{
			Address: []string{"10.7.0.5/32"},
			DNS:     []string{"10.7.0.1"},
			Peers:   []types.WireGuardPeer{{PublicKey: peerPub, Endpoint: "vpn.corp:51820", AllowedIPs: []string{"10.7.0.0/24", "0.0.0.0/0"}}},
		},
	})
	pol := types.AssignedPolicy{ID: "wg1", PolicyType: types.PolicyTypeNetworkProfile, Payload: payload}

	item := EnforceNetworkProfilePolicy(ctx, pol)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("apply: expected COMPLIANT, got %s (%s)", item.ComplianceStatus, item.ErrorMessage)
	}

	// Public key must be reported in ExecutionOutput and match the private key in the keyfile.
	var det map[string]any
	if err := json.Unmarshal(item.ExecutionOutput, &det); err != nil {
		t.Fatalf("exec output: %v", err)
	}
	reportedPub, _ := det["wireguard_public_key"].(string)
	if !wgKeyRe.MatchString(reportedPub) {
		t.Fatalf("missing/invalid reported wireguard_public_key: %q", reportedPub)
	}

	target := filepath.Join(dir, "spire-wg1.nmconnection")
	derivedPub := readExistingWGPublicKey(target)
	if derivedPub != reportedPub {
		t.Fatalf("keyfile-derived pub %q != reported pub %q (private key / reported pubkey mismatch)", derivedPub, reportedPub)
	}
	data, _ := os.ReadFile(target)
	if strings.Contains(string(data), "private-key=\n") || !strings.Contains(string(data), "private-key=") {
		t.Error("expected a non-empty private-key line in the WG keyfile")
	}
	if !strings.Contains(string(data), "endpoint=vpn.corp:51820") {
		t.Error("expected peer endpoint in keyfile")
	}

	// A second apply must NOT churn the device private key (keyfile present + loads).
	before, _ := os.ReadFile(target)
	item2 := EnforceNetworkProfilePolicy(ctx, pol)
	if item2.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("reapply: expected COMPLIANT, got %s", item2.ComplianceStatus)
	}
	after, _ := os.ReadFile(target)
	if string(before) != string(after) {
		t.Error("WireGuard keyfile (and device private key) must be stable across converged reapplies")
	}
}

func TestRemoveNetworkProfileOnlyTouchesOwnedFile(t *testing.T) {
	dir, _, restore := withNMFakes(t)
	defer restore()
	ctx := context.Background()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	// A non-spire profile that must be left untouched.
	foreign := filepath.Join(dir, "home-wifi.nmconnection")
	if err := os.WriteFile(foreign, []byte("[connection]\nid=home-wifi\n"), 0600); err != nil {
		t.Fatal(err)
	}
	owned := nmConnPath("wg1")
	if err := os.WriteFile(owned, []byte("[connection]\nid=spire-wg1\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := RemoveNetworkProfile(ctx, "wg1"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Error("expected owned profile removed")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Error("foreign profile must NOT be removed")
	}
}
