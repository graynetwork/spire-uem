package engine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/types"
)

const testDeviceID = "11111111-2222-3333-4444-555555555555"

// withNetworkCert points the engine at a temp dir. When issue is true it fills it with a real
// network certificate from a throwaway device CA.
func withNetworkCert(t *testing.T, issue bool) (NetworkCertPaths, func()) {
	t.Helper()
	dir := t.TempDir()
	paths := NetworkCertFilesIn(dir)
	orig, origNow := networkCertPaths, networkCertNow
	networkCertPaths = paths
	restore := func() { networkCertPaths, networkCertNow = orig, origNow }
	if issue {
		writeNetworkCert(t, paths, dir, testDeviceID)
	}
	return paths, restore
}

func writeNetworkCert(t *testing.T, paths NetworkCertPaths, caDir, deviceID string) {
	t.Helper()
	ca, err := crypto.NewFileDeviceCA(filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := ca.IssueWithOptions(csr, crypto.IssueOptions{DeviceID: deviceID, Purpose: crypto.CertPurposeNetwork, Validity: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	if err := os.WriteFile(paths.Key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Cert, []byte(issued.CertPEM), 0644); err != nil {
		t.Fatal(err)
	}
}

func deviceWired() types.NetworkProfilePayload {
	return types.NetworkProfilePayload{
		Kind:  types.NetworkProfileWiredDot1x,
		Wired: &types.WiredDot1xProfile{EAP: types.EAPTLS, ClientCertSource: types.ClientCertSourceDevice},
	}
}

func deviceWifi() types.NetworkProfilePayload {
	return types.NetworkProfilePayload{
		Kind: types.NetworkProfileWifi,
		Wifi: &types.WifiProfile{SSID: "corp", Security: types.WifiWPA2Enterprise, EAP: types.EAPTLS, ClientCertSource: types.ClientCertSourceDevice},
	}
}

func TestClientCertSourceValidation(t *testing.T) {
	pasted := "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----"
	key := types.SecretEnvelope{Plaintext: "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----"}
	sealedKey := types.SecretEnvelope{Ciphertext: "a", EncryptedDEK: "b", Nonce: "c"}

	mutate := func(base func() types.NetworkProfilePayload, f func(p *types.NetworkProfilePayload)) types.NetworkProfilePayload {
		p := base()
		f(&p)
		return p
	}
	bad := map[string]types.NetworkProfilePayload{
		"wired device + pasted cert":   mutate(deviceWired, func(p *types.NetworkProfilePayload) { p.Wired.ClientCert = pasted }),
		"wired device + plaintext key": mutate(deviceWired, func(p *types.NetworkProfilePayload) { p.Wired.ClientKey = key }),
		"wired device + sealed key":    mutate(deviceWired, func(p *types.NetworkProfilePayload) { p.Wired.ClientKey = sealedKey }),
		"wired device + password":      mutate(deviceWired, func(p *types.NetworkProfilePayload) { p.Wired.Password = types.SecretEnvelope{Plaintext: "pw"} }),
		"wired device + peap": mutate(deviceWired, func(p *types.NetworkProfilePayload) {
			p.Wired.EAP = types.EAPPEAPMSCHAPv2
			p.Wired.Identity = "u"
		}),
		"wired unknown source":      mutate(deviceWired, func(p *types.NetworkProfilePayload) { p.Wired.ClientCertSource = "magic" }),
		"wired DEVICE upper case":   mutate(deviceWired, func(p *types.NetworkProfilePayload) { p.Wired.ClientCertSource = "DEVICE" }),
		"wifi device + pasted cert": mutate(deviceWifi, func(p *types.NetworkProfilePayload) { p.Wifi.ClientCert = pasted }),
		"wifi device + key":         mutate(deviceWifi, func(p *types.NetworkProfilePayload) { p.Wifi.ClientKey = key }),
		"wifi device + peap": mutate(deviceWifi, func(p *types.NetworkProfilePayload) {
			p.Wifi.EAP = types.EAPPEAPMSCHAPv2
			p.Wifi.Identity = "u"
		}),
		"wifi unknown source": mutate(deviceWifi, func(p *types.NetworkProfilePayload) { p.Wifi.ClientCertSource = "x" }),
		"wifi personal + device": {
			Kind: types.NetworkProfileWifi,
			Wifi: &types.WifiProfile{SSID: "home", Security: types.WifiWPA2Personal, PSK: types.SecretEnvelope{Plaintext: "longenough"}, ClientCertSource: types.ClientCertSourceDevice},
		},
	}
	for name, p := range bad {
		if err := ValidateNetworkProfilePayload(p); err == nil {
			t.Errorf("%s: server validation accepted it", name)
		}
		if err := ValidateNetworkProfileClientCertSource(p); err == nil {
			t.Errorf("%s: raw-payload check accepted it", name)
		}
		// The agent runs the same validation at apply time and must refuse it too, writing nothing.
		dir, _, restore := withNMFakes(t)
		payload, _ := json.Marshal(p)
		item := EnforceNetworkProfilePolicy(context.Background(), types.AssignedPolicy{ID: "bad1", PolicyType: types.PolicyTypeNetworkProfile, Payload: payload})
		if item.ComplianceStatus != types.ComplianceFailed {
			t.Errorf("%s: agent returned %s, want FAILED", name, item.ComplianceStatus)
		}
		if _, err := os.Stat(filepath.Join(dir, "spire-bad1.nmconnection")); err == nil {
			t.Errorf("%s: agent wrote a keyfile", name)
		}
		restore()
	}

	good := []types.NetworkProfilePayload{deviceWired(), deviceWifi(),
		mutate(deviceWired, func(p *types.NetworkProfilePayload) { p.Wired.Identity = "host/x" }),
		// inline and empty keep today's rules.
		{Kind: types.NetworkProfileWiredDot1x, Wired: &types.WiredDot1xProfile{EAP: types.EAPTLS, ClientCert: pasted, ClientKey: key}},
		{Kind: types.NetworkProfileWiredDot1x, Wired: &types.WiredDot1xProfile{EAP: types.EAPTLS, ClientCert: pasted, ClientKey: key, ClientCertSource: types.ClientCertSourceInline}},
	}
	for i, p := range good {
		if err := ValidateNetworkProfilePayload(p); err != nil {
			t.Errorf("good[%d]: %v", i, err)
		}
		if err := ValidateNetworkProfileClientCertSource(p); err != nil {
			t.Errorf("good[%d] raw check: %v", i, err)
		}
	}
	// Inline EAP-TLS without a pasted pair is still refused.
	if err := ValidateNetworkProfilePayload(types.NetworkProfilePayload{Kind: types.NetworkProfileWiredDot1x, Wired: &types.WiredDot1xProfile{EAP: types.EAPTLS}}); err == nil {
		t.Error("inline EAP-TLS with no certificate was accepted")
	}
}

func TestDeviceCertKeyfileUsesFilePaths(t *testing.T) {
	paths, restoreCert := withNetworkCert(t, true)
	defer restoreCert()
	dir, fr, restore := withNMFakes(t)
	defer restore()
	fr.outputs["nmcli -t"] = "spire-w1\nspire-wifi1"

	for _, tc := range []struct {
		id      string
		payload types.NetworkProfilePayload
		typeLn  string
	}{
		{"w1", deviceWired(), "type=ethernet"},
		{"wifi1", deviceWifi(), "type=wifi"},
	} {
		raw, _ := json.Marshal(tc.payload)
		item := EnforceNetworkProfilePolicy(context.Background(), types.AssignedPolicy{ID: tc.id, PolicyType: types.PolicyTypeNetworkProfile, Payload: raw})
		if item.ComplianceStatus != types.ComplianceCompliant {
			t.Fatalf("%s: %s (%s)", tc.id, item.ComplianceStatus, item.ErrorMessage)
		}
		data, err := os.ReadFile(filepath.Join(dir, "spire-"+tc.id+".nmconnection"))
		if err != nil {
			t.Fatal(err)
		}
		s := string(data)
		for _, want := range []string{
			"eap=tls\n",
			"client-cert=" + paths.Cert + "\n",
			"private-key=" + paths.Key + "\n",
			"private-key-password-flags=4\n",
			"identity=" + testDeviceID + "\n",
			tc.typeLn,
		} {
			if !strings.Contains(s, want) {
				t.Errorf("%s: keyfile lacks %q:\n%s", tc.id, want, s)
			}
		}
		// NetworkManager must be handed file paths: no inline blob and no key material.
		if strings.Contains(s, "data:;base64,") || strings.Contains(s, "PRIVATE KEY") || strings.Contains(s, "private-key-password=") {
			t.Errorf("%s: keyfile carries inline data:\n%s", tc.id, s)
		}
		for _, line := range strings.Split(s, "\n") {
			if strings.HasPrefix(line, "client-cert=") || strings.HasPrefix(line, "private-key=") {
				p := line[strings.Index(line, "=")+1:]
				if !filepath.IsAbs(p) {
					t.Errorf("%s: %q is not an absolute path", tc.id, line)
				}
				if _, err := os.Stat(p); err != nil {
					t.Errorf("%s: %q points at a missing file", tc.id, line)
				}
			}
		}
	}

	// An identity set by the admin wins over the device id.
	p := deviceWired()
	p.Wired.Identity = "host/corp"
	raw, _ := json.Marshal(p)
	EnforceNetworkProfilePolicy(context.Background(), types.AssignedPolicy{ID: "w1", PolicyType: types.PolicyTypeNetworkProfile, Payload: raw})
	data, _ := os.ReadFile(filepath.Join(dir, "spire-w1.nmconnection"))
	if !strings.Contains(string(data), "identity=host/corp\n") || strings.Contains(string(data), "identity="+testDeviceID) {
		t.Errorf("admin identity not honoured:\n%s", data)
	}
}

func TestDeviceCertProfileNonCompliantWithoutValidCert(t *testing.T) {
	raw, _ := json.Marshal(deviceWired())
	pol := types.AssignedPolicy{ID: "w2", PolicyType: types.PolicyTypeNetworkProfile, Payload: raw}

	t.Run("no files", func(t *testing.T) {
		_, rc := withNetworkCert(t, false)
		defer rc()
		dir, fr, restore := withNMFakes(t)
		defer restore()
		item := EnforceNetworkProfilePolicy(context.Background(), pol)
		if item.ComplianceStatus != types.ComplianceNonCompliant || !strings.Contains(item.ErrorMessage, "network certificate") {
			t.Fatalf("got %s %q", item.ComplianceStatus, item.ErrorMessage)
		}
		if _, err := os.Stat(filepath.Join(dir, "spire-w2.nmconnection")); err == nil {
			t.Fatal("a keyfile was written with no certificate")
		}
		if fr.called("nmcli connection reload") {
			t.Fatal("NetworkManager was reloaded")
		}
	})
	t.Run("key does not match certificate", func(t *testing.T) {
		paths, rc := withNetworkCert(t, true)
		defer rc()
		other := t.TempDir()
		otherPaths := NetworkCertFilesIn(other)
		writeNetworkCert(t, otherPaths, other, testDeviceID)
		b, _ := os.ReadFile(otherPaths.Key)
		_ = os.WriteFile(paths.Key, b, 0600)
		dir, _, restore := withNMFakes(t)
		defer restore()
		item := EnforceNetworkProfilePolicy(context.Background(), pol)
		if item.ComplianceStatus != types.ComplianceNonCompliant {
			t.Fatalf("got %s", item.ComplianceStatus)
		}
		if _, err := os.Stat(filepath.Join(dir, "spire-w2.nmconnection")); err == nil {
			t.Fatal("a keyfile was written for a mismatched pair")
		}
	})
	t.Run("expired", func(t *testing.T) {
		_, rc := withNetworkCert(t, true)
		defer rc()
		networkCertNow = func() time.Time { return time.Now().Add(31 * 24 * time.Hour) }
		dir, _, restore := withNMFakes(t)
		defer restore()
		item := EnforceNetworkProfilePolicy(context.Background(), pol)
		if item.ComplianceStatus != types.ComplianceNonCompliant || !strings.Contains(item.ErrorMessage, "validity") {
			t.Fatalf("got %s %q", item.ComplianceStatus, item.ErrorMessage)
		}
		if _, err := os.Stat(filepath.Join(dir, "spire-w2.nmconnection")); err == nil {
			t.Fatal("a keyfile was written for an expired certificate")
		}
	})
	t.Run("existing keyfile is left alone", func(t *testing.T) {
		_, rc := withNetworkCert(t, false)
		defer rc()
		dir, _, restore := withNMFakes(t)
		defer restore()
		_ = os.MkdirAll(dir, 0700)
		target := filepath.Join(dir, "spire-w2.nmconnection")
		_ = os.WriteFile(target, []byte("old"), 0600)
		EnforceNetworkProfilePolicy(context.Background(), pol)
		if b, _ := os.ReadFile(target); string(b) != "old" {
			t.Fatalf("keyfile was changed: %q", b)
		}
	})
}

func TestRenderDeviceProfileRefusesMissingCert(t *testing.T) {
	if _, _, err := renderNetworkProfile("w3", deviceWired(), nil); err == nil {
		t.Fatal("render produced a keyfile with no certificate")
	}
}

func TestPayloadUsesDeviceNetworkCert(t *testing.T) {
	if !PayloadUsesDeviceNetworkCert(deviceWired()) || !PayloadUsesDeviceNetworkCert(deviceWifi()) {
		t.Fatal("device profiles not detected")
	}
	if PayloadUsesDeviceNetworkCert(types.NetworkProfilePayload{Kind: types.NetworkProfileWireGuard}) {
		t.Fatal("wireguard detected as device cert")
	}
	inline := deviceWired()
	inline.Wired.ClientCertSource = types.ClientCertSourceInline
	if PayloadUsesDeviceNetworkCert(inline) {
		t.Fatal("inline detected as device cert")
	}
}
