package engine

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/types"
)

// NetworkCertPaths are the root-only files that hold the device's network key, its network
// certificate and the device CA. NetworkManager (running as root) reads the key and
// certificate by path; the agent writes them (cmd/spired/network_cert.go).
type NetworkCertPaths struct {
	Key  string
	Cert string
	CA   string
}

// NetworkCertFilesIn returns the network certificate files inside dir (the directory that
// holds the agent token and key).
func NetworkCertFilesIn(dir string) NetworkCertPaths {
	return NetworkCertPaths{
		Key:  filepath.Join(dir, "network.key"),
		Cert: filepath.Join(dir, "network.crt"),
		CA:   filepath.Join(dir, "device-ca.crt"),
	}
}

// networkCertPaths is where the engine looks for the network key and certificate. spired sets
// it at start-up; tests point it at a temp dir.
var networkCertPaths = NetworkCertFilesIn("/etc/spire")

// SetNetworkCertPaths tells the engine where the agent keeps the network certificate files.
func SetNetworkCertPaths(p NetworkCertPaths) { networkCertPaths = p }

// networkCertNow is the clock used to judge certificate validity (replaced in tests).
var networkCertNow = time.Now

// networkCertInfo describes a network certificate the engine checked and found usable.
type networkCertInfo struct {
	KeyPath  string
	CertPath string
	DeviceID string
	NotAfter time.Time
}

// loadNetworkCert returns the network certificate if, and only if, the key and certificate
// files exist, parse, match each other, name a device, and are inside their validity window.
// Any other state returns an error that says what is missing, so callers can report it.
func loadNetworkCert() (*networkCertInfo, error) {
	p := networkCertPaths
	certPEM, err := os.ReadFile(p.Cert)
	if err != nil {
		return nil, fmt.Errorf("the device has no network certificate yet (%s unreadable)", filepath.Base(p.Cert))
	}
	keyPEM, err := os.ReadFile(p.Key)
	if err != nil {
		return nil, fmt.Errorf("the device has no network key yet (%s unreadable)", filepath.Base(p.Key))
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return nil, fmt.Errorf("the network key and certificate do not match: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("the network certificate is not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse the network certificate: %v", err)
	}
	now := networkCertNow()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("the network certificate is outside its validity window (%s to %s)",
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	id := crypto.DeviceIDFromCert(leaf)
	if id == "" {
		return nil, fmt.Errorf("the network certificate names no device")
	}
	return &networkCertInfo{KeyPath: p.Key, CertPath: p.Cert, DeviceID: id, NotAfter: leaf.NotAfter}, nil
}

// checkClientCertSource validates the client_cert_source of a 802.1X profile together with the
// fields it constrains. It returns device=true when the SpireUEM-issued certificate is used.
//
// "" and "inline" are today's behaviour. "device" needs EAP-TLS and no pasted certificate, key
// or key passphrase: the key never leaves the endpoint, so the server has nothing to carry.
func checkClientCertSource(src types.ClientCertSource, eap types.EAPMethod, clientCert string, clientKey, password types.SecretEnvelope) (device bool, err error) {
	switch src {
	case "", types.ClientCertSourceInline:
		return false, nil
	case types.ClientCertSourceDevice:
	default:
		return false, fmt.Errorf("invalid client_cert_source %q (want inline or device)", src)
	}
	if eap != types.EAPTLS {
		return false, fmt.Errorf("client_cert_source device requires eap tls")
	}
	if strings.TrimSpace(clientCert) != "" || clientKey.HasValue() || password.HasValue() {
		return false, fmt.Errorf("client_cert_source device must not carry client_cert, client_key or password")
	}
	return true, nil
}

// ValidateNetworkProfileClientCertSource runs only the client_cert_source checks on a payload.
// The raw-JSON policy paths call it, since they accept payloads the form builder never sees.
func ValidateNetworkProfileClientCertSource(p types.NetworkProfilePayload) error {
	switch p.Kind {
	case types.NetworkProfileWifi:
		if p.Wifi == nil {
			return nil
		}
		w := p.Wifi
		if w.Security != types.WifiWPA2Enterprise && w.Security != types.WifiWPA3Enterprise {
			if w.ClientCertSource != "" && w.ClientCertSource != types.ClientCertSourceInline {
				return fmt.Errorf("client_cert_source only applies to 802.1X (enterprise) Wi-Fi")
			}
			return nil
		}
		_, err := checkClientCertSource(w.ClientCertSource, w.EAP, w.ClientCert, w.ClientKey, w.Password)
		return err
	case types.NetworkProfileWiredDot1x:
		if p.Wired == nil {
			return nil
		}
		w := p.Wired
		_, err := checkClientCertSource(w.ClientCertSource, w.EAP, w.ClientCert, w.ClientKey, w.Password)
		return err
	default:
		return nil
	}
}

// PayloadUsesDeviceNetworkCert reports whether a NETWORK_PROFILE payload asks for the
// device's own network certificate.
func PayloadUsesDeviceNetworkCert(p types.NetworkProfilePayload) bool {
	switch p.Kind {
	case types.NetworkProfileWifi:
		return p.Wifi != nil && p.Wifi.ClientCertSource == types.ClientCertSourceDevice
	case types.NetworkProfileWiredDot1x:
		return p.Wired != nil && p.Wired.ClientCertSource == types.ClientCertSourceDevice
	}
	return false
}
