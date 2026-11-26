package web_test

import (
	"fmt"
	"testing"
	"time"
)

// addCert gives the device another certificate of the given purpose and returns its serial
// (hex, as FreeRADIUS reports it) and fingerprint.
func (e *radEnv) addCert(deviceID, purpose string) (hexSerial, fingerprint string) {
	e.t.Helper()
	e.seq++
	n := time.Now().UnixNano()/1000 + int64(e.seq)
	fingerprint = fmt.Sprintf("%064x", n*31)
	user := ""
	if purpose == "browser" {
		user = "alice"
	}
	e.exec(`INSERT INTO device_certificates (device_id, serial, fingerprint_sha256, purpose, subject_user, not_before, not_after)
		VALUES ($1,$2,$3,$4,$5,NOW()-interval '1 hour',NOW()+interval '1 day')`, deviceID, fmt.Sprint(n), fingerprint, purpose, user)
	return fmt.Sprintf("%x", n), fingerprint
}

// Only a network certificate identifies a device to RADIUS. The device's agent and browser
// certificates chain to the same CA but must be refused, by serial and by fingerprint.
func TestRadiusAuthorize_OnlyNetworkCertificateAccepted(t *testing.T) {
	e := newRadEnv(t)
	tok := e.postureToken()
	dev := e.device("COMPLIANT") // has a network certificate (dev.hex)

	agentSerial, agentFP := e.addCert(dev.d.ID, "agent")
	browserSerial, browserFP := e.addCert(dev.d.ID, "browser")

	rejected(t, "agent serial", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": agentSerial}))
	rejected(t, "browser serial", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": browserSerial}))
	rejected(t, "agent fingerprint", e.authz(tok, map[string]string{"TLS-Client-Cert-Fingerprint": agentFP}))
	rejected(t, "browser fingerprint", e.authz(tok, map[string]string{"TLS-Client-Cert-Fingerprint": browserFP}))
	// An agent serial next to the device's own good MAC still must not open the door.
	rejected(t, "agent serial + own MAC", e.authz(tok, map[string]string{
		"TLS-Client-Cert-Serial": agentSerial, "Calling-Station-Id": dev.mac}))

	m := accepted(t, e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": dev.hex}))
	if m["control:Tmp-String-1"] != "strong" {
		t.Fatalf("network certificate identity strength: %v", m)
	}

	// A device that has no network certificate at all (only agent and browser ones) is unknown.
	other := e.device("COMPLIANT")
	e.exec(`UPDATE device_certificates SET purpose='agent' WHERE device_id=$1 AND serial=$2`, other.d.ID, other.serial)
	hexB, _ := e.addCert(other.d.ID, "browser")
	rejected(t, "device with no network certificate: former network serial", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": other.hex}))
	rejected(t, "device with no network certificate: browser serial", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": hexB}))

	// A revoked network certificate is refused even though the device is compliant.
	e.exec(`UPDATE device_certificates SET revoked_at = NOW() WHERE device_id=$1 AND purpose='network'`, dev.d.ID)
	rejected(t, "revoked network certificate", e.authz(tok, map[string]string{"TLS-Client-Cert-Serial": dev.hex}))
}
