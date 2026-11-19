package radius

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
)

// AcceptMarker is the value SpireUEM sets in control:Tmp-String-0 on every accept. The
// FreeRADIUS policy accepts only when it sees it, so a missing, empty or unparseable answer
// can never turn into an accept ("noop then accept"). See contrib/freeradius.
const AcceptMarker = "spire-accept"

// Names of the attributes FreeRADIUS 3.2 sends that this connector reads.
const (
	attrUserName    = "User-Name"
	attrCalling     = "Calling-Station-Id"
	attrNASIP       = "NAS-IP-Address"
	attrNASIPv6     = "NAS-IPv6-Address"
	attrNASID       = "NAS-Identifier"
	attrAcctSession = "Acct-Session-Id"
	attrCertSerial  = "TLS-Client-Cert-Serial"
	// attrCertFingerprint is not a stock FreeRADIUS attribute; deployments that compute a
	// SHA-256 fingerprint themselves may send it. The serial is the normal key.
	attrCertFingerprint = "TLS-Client-Cert-Fingerprint"
)

const maxAttrLen = 256

// Request is the part of a FreeRADIUS request this connector uses.
type Request struct {
	UserName         string
	CallingStationID string
	NASIPAddress     string
	NASIdentifier    string
	AcctSessionID    string
	CertSerialHex    string // as FreeRADIUS exposes it (hex)
	CertFingerprint  string
}

// ParseRESTRequest decodes the JSON body rlm_rest sends in FreeRADIUS 3.2:
//
//	{"User-Name":{"type":"string","value":["bob"]}, "Calling-Station-Id":{...}, ...}
//
// A bare string or a {"value": "x"} object is accepted too. Unknown attributes are ignored.
// If an identity attribute appears with two different values the request is refused: it is
// ambiguous and the caller must reject. Values longer than 256 bytes are refused.
func ParseRESTRequest(body []byte) (*Request, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, errors.New("request body is not a JSON object")
	}
	get := func(name string) (string, error) {
		m, ok := raw[name]
		if !ok {
			return "", nil
		}
		vals, err := attrValues(m)
		if err != nil {
			return "", fmt.Errorf("attribute %s: %w", name, err)
		}
		if len(vals) == 0 {
			return "", nil
		}
		for _, v := range vals[1:] {
			if v != vals[0] {
				return "", fmt.Errorf("attribute %s has conflicting values", name)
			}
		}
		if len(vals[0]) > maxAttrLen {
			return "", fmt.Errorf("attribute %s is too long", name)
		}
		return vals[0], nil
	}
	var r Request
	var err error
	for _, f := range []struct {
		name string
		dst  *string
	}{
		{attrUserName, &r.UserName}, {attrCalling, &r.CallingStationID},
		{attrNASIP, &r.NASIPAddress}, {attrNASIPv6, nil}, {attrNASID, &r.NASIdentifier},
		{attrAcctSession, &r.AcctSessionID}, {attrCertSerial, &r.CertSerialHex},
		{attrCertFingerprint, &r.CertFingerprint},
	} {
		v, e := get(f.name)
		if e != nil {
			err = e
			break
		}
		if f.dst != nil {
			*f.dst = strings.TrimSpace(v)
		} else if v != "" && r.NASIPAddress == "" {
			r.NASIPAddress = strings.TrimSpace(v)
		}
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// attrValues extracts the string values of one attribute in any of rlm_rest's shapes.
func attrValues(m json.RawMessage) ([]string, error) {
	m = bytes.TrimSpace(m)
	if len(m) == 0 {
		return nil, errors.New("empty")
	}
	switch m[0] {
	case '{':
		var o struct {
			Value json.RawMessage `json:"value"`
		}
		if err := json.Unmarshal(m, &o); err != nil {
			return nil, err
		}
		if len(o.Value) == 0 {
			return nil, errors.New("object without a value")
		}
		return attrValues(o.Value)
	case '[':
		var arr []json.RawMessage
		if err := json.Unmarshal(m, &arr); err != nil {
			return nil, err
		}
		var out []string
		for _, e := range arr {
			vs, err := attrValues(e)
			if err != nil {
				return nil, err
			}
			out = append(out, vs...)
		}
		return out, nil
	case '"':
		var s string
		if err := json.Unmarshal(m, &s); err != nil {
			return nil, err
		}
		return []string{s}, nil
	case 'n':
		return nil, errors.New("null value")
	default:
		var n json.Number
		if err := json.Unmarshal(m, &n); err != nil {
			return nil, errors.New("unsupported value")
		}
		return []string{n.String()}, nil
	}
}

// CertSerialDecimal converts the hex serial FreeRADIUS reports (for example "01a2b3", with
// or without 0x, colons or spaces) to the decimal string SpireUEM stores for device-CA
// certificates.
func CertSerialDecimal(hexSerial string) (string, error) {
	s := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(hexSerial)))
	s = strings.TrimPrefix(s, "0x")
	if s == "" || len(s) > 80 {
		return "", errors.New("certificate serial is empty or too long")
	}
	n, ok := new(big.Int).SetString(s, 16)
	if !ok || n.Sign() <= 0 {
		return "", errors.New("certificate serial is not a positive hexadecimal number")
	}
	return n.String(), nil
}

// NormalizeFingerprint returns a lowercase 64-hex SHA-256 fingerprint or an error.
func NormalizeFingerprint(fp string) (string, error) {
	s := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(fp)))
	if len(s) != 64 {
		return "", errors.New("fingerprint must be 64 hex characters (SHA-256)")
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", errors.New("fingerprint must be hexadecimal")
		}
	}
	return s, nil
}

// ---------------------------------------------------------------------------------------
// Decision mapping
// ---------------------------------------------------------------------------------------

// Settings is the administrator-configured mapping (table radius_settings).
type Settings struct {
	CompliantVLAN     string // "" = accept without VLAN attributes
	QuarantineVLAN    string // "" = reject quarantined devices
	RemediationVLAN   string // "" = reject non-compliant devices
	GuestVLAN         string
	GuestEnabled      bool // guest VLAN is used only when explicitly enabled
	AllowWeakIdentity bool // accept MAC (MAB) identity; default off
}

// ValidVLAN reports whether s is a VLAN id 1-4094 written as plain digits.
func ValidVLAN(s string) bool {
	if s == "" || len(s) > 4 {
		return false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n >= 1 && n <= 4094 && s[0] != '0'
}

// Verdict is the connector's answer for one request.
type Verdict struct {
	Accept bool
	VLAN   string // "" = no VLAN attributes
	Class  string // machine-readable reason, logged and never sent to the caller
}

// Decide maps an effective posture state to a verdict. UNKNOWN is rejected unless the
// administrator explicitly enabled a guest VLAN.
func Decide(s Settings, st types.PostureState) Verdict {
	switch st {
	case types.PostureCompliant:
		return Verdict{Accept: true, VLAN: s.CompliantVLAN, Class: "compliant"}
	case types.PostureQuarantined:
		if s.QuarantineVLAN != "" {
			return Verdict{Accept: true, VLAN: s.QuarantineVLAN, Class: "quarantined_vlan"}
		}
		return Verdict{Class: "quarantined"}
	case types.PostureNoncompliant:
		if s.RemediationVLAN != "" {
			return Verdict{Accept: true, VLAN: s.RemediationVLAN, Class: "noncompliant_vlan"}
		}
		return Verdict{Class: "noncompliant"}
	}
	return DecideUnknown(s)
}

// DecideUnknown is the verdict for a device SpireUEM looked up and does not know (no match,
// out of the caller's tag scope) or whose posture is UNKNOWN or stale.
func DecideUnknown(s Settings) Verdict {
	if s.GuestEnabled && ValidVLAN(s.GuestVLAN) {
		return Verdict{Accept: true, VLAN: s.GuestVLAN, Class: "guest_vlan"}
	}
	return Verdict{Class: "unknown"}
}

// Reject is the verdict for anything that is not a clean lookup: errors, ambiguity, bad input,
// weak identity not allowed. It never maps to the guest VLAN.
func Reject(class string) Verdict { return Verdict{Class: class} }

// ReplyAttrs renders an accept in the shape rlm_rest parses (FreeRADIUS 3.2): attribute names
// prefixed with the list they belong to. The marker proves to the policy that SpireUEM
// answered; the VLAN attributes are RFC 3580.
func ReplyAttrs(vlan string) map[string]any {
	m := map[string]any{"control:Tmp-String-0": AcceptMarker}
	if vlan != "" {
		m["reply:Tunnel-Type:0"] = "VLAN"
		m["reply:Tunnel-Medium-Type:0"] = "IEEE-802"
		m["reply:Tunnel-Private-Group-Id:0"] = vlan
	}
	return m
}
