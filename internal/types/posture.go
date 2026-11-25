package types

import "time"

// PostureState is a device's single access verdict, read by conditional-access connectors.
type PostureState string

const (
	// PostureCompliant: every enabled access check passed and the device is not quarantined.
	PostureCompliant PostureState = "COMPLIANT"
	// PostureNoncompliant: at least one enabled access check failed.
	PostureNoncompliant PostureState = "NONCOMPLIANT"
	// PostureQuarantined: an administrator or a rule quarantined the device. Takes
	// precedence over every other state.
	PostureQuarantined PostureState = "QUARANTINED"
	// PostureUnknown: never evaluated, evaluation failed, or the verdict is stale.
	// Connectors treat it as not allowed unless explicitly configured otherwise.
	PostureUnknown PostureState = "UNKNOWN"
)

// Valid reports whether s is a known posture state.
func (s PostureState) Valid() bool {
	switch s {
	case PostureCompliant, PostureNoncompliant, PostureQuarantined, PostureUnknown:
		return true
	}
	return false
}

// PostureCheck is the result of one access check in a posture evaluation.
type PostureCheck struct {
	ID     string `json:"id"` // stable check id, e.g. "attestation_trusted"
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"` // short explanation, safe to show to admins
}

// DevicePosture is the stored verdict for one device (table device_posture).
type DevicePosture struct {
	DeviceID       string         `json:"device_id"`
	State          PostureState   `json:"state"`
	Reasons        []string       `json:"reasons"`
	Checks         []PostureCheck `json:"checks"`
	RuleSetVersion int            `json:"rule_set_version"`
	EvaluatedAt    time.Time      `json:"evaluated_at"`
	ValidUntil     time.Time      `json:"valid_until"`
	StateChangedAt time.Time      `json:"state_changed_at"`
}

// EffectiveState is the state a connector must act on: UNKNOWN for a nil posture or one
// past ValidUntil, otherwise the stored state. Connectors must call this rather than read
// State directly, so a stale verdict never grants access.
func (p *DevicePosture) EffectiveState(now time.Time) PostureState {
	if p == nil || !p.State.Valid() || !now.Before(p.ValidUntil) {
		return PostureUnknown
	}
	return p.State
}

// Allowed reports whether the effective state is COMPLIANT.
func (p *DevicePosture) Allowed(now time.Time) bool {
	return p.EffectiveState(now) == PostureCompliant
}

// AccessIdentity is what a connector knows about the device asking for access. Exactly one
// field is normally set. Strength differs: a certificate serial or fingerprint from the
// SpireUEM device CA is cryptographic; a MAC address, IP address or user name is only a hint
// that can be spoofed or shared, and connectors must document which they rely on.
type AccessIdentity struct {
	CertSerial      string // decimal serial of a SpireUEM device-CA certificate
	CertFingerprint string // lowercase hex SHA-256 of a SpireUEM device-CA certificate
	MAC             string // any common notation; normalised to aa:bb:cc:dd:ee:ff
	IP              string // last IP the device checked in from
	User            string // last active desktop user reported by the agent
	// CertPurposes limits a certificate lookup to certificates of these purposes. Empty
	// matches any purpose; a connector should always name its own (RADIUS: network,
	// forward-auth: browser) so a certificate issued for something else never matches.
	CertPurposes []CertPurpose
}

// Weak reports whether the identity rests only on spoofable hints (MAC, IP, user).
func (a AccessIdentity) Weak() bool {
	return a.CertSerial == "" && a.CertFingerprint == ""
}
