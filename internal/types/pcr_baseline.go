package types

import "time"

// Additional attestation outcomes produced by baseline comparison. The base verdicts
// (UNATTESTED / ATTESTED / FAILED / POLICY_VIOLATION) live in security.go; these two are
// produced only when an active, in-scope baseline exists for the device.
const (
	// AttestationBaselineMatch means a verified quote matched every PCR of an active,
	// in-scope approved baseline.
	AttestationBaselineMatch AttestationStatus = "BASELINE_MATCH"
	// AttestationBaselineMismatch means in-scope baselines exist but none matched the
	// verified quote. The differing PCR indices are recorded on the result.
	AttestationBaselineMismatch AttestationStatus = "BASELINE_MISMATCH"
)

// AttestationEnforcementMode controls whether an untrusted device is denied sealed secrets.
type AttestationEnforcementMode string

const (
	// EnforcementOff keeps the pre-baseline behaviour: secrets are always delivered.
	EnforcementOff AttestationEnforcementMode = "off"
	// EnforcementWarn delivers secrets to untrusted devices but raises an alert.
	EnforcementWarn AttestationEnforcementMode = "warn"
	// EnforcementEnforce withholds sealed secrets from untrusted devices.
	EnforcementEnforce AttestationEnforcementMode = "enforce"
)

// ParseEnforcementMode normalises a stored/admin value to a known mode, defaulting to off.
func ParseEnforcementMode(s string) AttestationEnforcementMode {
	switch AttestationEnforcementMode(s) {
	case EnforcementWarn:
		return EnforcementWarn
	case EnforcementEnforce:
		return EnforcementEnforce
	default:
		return EnforcementOff
	}
}

// Setting keys and defaults for attestation enforcement (system_settings, category "crypto").
const (
	SettingAttestationEnforcement = "crypto.attestation_enforcement"
	SettingAttestationMaxAgeHours = "crypto.attestation_max_age_hours"

	DefaultAttestationMaxAgeHours = 24
	// MaxExceptionDays caps how long a device attestation exception may last.
	MaxExceptionDays = 30
	// AttestationHistoryLimit bounds the per-device attestation result history.
	AttestationHistoryLimit = 50
)

// TPMBaseline is an administrator-approved set of expected SHA-256 PCR values. Baselines are
// immutable: an edit creates a new version that supersedes the previous one.
type TPMBaseline struct {
	ID          string `db:"id" json:"id"`
	Name        string `db:"name" json:"name"`
	Description string `db:"description" json:"description"`
	// PCRValues maps a PCR index (decimal string, from RequiredAttestationPCRs: 0,2,4,7) to
	// its expected lowercase hex SHA-256 digest.
	PCRValues map[string]string `db:"pcr_values" json:"pcr_values"`
	// Scope: a baseline applies to a device when its tags intersect ScopeTags (or ScopeTags
	// is empty) AND its ring equals ScopeRing (or ScopeRing is empty). Empty scope = all
	// devices.
	ScopeTags []string `db:"scope_tags" json:"scope_tags"`
	ScopeRing string   `db:"scope_ring" json:"scope_ring,omitempty"`
	Active    bool     `db:"active" json:"active"`
	CreatedBy string   `db:"created_by" json:"created_by"`
	// Version increments across edits; Supersedes points at the baseline this one replaced.
	Version    int       `db:"version" json:"version"`
	Supersedes *string   `db:"supersedes" json:"supersedes,omitempty"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
}

// AppliesToDevice reports whether this baseline's scope matches the given device facts.
// Empty ScopeTags means any tags; empty ScopeRing means any ring.
func (b *TPMBaseline) AppliesToDevice(deviceTags []string, deviceRing string) bool {
	if b.ScopeRing != "" && b.ScopeRing != deviceRing {
		return false
	}
	if len(b.ScopeTags) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(b.ScopeTags))
	for _, t := range b.ScopeTags {
		set[t] = struct{}{}
	}
	for _, t := range deviceTags {
		if _, ok := set[t]; ok {
			return true
		}
	}
	return false
}

// TPMBaselineException temporarily exempts one device from baseline-match enforcement. It
// always carries a reason and a mandatory expiry (at most MaxExceptionDays out).
type TPMBaselineException struct {
	ID        string    `db:"id" json:"id"`
	DeviceID  string    `db:"device_id" json:"device_id"`
	Reason    string    `db:"reason" json:"reason"`
	CreatedBy string    `db:"created_by" json:"created_by"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
	ExpiresAt time.Time `db:"expires_at" json:"expires_at"`
}

// IsActive reports whether the exception has not yet expired at time now.
func (e *TPMBaselineException) IsActive(now time.Time) bool {
	return e != nil && now.Before(e.ExpiresAt)
}

// AttestationResult is one entry in a device's bounded attestation history.
type AttestationResult struct {
	ID       string            `db:"id" json:"id"`
	DeviceID string            `db:"device_id" json:"device_id"`
	Status   AttestationStatus `db:"status" json:"status"`
	// BaselineID is the matching baseline for BASELINE_MATCH, else nil.
	BaselineID *string `db:"baseline_id" json:"baseline_id,omitempty"`
	// MismatchedPCRs lists the PCR indices that differed, for BASELINE_MISMATCH.
	MismatchedPCRs []string          `db:"mismatched_pcrs" json:"mismatched_pcrs,omitempty"`
	PCRValues      map[string]string `db:"pcr_values" json:"pcr_values,omitempty"`
	SecureBoot     bool              `db:"secure_boot_enabled" json:"secure_boot_enabled"`
	CreatedAt      time.Time         `db:"created_at" json:"created_at"`
}

// TrustEvaluation is the outcome of applying the trust decision table to a device.
type TrustEvaluation struct {
	Trusted bool
	// Reason is a short machine-ish label (also surfaced in the UI and logs).
	Reason string
	// HasException is true when an unexpired exception is what makes the device trusted (or
	// would, under enforce).
	HasException bool
}
