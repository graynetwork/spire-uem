package types

import (
	"encoding/json"
	"time"
)

// AttestationStatus represents the hardware TPM 2.0 attestation status of a device.
type AttestationStatus string

const (
	AttestationUnattested      AttestationStatus = "UNATTESTED"
	AttestationAttested        AttestationStatus = "ATTESTED"
	AttestationFailed          AttestationStatus = "FAILED"
	AttestationPolicyViolation AttestationStatus = "POLICY_VIOLATION"
)

// DeviceTPMAttestation represents a record in device_tpm_attestation.
type DeviceTPMAttestation struct {
	ID                string            `db:"id" json:"id"`
	DeviceID          string            `db:"device_id" json:"device_id"`
	EKPublicPEM       string            `db:"ek_public_pem" json:"ek_public_pem"`
	AKPublicPEM       string            `db:"ak_public_pem" json:"ak_public_pem"`
	PCRValues         map[string]string `db:"pcr_values" json:"pcr_values"`
	QuoteSignature    []byte            `db:"quote_signature" json:"quote_signature,omitempty"`
	AttestationStatus AttestationStatus `db:"attestation_status" json:"attestation_status"`
	SecureBootEnabled bool              `db:"secure_boot_enabled" json:"secure_boot_enabled"`
	ChallengeNonce    string            `db:"challenge_nonce" json:"challenge_nonce,omitempty"`
	LastAttestedAt    time.Time         `db:"last_attested_at" json:"last_attested_at"`
	CreatedAt         time.Time         `db:"created_at" json:"created_at"`
	UpdatedAt         time.Time         `db:"updated_at" json:"updated_at"`
}

// DeviceLUKSEscrow represents an envelope-encrypted LUKS2 recovery key record in device_luks_escrow.
type DeviceLUKSEscrow struct {
	ID                   string    `db:"id" json:"id"`
	DeviceID             string    `db:"device_id" json:"device_id"`
	VolumeUUID           string    `db:"volume_uuid" json:"volume_uuid"`
	DevicePath           string    `db:"device_path" json:"device_path"`
	MountPoint           string    `db:"mount_point" json:"mount_point"`
	EncryptedDEK         []byte    `db:"encrypted_dek" json:"-"`
	EncryptedRecoveryKey []byte    `db:"encrypted_recovery_key" json:"-"`
	Nonce                []byte    `db:"nonce" json:"-"`
	KeySlot              int       `db:"key_slot" json:"key_slot"`
	EscrowedAt           time.Time `db:"escrowed_at" json:"escrowed_at"`
	UpdatedAt            time.Time `db:"updated_at" json:"updated_at"`
}

// LUKSRecoveryAuditEntry represents an audit trail entry in luks_recovery_audit_log.
type LUKSRecoveryAuditEntry struct {
	ID            string    `db:"id" json:"id"`
	DeviceID      string    `db:"device_id" json:"device_id"`
	VolumeUUID    string    `db:"volume_uuid" json:"volume_uuid"`
	AdminUsername string    `db:"admin_username" json:"admin_username"`
	Reason        string    `db:"reason" json:"reason"`
	SourceIP      string    `db:"source_ip" json:"source_ip"`
	AccessedAt    time.Time `db:"accessed_at" json:"accessed_at"`
}

// AttestationChallengeRequest is sent by spired to POST /api/v1/desktop/attest/challenge.
type AttestationChallengeRequest struct {
	HardwareUUID     string `json:"hardware_uuid"`
	EKPublicPEM      string `json:"ek_public_pem"`
	AKPublicPEM      string `json:"ak_public_pem,omitempty"`
	EKCertificatePEM string `json:"ek_certificate_pem,omitempty"`
	// AKPublicTPM is the AK's TPMT_PUBLIC area; the server derives the AK name from it
	// for credential activation. Required for hardware attestation.
	AKPublicTPM []byte `json:"ak_public_tpm,omitempty"`
	// Simulated marks a software-simulated TPM (accepted only when the server allows it).
	Simulated bool `json:"simulated,omitempty"`
}

// AttestationChallengeResponse is returned by POST /api/v1/desktop/attest/challenge.
type AttestationChallengeResponse struct {
	EncryptedNonce []byte `json:"encrypted_nonce,omitempty"` // simulated mode only
	// CredentialBlob and EncryptedSecret are TPM2_ActivateCredential inputs (hardware mode).
	CredentialBlob  []byte `json:"credential_blob,omitempty"`
	EncryptedSecret []byte `json:"encrypted_secret,omitempty"`
	ChallengeID     string `json:"challenge_id,omitempty"`
	ServerKEKPEM    string `json:"server_kek_pem,omitempty"`
}

// AttestationVerifyRequest is sent by spired to POST /api/v1/desktop/attest/verify.
type AttestationVerifyRequest struct {
	HardwareUUID     string            `json:"hardware_uuid"`
	EKPublicPEM      string            `json:"ek_public_pem"`
	AKPublicPEM      string            `json:"ak_public_pem"`
	EKCertificatePEM string            `json:"ek_certificate_pem,omitempty"`
	Nonce            string            `json:"nonce"`
	PCRValues        map[string]string `json:"pcr_values"`
	QuoteAttest      []byte            `json:"quote_attest,omitempty"`
	QuoteSignature   []byte            `json:"quote_signature"`
	// SecureBootEnabled is informational only; the server derives Secure Boot state from the
	// quote-verified PCR 7 value.
	SecureBootEnabled bool `json:"secure_boot_enabled"`
	Simulated         bool `json:"simulated,omitempty"`
}

// AttestationVerifyResponse is returned by POST /api/v1/desktop/attest/verify.
type AttestationVerifyResponse struct {
	Status            AttestationStatus `json:"status"`
	SecureBootEnabled bool              `json:"secure_boot_enabled"`
	VerifiedAt        time.Time         `json:"verified_at"`
}

// LUKSEscrowPayload is sent by spired to POST /api/v1/desktop/escrow/luks.
// Supports both RSA-OAEP-4096 + AES-256-GCM client-side envelope fields and optional raw recovery key fallback.
type LUKSEscrowPayload struct {
	HardwareUUID         string          `json:"hardware_uuid,omitempty"`
	VolumeUUID           string          `json:"volume_uuid"`
	DevicePath           string          `json:"device_path,omitempty"`
	MountPoint           string          `json:"mount_point"`
	KeySlot              int             `json:"key_slot,omitempty"`
	EncryptedDEK         []byte          `json:"encrypted_dek,omitempty"`
	EncryptedRecoveryKey []byte          `json:"encrypted_recovery_key,omitempty"`
	Nonce                []byte          `json:"nonce,omitempty"`
	RecoveryKey          string          `json:"recovery_key,omitempty"`
	Metadata             json.RawMessage `json:"metadata,omitempty"`
}

// RevealRecoveryKeyRequest is sent by an administrator to POST /admin/devices/{id}/luks/reveal or POST /api/v1/auth/recovery-key.
type RevealRecoveryKeyRequest struct {
	DeviceID   string `json:"device_id,omitempty"`
	VolumeUUID string `json:"volume_uuid"`
	Reason     string `json:"reason"`
	Ticket     string `json:"ticket,omitempty"`
}

// RevealRecoveryKeyResponse is returned when a LUKS2 recovery key is decrypted for an administrator.
type RevealRecoveryKeyResponse struct {
	DeviceID    string    `json:"device_id"`
	VolumeUUID  string    `json:"volume_uuid"`
	MountPoint  string    `json:"mount_point"`
	RecoveryKey string    `json:"recovery_key"`
	Reason      string    `json:"reason"`
	RevealedAt  time.Time `json:"revealed_at"`
}
