package types

import (
	"encoding/json"
	"time"
)

// ActionDirectivePrefix tags a device_commands row as a structured lost-device action
// directive rather than an ad-hoc shell command. The agent recognizes the prefix and
// routes the JSON body to the device-actions engine instead of /bin/sh. The remaining
// bytes after the prefix are a JSON-encoded ActionDirective.
const ActionDirectivePrefix = "__spire_action__:"

// InventoryRefreshCommand is a queued command string that asks the agent to collect and send
// a fresh rich inventory report on its next check-in, bypassing the normal inventory_interval
// cadence. The agent recognizes it, arms a one-shot force flag, triggers a check-in, and
// reports the command completed. It carries no arguments and touches no shell.
const InventoryRefreshCommand = "__spire_inventory_refresh__"

// ActionKind enumerates the structured lost-device actions dispatched over the command queue.
type ActionKind string

const (
	ActionLock       ActionKind = "LOCK"        // lock all graphical sessions now
	ActionLostApply  ActionKind = "LOST_APPLY"  // enter lost mode (lock, nologin, expire sessions, fast check-in)
	ActionLostRevert ActionKind = "LOST_REVERT" // leave lost mode, undo what the agent changed
	ActionWipe       ActionKind = "WIPE"        // crypto-erase escrowed LUKS volumes then power off
	ActionLUKSRotate ActionKind = "LUKS_ROTATE" // rotate a revealed LUKS recovery key
)

// ActionDirective is the structured body carried in a queued command for a lost-device
// action. Only the fields relevant to Kind are populated.
type ActionDirective struct {
	Kind    ActionKind `json:"kind"`
	ActorID string     `json:"actor_id,omitempty"` // server-side request/row id for correlation

	// LOCK / LOST_APPLY: optional message shown to the signed-in user.
	Message string `json:"message,omitempty"`

	// WIPE: the Ed25519-signed, base64url wipe order and its signature. The agent verifies
	// the signature against the public key it pinned at enrollment before acting.
	SignedOrder    []byte `json:"signed_order,omitempty"`
	OrderSignature []byte `json:"order_signature,omitempty"`

	// LUKS_ROTATE: which escrowed volume to rotate.
	VolumeUUID string `json:"volume_uuid,omitempty"`
	DevicePath string `json:"device_path,omitempty"`
	KeySlot    int    `json:"key_slot,omitempty"`
}

// WipeOrder is the canonical, signed payload the agent must verify before crypto-erasing.
// It names exactly one device and the volumes (by UUID) the agent itself reported as
// escrowed; the agent must never wipe a volume not named here.
type WipeOrder struct {
	Version      int       `json:"version"`
	RequestID    string    `json:"request_id"`
	DeviceID     string    `json:"device_id"`
	HardwareUUID string    `json:"hardware_uuid"`
	Hostname     string    `json:"hostname"`
	VolumeUUIDs  []string  `json:"volume_uuids"`
	IssuedAt     time.Time `json:"issued_at"`
	// ExpiresAt bounds how long a signed order is honoured once delivered; a stale order
	// is refused by the agent.
	ExpiresAt time.Time `json:"expires_at"`
}

// MarshalCanonical returns the deterministic JSON bytes that are signed/verified. Using the
// same marshaller on both sides keeps the signed bytes byte-identical.
func (o WipeOrder) MarshalCanonical() ([]byte, error) {
	return json.Marshal(o)
}

// DeviceLostState mirrors a row in device_lost_state.
type DeviceLostState struct {
	DeviceID       string     `db:"device_id" json:"device_id"`
	DesiredLost    bool       `db:"desired_lost" json:"desired_lost"`
	LockMessage    string     `db:"lock_message" json:"lock_message"`
	ApplyStatus    string     `db:"apply_status" json:"apply_status"`
	ApplyDetail    string     `db:"apply_detail" json:"apply_detail"`
	MarkedBy       string     `db:"marked_by" json:"marked_by"`
	MarkedAt       time.Time  `db:"marked_at" json:"marked_at"`
	AcknowledgedAt *time.Time `db:"acknowledged_at" json:"acknowledged_at,omitempty"`
	UpdatedAt      time.Time  `db:"updated_at" json:"updated_at"`
}

// WipeRequestStatus mirrors the wipe_request_status enum.
type WipeRequestStatus string

const (
	WipePendingApproval WipeRequestStatus = "PENDING_APPROVAL"
	WipeApproved        WipeRequestStatus = "APPROVED"
	WipeDelivered       WipeRequestStatus = "DELIVERED"
	WipeCompleted       WipeRequestStatus = "COMPLETED"
	WipeCancelled       WipeRequestStatus = "CANCELLED"
	WipeExpired         WipeRequestStatus = "EXPIRED"
	WipeFailed          WipeRequestStatus = "FAILED"
)

// DeviceWipeRequest mirrors a row in device_wipe_requests.
type DeviceWipeRequest struct {
	ID               string            `db:"id" json:"id"`
	DeviceID         string            `db:"device_id" json:"device_id"`
	Status           WipeRequestStatus `db:"status" json:"status"`
	ConfirmHostname  string            `db:"confirm_hostname" json:"confirm_hostname"`
	Reason           string            `db:"reason" json:"reason"`
	RequestedBy      string            `db:"requested_by" json:"requested_by"`
	RequestedAt      time.Time         `db:"requested_at" json:"requested_at"`
	ApprovalDeadline time.Time         `db:"approval_deadline" json:"approval_deadline"`
	ApprovedBy       *string           `db:"approved_by" json:"approved_by,omitempty"`
	ApprovedAt       *time.Time        `db:"approved_at" json:"approved_at,omitempty"`
	CancelledBy      *string           `db:"cancelled_by" json:"cancelled_by,omitempty"`
	CancelledAt      *time.Time        `db:"cancelled_at" json:"cancelled_at,omitempty"`
	SignedOrder      []byte            `db:"signed_order" json:"-"`
	OrderSignature   []byte            `db:"order_signature" json:"-"`
	DeliveredAt      *time.Time        `db:"delivered_at" json:"delivered_at,omitempty"`
	CompletedAt      *time.Time        `db:"completed_at" json:"completed_at,omitempty"`
	ResultDetail     string            `db:"result_detail" json:"result_detail"`
	CreatedAt        time.Time         `db:"created_at" json:"created_at"`
	UpdatedAt        time.Time         `db:"updated_at" json:"updated_at"`
}

// LUKSRotationStatus mirrors the luks_rotation_status enum.
type LUKSRotationStatus string

const (
	RotationPending LUKSRotationStatus = "PENDING"
	RotationDone    LUKSRotationStatus = "DONE"
	RotationFailed  LUKSRotationStatus = "FAILED"
)

// LUKSRotationState mirrors a row in luks_rotation_state.
type LUKSRotationState struct {
	ID          string             `db:"id" json:"id"`
	DeviceID    string             `db:"device_id" json:"device_id"`
	VolumeUUID  string             `db:"volume_uuid" json:"volume_uuid"`
	Status      LUKSRotationStatus `db:"status" json:"status"`
	Reason      string             `db:"reason" json:"reason"`
	RequestedBy string             `db:"requested_by" json:"requested_by"`
	Detail      string             `db:"detail" json:"detail"`
	RequestedAt time.Time          `db:"requested_at" json:"requested_at"`
	CompletedAt *time.Time         `db:"completed_at" json:"completed_at,omitempty"`
	UpdatedAt   time.Time          `db:"updated_at" json:"updated_at"`
}

// ActionReportRequest is POSTed by the agent to report the outcome of a structured action
// that it executed from a queued directive (lost apply/revert, wipe, rotation). The command
// result itself still flows through the normal command-report path; this carries the
// richer, action-specific status the device page shows.
type ActionReportRequest struct {
	Kind       ActionKind `json:"kind"`
	ActorID    string     `json:"actor_id,omitempty"`
	VolumeUUID string     `json:"volume_uuid,omitempty"`
	Status     string     `json:"status"` // APPLIED | REVERTED | DONE | FAILED
	Detail     string     `json:"detail,omitempty"`

	// LUKS_ROTATE success carries the freshly-escrowed envelope of the NEW recovery key so
	// the server replaces the stored one in the same report.
	NewEncryptedDEK         []byte `json:"new_encrypted_dek,omitempty"`
	NewEncryptedRecoveryKey []byte `json:"new_encrypted_recovery_key,omitempty"`
	NewNonce                []byte `json:"new_nonce,omitempty"`
	NewKeySlot              int    `json:"new_key_slot,omitempty"`
}

// WipePinResponse is embedded in enroll/check-in responses so the agent can pin the
// server's Ed25519 wipe-signing public key once and persist it next to its token.
type WipePinResponse struct {
	// WipeSigningPublicKey is the base64 (std) DER/raw Ed25519 public key the agent pins.
	WipeSigningPublicKey string `json:"wipe_signing_public_key,omitempty"`
}
