package types

import (
	"encoding/json"
	"time"
)

// DeviceStatus represents the enrollment/lifecycle status of a managed endpoint.
type DeviceStatus string

const (
	StatusPendingApproval DeviceStatus = "PENDING_APPROVAL"
	StatusApproved        DeviceStatus = "APPROVED"
	StatusRejected        DeviceStatus = "REJECTED"
	StatusRevoked         DeviceStatus = "REVOKED"
)

// PolicyType represents the category of desired-state policy.
type PolicyType string

const (
	PolicyTypePackageAbsence  PolicyType = "PACKAGE_ABSENCE"
	PolicyTypePackagePresence PolicyType = "PACKAGE_PRESENCE"
	PolicyTypeDconfSetting    PolicyType = "DCONF_SETTING"
	PolicyTypeSystemdService  PolicyType = "SYSTEMD_SERVICE"
)

// ComplianceStatus represents the enforcement status of a policy on a device.
type ComplianceStatus string

const (
	CompliancePending      ComplianceStatus = "PENDING"
	ComplianceCompliant    ComplianceStatus = "COMPLIANT"
	ComplianceNonCompliant ComplianceStatus = "NON_COMPLIANT"
	ComplianceFailed       ComplianceStatus = "FAILED"
	ComplianceRevoked      ComplianceStatus = "REVOKED"
)

// ReportedState represents the inventory snapshot reported by spired on check-in.
type ReportedState struct {
	Packages      []string  `json:"packages"`
	ActiveSession string    `json:"active_session"`
	CheckedInAt   time.Time `json:"checked_in_at"`
}

// Device represents a managed Debian desktop endpoint in the devices table.
type Device struct {
	ID            string          `db:"id" json:"id"`
	HardwareUUID  string          `db:"hardware_uuid" json:"hardware_uuid"`
	Hostname      string          `db:"hostname" json:"hostname"`
	Status        DeviceStatus    `db:"status" json:"status"`
	Tags          []string        `db:"tags" json:"tags"`
	AuthTokenHash *string         `db:"auth_token_hash" json:"-"`
	ReportedState json.RawMessage `db:"reported_state" json:"reported_state"`
	LastCheckinAt *time.Time      `db:"last_checkin_at" json:"last_checkin_at,omitempty"`
	CreatedAt     time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time       `db:"updated_at" json:"updated_at"`
}

// Policy represents a declarative desired-state policy in the policies table.
type Policy struct {
	ID          string          `db:"id" json:"id"`
	Name        string          `db:"name" json:"name"`
	Description string          `db:"description" json:"description"`
	PolicyType  PolicyType      `db:"policy_type" json:"policy_type"`
	Payload     json.RawMessage `db:"payload" json:"payload"`
	TargetTags  []string        `db:"target_tags" json:"target_tags"`
	IsActive    bool            `db:"is_active" json:"is_active"`
	Version     int             `db:"version" json:"version"`
	CreatedAt   time.Time       `db:"created_at" json:"created_at"`
	UpdatedAt   time.Time       `db:"updated_at" json:"updated_at"`
}

// DevicePolicy represents the per-device compliance record in device_policies.
type DevicePolicy struct {
	ID               string           `db:"id" json:"id"`
	DeviceID         string           `db:"device_id" json:"device_id"`
	PolicyID         string           `db:"policy_id" json:"policy_id"`
	ComplianceStatus ComplianceStatus `db:"compliance_status" json:"compliance_status"`
	LastEnforcedAt   *time.Time       `db:"last_enforced_at" json:"last_enforced_at,omitempty"`
	ErrorMessage     *string          `db:"error_message" json:"error_message,omitempty"`
	ExecutionOutput  json.RawMessage  `db:"execution_output" json:"execution_output,omitempty"`
}

// DevicePolicyDetail joins a device's policy compliance state with policy metadata for the inspection drawer.
type DevicePolicyDetail struct {
	PolicyID         string           `json:"policy_id"`
	PolicyName       string           `json:"policy_name"`
	PolicyType       PolicyType       `json:"policy_type"`
	TargetTags       []string         `json:"target_tags"`
	ComplianceStatus ComplianceStatus `json:"compliance_status"`
	LastEnforcedAt   *time.Time       `json:"last_enforced_at,omitempty"`
	ErrorMessage     string           `json:"error_message,omitempty"`
	ExecutionOutput  string           `json:"execution_output,omitempty"`
}

// DeviceCommand represents a diagnostic command record in device_commands.
type DeviceCommand struct {
	ID         string     `db:"id" json:"id"`
	DeviceID   string     `db:"device_id" json:"device_id"`
	Command    string     `db:"command" json:"command"`
	Status     string     `db:"status" json:"status"`
	ExitCode   *int       `db:"exit_code" json:"exit_code,omitempty"`
	Stdout     string     `db:"stdout" json:"stdout,omitempty"`
	Stderr     string     `db:"stderr" json:"stderr,omitempty"`
	CreatedAt  time.Time  `db:"created_at" json:"created_at"`
	ExecutedAt *time.Time `db:"executed_at" json:"executed_at,omitempty"`
}

// FleetSummary holds fleet-wide compliance and enrollment analytics for the Web UI header.
type FleetSummary struct {
	TotalDevices        int `json:"total_devices"`
	ApprovedDevices     int `json:"approved_devices"`
	PendingDevices      int `json:"pending_devices"`
	RevokedDevices      int `json:"revoked_devices"`
	NonCompliantDevices int `json:"non_compliant_devices"`
	CompliancePercent   int `json:"compliance_percent"`
}

// ComplianceAuditRecord represents a fleet-wide compliance audit snapshot row for CSV/JSON export.
type ComplianceAuditRecord struct {
	Hostname         string           `json:"hostname"`
	HardwareUUID     string           `json:"hardware_uuid"`
	DeviceStatus     DeviceStatus     `json:"device_status"`
	DeviceTags       []string         `json:"device_tags"`
	PolicyName       string           `json:"policy_name"`
	PolicyType       PolicyType       `json:"policy_type"`
	TargetTags       []string         `json:"target_tags"`
	ComplianceStatus ComplianceStatus `json:"compliance_status"`
	LastEnforcedAt   *time.Time       `json:"last_enforced_at,omitempty"`
	ErrorMessage     string           `json:"error_message,omitempty"`
}

// Declarative Policy Payloads

// PackageAbsencePayload defines the payload for PACKAGE_ABSENCE policies.
type PackageAbsencePayload struct {
	PackageName string `json:"package_name"`
}

// PackagePresencePayload defines the payload for PACKAGE_PRESENCE policies.
type PackagePresencePayload struct {
	PackageName string `json:"package_name"`
}

// DconfSettingPayload defines the payload for DCONF_SETTING policies.
type DconfSettingPayload struct {
	SchemaPath    string            `json:"schema_path"`
	Key           string            `json:"key"`
	Value         string            `json:"value"`
	ExtraSettings map[string]string `json:"extra_settings,omitempty"`
	Locked        bool              `json:"locked"`
}

// SystemdServicePayload defines the payload for SYSTEMD_SERVICE policies.
type SystemdServicePayload struct {
	ServiceName string `json:"service_name"`
	State       string `json:"state"`   // "started" | "stopped"
	Enabled     bool   `json:"enabled"` // true -> systemctl enable, false -> systemctl disable
}

// Ingress REST API DTOs

// EnrollRequest is sent by spired to POST /api/v1/desktop/enroll.
type EnrollRequest struct {
	HardwareUUID string `json:"hardware_uuid"`
	Hostname     string `json:"hostname"`
}

// EnrollResponse is returned by POST /api/v1/desktop/enroll.
type EnrollResponse struct {
	DeviceID string       `json:"device_id"`
	Status   DeviceStatus `json:"status"`
	Token    string       `json:"token,omitempty"`
}

// AssignedPolicy is returned to a device during check-in.
type AssignedPolicy struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	PolicyType PolicyType      `json:"policy_type"`
	Payload    json.RawMessage `json:"payload"`
	Version    int             `json:"version"`
}

// CommandDTO is dispatched to a device in CheckinResponse.
type CommandDTO struct {
	ID      string `json:"id"`
	Command string `json:"command"`
}

// CheckinRequest is sent by spired to POST /api/v1/desktop/checkin.
type CheckinRequest struct {
	HardwareUUID  string   `json:"hardware_uuid"`
	Hostname      string   `json:"hostname"`
	Packages      []string `json:"packages"`
	ActiveSession string   `json:"active_session"`
}

// CheckinResponse is returned by POST /api/v1/desktop/checkin.
type CheckinResponse struct {
	DeviceID        string           `json:"device_id"`
	Status          DeviceStatus     `json:"status"`
	Policies        []AssignedPolicy `json:"policies"`
	RevokedPolicies []AssignedPolicy `json:"revoked_policies,omitempty"`
	QueuedCommands  []CommandDTO     `json:"queued_commands,omitempty"`
}

// PolicyExecutionItem represents a single policy enforcement outcome reported by spired.
type PolicyExecutionItem struct {
	PolicyID         string           `json:"policy_id"`
	ComplianceStatus ComplianceStatus `json:"compliance_status"`
	ErrorMessage     string           `json:"error_message,omitempty"`
	ExecutionOutput  json.RawMessage  `json:"execution_output,omitempty"`
}

// PolicyReportRequest is sent by spired to POST /api/v1/desktop/report.
type PolicyReportRequest struct {
	HardwareUUID string                `json:"hardware_uuid,omitempty"`
	Results      []PolicyExecutionItem `json:"results"`
}

// CommandReportRequest is sent by spired to POST /api/v1/desktop/commands/report.
type CommandReportRequest struct {
	CommandID string `json:"command_id"`
	Status    string `json:"status"`
	ExitCode  int    `json:"exit_code"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
}
