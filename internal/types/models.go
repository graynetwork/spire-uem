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
	PolicyTypeFlatpakApp      PolicyType = "FLATPAK_APP"
	PolicyFlatpakApp          PolicyType = "FLATPAK_APP"
	PolicyTypeFlatpakBundle   PolicyType = "FLATPAK_BUNDLE"
	PolicyFlatpakBundle       PolicyType = "FLATPAK_BUNDLE"
	PolicyTypeSysctlSetting   PolicyType = "SYSCTL_SETTING"
	PolicyTypeAptConfig       PolicyType = "APT_CONFIG"
)

// DeploymentRing represents the phased patch deployment ring of a device or policy.
type DeploymentRing string

const (
	RingCanary     DeploymentRing = "CANARY"
	RingBeta       DeploymentRing = "BETA"
	RingPilot      DeploymentRing = "PILOT"
	RingProduction DeploymentRing = "PRODUCTION"
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

// ApplicationAssignmentType distinguishes mandatory compliance applications from optional self-service catalog items.
type ApplicationAssignmentType string

const (
	AssignmentRequired  ApplicationAssignmentType = "REQUIRED"
	AssignmentAvailable ApplicationAssignmentType = "AVAILABLE"
)

// ReportedState represents the inventory snapshot reported by spired on check-in.
type ReportedState struct {
	Packages       []string  `json:"packages"`
	Flatpaks       []string  `json:"flatpaks,omitempty"`
	ActiveSession  string    `json:"active_session"`
	RebootRequired bool      `json:"reboot_required"`
	OSName         string    `json:"os_name,omitempty"`
	KernelVersion  string    `json:"kernel_version,omitempty"`
	CheckedInAt    time.Time `json:"checked_in_at"`

	// SourcePackages carries the source-package name/version per installed binary, used
	// for CVE matching against Debian security data. Optional for backward compatibility
	// with older agents that report only Packages.
	SourcePackages  []ReportedPackage `json:"source_packages,omitempty"`
	ReleaseCodename string            `json:"release_codename,omitempty"` // VERSION_CODENAME, e.g. "bookworm"
}

// Device represents a managed Debian desktop endpoint in the devices table.
type Device struct {
	ID                string            `db:"id" json:"id"`
	HardwareUUID      string            `db:"hardware_uuid" json:"hardware_uuid"`
	Hostname          string            `db:"hostname" json:"hostname"`
	Status            DeviceStatus      `db:"status" json:"status"`
	Tags              []string          `db:"tags" json:"tags"`
	PatchRing         DeploymentRing    `db:"patch_ring" json:"patch_ring"`
	RebootRequired    bool              `db:"reboot_required" json:"reboot_required"`
	AuthTokenHash     *string           `db:"auth_token_hash" json:"-"`
	ReportedState     json.RawMessage   `db:"reported_state" json:"reported_state"`
	LastCheckinAt     *time.Time        `db:"last_checkin_at" json:"last_checkin_at,omitempty"`
	HasTPM2           bool              `db:"has_tpm2" json:"has_tpm2"`
	AttestationStatus AttestationStatus `db:"attestation_status" json:"attestation_status"`
	SecureBootEnabled bool              `db:"secure_boot_enabled" json:"secure_boot_enabled"`
	LastAttestedAt    *time.Time        `db:"last_attested_at" json:"last_attested_at,omitempty"`
	WSConnected       bool              `db:"ws_connected" json:"ws_connected"`
	LastWSSeenAt      *time.Time        `db:"last_ws_seen_at" json:"last_ws_seen_at,omitempty"`
	CreatedAt         time.Time         `db:"created_at" json:"created_at"`
	UpdatedAt         time.Time         `db:"updated_at" json:"updated_at"`

	// Patch telemetry fields joined from device_patch_status
	PatchStatus          *DevicePatchStatus `db:"-" json:"patch_status,omitempty"`
	PendingUpdatesCount  int                `db:"pending_updates_count" json:"pending_updates_count"`
	SecurityUpdatesCount int                `db:"security_updates_count" json:"security_updates_count"`
	RebootRequiredPkgs   []string           `db:"reboot_required_pkgs" json:"reboot_required_pkgs,omitempty"`
}

// PendingPkg represents an upgradeable Debian package identified via apt simulation.
type PendingPkg struct {
	Name           string `json:"name"`
	CurrentVersion string `json:"current_version"`
	NewVersion     string `json:"new_version"`
	IsSecurity     bool   `json:"is_security"`
	Repository     string `json:"repository,omitempty"`
}

// DevicePatchStatus tracks pending upgrades, security updates, and reboot status in device_patch_status.
type DevicePatchStatus struct {
	DeviceID             string       `db:"device_id" json:"device_id"`
	RebootRequired       bool         `db:"reboot_required" json:"reboot_required"`
	RebootRequiredPkgs   []string     `db:"reboot_required_pkgs" json:"reboot_required_pkgs"`
	PendingUpdatesCount  int          `db:"pending_updates_count" json:"pending_updates_count"`
	SecurityUpdatesCount int          `db:"security_updates_count" json:"security_updates_count"`
	PendingPackages      []PendingPkg `db:"pending_packages" json:"pending_packages"`
	LastPatchRunAt       *time.Time   `db:"last_patch_run_at" json:"last_patch_run_at,omitempty"`
	LastPatchStatus      string       `db:"last_patch_status" json:"last_patch_status"`
	UpdatedAt            time.Time    `db:"updated_at" json:"updated_at"`
}

// DeviceListItem represents a device with aggregated patch metrics and status for fleet listings.
type DeviceListItem struct {
	Device
	PatchStatus          *DevicePatchStatus `json:"patch_status,omitempty"`
	PendingUpdatesCount  int                `json:"pending_updates_count"`
	SecurityUpdatesCount int                `json:"security_updates_count"`
}

// DeviceDetailResponse contains complete device telemetry, patch status, and compliance.
type DeviceDetailResponse struct {
	Device         Device                `json:"device"`
	PatchStatus    *DevicePatchStatus    `json:"patch_status,omitempty"`
	Policies       []DevicePolicyDetail  `json:"policies,omitempty"`
	Commands       []DeviceCommand       `json:"commands,omitempty"`
	TPMAttestation *DeviceTPMAttestation `json:"tpm_attestation,omitempty"`
	BenchmarkScans []*BenchmarkScan      `json:"benchmark_scans,omitempty"`
}

// PatchWindow represents a scheduled maintenance window in patch_windows.
type PatchWindow struct {
	ID                 string    `db:"id" json:"id"`
	Name               string    `db:"name" json:"name"`
	CronExpression     string    `db:"cron_expression" json:"cron_expression"`
	DurationMinutes    int       `db:"duration_minutes" json:"duration_minutes"`
	AllowReboot        bool      `db:"allow_reboot" json:"allow_reboot"`
	GracePeriodMinutes int       `db:"grace_period_minutes" json:"grace_period_minutes"`
	CreatedAt          time.Time `db:"created_at" json:"created_at"`
}

// Policy represents a declarative desired-state policy in the policies table.
type Policy struct {
	ID             string                    `db:"id" json:"id"`
	Name           string                    `db:"name" json:"name"`
	Description    string                    `db:"description" json:"description"`
	PolicyType     PolicyType                `db:"policy_type" json:"policy_type"`
	Payload        json.RawMessage           `db:"payload" json:"payload"`
	TargetTags     []string                  `db:"target_tags" json:"target_tags"`
	TargetRing     *DeploymentRing           `db:"target_ring" json:"target_ring,omitempty"`
	PatchWindowID  *string                   `db:"patch_window_id" json:"patch_window_id,omitempty"`
	RequiresReboot bool                      `db:"requires_reboot" json:"requires_reboot"`
	IsSelfService  bool                      `db:"is_self_service" json:"is_self_service"`
	AssignmentType ApplicationAssignmentType `db:"assignment_type" json:"assignment_type"`
	IsActive       bool                      `db:"is_active" json:"is_active"`
	Version        int                       `db:"version" json:"version"`
	CreatedAt      time.Time                 `db:"created_at" json:"created_at"`
	UpdatedAt      time.Time                 `db:"updated_at" json:"updated_at"`
}

// SelfServiceCatalogItem represents an optional self-service policy in the catalog.
type SelfServiceCatalogItem struct {
	PolicyID       string                    `json:"policy_id"`
	Name           string                    `json:"name"`
	Description    string                    `json:"description"`
	PolicyType     PolicyType                `json:"policy_type"`
	AssignmentType ApplicationAssignmentType `json:"assignment_type,omitempty"`
	Payload        json.RawMessage           `json:"payload"`
	Installed      bool                      `json:"installed"`
}

// SelfServiceInstallRequest is the payload for POST /api/v1/desktop/self-service/install.
type SelfServiceInstallRequest struct {
	HardwareUUID string `json:"hardware_uuid,omitempty"`
	PolicyID     string `json:"policy_id"`
}

// SelfServiceUninstallRequest is the payload for POST /api/v1/desktop/self-service/uninstall.
type SelfServiceUninstallRequest struct {
	HardwareUUID string `json:"hardware_uuid,omitempty"`
	PolicyID     string `json:"policy_id"`
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
	PolicyID         string                    `json:"policy_id"`
	PolicyName       string                    `json:"policy_name"`
	PolicyType       PolicyType                `json:"policy_type"`
	AssignmentType   ApplicationAssignmentType `json:"assignment_type,omitempty"`
	TargetTags       []string                  `json:"target_tags"`
	ComplianceStatus ComplianceStatus          `json:"compliance_status"`
	LastEnforcedAt   *time.Time                `json:"last_enforced_at,omitempty"`
	ErrorMessage     string                    `json:"error_message,omitempty"`
	ExecutionOutput  string                    `json:"execution_output,omitempty"`
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
	PackageName    string                    `json:"package_name"`
	Version        string                    `json:"version,omitempty"`
	AssignmentType ApplicationAssignmentType `json:"assignment_type,omitempty"`
	AutoInstall    *bool                     `json:"auto_install,omitempty"`
}

// ApplicationPolicyPayload defines the unified payload structure for application policies (FLATPAK_APP / PACKAGE_PRESENCE).
type ApplicationPolicyPayload struct {
	AppID          string                    `json:"app_id,omitempty"`
	PackageName    string                    `json:"package_name,omitempty"`
	State          string                    `json:"state,omitempty"`
	Remote         string                    `json:"remote,omitempty"`
	Version        string                    `json:"version,omitempty"`
	AssignmentType ApplicationAssignmentType `json:"assignment_type,omitempty"`
	AutoInstall    *bool                     `json:"auto_install,omitempty"`
}

// DconfSettingPayload defines the payload for DCONF_SETTING policies.
type DconfSettingPayload struct {
	SchemaPath    string                       `json:"schema_path"`
	Key           string                       `json:"key"`
	Value         string                       `json:"value"`
	ExtraSettings map[string]string            `json:"extra_settings,omitempty"`
	Sections      map[string]map[string]string `json:"sections,omitempty"`
	Locks         []string                     `json:"locks,omitempty"`
	FileName      string                       `json:"file_name,omitempty"`
	Locked        bool                         `json:"locked"`
	AssetURL      string                       `json:"asset_url,omitempty"`
	AssetSHA256   string                       `json:"asset_sha256,omitempty"`
	AssetDestPath string                       `json:"asset_dest_path,omitempty"`
}

// SysctlSettingPayload defines the payload for SYSCTL_SETTING policies.
type SysctlSettingPayload struct {
	Settings map[string]string `json:"settings"`
}

// AptConfigPayload defines the payload for APT_CONFIG policies.
type AptConfigPayload struct {
	FileName string `json:"file_name"`
	Content  string `json:"content"`
}

// SystemdServicePayload defines the payload for SYSTEMD_SERVICE policies.
type SystemdServicePayload struct {
	ServiceName string `json:"service_name"`
	State       string `json:"state"`   // "started" | "stopped"
	Enabled     bool   `json:"enabled"` // true -> systemctl enable, false -> systemctl disable
}

// FlatpakAppPayload defines the payload for FLATPAK_APP policies.
type FlatpakAppPayload struct {
	AppID          string                    `json:"app_id"`
	State          string                    `json:"state"`  // "present" | "absent"
	Remote         string                    `json:"remote"` // default: "flathub"
	Version        string                    `json:"version,omitempty"`
	AssignmentType ApplicationAssignmentType `json:"assignment_type,omitempty"`
	AutoInstall    *bool                     `json:"auto_install,omitempty"`
}

// FlatpakBundlePayload defines the payload for FLATPAK_BUNDLE custom single-file bundle policies.
type FlatpakBundlePayload struct {
	AppID          string                    `json:"app_id"`
	BundleName     string                    `json:"bundle_name"`
	DownloadURL    string                    `json:"download_url"`
	SHA256         string                    `json:"sha256"`
	SizeBytes      int64                     `json:"size_bytes"`
	AssignmentType ApplicationAssignmentType `json:"assignment_type"`
	AutoInstall    bool                      `json:"auto_install"`
}

// CustomBundle represents a stored .flatpak single-file bundle in the custom_bundles table.
type CustomBundle struct {
	ID          string    `db:"id" json:"id"`
	PolicyID    string    `db:"policy_id" json:"policy_id"`
	AppID       string    `db:"app_id" json:"app_id"`
	BundleName  string    `db:"bundle_name" json:"bundle_name"`
	StoragePath string    `db:"storage_path" json:"storage_path"`
	SHA256      string    `db:"sha256" json:"sha256"`
	SizeBytes   int64     `db:"size_bytes" json:"size_bytes"`
	CreatedAt   time.Time `db:"created_at" json:"created_at"`
}

// PolicyStatusItem represents a security or configuration baseline policy compliance item.
type PolicyStatusItem struct {
	PolicyID         string           `json:"policy_id"`
	Name             string           `json:"name"`
	PolicyType       PolicyType       `json:"policy_type"`
	ComplianceStatus ComplianceStatus `json:"compliance_status"`
	IsCompliant      bool             `json:"is_compliant"`
	ErrorMessage     string           `json:"error_message,omitempty"`
}

// AppStatusItem represents a mandatory application policy evaluated for compliance.
type AppStatusItem struct {
	PolicyID         string                    `json:"policy_id"`
	Name             string                    `json:"name"`
	AppID            string                    `json:"app_id,omitempty"`
	Version          string                    `json:"version,omitempty"`
	PolicyType       PolicyType                `json:"policy_type"`
	AssignmentType   ApplicationAssignmentType `json:"assignment_type"`
	Installed        bool                      `json:"installed"`
	IsCompliant      bool                      `json:"is_compliant"`
	ComplianceStatus ComplianceStatus          `json:"compliance_status"`
}

// CatalogAppItem represents an optional self-service catalog item (non-evaluative).
type CatalogAppItem struct {
	PolicyID       string                    `json:"policy_id"`
	Name           string                    `json:"name"`
	Description    string                    `json:"description,omitempty"`
	AppID          string                    `json:"app_id,omitempty"`
	Version        string                    `json:"version,omitempty"`
	PolicyType     PolicyType                `json:"policy_type"`
	AssignmentType ApplicationAssignmentType `json:"assignment_type"`
	Payload        json.RawMessage           `json:"payload,omitempty"`
	Installed      bool                      `json:"installed"`
}

// DeviceStatusResponse partitions compliance data so configuration baselines and software are distinct.
type DeviceStatusResponse struct {
	DeviceID         string             `json:"device_id"`
	IsCompliant      bool               `json:"is_compliant"`
	SecurityPolicies []PolicyStatusItem `json:"security_policies"` // Sysctl, Dconf, APT config, TPM, LUKS
	MandatoryApps    []AppStatusItem    `json:"mandatory_apps"`    // Evaluated for compliance
	AvailableCatalog []CatalogAppItem   `json:"available_catalog"` // Optional self-service items (non-evaluative)
}

// Ingress REST API DTOs

// EnrollRequest is sent by spired to POST /api/v1/desktop/enroll.
type EnrollRequest struct {
	HardwareUUID string `json:"hardware_uuid"`
	Hostname     string `json:"hostname"`
	// EnrollmentKey is a random secret the agent generates once and keeps. The device is
	// bound to it when first staged, and its token is released only to that key.
	EnrollmentKey string `json:"enrollment_key"`
}

// EnrollResponse is returned by POST /api/v1/desktop/enroll.
type EnrollResponse struct {
	DeviceID string       `json:"device_id"`
	Status   DeviceStatus `json:"status"`
	Token    string       `json:"token,omitempty"`
}

// AssignedPolicy is returned to a device during check-in.
type AssignedPolicy struct {
	ID                      string                    `json:"id"`
	Name                    string                    `json:"name"`
	PolicyType              PolicyType                `json:"policy_type"`
	AssignmentType          ApplicationAssignmentType `json:"assignment_type,omitempty"`
	Payload                 json.RawMessage           `json:"payload"`
	TargetRing              *DeploymentRing           `json:"target_ring,omitempty"`
	RequiresReboot          bool                      `json:"requires_reboot,omitempty"`
	WithinMaintenanceWindow bool                      `json:"within_maintenance_window"`
	Version                 int                       `json:"version"`
}

// CommandDTO is dispatched to a device in CheckinResponse.
type CommandDTO struct {
	ID      string `json:"id"`
	Command string `json:"command"`
}

// CheckinRequest is sent by spired to POST /api/v1/desktop/checkin.
type CheckinRequest struct {
	HardwareUUID   string             `json:"hardware_uuid"`
	Hostname       string             `json:"hostname"`
	Packages       []string           `json:"packages"`
	Flatpaks       []string           `json:"flatpaks,omitempty"`
	ActiveSession  string             `json:"active_session"`
	RebootRequired bool               `json:"reboot_required"`
	PatchStatus    *DevicePatchStatus `json:"patch_status,omitempty"`
	OSName         string             `json:"os_name,omitempty"`
	KernelVersion  string             `json:"kernel_version,omitempty"`

	// SourcePackages and ReleaseCodename feed CVE matching; optional for old agents.
	SourcePackages  []ReportedPackage `json:"source_packages,omitempty"`
	ReleaseCodename string            `json:"release_codename,omitempty"`
}

// CheckinResponse is returned by POST /api/v1/desktop/checkin.
type CheckinResponse struct {
	DeviceID                string           `json:"device_id"`
	Status                  DeviceStatus     `json:"status"`
	PatchRing               DeploymentRing   `json:"patch_ring,omitempty"`
	MaintenanceWindowActive bool             `json:"maintenance_window_active"`
	Policies                []AssignedPolicy `json:"policies"`
	RevokedPolicies         []AssignedPolicy `json:"revoked_policies,omitempty"`
	QueuedCommands          []CommandDTO     `json:"queued_commands,omitempty"`
	ServerKEKPublicPEM      string           `json:"server_kek_public_pem,omitempty"`
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

// FailedRuleItem represents a single failed or non-compliant rule in an OpenSCAP evaluation.
type FailedRuleItem struct {
	RuleID      string `json:"rule_id"`
	Title       string `json:"title,omitempty"`
	Result      string `json:"result"`
	Severity    string `json:"severity,omitempty"`
	Description string `json:"description,omitempty"`
}

// BenchmarkScan represents a benchmark scan execution recorded in PostgreSQL.
type BenchmarkScan struct {
	ID            string           `json:"id"`
	DeviceID      string           `json:"device_id"`
	Hostname      string           `json:"hostname,omitempty"`
	BenchmarkType string           `json:"benchmark_type"`
	Profile       string           `json:"profile"`
	Status        string           `json:"status"` // PENDING, RUNNING, COMPLETED, FAILED
	Score         float64          `json:"score"`
	RulesPassed   int              `json:"rules_passed"`
	RulesFailed   int              `json:"rules_failed"`
	RulesOther    int              `json:"rules_other"`
	FailedRules   []FailedRuleItem `json:"failed_rules"`
	ErrorMessage  *string          `json:"error_message,omitempty"`
	StartedAt     *time.Time       `json:"started_at,omitempty"`
	CompletedAt   *time.Time       `json:"completed_at,omitempty"`
	CreatedAt     time.Time        `json:"created_at"`
}

// BenchmarkResultPayload is sent by spired or local workers to report scan execution status and results.
type BenchmarkResultPayload struct {
	ScanID       string           `json:"scan_id"`
	DeviceID     string           `json:"device_id,omitempty"`
	Status       string           `json:"status"` // RUNNING, COMPLETED, FAILED
	Score        float64          `json:"score"`
	RulesPassed  int              `json:"rules_passed"`
	RulesFailed  int              `json:"rules_failed"`
	RulesOther   int              `json:"rules_other"`
	FailedRules  []FailedRuleItem `json:"failed_rules"`
	ErrorMessage string           `json:"error_message,omitempty"`
}

// BenchmarkSummary encapsulates aggregated fleet-wide benchmark metrics for the administrative dashboard.
type BenchmarkSummary struct {
	TotalScans        int              `json:"total_scans"`
	ActiveScansCount  int              `json:"active_scans_count"`
	LatestScore       float64          `json:"latest_score"`
	RulesPassed       int              `json:"rules_passed"`
	RulesFailed       int              `json:"rules_failed"`
	RulesOther        int              `json:"rules_other"`
	LastScanAt        *time.Time       `json:"last_scan_at,omitempty"`
	LastScanRelative  string           `json:"last_scan_relative,omitempty"`
	ActiveScans       []*BenchmarkScan `json:"active_scans,omitempty"`
	LatestFailedRules []FailedRuleItem `json:"latest_failed_rules,omitempty"`
	LatestDeviceID    string           `json:"latest_device_id,omitempty"`
}

// ApplicationListItem represents an application policy (FLATPAK_APP, FLATPAK_BUNDLE, or PACKAGE_PRESENCE) with fleet adoption statistics.
type ApplicationListItem struct {
	ID               string                    `json:"id"`
	Name             string                    `json:"name"`
	Description      string                    `json:"description"`
	PolicyType       PolicyType                `json:"policy_type"`
	PackageTypeLabel string                    `json:"package_type_label"`
	PackageID        string                    `json:"package_id"`
	Version          string                    `json:"version"`
	Remote           string                    `json:"remote,omitempty"`
	BundleName       string                    `json:"bundle_name,omitempty"`
	SHA256           string                    `json:"sha256,omitempty"`
	SizeBytes        int64                     `json:"size_bytes,omitempty"`
	AutoInstall      bool                      `json:"auto_install"`
	AssignmentType   ApplicationAssignmentType `json:"assignment_type"`
	TargetTags       []string                  `json:"target_tags"`
	TargetRing       *DeploymentRing           `json:"target_ring,omitempty"`
	IsActive         bool                      `json:"is_active"`
	InstalledCount   int                       `json:"installed_count"`
	TargetCount      int                       `json:"target_count"`
	AdoptionPercent  int                       `json:"adoption_percent"`
	CreatedAt        time.Time                 `json:"created_at"`
	UpdatedAt        time.Time                 `json:"updated_at"`
}

// ApplicationCatalogStats holds top-level stat ribbon metrics for /admin/applications.
type ApplicationCatalogStats struct {
	TotalApplications    int `json:"total_applications"`
	MandatoryCount       int `json:"mandatory_count"`
	AvailableCount       int `json:"available_count"`
	FleetAdoptionPercent int `json:"fleet_adoption_percent"`
}

// SystemSetting represents a persistent configuration parameter stored in PostgreSQL.
type SystemSetting struct {
	Key         string          `json:"key"`
	Category    string          `json:"category"`
	Value       json.RawMessage `json:"value"`
	Description string          `json:"description"`
	IsSecret    bool            `json:"is_secret"`
	UpdatedAt   time.Time       `json:"updated_at"`
	UpdatedBy   string          `json:"updated_by"`
}

// EnrollmentToken represents a dynamic pre-shared token used to register endpoints.
type EnrollmentToken struct {
	ID          string         `json:"id"`
	TokenHash   string         `json:"token_hash"`
	TokenPrefix string         `json:"token_prefix"`
	Description string         `json:"description"`
	TargetRing  DeploymentRing `json:"target_ring"`
	TargetTags  []string       `json:"target_tags"`
	MaxUses     int            `json:"max_uses"`
	UsesCount   int            `json:"uses_count"`
	ExpiresAt   *time.Time     `json:"expires_at,omitempty"`
	IsRevoked   bool           `json:"is_revoked"`
	CreatedAt   time.Time      `json:"created_at"`
}

// CreateTokenRequest defines the parameters for generating a new enrollment token.
type CreateTokenRequest struct {
	Description    string         `json:"description"`
	TargetRing     DeploymentRing `json:"target_ring"`
	TargetTags     []string       `json:"target_tags"`
	MaxUses        int            `json:"max_uses"`
	ExpiresInHours int            `json:"expires_in_hours"`
}

// EnrollmentRegisterRequest is submitted by an endpoint to POST /api/v1/enrollment/register.
type EnrollmentRegisterRequest struct {
	Token        string   `json:"token"`
	HardwareUUID string   `json:"hardware_uuid"`
	Hostname     string   `json:"hostname"`
	Tags         []string `json:"tags,omitempty"`
}

// EnrollmentRegisterResponse is returned on successful registration.
type EnrollmentRegisterResponse struct {
	DeviceID      string         `json:"device_id"`
	Status        DeviceStatus   `json:"status"`
	PatchRing     DeploymentRing `json:"patch_ring"`
	AuthToken     string         `json:"auth_token,omitempty"`
	ServerBaseURL string         `json:"server_base_url,omitempty"`
}

// GeneralSettings encapsulates basic control plane operational parameters.
type GeneralSettings struct {
	ServerBaseURL     string `json:"server_base_url"`
	AgentSyncInterval int    `json:"agent_sync_interval"`
}

// StorageSettings encapsulates Flatpak bundle and wallpaper storage limits.
type StorageSettings struct {
	MaxBundleSizeMB int `json:"max_bundle_size_mb"`
}

// CryptoSettings encapsulates TPM and LUKS cryptographic baselines.
type CryptoSettings struct {
	TPMEnforceSecureBoot bool `json:"tpm_enforce_secure_boot"`
	LUKSRequireTicket    bool `json:"luks_require_ticket"`
}

// ComplianceSettings encapsulates desired-state auto-remediation behaviors.
type ComplianceSettings struct {
	AutoRemediateDrift bool `json:"auto_remediate_drift"`
}

// SIEMSettings encapsulates external RFC 5424 syslog log forwarding.
type SIEMSettings struct {
	SyslogEnabled bool   `json:"syslog_enabled"`
	SyslogServer  string `json:"syslog_server,omitempty"`
	SyslogProto   string `json:"syslog_proto,omitempty"` // "udp", "tcp", "tls"
	RetentionDays int    `json:"retention_days"`
}

// AdminRole defines the role-based access level for administrative control plane users.
type AdminRole string

const (
	RoleSuperAdmin    AdminRole = "SUPER_ADMIN"
	RoleSecurityAdmin AdminRole = "SECURITY_ADMIN"
	RoleOperator      AdminRole = "OPERATOR"
	RoleAuditor       AdminRole = "AUDITOR"
)

// AuthProviderType defines whether an administrative account is local or federated via OIDC.
type AuthProviderType string

const (
	AuthProviderLocal AuthProviderType = "LOCAL"
	AuthProviderOIDC  AuthProviderType = "OIDC"
)

// AdminUser represents an administrative user stored in PostgreSQL.
type AdminUser struct {
	ID           string           `json:"id" db:"id"`
	Username     string           `json:"username" db:"username"`
	Email        string           `json:"email" db:"email"`
	DisplayName  string           `json:"display_name" db:"display_name"`
	PasswordHash string           `json:"-" db:"password_hash"`
	Role         AdminRole        `json:"role" db:"role"`
	AuthProvider AuthProviderType `json:"auth_provider" db:"auth_provider"`
	OIDCSubject  *string          `json:"oidc_subject,omitempty" db:"oidc_subject"`
	IsActive     bool             `json:"is_active" db:"is_active"`
	CreatedAt    time.Time        `json:"created_at" db:"created_at"`
	LastLoginAt  *time.Time       `json:"last_login_at,omitempty" db:"last_login_at"`
}

// OIDCGroupMapping maps an Identity Provider group claim to an administrative SpireUEM role.
type OIDCGroupMapping struct {
	ID           string    `json:"id" db:"id"`
	IDPGroupName string    `json:"idp_group_name" db:"idp_group_name"`
	MappedRole   AdminRole `json:"mapped_role" db:"mapped_role"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

// SSOSettings encapsulates OpenID Connect (OIDC) Single Sign-On configuration.
type SSOSettings struct {
	OIDCEnabled     bool   `json:"oidc_enabled"`
	IssuerURL       string `json:"issuer_url"`
	ClientID        string `json:"client_id"`
	ClientSecret    string `json:"client_secret"`
	Scopes          string `json:"scopes"`
	GroupsClaim     string `json:"groups_claim"`
	AllowLocalLogin bool   `json:"allow_local_login"`
}

// CreateUserRequest defines payload to create a new local admin user.
type CreateUserRequest struct {
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Password    string    `json:"password"`
	Role        AdminRole `json:"role"`
}

// UpdateUserRequest defines payload to update an existing admin user.
type UpdateUserRequest struct {
	DisplayName *string    `json:"display_name,omitempty"`
	Role        *AdminRole `json:"role,omitempty"`
	IsActive    *bool      `json:"is_active,omitempty"`
	Password    *string    `json:"password,omitempty"`
}


