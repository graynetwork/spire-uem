package types

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Reusable scripts, custom sensors, and the SCRIPT_POLICY policy type.
//
// A Script is a named, versioned program run on endpoints as root (or as the active seat
// user). Versions are immutable: editing content creates a new version with its own sha256.
// Sensors run a script version on a schedule and store the trimmed, typed result as a device
// attribute. SCRIPT_POLICY is a desired-state policy whose detect/remediate/remove steps are
// script versions.

// ScriptInterpreter is the fixed allowlist of interpreters a script may run under. The agent
// maps each to an absolute binary path and refuses anything else; the name is never used to
// build a shell command.
type ScriptInterpreter string

const (
	InterpreterBash    ScriptInterpreter = "bash"
	InterpreterPython3 ScriptInterpreter = "python3"
)

// InterpreterPath returns the fixed absolute binary for an interpreter, and whether it is
// allowed. The map is the single source of truth for the allowlist on the agent.
func InterpreterPath(i ScriptInterpreter) (string, bool) {
	switch i {
	case InterpreterBash:
		return "/bin/bash", true
	case InterpreterPython3:
		return "/usr/bin/python3", true
	default:
		return "", false
	}
}

// ValidInterpreter reports whether i is in the allowlist.
func ValidInterpreter(i ScriptInterpreter) bool {
	_, ok := InterpreterPath(i)
	return ok
}

// ScriptRunAs selects the identity a script runs under on the endpoint.
type ScriptRunAs string

const (
	RunAsRoot       ScriptRunAs = "root"        // run directly as root (spired's own uid)
	RunAsActiveUser ScriptRunAs = "active_user" // runuser to the seat0 graphical user
)

// ValidRunAs reports whether r is a known run-as identity.
func ValidRunAs(r ScriptRunAs) bool {
	return r == RunAsRoot || r == RunAsActiveUser
}

// Script limits and defaults.
const (
	ScriptDefaultTimeoutSeconds = 300
	ScriptMaxTimeoutSeconds     = 3600
	ScriptDefaultMaxOutputBytes = 64 * 1024
	ScriptMaxOutputBytesCeiling = 1024 * 1024
	MaxScriptContentBytes       = 256 * 1024 // 256 KiB of source
	MaxScriptParameters         = 32
)

// ScriptParamType is the declared type of a script parameter value.
type ScriptParamType string

const (
	ScriptParamString  ScriptParamType = "string"
	ScriptParamInteger ScriptParamType = "integer"
	ScriptParamBoolean ScriptParamType = "boolean"
)

var (
	scriptNameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$`)
	scriptParamRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,31}$`)
	sensorNameRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,47}$`)
)

// ValidScriptParamName reports whether name matches ^[A-Z][A-Z0-9_]{0,31}$.
func ValidScriptParamName(name string) bool { return scriptParamRe.MatchString(name) }

// ValidSensorName reports whether name matches ^[a-z][a-z0-9_]{0,47}$.
func ValidSensorName(name string) bool { return sensorNameRe.MatchString(name) }

// ScriptParam declares one parameter of a script version.
type ScriptParam struct {
	Name     string          `json:"name"`
	Type     ScriptParamType `json:"type"`
	Required bool            `json:"required"`
	Default  string          `json:"default,omitempty"`
	Secret   bool            `json:"secret"`
	Help     string          `json:"help,omitempty"`
	// DefaultSet is set only on API responses, where a secret parameter's Default is
	// redacted: it tells the reader a default exists without revealing it. Never stored.
	DefaultSet bool `json:"default_set,omitempty"`
}

// RedactSecretDefaults returns a copy of params with every secret parameter's default
// removed (DefaultSet marks that one exists). Use it on anything sent to an API client.
func RedactSecretDefaults(params []ScriptParam) []ScriptParam {
	if params == nil {
		return nil
	}
	out := make([]ScriptParam, len(params))
	for i, p := range params {
		p.DefaultSet = false
		if p.Secret && p.Default != "" {
			p.Default = ""
			p.DefaultSet = true
		}
		out[i] = p
	}
	return out
}

// Validate checks the parameter declaration itself (not a supplied value).
func (p ScriptParam) Validate() error {
	if !ValidScriptParamName(p.Name) {
		return fmt.Errorf("invalid parameter name %q (must match ^[A-Z][A-Z0-9_]{0,31}$)", p.Name)
	}
	switch p.Type {
	case ScriptParamString, ScriptParamInteger, ScriptParamBoolean:
	default:
		return fmt.Errorf("parameter %s: unknown type %q", p.Name, p.Type)
	}
	if p.Default != "" {
		if err := validateParamValue(p.Type, p.Default); err != nil {
			return fmt.Errorf("parameter %s default: %w", p.Name, err)
		}
	}
	if len(p.Help) > 512 {
		return fmt.Errorf("parameter %s help text too long", p.Name)
	}
	return nil
}

// validateParamValue checks a concrete value string against a declared type. The value is
// always carried as a string; for integer/boolean we confirm it parses so a bad value is
// rejected at the server, never shipped to an endpoint.
func validateParamValue(t ScriptParamType, v string) error {
	switch t {
	case ScriptParamString:
		if len(v) > 4096 {
			return fmt.Errorf("string value exceeds 4096 bytes")
		}
		return nil
	case ScriptParamInteger:
		if _, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err != nil {
			return fmt.Errorf("not an integer: %q", v)
		}
		return nil
	case ScriptParamBoolean:
		switch strings.TrimSpace(v) {
		case "true", "false":
			return nil
		default:
			return fmt.Errorf("boolean must be \"true\" or \"false\", got %q", v)
		}
	default:
		return fmt.Errorf("unknown parameter type %q", t)
	}
}

// NormalizeBool canonicalizes a boolean parameter value to "true"/"false".
func NormalizeBool(v string) string {
	if strings.TrimSpace(v) == "true" {
		return "true"
	}
	return "false"
}

// ValidateScriptParamValue is the exported form of validateParamValue for callers outside the
// types package (the db layer validating supplied run values against a declared type).
func ValidateScriptParamValue(t ScriptParamType, v string) error {
	return validateParamValue(t, v)
}

// Script is a named, versioned program. The current version is the one dispatched.
type Script struct {
	ID               string      `db:"id" json:"id"`
	Name             string      `db:"name" json:"name"`
	Description      string      `db:"description" json:"description"`
	Interpreter      ScriptInterpreter `db:"interpreter" json:"interpreter"`
	RunAs            ScriptRunAs `db:"run_as" json:"run_as"`
	TimeoutSeconds   int         `db:"timeout_seconds" json:"timeout_seconds"`
	MaxOutputBytes   int         `db:"max_output_bytes" json:"max_output_bytes"`
	CurrentVersionID *string     `db:"current_version_id" json:"current_version_id,omitempty"`
	CreatedBy        string      `db:"created_by" json:"created_by"`
	CreatedAt        time.Time   `db:"created_at" json:"created_at"`
	UpdatedAt        time.Time   `db:"updated_at" json:"updated_at"`

	// CurrentVersion is populated on reads that join the current version.
	CurrentVersion *ScriptVersion `db:"-" json:"current_version,omitempty"`
}

// ValidateMeta checks the script's mutable metadata (not content or params).
func (s *Script) ValidateMeta() error {
	if !scriptNameRe.MatchString(strings.TrimSpace(s.Name)) {
		return fmt.Errorf("invalid script name %q", s.Name)
	}
	if !ValidInterpreter(s.Interpreter) {
		return fmt.Errorf("interpreter %q is not allowed", s.Interpreter)
	}
	if !ValidRunAs(s.RunAs) {
		return fmt.Errorf("invalid run_as %q", s.RunAs)
	}
	if len(s.Description) > 2048 {
		return fmt.Errorf("description too long")
	}
	return nil
}

// NormalizeLimits clamps timeout and output to their legal ranges, applying defaults for zero.
func (s *Script) NormalizeLimits() {
	if s.TimeoutSeconds <= 0 {
		s.TimeoutSeconds = ScriptDefaultTimeoutSeconds
	}
	if s.TimeoutSeconds > ScriptMaxTimeoutSeconds {
		s.TimeoutSeconds = ScriptMaxTimeoutSeconds
	}
	if s.MaxOutputBytes <= 0 {
		s.MaxOutputBytes = ScriptDefaultMaxOutputBytes
	}
	if s.MaxOutputBytes > ScriptMaxOutputBytesCeiling {
		s.MaxOutputBytes = ScriptMaxOutputBytesCeiling
	}
}

// ScriptVersion is an immutable snapshot of a script's content and parameter schema.
type ScriptVersion struct {
	ID         string        `db:"id" json:"id"`
	ScriptID   string        `db:"script_id" json:"script_id"`
	Version    int           `db:"version" json:"version"`
	Content    string        `db:"content" json:"content"`
	SHA256     string        `db:"sha256" json:"sha256"`
	Params     []ScriptParam `db:"-" json:"params"`
	ParamsJSON json.RawMessage `db:"params" json:"-"`
	CreatedBy  string        `db:"created_by" json:"created_by"`
	CreatedAt  time.Time     `db:"created_at" json:"created_at"`
}

// ComputeScriptSHA256 returns the lowercase hex sha256 of script content. This is the exact
// value the agent recomputes and compares before running, so both sides hash the raw bytes.
func ComputeScriptSHA256(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// ParamByName finds a declared parameter, case-sensitively.
func (v *ScriptVersion) ParamByName(name string) (ScriptParam, bool) {
	for _, p := range v.Params {
		if p.Name == name {
			return p, true
		}
	}
	return ScriptParam{}, false
}

// ScriptRunStatus is the lifecycle status of one per-device script run.
type ScriptRunStatus string

const (
	ScriptRunQueued      ScriptRunStatus = "QUEUED"
	ScriptRunRunning     ScriptRunStatus = "RUNNING"
	ScriptRunCompleted   ScriptRunStatus = "COMPLETED"
	ScriptRunFailed      ScriptRunStatus = "FAILED"
	ScriptRunTimedOut    ScriptRunStatus = "TIMED_OUT"
	ScriptRunInterrupted ScriptRunStatus = "INTERRUPTED"
)

// ScriptRunTrigger records why a run was created.
type ScriptRunTrigger string

const (
	TriggerOnDemand   ScriptRunTrigger = "on_demand"
	TriggerScheduled  ScriptRunTrigger = "scheduled"
	TriggerAgentStart ScriptRunTrigger = "agent_start"
)

// ScriptRun is one execution of a script version on one device.
type ScriptRun struct {
	ID              string          `db:"id" json:"id"`
	DeviceID        string          `db:"device_id" json:"device_id"`
	ScriptID        string          `db:"script_id" json:"script_id"`
	ScriptVersionID string          `db:"script_version_id" json:"script_version_id"`
	Version         int             `db:"version" json:"version"`
	Trigger         ScriptRunTrigger `db:"trigger" json:"trigger"`
	Status          ScriptRunStatus `db:"status" json:"status"`
	ExitCode        *int            `db:"exit_code" json:"exit_code,omitempty"`
	Stdout          string          `db:"stdout" json:"stdout,omitempty"`
	Stderr          string          `db:"stderr" json:"stderr,omitempty"`
	DurationMS      int64           `db:"duration_ms" json:"duration_ms"`
	// Params carries NON-secret parameter values bound for this run. Secret values are stored
	// sealed in script_run_secrets, never here, and are opened only when the directive is built.
	ParamsJSON json.RawMessage `db:"params" json:"params,omitempty"`
	RequestedBy string          `db:"requested_by" json:"requested_by"`
	CreatedAt   time.Time       `db:"created_at" json:"created_at"`
	ReportedAt  *time.Time      `db:"reported_at" json:"reported_at,omitempty"`
}

// ScriptDirective is the on-the-wire instruction the server sends a device to run a script.
// Secret parameter values are already opened (plaintext) here; this travels only over the
// deployment's TLS link to the one target device and is never persisted in this form.
type ScriptDirective struct {
	RunID       string            `json:"run_id"`
	ScriptID    string            `json:"script_id"`
	VersionID   string            `json:"version_id"`
	Version     int               `json:"version"`
	Interpreter ScriptInterpreter `json:"interpreter"`
	RunAs       ScriptRunAs       `json:"run_as"`
	Content     string            `json:"content"`
	SHA256      string            `json:"sha256"`
	TimeoutSecs int               `json:"timeout_secs"`
	MaxOutput   int               `json:"max_output_bytes"`
	// Params maps SPIRE_PARAM_<NAME> name (without prefix) to its value; both secret and
	// non-secret parameters are present, already resolved.
	Params map[string]string `json:"params,omitempty"`
}

// ScriptRunReport is sent by spired to POST /api/v1/desktop/scripts/report.
type ScriptRunReport struct {
	HardwareUUID string              `json:"hardware_uuid,omitempty"`
	Runs         []ScriptRunResult   `json:"runs"`
}

// ScriptRunResult is one run's outcome reported by the agent.
type ScriptRunResult struct {
	RunID      string          `json:"run_id"`
	Status     ScriptRunStatus `json:"status"`
	ExitCode   int             `json:"exit_code"`
	Stdout     string          `json:"stdout"`
	Stderr     string          `json:"stderr"`
	DurationMS int64           `json:"duration_ms"`
}

// ----- Sensors -----

// SensorReturnType mirrors AttributeType for a sensor's parsed value.
type SensorReturnType string

const (
	SensorString   SensorReturnType = "string"
	SensorInteger  SensorReturnType = "integer"
	SensorBoolean  SensorReturnType = "boolean"
	SensorDatetime SensorReturnType = "datetime"
	SensorJSON     SensorReturnType = "json"
)

// AttributeTypeFor maps a sensor return type to the attribute store's type.
func (t SensorReturnType) AttributeTypeFor() (AttributeType, bool) {
	switch t {
	case SensorString:
		return AttrString, true
	case SensorInteger:
		return AttrInteger, true
	case SensorBoolean:
		return AttrBoolean, true
	case SensorDatetime:
		return AttrDatetime, true
	case SensorJSON:
		return AttrJSON, true
	default:
		return "", false
	}
}

// SensorMinIntervalSeconds is the minimum sensor interval (15 minutes).
const SensorMinIntervalSeconds = 15 * 60

// SensorSHByDevice cap on retained sensor result history rows per device+sensor.
const SensorResultHistoryPerDevice = 50

// Sensor runs a script version on a schedule and records its typed result as an attribute.
type Sensor struct {
	ID              string           `db:"id" json:"id"`
	Name            string           `db:"name" json:"name"`
	Description     string           `db:"description" json:"description"`
	ScriptID        string           `db:"script_id" json:"script_id"`
	ScriptVersionID string           `db:"script_version_id" json:"script_version_id"`
	ReturnType      SensorReturnType `db:"return_type" json:"return_type"`
	IntervalSeconds int              `db:"interval_seconds" json:"interval_seconds"`
	TargetTags      []string         `db:"target_tags" json:"target_tags"`
	TargetRing      *DeploymentRing  `db:"target_ring" json:"target_ring,omitempty"`
	Enabled         bool             `db:"enabled" json:"enabled"`
	CreatedBy       string           `db:"created_by" json:"created_by"`
	CreatedAt       time.Time        `db:"created_at" json:"created_at"`
	UpdatedAt       time.Time        `db:"updated_at" json:"updated_at"`
}

// Validate checks the sensor's name, return type, and interval floor.
func (s *Sensor) Validate() error {
	if !ValidSensorName(s.Name) {
		return fmt.Errorf("invalid sensor name %q (must match ^[a-z][a-z0-9_]{0,47}$)", s.Name)
	}
	if _, ok := s.ReturnType.AttributeTypeFor(); !ok {
		return fmt.Errorf("invalid sensor return type %q", s.ReturnType)
	}
	if s.IntervalSeconds < SensorMinIntervalSeconds {
		return fmt.Errorf("sensor interval %ds is below the minimum of %ds (15 minutes)", s.IntervalSeconds, SensorMinIntervalSeconds)
	}
	if strings.TrimSpace(s.ScriptVersionID) == "" {
		return fmt.Errorf("sensor must reference a script version")
	}
	return nil
}

// SensorDirective instructs a device to run one sensor's script and report a typed value.
type SensorDirective struct {
	SensorName  string            `json:"sensor_name"`
	ReturnType  SensorReturnType  `json:"return_type"`
	VersionID   string            `json:"version_id"`
	Version     int               `json:"version"`
	Interpreter ScriptInterpreter `json:"interpreter"`
	RunAs       ScriptRunAs       `json:"run_as"`
	Content     string            `json:"content"`
	SHA256      string            `json:"sha256"`
	TimeoutSecs int               `json:"timeout_secs"`
	MaxOutput   int               `json:"max_output_bytes"`
	// IntervalSecs lets the agent decide locally whether a sensor is due again, though the
	// server also only dispatches due sensors.
	IntervalSecs int `json:"interval_secs"`
}

// SensorReport is sent by spired to POST /api/v1/desktop/sensors/report.
type SensorReport struct {
	HardwareUUID string               `json:"hardware_uuid,omitempty"`
	Results      []SensorResultReport `json:"results"`
}

// SensorResultReport is one sensor's reading reported by the agent. RawValue is the trimmed
// stdout; the server parses it to the declared type. A non-zero exit or parse failure is
// signalled with Error set and the value left for the server to drop.
type SensorResultReport struct {
	SensorName string `json:"sensor_name"`
	ExitCode   int    `json:"exit_code"`
	RawValue   string `json:"raw_value"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

// SensorResult is a stored historical reading for a device+sensor.
type SensorResult struct {
	ID         string          `db:"id" json:"id"`
	DeviceID   string          `db:"device_id" json:"device_id"`
	SensorName string          `db:"sensor_name" json:"sensor_name"`
	OK         bool            `db:"ok" json:"ok"`
	Value      json.RawMessage `db:"value" json:"value,omitempty"`
	ErrorMsg   string          `db:"error_msg" json:"error_msg,omitempty"`
	ExitCode   int             `db:"exit_code" json:"exit_code"`
	CreatedAt  time.Time       `db:"created_at" json:"created_at"`
}

// ParseSensorValue parses trimmed stdout into a typed DeviceAttribute for sensor.<name>.
// It fails (so the caller keeps the last good value) on a type mismatch.
func ParseSensorValue(sensorName string, t SensorReturnType, raw string) (DeviceAttribute, error) {
	key := AttrKeySensorPrefix + sensorName
	raw = strings.TrimSpace(raw)
	switch t {
	case SensorString:
		if len(raw) > MaxAttributeValue-2 {
			raw = raw[:MaxAttributeValue-2]
		}
		return StringAttr(key, raw), nil
	case SensorInteger:
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return DeviceAttribute{}, fmt.Errorf("sensor %s: %q is not an integer", sensorName, raw)
		}
		return IntAttr(key, n), nil
	case SensorBoolean:
		switch strings.ToLower(raw) {
		case "true", "1", "yes", "on":
			return BoolAttr(key, true), nil
		case "false", "0", "no", "off", "":
			return BoolAttr(key, false), nil
		default:
			return DeviceAttribute{}, fmt.Errorf("sensor %s: %q is not a boolean", sensorName, raw)
		}
	case SensorDatetime:
		ts, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return DeviceAttribute{}, fmt.Errorf("sensor %s: %q is not RFC3339", sensorName, raw)
		}
		return TimeAttr(key, ts), nil
	case SensorJSON:
		if !json.Valid([]byte(raw)) {
			return DeviceAttribute{}, fmt.Errorf("sensor %s: output is not valid JSON", sensorName)
		}
		if len(raw) > MaxAttributeValue {
			return DeviceAttribute{}, fmt.Errorf("sensor %s: JSON value exceeds %d bytes", sensorName, MaxAttributeValue)
		}
		return DeviceAttribute{Key: key, Type: AttrJSON, Value: json.RawMessage(raw)}, nil
	default:
		return DeviceAttribute{}, fmt.Errorf("sensor %s: unknown return type %q", sensorName, t)
	}
}

// ----- SCRIPT_POLICY -----

// PolicyTypeScriptPolicy is the script-based desired-state policy type.
const PolicyTypeScriptPolicy PolicyType = "SCRIPT_POLICY"

// ScriptPolicyPayload references the script versions that implement a SCRIPT_POLICY. detect
// (exit 0 == compliant), remediate, and an optional remove run on unassignment. Each step is
// a pinned script version id so a policy's behaviour does not shift when a script is edited.
type ScriptPolicyPayload struct {
	DetectVersionID    string            `json:"detect_version_id"`
	RemediateVersionID string            `json:"remediate_version_id,omitempty"`
	RemoveVersionID    string            `json:"remove_version_id,omitempty"`
	// Params are non-secret parameter values applied to every step, keyed by SPIRE_PARAM name.
	Params map[string]string `json:"params,omitempty"`
}

// ScriptPolicyStep is one resolved step shipped inside an AssignedPolicy of type SCRIPT_POLICY.
type ScriptPolicyStep struct {
	VersionID   string            `json:"version_id"`
	Version     int               `json:"version"`
	Interpreter ScriptInterpreter `json:"interpreter"`
	RunAs       ScriptRunAs       `json:"run_as"`
	Content     string            `json:"content"`
	SHA256      string            `json:"sha256"`
	TimeoutSecs int               `json:"timeout_secs"`
	MaxOutput   int               `json:"max_output_bytes"`
}

// ScriptPolicyDirective is the resolved payload the server places in an AssignedPolicy.Payload
// for a SCRIPT_POLICY. A nil step (e.g. Remediate) means that step is not configured. If a
// referenced version was deleted, Missing is set and the agent reports FAILED without acting.
type ScriptPolicyDirective struct {
	Detect    *ScriptPolicyStep `json:"detect,omitempty"`
	Remediate *ScriptPolicyStep `json:"remediate,omitempty"`
	Remove    *ScriptPolicyStep `json:"remove,omitempty"`
	Params    map[string]string `json:"params,omitempty"`
	Missing   string            `json:"missing,omitempty"`
}
