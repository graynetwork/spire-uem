package types

import (
	"encoding/json"
	"time"
)

// GatewayFrameType identifies the duplex WebSocket message type between spire-server and spired.
type GatewayFrameType string

const (
	FrameTypePing                 GatewayFrameType = "TYPE_PING"
	FrameTypePong                 GatewayFrameType = "TYPE_PONG"
	FrameTypeCommandPush          GatewayFrameType = "TYPE_COMMAND_PUSH"
	FrameTypeCommandResult        GatewayFrameType = "TYPE_COMMAND_RESULT"
	FrameTypeTriggerCheckin       GatewayFrameType = "TYPE_TRIGGER_CHECKIN"
	FrameTypePTYStart             GatewayFrameType = "TYPE_PTY_START"
	FrameTypePTYInput             GatewayFrameType = "TYPE_PTY_INPUT"
	FrameTypePTYOutput            GatewayFrameType = "TYPE_PTY_OUTPUT"
	FrameTypePTYResize            GatewayFrameType = "TYPE_PTY_RESIZE"
	FrameTypePTYStop              GatewayFrameType = "TYPE_PTY_STOP"
	FrameTypeRemoteAssistRequest  GatewayFrameType = "TYPE_REMOTE_ASSIST_REQUEST"
	FrameTypeRemoteAssistResponse GatewayFrameType = "TYPE_REMOTE_ASSIST_RESPONSE"
	FrameTypeBenchmarkStart       GatewayFrameType = "TYPE_BENCHMARK_START"
	FrameTypeTriggerPatchRun      GatewayFrameType = "TYPE_TRIGGER_PATCH_RUN"
)

// GatewayFrame is the JSON envelope exchanged over /api/v1/desktop/stream.
type GatewayFrame struct {
	Type      GatewayFrameType `json:"type"`
	DeviceID  string           `json:"device_id,omitempty"`
	Timestamp time.Time        `json:"timestamp"`
	Payload   json.RawMessage  `json:"payload,omitempty"`
}

// CommandPushPayload is the payload inside a TYPE_COMMAND_PUSH frame.
type CommandPushPayload struct {
	ID      string `json:"id"`
	Command string `json:"command"`
}

// CommandResultPayload is the payload inside a TYPE_COMMAND_RESULT frame.
type CommandResultPayload struct {
	CommandID string `json:"command_id"`
	Status    string `json:"status"`
	ExitCode  int    `json:"exit_code"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Final     bool   `json:"final"`
}

// PTYStartPayload initiates an interactive PTY session on spired.
type PTYStartPayload struct {
	SessionID string `json:"session_id"`
	Rows      uint16 `json:"rows"`
	Cols      uint16 `json:"cols"`
}

// PTYDataPayload carries stdin or stdout/stderr bytes for an interactive PTY session.
type PTYDataPayload struct {
	SessionID string `json:"session_id"`
	Data      string `json:"data"`
}

// PTYResizePayload updates the terminal window dimensions of an active PTY session.
type PTYResizePayload struct {
	SessionID string `json:"session_id"`
	Rows      uint16 `json:"rows"`
	Cols      uint16 `json:"cols"`
}

// PTYStopPayload signals termination of an interactive PTY session.
type PTYStopPayload struct {
	SessionID string `json:"session_id"`
	Reason    string `json:"reason,omitempty"`
}

// RemoteAssistRequestPayload requests an attended remote desktop assistance session.
type RemoteAssistRequestPayload struct {
	SessionID  string `json:"session_id"`
	AdminActor string `json:"admin_actor"`
}

// RemoteAssistResponsePayload reports user consent and connection credentials for remote assistance.
type RemoteAssistResponsePayload struct {
	SessionID    string `json:"session_id"`
	Status       string `json:"status"` // APPROVED, REJECTED_BY_USER, FAILED
	Credentials  string `json:"credentials,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// SystemAuditEvent represents a row in system_audit_events and an RFC 5424 SIEM audit record.
type SystemAuditEvent struct {
	ID        string          `db:"id" json:"id"`
	Actor     string          `db:"actor" json:"actor"`
	Action    string          `db:"action" json:"action"`
	TargetID  *string         `db:"target_id" json:"target_id,omitempty"`
	Details   json.RawMessage `db:"details" json:"details"`
	IPAddress string          `db:"ip_address" json:"ip_address"`
	CreatedAt time.Time       `db:"created_at" json:"created_at"`
}

// BenchmarkStartPayload initiates an OpenSCAP benchmark scan on spired.
type BenchmarkStartPayload struct {
	ScanID         string `json:"scan_id"`
	Profile        string `json:"profile"`
	DatastreamPath string `json:"datastream_path,omitempty"`
}
