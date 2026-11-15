package alerts

import "time"

// ChannelKind enumerates the supported outbound transports.
type ChannelKind string

const (
	ChannelWebhook ChannelKind = "webhook" // generic HMAC-signed JSON POST
	ChannelSlack   ChannelKind = "slack"   // Slack-compatible incoming webhook
	ChannelEmail   ChannelKind = "email"   // SMTP
)

// EventRoute is one row of a channel's per-event routing table.
type EventRoute struct {
	Kind        EventKind `json:"kind"`
	Enabled     bool      `json:"enabled"`
	MinSeverity Severity  `json:"min_severity"`
}

// WebhookConfig is the non-secret configuration for a generic webhook channel.
// The HMAC secret is held separately as encrypted bytes, never in this struct.
type WebhookConfig struct {
	URL string `json:"url"`
}

// EmailConfig is the non-secret configuration for an SMTP email channel.
// The SMTP password is held separately as encrypted bytes.
type EmailConfig struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	TLSMode  string   `json:"tls_mode"` // "starttls" | "implicit" | "none"
	Username string   `json:"username"`
	From     string   `json:"from"`
	To       []string `json:"to"`
}

// SlackConfig holds no non-secret fields — the webhook URL is itself the secret.
type SlackConfig struct{}

// Channel is a configured outbound channel. Secret material is carried as the
// already-decrypted plaintext ONLY inside the notifier's send path; the DB layer
// passes encrypted bytes. Secret and Secret2 are populated by the DB layer when a
// delivery worker loads a channel for sending, and are otherwise empty.
type Channel struct {
	ID      string
	Name    string
	Kind    ChannelKind
	Enabled bool

	Webhook WebhookConfig
	Email   EmailConfig

	// Secret: generic-webhook HMAC secret, or (for slack) the webhook URL.
	// Secret2: SMTP password (email only). Empty when not loaded for sending.
	Secret  string
	Secret2 string

	// HasSecret / HasSecret2 report whether encrypted secret bytes exist, so the
	// UI can render "set" / "not set" without ever decrypting.
	HasSecret  bool
	HasSecret2 bool

	Routes    []EventRoute
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Delivery is one row of the recent delivery log.
type Delivery struct {
	ID          string
	ChannelName string
	EventKind   string
	Severity    string
	Subject     string
	Status      string
	Attempts    int
	LastError   string
	CreatedAt   time.Time
}

// backoffSchedule returns the delay before the next attempt, given how many
// attempts have already been made (1-based). Exponential with a 1h ceiling:
// 30s, 1m, 2m, 4m, 8m, 16m, ... capped at 3600s.
func backoffSchedule(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	const base = 30 * time.Second
	const ceil = time.Hour
	d := base
	for i := 1; i < attempts; i++ {
		d *= 2
		if d >= ceil {
			return ceil
		}
	}
	if d > ceil {
		d = ceil
	}
	return d
}
