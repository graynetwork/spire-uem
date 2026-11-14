package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// outboundTimeout bounds every outbound alert request (dial + TLS + round trip).
const outboundTimeout = 10 * time.Second

// errRedirectBlocked is returned by the HTTP client's CheckRedirect to refuse
// redirects outright — a 3xx to another host would defeat the SSRF posture
// applied to the originally-configured URL.
var errRedirectBlocked = errors.New("alerts: HTTP redirects are not permitted")

// httpClient builds an http.Client that never follows redirects and times out.
func httpClient() *http.Client {
	return &http.Client{
		Timeout: outboundTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirectBlocked
		},
	}
}

// validateOutboundURL enforces that a webhook/Slack URL is a well-formed http(s)
// URL with a host. It deliberately does NOT block private/internal addresses:
// an on-prem UEM legitimately needs to reach internal collectors, so the SSRF
// risk is mitigated by gating who may SET these URLs (SUPER_ADMIN only) rather
// than by blocking the destination. Non-http(s) schemes are always refused.
func validateOutboundURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported url scheme %q: only http and https are allowed", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("url has no host")
	}
	return u, nil
}

// SignWebhookBody computes the hex-encoded HMAC-SHA256 of timestamp + "." + body
// using the channel secret. Binding the timestamp into the signed string lets a
// receiver reject replays without a separate trust decision.
func SignWebhookBody(secret string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.", timestamp)
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// webhookEnvelope is the JSON body POSTed to a generic webhook channel.
type webhookEnvelope struct {
	Kind      string         `json:"kind"`
	Severity  string         `json:"severity"`
	Subject   string         `json:"subject"`
	DeviceID  string         `json:"device_id,omitempty"`
	Hostname  string         `json:"hostname,omitempty"`
	Details   map[string]any `json:"details,omitempty"`
	Timestamp string         `json:"timestamp"`
}

// Header names for the generic webhook signature scheme.
const (
	HeaderSignature = "X-Spire-Signature" // "sha256=<hex>"
	HeaderTimestamp = "X-Spire-Timestamp" // unix seconds, also bound into the HMAC
	HeaderEvent     = "X-Spire-Event"     // event kind, convenience only
)

// sendWebhook delivers a signed JSON POST to a generic webhook channel.
func sendWebhook(ctx context.Context, ch *Channel, ev Event) error {
	if _, err := validateOutboundURL(ch.Webhook.URL); err != nil {
		return err
	}
	env := webhookEnvelope{
		Kind:      string(ev.Kind),
		Severity:  string(ev.Severity),
		Subject:   ev.Subject,
		DeviceID:  ev.DeviceID,
		Hostname:  ev.Hostname,
		Details:   ev.Details,
		Timestamp: ev.Timestamp.UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal webhook body: %w", err)
	}

	ts := ev.Timestamp.UTC().Unix()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ch.Webhook.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "spire-uem-alerts/1")
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderEvent, string(ev.Kind))
	if ch.Secret != "" {
		req.Header.Set(HeaderSignature, "sha256="+SignWebhookBody(ch.Secret, ts, body))
	}

	resp, err := httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("deliver webhook: %w", unwrapRedirect(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// slackMessage is the minimal Slack incoming-webhook payload.
type slackMessage struct {
	Text string `json:"text"`
}

// sendSlack posts a text message to a Slack-compatible incoming webhook. The URL
// is the channel secret (ch.Secret).
func sendSlack(ctx context.Context, ch *Channel, ev Event) error {
	if _, err := validateOutboundURL(ch.Secret); err != nil {
		return fmt.Errorf("slack webhook url: %w", err)
	}
	text := fmt.Sprintf("*[%s] %s*\n%s", ev.Severity, ev.Kind.Label(), ev.Subject)
	if ev.Hostname != "" {
		text += "\nhost: " + ev.Hostname
	}
	body, err := json.Marshal(slackMessage{Text: text})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ch.Secret, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "spire-uem-alerts/1")

	resp, err := httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("deliver slack: %w", unwrapRedirect(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// unwrapRedirect converts the sentinel redirect error (wrapped by net/http in a
// *url.Error) into a stable message.
func unwrapRedirect(err error) error {
	if errors.Is(err, errRedirectBlocked) {
		return errRedirectBlocked
	}
	return err
}

// BuildEmailMessage renders the RFC 5322 message bytes for an alert email.
// Exported for tests.
func BuildEmailMessage(cfg EmailConfig, ev Event) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", cfg.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(cfg.To, ", "))
	fmt.Fprintf(&b, "Subject: [SpireUEM][%s] %s\r\n", ev.Severity, firstLine(ev.Subject))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "Event: %s\r\n", ev.Kind.Label())
	fmt.Fprintf(&b, "Severity: %s\r\n", ev.Severity)
	fmt.Fprintf(&b, "Time: %s\r\n", ev.Timestamp.UTC().Format(time.RFC3339))
	if ev.Hostname != "" {
		fmt.Fprintf(&b, "Host: %s\r\n", ev.Hostname)
	}
	if ev.DeviceID != "" {
		fmt.Fprintf(&b, "Device: %s\r\n", ev.DeviceID)
	}
	b.WriteString("\r\n")
	b.WriteString(ev.Subject)
	b.WriteString("\r\n")
	return []byte(b.String())
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// smtpDialer is overridable in tests to avoid real network connections.
var smtpDialer = net.DialTimeout

// sendEmail delivers an alert over SMTP, supporting STARTTLS, implicit TLS, and
// plaintext (test-only). A username enables PLAIN auth. The SMTP password is in
// ch.Secret2.
func sendEmail(ctx context.Context, ch *Channel, ev Event) error {
	cfg := ch.Email
	if strings.TrimSpace(cfg.Host) == "" || cfg.Port == 0 {
		return errors.New("smtp host and port are required")
	}
	if cfg.From == "" || len(cfg.To) == 0 {
		return errors.New("smtp from and at least one recipient are required")
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	mode := strings.ToLower(strings.TrimSpace(cfg.TLSMode))

	conn, err := smtpDialer("tcp", addr, outboundTimeout)
	if err != nil {
		return fmt.Errorf("smtp dial %s: %w", addr, err)
	}

	if mode == "implicit" {
		conn = tls.Client(conn, &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12})
	}

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()

	// Bound the whole conversation to the request context.
	done := make(chan error, 1)
	go func() { done <- deliverSMTP(client, ch, cfg, mode, ev) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case e := <-done:
		return e
	}
}

func deliverSMTP(client *smtp.Client, ch *Channel, cfg EmailConfig, mode string, ev Event) error {
	if mode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
				return fmt.Errorf("smtp starttls: %w", err)
			}
		} else {
			return errors.New("smtp server does not advertise STARTTLS")
		}
	}

	if strings.TrimSpace(cfg.Username) != "" {
		auth := smtp.PlainAuth("", cfg.Username, ch.Secret2, cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	if err := client.Mail(cfg.From); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	for _, rcpt := range cfg.To {
		if err := client.Rcpt(strings.TrimSpace(rcpt)); err != nil {
			return fmt.Errorf("smtp RCPT TO %s: %w", rcpt, err)
		}
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := wc.Write(BuildEmailMessage(cfg, ev)); err != nil {
		wc.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	return client.Quit()
}

// deliver dispatches an event to a channel by kind. It is the single switch the
// queue worker calls; call sites never touch transport code.
func deliver(ctx context.Context, ch *Channel, ev Event) error {
	switch ch.Kind {
	case ChannelWebhook:
		return sendWebhook(ctx, ch, ev)
	case ChannelSlack:
		return sendSlack(ctx, ch, ev)
	case ChannelEmail:
		return sendEmail(ctx, ch, ev)
	default:
		return fmt.Errorf("unknown channel kind %q", ch.Kind)
	}
}
