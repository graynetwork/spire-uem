package webhooks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// RequestTimeout bounds one delivery attempt end to end.
	RequestTimeout = 10 * time.Second
	// MaxResponseRead caps how much of a receiver's response body is read.
	MaxResponseRead = 2048
	// SnippetLen is how much of the response is kept in the attempt log.
	SnippetLen = 512
)

// Result is the outcome of one HTTP attempt.
type Result struct {
	StatusCode int
	Err        string
	Duration   time.Duration
	Snippet    string
}

// OK reports a 2xx response with no transport error.
func (r Result) OK() bool { return r.Err == "" && r.StatusCode >= 200 && r.StatusCode < 300 }

// Sender performs signed deliveries.
type Sender struct {
	timeout             time.Duration
	unsafeAllowLoopback bool
}

// SenderOption customises a Sender.
type SenderOption func(*Sender)

// UnsafeAllowLoopbackForTests lets the sender connect to 127.0.0.1 so tests can use a local
// receiver. Production code must never pass it; link-local and metadata addresses stay blocked.
func UnsafeAllowLoopbackForTests() SenderOption {
	return func(s *Sender) { s.unsafeAllowLoopback = true }
}

// WithTimeout overrides the per-attempt timeout (tests).
func WithTimeout(d time.Duration) SenderOption { return func(s *Sender) { s.timeout = d } }

// NewSender returns a Sender with the production policy.
func NewSender(opts ...SenderOption) *Sender {
	s := &Sender{timeout: RequestTimeout}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Send POSTs body to rawURL signed with secret. It re-validates the URL (https required
// unless the subscription allows private networks) and enforces the address policy at
// connect time. Redirects are not followed; a 3xx is a failed attempt.
func (s *Sender) Send(ctx context.Context, rawURL, secret string, allowPrivate bool, eventID string, body []byte) Result {
	start := time.Now()
	fail := func(err error) Result {
		return Result{Err: capStr(err.Error(), 500), Duration: time.Since(start)}
	}
	pol := dialPolicy{allowPrivate: allowPrivate, unsafeAllowLoopback: s.unsafeAllowLoopback}
	u, err := validateURL(rawURL, pol)
	if err != nil {
		return fail(err)
	}
	pol.privateOnly = u.Scheme == "http" && !s.unsafeAllowLoopback
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return fail(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "spire-uem-webhooks/1")
	req.Header.Set(HeaderEventID, eventID)
	req.Header.Set(HeaderSignature, Sign(secret, time.Now(), body))
	resp, err := newClient(pol, s.timeout).Do(req)
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()
	snip, _ := io.ReadAll(io.LimitReader(resp.Body, MaxResponseRead))
	return Result{
		StatusCode: resp.StatusCode,
		Duration:   time.Since(start),
		Snippet:    capStr(strings.ToValidUTF8(string(snip), ""), SnippetLen),
		Err: func() string {
			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				return "redirect (HTTP " + strconv.Itoa(resp.StatusCode) + ") not followed"
			}
			return ""
		}(),
	}
}

// BodyFromPayload re-serialises a stored envelope compactly.
func BodyFromPayload(payload []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, payload); err != nil {
		return nil, fmt.Errorf("compact payload: %w", err)
	}
	return buf.Bytes(), nil
}

func capStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
