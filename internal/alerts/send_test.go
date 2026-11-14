package alerts

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSignWebhookBody_Deterministic_And_Verifiable(t *testing.T) {
	secret := "s3cr3t-key"
	body := []byte(`{"kind":"test"}`)
	var ts int64 = 1731570000

	got := SignWebhookBody(secret, ts, body)

	// Recompute independently the way a receiver would.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10) + "."))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))

	if got != want {
		t.Fatalf("signature mismatch:\n got=%s\nwant=%s", got, want)
	}
	// Changing the timestamp must change the signature (replay binding).
	if SignWebhookBody(secret, ts+1, body) == got {
		t.Fatal("signature did not change when timestamp changed")
	}
	// Changing the body must change the signature.
	if SignWebhookBody(secret, ts, []byte(`{"kind":"other"}`)) == got {
		t.Fatal("signature did not change when body changed")
	}
}

func TestValidateOutboundURL(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		name string
	}{
		{"https://example.com/hook", true, "https ok"},
		{"http://10.0.0.5/hook", true, "internal http allowed (SSRF gated by RBAC)"},
		{"ftp://example.com", false, "ftp refused"},
		{"file:///etc/passwd", false, "file scheme refused"},
		{"gopher://x", false, "gopher refused"},
		{"notaurl", false, "missing scheme/host"},
		{"https://", false, "no host"},
	}
	for _, c := range cases {
		_, err := validateOutboundURL(c.in)
		if (err == nil) != c.ok {
			t.Errorf("%s: validateOutboundURL(%q) err=%v, want ok=%v", c.name, c.in, err, c.ok)
		}
	}
}

func TestBuildEmailMessage(t *testing.T) {
	cfg := EmailConfig{From: "alerts@spire.local", To: []string{"ops@spire.local", "sec@spire.local"}}
	ev := Event{Kind: EventPatchFailed, Severity: SeverityWarning, Subject: "Patch run FAILED on host-1", Hostname: "host-1", Timestamp: time.Unix(1731570000, 0).UTC()}
	msg := string(BuildEmailMessage(cfg, ev))

	for _, want := range []string{
		"From: alerts@spire.local",
		"To: ops@spire.local, sec@spire.local",
		"Subject: [SpireUEM][WARNING] Patch run FAILED on host-1",
		"Content-Type: text/plain; charset=utf-8",
		"Host: host-1",
		"Patch run FAILED on host-1",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("email message missing %q\n---\n%s", want, msg)
		}
	}
	// Headers must be CRLF-terminated.
	if !strings.Contains(msg, "\r\n\r\n") {
		t.Error("email message missing header/body separator")
	}
}

func TestSendWebhook_SignedDelivery(t *testing.T) {
	secret := "whsec"
	var gotSig, gotTs, gotEvent string
	var gotBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get(HeaderSignature)
		gotTs = r.Header.Get(HeaderTimestamp)
		gotEvent = r.Header.Get(HeaderEvent)
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	ch := &Channel{Kind: ChannelWebhook, Webhook: WebhookConfig{URL: srv.URL}, Secret: secret}
	ev := Event{Kind: EventDeviceOffline, Severity: SeverityWarning, Subject: "offline", Timestamp: time.Now().UTC()}

	if err := sendWebhook(context.Background(), ch, ev); err != nil {
		t.Fatalf("sendWebhook: %v", err)
	}
	if gotEvent != string(EventDeviceOffline) {
		t.Errorf("event header=%q", gotEvent)
	}
	// Verify the signature the receiver would check.
	ts, _ := strconv.ParseInt(gotTs, 10, 64)
	want := "sha256=" + SignWebhookBody(secret, ts, gotBody)
	if gotSig != want {
		t.Errorf("signature header mismatch: got=%s want=%s", gotSig, want)
	}
	// Body must be valid JSON carrying the kind.
	var env map[string]any
	if err := json.Unmarshal(gotBody, &env); err != nil {
		t.Fatalf("body not json: %v", err)
	}
	if env["kind"] != string(EventDeviceOffline) {
		t.Errorf("body kind=%v", env["kind"])
	}
}

func TestSendWebhook_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()
	ch := &Channel{Kind: ChannelWebhook, Webhook: WebhookConfig{URL: srv.URL}}
	if err := sendWebhook(context.Background(), ch, Event{Timestamp: time.Now()}); err == nil {
		t.Fatal("expected error on HTTP 500")
	}
}

func TestSendWebhook_RedirectRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/other", http.StatusFound)
	}))
	defer srv.Close()
	ch := &Channel{Kind: ChannelWebhook, Webhook: WebhookConfig{URL: srv.URL}}
	err := sendWebhook(context.Background(), ch, Event{Timestamp: time.Now()})
	if err == nil {
		t.Fatal("expected redirect to be refused")
	}
}

func TestSendSlack_TextPayload(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ch := &Channel{Kind: ChannelSlack, Secret: srv.URL}
	ev := Event{Kind: EventDeviceRevoked, Severity: SeverityCritical, Subject: "device revoked", Hostname: "h1", Timestamp: time.Now()}
	if err := sendSlack(context.Background(), ch, ev); err != nil {
		t.Fatalf("sendSlack: %v", err)
	}
	var m slackMessage
	if err := json.Unmarshal(gotBody, &m); err != nil {
		t.Fatalf("slack body not json: %v", err)
	}
	if !strings.Contains(m.Text, "device revoked") || !strings.Contains(m.Text, "h1") {
		t.Errorf("slack text missing content: %q", m.Text)
	}
}
