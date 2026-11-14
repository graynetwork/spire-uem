package alerts

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// okWebhook starts a 200-returning webhook and returns its URL (closed via t.Cleanup).
func okWebhook(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// failWebhook starts a 500-returning webhook.
func failWebhook(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// fakeSMTP is a minimal in-process SMTP server (no TLS) that accepts one message
// and records the DATA body. It implements just enough of the protocol for the
// net/smtp client with mode="none".
type fakeSMTP struct {
	ln   net.Listener
	host string
	port int
	data chan string
}

func startFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().(*net.TCPAddr)
	f := &fakeSMTP{ln: ln, host: "127.0.0.1", port: addr.Port, data: make(chan string, 1)}
	go f.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return f
}

func (f *fakeSMTP) serve() {
	conn, err := f.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	br := bufio.NewReader(conn)
	w := conn

	write := func(s string) { _, _ = w.Write([]byte(s)) }
	write("220 fake ESMTP\r\n")

	inData := false
	var body strings.Builder
	for {
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if inData {
			if line == ".\r\n" {
				inData = false
				write("250 OK\r\n")
				f.data <- body.String()
				continue
			}
			body.WriteString(line)
			continue
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			write("250-fake\r\n250 OK\r\n")
		case strings.HasPrefix(cmd, "MAIL FROM"), strings.HasPrefix(cmd, "RCPT TO"):
			write("250 OK\r\n")
		case cmd == "DATA":
			inData = true
			write("354 End data with <CR><LF>.<CR><LF>\r\n")
		case cmd == "QUIT":
			write("221 Bye\r\n")
			return
		default:
			write("250 OK\r\n")
		}
	}
}

func TestSendEmail_FakeServer(t *testing.T) {
	srv := startFakeSMTP(t)
	ch := &Channel{
		Kind: ChannelEmail,
		Email: EmailConfig{
			Host: srv.host, Port: srv.port, TLSMode: "none",
			From: "alerts@spire.local", To: []string{"ops@spire.local"},
		},
	}
	ev := Event{Kind: EventPatchFailed, Severity: SeverityWarning, Subject: "Patch FAILED on host-9", Hostname: "host-9", Timestamp: time.Now().UTC()}

	if err := sendEmail(context.Background(), ch, ev); err != nil {
		t.Fatalf("sendEmail: %v", err)
	}

	select {
	case got := <-srv.data:
		if !strings.Contains(got, "Patch FAILED on host-9") {
			t.Errorf("DATA body missing subject/body: %q", got)
		}
		if !strings.Contains(got, "To: ops@spire.local") {
			t.Errorf("DATA body missing recipient header: %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("fake SMTP never received DATA")
	}
}

func TestSendEmail_RejectsMissingConfig(t *testing.T) {
	ch := &Channel{Kind: ChannelEmail, Email: EmailConfig{Host: "", Port: 0}}
	if err := sendEmail(context.Background(), ch, Event{Timestamp: time.Now()}); err == nil {
		t.Fatal("expected error for missing SMTP host/port")
	}
}
