package audit

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// DefaultRFC5424SpoolPath is a local spool file where RFC 5424 syslog lines are mirrored.
const DefaultRFC5424SpoolPath = "/tmp/spire-siem-rfc5424.log"

// Forwarder records enterprise security/admin audit events in PostgreSQL (system_audit_events)
// and emits RFC 5424 Syslog messages over UDP, TCP, or TLS to a configured SIEM collector.
type Forwarder struct {
	repo       *db.Repository
	syslogAddr string
	hostname   string
	mu         sync.Mutex
	recent     []string
}

// NewForwarder creates a new audit Forwarder.
func NewForwarder(repo *db.Repository, syslogAddr string) *Forwarder {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		host = "spire-server"
	}
	if strings.TrimSpace(syslogAddr) == "" {
		syslogAddr = strings.TrimSpace(os.Getenv("SPIRE_SIEM_SYSLOG_ADDR"))
	}
	return &Forwarder{
		repo:       repo,
		syslogAddr: syslogAddr,
		hostname:   host,
		recent:     make([]string, 0, 64),
	}
}

// Emit persists a SystemAuditEvent to PostgreSQL and forwards an RFC 5424 Syslog frame.
func (f *Forwarder) Emit(ctx context.Context, actor, action, targetID, ipAddr string, details map[string]any) (*types.SystemAuditEvent, string, error) {
	if strings.TrimSpace(actor) == "" {
		actor = "system"
	}
	if strings.TrimSpace(ipAddr) == "" {
		ipAddr = "127.0.0.1"
	}
	if details == nil {
		details = map[string]any{}
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		detailsJSON = []byte("{}")
	}

	var targetPtr *string
	if strings.TrimSpace(targetID) != "" {
		t := strings.TrimSpace(targetID)
		targetPtr = &t
	}

	ev, err := f.repo.RecordSystemAuditEvent(ctx, actor, action, targetPtr, detailsJSON, ipAddr)
	if err != nil {
		log.Printf("[audit] failed to record system_audit_events row (%s): %v", action, err)
		ev = &types.SystemAuditEvent{
			ID:        "00000000-0000-0000-0000-000000000000",
			Actor:     actor,
			Action:    action,
			TargetID:  targetPtr,
			Details:   detailsJSON,
			IPAddress: ipAddr,
			CreatedAt: time.Now().UTC(),
		}
	}

	rfc5424Line := FormatRFC5424(f.hostname, ev)
	log.Printf("[audit-rfc5424] %s", rfc5424Line)

	f.mu.Lock()
	if len(f.recent) >= 100 {
		f.recent = f.recent[1:]
	}
	f.recent = append(f.recent, rfc5424Line)
	f.mu.Unlock()

	f.appendSpool(rfc5424Line)

	if f.syslogAddr != "" {
		if sendErr := f.sendSyslog(rfc5424Line); sendErr != nil {
			log.Printf("[audit] warning: SIEM syslog forward to %s failed: %v", f.syslogAddr, sendErr)
		}
	}

	return ev, rfc5424Line, err
}

// FormatRFC5424 formats a SystemAuditEvent as an RFC 5424 compliant Syslog message:
// <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [spireAudit@32473 ...] MSG
func FormatRFC5424(hostname string, ev *types.SystemAuditEvent) string {
	// Facility 16 (local0) * 8 + Severity 6 (Informational) = 134; Security-sensitive actions use Facility 10 (security/authpriv) * 8 + Severity 5 (Notice) = 85
	pri := 134
	if ev.Action == "LUKS_KEY_REVEAL" || ev.Action == "DEVICE_REVOKE" {
		pri = 85
	}
	ts := ev.CreatedAt.UTC().Format(time.RFC3339Nano)
	procID := fmt.Sprintf("%d", os.Getpid())
	msgID := sanitizeToken(ev.Action)
	targetStr := "-"
	if ev.TargetID != nil && *ev.TargetID != "" {
		targetStr = escapeSDParam(*ev.TargetID)
	}

	sd := fmt.Sprintf(`[spireAudit@32473 eventId="%s" actor="%s" action="%s" targetId="%s" ip="%s"]`,
		escapeSDParam(ev.ID),
		escapeSDParam(ev.Actor),
		escapeSDParam(ev.Action),
		targetStr,
		escapeSDParam(ev.IPAddress),
	)

	return fmt.Sprintf("<%d>1 %s %s spire-uem %s %s %s %s",
		pri,
		ts,
		sanitizeToken(hostname),
		procID,
		msgID,
		sd,
		string(ev.Details),
	)
}

func (f *Forwarder) sendSyslog(rfc5424Line string) error {
	addr := strings.TrimSpace(f.syslogAddr)
	network := "udp"
	useTLS := false

	switch {
	case strings.HasPrefix(addr, "udp://"):
		network = "udp"
		addr = strings.TrimPrefix(addr, "udp://")
	case strings.HasPrefix(addr, "tcp://"):
		network = "tcp"
		addr = strings.TrimPrefix(addr, "tcp://")
	case strings.HasPrefix(addr, "tls://"):
		network = "tcp"
		useTLS = true
		addr = strings.TrimPrefix(addr, "tls://")
	}

	dialer := &net.Dialer{Timeout: 2 * time.Second}
	var (
		conn net.Conn
		err  error
	)
	if useTLS {
		conn, err = tls.DialWithDialer(dialer, network, addr, &tls.Config{
			MinVersion: tls.VersionTLS12,
		})
	} else {
		conn, err = dialer.Dial(network, addr)
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write([]byte(rfc5424Line + "\n"))
	return err
}

func (f *Forwarder) appendSpool(line string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fl, err := os.OpenFile(DefaultRFC5424SpoolPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer fl.Close()
	_, _ = fl.WriteString(line + "\n")
}

// RecentRFC5424 returns recent RFC 5424 formatted audit lines emitted by this server instance.
func (f *Forwarder) RecentRFC5424() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.recent))
	copy(out, f.recent)
	return out
}

func sanitizeToken(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	return strings.ReplaceAll(s, " ", "_")
}

func escapeSDParam(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`)
	return r.Replace(s)
}
