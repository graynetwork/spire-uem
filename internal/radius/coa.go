package radius

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/spire-uem/spire-uem/internal/webhooks"
)

// Delivery outcomes.
const (
	OutcomeACK    = "ACKED"  // NAS acknowledged (or reported the session already gone)
	OutcomeNAK    = "NAKED"  // NAS refused
	OutcomeFailed = "FAILED" // no valid answer (timeout, unreachable, bad authenticator)
)

// Sender sends Disconnect-Requests. Only admin-configured NAS addresses ever reach it, and
// it re-checks the address class at connect time with the webhook package's rules.
type Sender struct {
	Timeout  time.Duration // per attempt
	Attempts int           // total tries (retransmissions of the identical packet)

	unsafeAllowLoopback bool
	now                 func() time.Time
}

// SenderOption customises a Sender.
type SenderOption func(*Sender)

// UnsafeAllowLoopbackForTests lets the sender reach 127.0.0.1 so tests can use a local
// listener. Production code must never pass it.
func UnsafeAllowLoopbackForTests() SenderOption {
	return func(s *Sender) { s.unsafeAllowLoopback = true }
}

// WithTiming overrides the per-attempt timeout and attempt count (tests).
func WithTiming(timeout time.Duration, attempts int) SenderOption {
	return func(s *Sender) { s.Timeout, s.Attempts = timeout, attempts }
}

// NewSender returns a Sender with the production policy: 3 s per attempt, 3 attempts.
func NewSender(opts ...SenderOption) *Sender {
	s := &Sender{Timeout: 3 * time.Second, Attempts: 3, now: time.Now}
	for _, o := range opts {
		o(s)
	}
	return s
}

// CheckNASAddress validates a NAS address at save time and again at connect time. It must be
// an IP literal (no DNS, so nothing can be rebound); loopback, link-local (including the
// cloud-metadata address), multicast and unspecified addresses are refused. Private ranges
// are allowed: a NAS lives on the management network by nature, and the address is one an
// administrator typed in and an audit event recorded.
func CheckNASAddress(addr string) error {
	ip := net.ParseIP(addr)
	if ip == nil {
		return fmt.Errorf("%q is not an IP address (hostnames are not accepted)", addr)
	}
	if webhooks.ClassifyIP(ip) == webhooks.ClassForbidden {
		return fmt.Errorf("%s is a loopback, link-local, multicast or unspecified address", ip)
	}
	return nil
}

// Result is the outcome of one Disconnect delivery.
type Result struct {
	Outcome    string
	ErrorCause int // from a NAK, 0 if none
	Attempts   int
	Detail     string
}

// SendDisconnect sends a Disconnect-Request carrying attrs to host:port and waits for the
// ACK/NAK. The packet is signed with secret; the answer must carry a valid Response
// Authenticator for it, anything else is ignored (as the RFC requires). An Event-Timestamp is
// added so a NAS that enforces a replay window accepts it.
func (s *Sender) SendDisconnect(ctx context.Context, host string, port int, secret []byte, attrs []Attr) Result {
	if ip := net.ParseIP(host); !(s.unsafeAllowLoopback && ip != nil && ip.IsLoopback()) {
		if err := CheckNASAddress(host); err != nil {
			return Result{Outcome: OutcomeFailed, Detail: err.Error()}
		}
	}
	if port < 1 || port > 65535 {
		return Result{Outcome: OutcomeFailed, Detail: "invalid port"}
	}
	all := append(append([]Attr(nil), attrs...), Uint32Attr(AttrEventTimestamp, uint32(s.now().Unix())))
	pkt := &Packet{Code: CodeDisconnectRequest, ID: NewID(), Attrs: all}
	raw, err := pkt.EncodeRequest(secret)
	if err != nil {
		return Result{Outcome: OutcomeFailed, Detail: err.Error()}
	}
	dialer := &net.Dialer{Timeout: s.Timeout, Control: s.control}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return Result{Outcome: OutcomeFailed, Detail: "dial: " + err.Error()}
	}
	defer conn.Close()

	attempts := s.Attempts
	if attempts < 1 {
		attempts = 1
	}
	buf := make([]byte, maxPacket)
	var last string
	for i := 1; i <= attempts; i++ {
		if ctx.Err() != nil {
			return Result{Outcome: OutcomeFailed, Attempts: i - 1, Detail: ctx.Err().Error()}
		}
		if _, err := conn.Write(raw); err != nil {
			last = "write: " + err.Error()
			continue
		}
		deadline := time.Now().Add(s.Timeout)
		for { // keep reading until a VALID answer or the attempt times out
			_ = conn.SetReadDeadline(deadline)
			n, err := conn.Read(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					last = "timeout"
				} else {
					last = "read: " + err.Error()
				}
				break
			}
			resp, err := VerifyResponse(buf[:n], pkt.Authenticator, secret)
			if err != nil || resp.ID != pkt.ID {
				last = "ignored an invalid response"
				continue
			}
			switch resp.Code {
			case CodeDisconnectACK:
				return Result{Outcome: OutcomeACK, Attempts: i}
			case CodeDisconnectNAK:
				cause := 0
				if v, ok := resp.Get(AttrErrorCause); ok && len(v) == 4 {
					cause = int(v[0])<<24 | int(v[1])<<16 | int(v[2])<<8 | int(v[3])
				}
				if cause == ErrorCauseSessionNotFound {
					return Result{Outcome: OutcomeACK, ErrorCause: cause, Attempts: i, Detail: "session already gone on the NAS"}
				}
				return Result{Outcome: OutcomeNAK, ErrorCause: cause, Attempts: i, Detail: "NAS refused the disconnect"}
			default:
				last = fmt.Sprintf("unexpected response code %d", resp.Code)
			}
		}
	}
	return Result{Outcome: OutcomeFailed, Attempts: attempts, Detail: last}
}

// control runs after resolution with the exact address about to be used.
func (s *Sender) control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("bad address %q", address)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("unresolved address %q", address)
	}
	if s.unsafeAllowLoopback && ip.IsLoopback() {
		return nil
	}
	if webhooks.ClassifyIP(ip) == webhooks.ClassForbidden {
		return fmt.Errorf("NAS address %s is not allowed", ip)
	}
	return nil
}
