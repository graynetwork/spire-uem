package webhooks

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClassifyIP(t *testing.T) {
	cases := []struct {
		ip   string
		want AddrClass
	}{
		{"127.0.0.1", ClassForbidden},
		{"127.8.8.8", ClassForbidden},
		{"::1", ClassForbidden},
		{"169.254.169.254", ClassForbidden},
		{"169.254.1.1", ClassForbidden},
		{"fe80::1", ClassForbidden},
		{"0.0.0.0", ClassForbidden},
		{"::", ClassForbidden},
		{"224.0.0.1", ClassForbidden},
		{"ff02::1", ClassForbidden},
		{"255.255.255.255", ClassForbidden},
		{"::ffff:127.0.0.1", ClassForbidden},       // v4-mapped loopback
		{"::ffff:169.254.169.254", ClassForbidden}, // v4-mapped metadata
		{"64:ff9b::7f00:1", ClassForbidden},        // NAT64 wrapping 127.0.0.1
		{"10.1.2.3", ClassPrivate},
		{"172.16.0.1", ClassPrivate},
		{"192.168.1.1", ClassPrivate},
		{"100.64.0.1", ClassPrivate}, // CGNAT
		{"100.127.255.255", ClassPrivate},
		{"fd00::1", ClassPrivate},
		{"0.1.2.3", ClassPrivate},
		{"198.18.0.1", ClassPrivate},
		{"8.8.8.8", ClassPublic},
		{"100.128.0.1", ClassPublic},
		{"2606:4700:4700::1111", ClassPublic},
	}
	for _, c := range cases {
		if got := ClassifyIP(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("ClassifyIP(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestValidateURL(t *testing.T) {
	bad := []struct {
		url   string
		allow bool
	}{
		{"http://example.com/x", false},          // https required
		{"ftp://example.com/x", true},            // scheme
		{"https://", false},                      // no host
		{"https://user:pw@example.com/x", false}, // credentials
		{"https://127.0.0.1/x", false},
		{"https://127.0.0.1/x", true}, // loopback blocked even with allow-private
		{"https://169.254.169.254/latest/meta-data", true},
		{"https://[::1]/x", true},
		{"https://10.0.0.5/x", false}, // private needs the flag
		{"not a url", false},
	}
	for _, b := range bad {
		if _, err := ValidateURL(b.url, b.allow); err == nil {
			t.Errorf("ValidateURL(%q, allow=%v) should fail", b.url, b.allow)
		}
	}
	good := []struct {
		url   string
		allow bool
	}{
		{"https://example.com/hook", false},
		{"https://10.0.0.5/x", true},
		{"http://10.0.0.5:8080/x", true},
		{"https://8.8.8.8/x", false},
	}
	for _, g := range good {
		if _, err := ValidateURL(g.url, g.allow); err != nil {
			t.Errorf("ValidateURL(%q, allow=%v) = %v", g.url, g.allow, err)
		}
	}
}

// A real local listener on 127.0.0.1 must be unreachable with the production sender, over
// both http (with allow-private) and https, whether addressed by IP literal or by a hostname
// that resolves to loopback (the DNS-rebinding case: the check is at connect time).
func TestSender_BlocksLoopbackAtConnectTime(t *testing.T) {
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	s := NewSender()
	for _, target := range []string{
		"https://127.0.0.1:" + port + "/",
		"https://localhost:" + port + "/", // hostname resolving to 127.0.0.1
	} {
		for _, allow := range []bool{false, true} {
			res := s.Send(context.Background(), target, "s", allow, "evt", []byte(`{}`))
			if res.OK() || res.StatusCode != 0 {
				t.Fatalf("send to %s (allowPrivate=%v) must be blocked, got %+v", target, allow, res)
			}
			if !strings.Contains(res.Err, "not allowed") {
				t.Errorf("send to %s: expected an SSRF block error, got %q", target, res.Err)
			}
		}
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("the loopback receiver must never be contacted, got %d hits", hits)
	}
}

// The connect-time hook itself (not just the URL check) rejects a forbidden address even if a
// URL got past validation: exercise the dialer against a hostname that resolves to loopback.
func TestDialer_ControlRejectsResolvedLoopback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	d := &net.Dialer{Timeout: time.Second, Control: dialPolicy{allowPrivate: true}.control}
	if c, err := d.Dial("tcp", "localhost:"+port); err == nil {
		c.Close()
		t.Fatal("dial of a hostname resolving to loopback must fail")
	}
	d.Control = dialPolicy{unsafeAllowLoopback: true}.control
	c, err := d.Dial("tcp", "localhost:"+port)
	if err != nil {
		t.Fatalf("test hook should allow loopback: %v", err)
	}
	c.Close()
}

// Private-network targets need the flag. Uses a real listener on a private interface address
// when the host has one.
func TestSender_PrivateNeedsFlag(t *testing.T) {
	addrs, _ := net.InterfaceAddrs()
	var privIP string
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && ClassifyIP(ipn.IP) == ClassPrivate {
			privIP = ipn.IP.String()
			break
		}
	}
	if privIP == "" {
		t.Skip("no private IPv4 interface address on this host")
	}
	var hits int32
	ln, err := net.Listen("tcp", privIP+":0")
	if err != nil {
		t.Skipf("cannot listen on %s: %v", privIP, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(204)
	})}
	go srv.Serve(ln)
	defer srv.Close()
	url := "http://" + ln.Addr().String() + "/"

	s := NewSender()
	if res := s.Send(context.Background(), url, "s", false, "e", []byte(`{}`)); res.OK() || atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("private target without the flag must be refused, got %+v hits=%d", res, hits)
	}
	if res := s.Send(context.Background(), url, "s", true, "e", []byte(`{}`)); !res.OK() || atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("private target with the flag should be delivered, got %+v hits=%d", res, hits)
	}
}

func TestSender_DoesNotFollowRedirects(t *testing.T) {
	var targetHits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
	}))
	defer target.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redir.Close()

	s := NewSender(UnsafeAllowLoopbackForTests())
	res := s.Send(context.Background(), redir.URL, "s", true, "e", []byte(`{}`))
	if res.OK() {
		t.Fatalf("a redirect must not count as delivered: %+v", res)
	}
	if res.StatusCode != http.StatusFound || !strings.Contains(res.Err, "redirect") {
		t.Errorf("expected the 302 to be reported as a failed attempt, got %+v", res)
	}
	if atomic.LoadInt32(&targetHits) != 0 {
		t.Fatalf("redirect target was contacted %d times; redirects must not be followed", targetHits)
	}
}

func TestSender_CapsResponseBodyAndSignsRequest(t *testing.T) {
	secret := "whsec_test"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		if err := Verify(secret, r.Header.Get(HeaderSignature), buf[:n], time.Now(), time.Minute); err != nil {
			t.Errorf("signature did not verify: %v", err)
		}
		if r.Header.Get(HeaderEventID) != "evt-1" {
			t.Errorf("missing event id header")
		}
		w.WriteHeader(200)
		big := strings.Repeat("A", 1<<20)
		w.Write([]byte(big))
	}))
	defer srv.Close()
	s := NewSender(UnsafeAllowLoopbackForTests())
	res := s.Send(context.Background(), srv.URL, secret, true, "evt-1", []byte(`{"a":1}`))
	if !res.OK() {
		t.Fatalf("expected success: %+v", res)
	}
	if len(res.Snippet) > SnippetLen {
		t.Errorf("snippet not capped: %d", len(res.Snippet))
	}
}

func TestSender_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer srv.Close()
	s := NewSender(UnsafeAllowLoopbackForTests(), WithTimeout(300*time.Millisecond))
	start := time.Now()
	res := s.Send(context.Background(), srv.URL, "s", true, "e", []byte(`{}`))
	if res.OK() || time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("expected a fast timeout failure, got %+v after %v", res, time.Since(start))
	}
}

func TestSignVerify(t *testing.T) {
	body := []byte(`{"id":"x"}`)
	now := time.Unix(1_700_000_000, 0)
	h := Sign("sec", now, body)
	if !strings.HasPrefix(h, "t=1700000000,v1=") {
		t.Fatalf("bad header %q", h)
	}
	if err := Verify("sec", h, body, now.Add(2*time.Minute), 5*time.Minute); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if Verify("other", h, body, now, time.Minute) == nil {
		t.Error("wrong secret accepted")
	}
	if Verify("sec", h, append(body, ' '), now, time.Minute) == nil {
		t.Error("tampered body accepted")
	}
	if Verify("sec", h, body, now.Add(time.Hour), 5*time.Minute) == nil {
		t.Error("stale timestamp accepted")
	}
	if Verify("sec", "garbage", body, now, time.Minute) == nil {
		t.Error("garbage header accepted")
	}
}

func TestSanitizeData(t *testing.T) {
	long := strings.Repeat("x", 5000)
	out := SanitizeData(map[string]any{
		"hostname":  "h1",
		"api_token": "SECRET",
		"Password":  "SECRET",
		"luks_key":  "SECRET",
		"old":       long,
		"nested":    map[string]any{"a": map[string]any{"b": map[string]any{"c": "deep"}}},
		"is_active": true,
		"count":     3,
		"weird":     make(chan int),
	})
	for _, k := range []string{"api_token", "Password", "luks_key"} {
		if _, ok := out[k]; ok {
			t.Errorf("secret-looking key %q was not dropped", k)
		}
	}
	if s, _ := out["old"].(string); len(s) > maxStringLen+4 {
		t.Errorf("long string not truncated: %d", len(s))
	}
	if out["hostname"] != "h1" || out["is_active"] != true {
		t.Errorf("benign fields lost: %v", out)
	}
	huge := map[string]any{}
	for i := 0; i < 31; i++ {
		huge[string(rune('a'+i%26))+string(rune('a'+i/26))] = strings.Repeat("y", 500)
	}
	if got := SanitizeData(huge); got["truncated"] != true {
		t.Errorf("oversized payload should collapse to a marker, got %d keys", len(got))
	}
}

func TestBackoff(t *testing.T) {
	prev := time.Duration(0)
	for n := 1; n <= 12; n++ {
		d := Backoff(n)
		if d < 24*time.Second || d > backoffCap*12/10+time.Second {
			t.Errorf("Backoff(%d)=%v out of range", n, d)
		}
		_ = prev
		prev = d
	}
	if Backoff(1) > 40*time.Second {
		t.Errorf("first retry should be ~30s, got %v", Backoff(1))
	}
	if Backoff(30) < backoffCap*8/10 {
		t.Errorf("backoff should plateau at the cap, got %v", Backoff(30))
	}
}
