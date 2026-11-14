package web

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestBearerPATExtraction(t *testing.T) {
	raw, _, _, _ := GeneratePAT()
	cases := []struct {
		hdr  string
		want string
	}{
		{"Bearer " + raw, raw},
		{"bearer " + raw, raw}, // scheme is case-insensitive
		{"Basic abc", ""},
		{"Bearer not_a_pat", ""},
		{"", ""},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/admin/dashboard", nil)
		if c.hdr != "" {
			r.Header.Set("Authorization", c.hdr)
		}
		if got := bearerPAT(r); got != c.want {
			t.Errorf("bearerPAT(%q) = %q, want %q", c.hdr, got, c.want)
		}
	}
}

func TestPATRateLimiter(t *testing.T) {
	l := newPATRateLimiter(3, time.Minute)
	ip := "10.0.0.1"
	for i := 0; i < 3; i++ {
		if !l.Allowed(ip) {
			t.Fatalf("attempt %d should be allowed", i)
		}
		l.RecordFailure(ip)
	}
	if l.Allowed(ip) {
		t.Fatal("4th attempt within window should be blocked")
	}
	// A successful auth resets the counter.
	l.Reset(ip)
	if !l.Allowed(ip) {
		t.Fatal("after reset the IP should be allowed again")
	}
}

func TestClientIP(t *testing.T) {
	if got := clientIP("192.168.1.5:54321"); got != "192.168.1.5" {
		t.Fatalf("clientIP host:port = %q", got)
	}
	if got := clientIP("192.168.1.5"); got != "192.168.1.5" {
		t.Fatalf("clientIP bare = %q", got)
	}
}
