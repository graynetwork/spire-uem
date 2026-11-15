package web

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// patRateLimiter throttles FAILED personal-access-token attempts per client IP, to blunt
// online guessing of the random token suffix. Successful auth does not count against the
// limit. It is an in-memory sliding counter — adequate for a single control-plane process;
// a multi-replica deployment would move this to shared state (noted in the runbook).
type patRateLimiter struct {
	mu       sync.Mutex
	attempts map[string]*ipAttempts
	max      int           // max failures per window
	window   time.Duration // sliding window length
}

type ipAttempts struct {
	count       int
	windowStart time.Time
}

// newPATRateLimiter builds a limiter allowing max failures per window per IP.
func newPATRateLimiter(max int, window time.Duration) *patRateLimiter {
	return &patRateLimiter{
		attempts: make(map[string]*ipAttempts),
		max:      max,
		window:   window,
	}
}

// clientIP extracts the IP portion of a RemoteAddr (host:port), falling back to the raw
// value. RemoteAddr is already proxy-resolved upstream by TrustedProxyRealIPMiddleware
// only when a proxy is trusted, so this does not trust client headers itself.
func clientIP(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// Allowed reports whether another attempt from ip is permitted right now.
func (l *patRateLimiter) Allowed(ip string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.attempts[ip]
	now := time.Now()
	if a == nil || now.Sub(a.windowStart) > l.window {
		return true
	}
	return a.count < l.max
}

// RecordFailure registers a failed attempt from ip, starting a fresh window when needed.
func (l *patRateLimiter) RecordFailure(ip string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	a := l.attempts[ip]
	if a == nil || now.Sub(a.windowStart) > l.window {
		l.attempts[ip] = &ipAttempts{count: 1, windowStart: now}
		return
	}
	a.count++
}

// Reset clears an IP's failure counter after a successful auth.
func (l *patRateLimiter) Reset(ip string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, ip)
}

// tooManyAttempts writes a 429 for a rate-limited caller.
func tooManyAttempts(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
}
