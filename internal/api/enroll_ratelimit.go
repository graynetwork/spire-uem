package api

import (
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// enrollRateLimiter throttles FAILED enrollment-token registration attempts per client IP,
// to blunt online guessing of a token secret. A successful registration does not count. It
// is an in-memory sliding counter, adequate for a single control-plane process; a
// multi-replica deployment would move this to shared state (documented in the runbook).
type enrollRateLimiter struct {
	mu       sync.Mutex
	attempts map[string]*enrollAttempts
	max      int
	window   time.Duration
}

type enrollAttempts struct {
	count       int
	windowStart time.Time
}

func newEnrollRateLimiter(max int, window time.Duration) *enrollRateLimiter {
	return &enrollRateLimiter{
		attempts: make(map[string]*enrollAttempts),
		max:      max,
		window:   window,
	}
}

// Allowed reports whether another attempt from ip is permitted right now.
func (l *enrollRateLimiter) Allowed(ip string) bool {
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
func (l *enrollRateLimiter) RecordFailure(ip string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	a := l.attempts[ip]
	if a == nil || now.Sub(a.windowStart) > l.window {
		l.attempts[ip] = &enrollAttempts{count: 1, windowStart: now}
		return
	}
	a.count++
}

// Reset clears an IP's failure counter after a successful registration.
func (l *enrollRateLimiter) Reset(ip string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, ip)
}

// enrollClientIP extracts the host portion of a RemoteAddr (host:port), falling back to the
// raw value. It does not trust client-supplied headers.
func enrollClientIP(remoteAddr string) string {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

// writeTooManyRequests writes a uniform 429 for a rate-limited enrollment caller.
func writeTooManyRequests(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many enrollment attempts; try again later"})
}

// hostnameMatchesPattern reports whether hostname matches the token's glob pattern. An empty
// pattern matches anything. The match is case-insensitive and uses shell-glob semantics
// (filepath.Match), so patterns like "lab-*" or "ws??.corp" work. A malformed pattern never
// matches (fails closed).
func hostnameMatchesPattern(pattern, hostname string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return true
	}
	ok, err := filepath.Match(strings.ToLower(pattern), strings.ToLower(strings.TrimSpace(hostname)))
	if err != nil {
		return false
	}
	return ok
}
