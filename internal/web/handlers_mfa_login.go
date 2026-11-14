package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// mfaPending represents a password-verified login awaiting its second factor.
type mfaPending struct {
	user *types.AdminUser
}

// newPendingChallenge mints a random challenge token and its HMAC-signed cookie value. The
// raw token's hash is stored server-side (single-use) so the cookie alone cannot be
// forged or replayed after consumption.
func newPendingChallenge(secure bool) (rawToken string, cookie *http.Cookie, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("generate pending challenge: %w", err)
	}
	rawToken = hex.EncodeToString(b)

	exp := time.Now().Add(pendingLoginTTL).Unix()
	payload := fmt.Sprintf("%s|%d", rawToken, exp)
	mac := hmac.New(sha256.New, sessionSecretKey)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	value := base64.URLEncoding.EncodeToString([]byte(payload + "|" + sig))

	cookie = &http.Cookie{
		Name:     pendingLoginCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(pendingLoginTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   secure,
	}
	return rawToken, cookie, nil
}

// readPendingChallenge validates the signed pending-login cookie and returns the raw
// challenge token it carries, or ok=false when missing/expired/tampered.
func readPendingChallenge(r *http.Request) (rawToken string, ok bool) {
	c, err := r.Cookie(pendingLoginCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	raw, err := base64.URLEncoding.DecodeString(c.Value)
	if err != nil {
		return "", false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return "", false
	}
	token, expStr, providedSig := parts[0], parts[1], parts[2]
	payload := token + "|" + expStr
	mac := hmac.New(sha256.New, sessionSecretKey)
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(providedSig), []byte(expectedSig)) != 1 {
		return "", false
	}
	var exp int64
	if _, err := fmt.Sscanf(expStr, "%d", &exp); err != nil || time.Now().Unix() > exp {
		return "", false
	}
	return token, true
}

func clearPendingCookie() *http.Cookie {
	return &http.Cookie{
		Name:     pendingLoginCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

// beginMFAChallenge records pending-login state and sets the signed cookie, instead of
// issuing a session. Called by LoginSubmit when a verified local user has MFA enabled.
func (h *Handler) beginMFAChallenge(w http.ResponseWriter, r *http.Request, u *types.AdminUser, secure bool) {
	rawToken, cookie, err := newPendingChallenge(secure)
	if err != nil {
		http.Error(w, "Failed to start MFA challenge", http.StatusInternalServerError)
		return
	}
	if err := h.repo.CreatePendingLogin(r.Context(), db.HashToken(rawToken), u.ID, u.Username, time.Now().Add(pendingLoginTTL)); err != nil {
		http.Error(w, "Failed to start MFA challenge", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, cookie)

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "mfa_required",
			"redirect": "/login/mfa",
		})
		return
	}
	http.Redirect(w, r, "/login/mfa", http.StatusSeeOther)
}

// MFAChallengePage handles GET /login/mfa — the second-factor entry page. Without a valid
// pending cookie it bounces back to /login.
func (h *Handler) MFAChallengePage(w http.ResponseWriter, r *http.Request) {
	if _, ok := readPendingChallenge(r); !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.tmpl.ExecuteTemplate(w, "mfa_challenge.html", map[string]any{
		"Title": "Two-Factor Authentication",
		"Error": r.URL.Query().Get("error"),
	})
}

// MFAChallengeSubmit handles POST /login/mfa — verifies the TOTP or recovery code, and
// only on success consumes the pending login and issues the real session. No session
// cookie is ever set before this point.
func (h *Handler) MFAChallengeSubmit(w http.ResponseWriter, r *http.Request) {
	rawToken, ok := readPendingChallenge(r)
	if !ok {
		http.Redirect(w, r, "/login?error=Session+expired%2C+sign+in+again", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}
	code := strings.TrimSpace(r.FormValue("code"))

	// Resolve and single-use-consume the pending login FIRST so a replayed challenge
	// cannot be retried indefinitely. We re-issue a fresh pending row only on a wrong code.
	userID, username, consumed, err := h.repo.ConsumePendingLogin(r.Context(), db.HashToken(rawToken))
	if err != nil || !consumed {
		http.SetCookie(w, clearPendingCookie())
		http.Redirect(w, r, "/login?error=Session+expired%2C+sign+in+again", http.StatusSeeOther)
		return
	}

	enr, err := h.repo.GetMFAEnrollment(r.Context(), userID)
	if err != nil || !enr.Enabled {
		http.SetCookie(w, clearPendingCookie())
		http.Redirect(w, r, "/login?error=MFA+state+changed%2C+sign+in+again", http.StatusSeeOther)
		return
	}

	if !h.verifySecondFactor(r, userID, enr, code) {
		// Wrong code: re-arm a fresh single-use pending challenge so the user can retry
		// within the window, and audit the failure.
		if h.auditor != nil {
			_, _, _ = h.auditor.Emit(r.Context(), username, "MFA_CHALLENGE_FAIL", userID, r.RemoteAddr, map[string]any{})
		}
		secure := ShouldEnforceHTTPSCookie(h.enforceHTTPS, r)
		newRaw, cookie, mkErr := newPendingChallenge(secure)
		if mkErr == nil {
			if cpErr := h.repo.CreatePendingLogin(r.Context(), db.HashToken(newRaw), userID, username, time.Now().Add(pendingLoginTTL)); cpErr == nil {
				http.SetCookie(w, cookie)
				http.Redirect(w, r, "/login/mfa?error=Invalid+code%2C+try+again", http.StatusSeeOther)
				return
			}
		}
		http.SetCookie(w, clearPendingCookie())
		http.Redirect(w, r, "/login?error=Invalid+code", http.StatusSeeOther)
		return
	}

	// Second factor passed — issue the real session now.
	http.SetCookie(w, clearPendingCookie())
	secure := ShouldEnforceHTTPSCookie(h.enforceHTTPS, r)
	sessionCookie, csrfToken, err := IssueSession(r.Context(), h.repo, username, secure)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, sessionCookie)
	_ = h.repo.UpdateAdminUserLastLogin(r.Context(), userID)
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), username, "LOGIN_SUCCESS", userID, r.RemoteAddr, map[string]any{
			"auth_provider": "LOCAL",
			"mfa":           true,
		})
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeJSON(w, http.StatusOK, map[string]any{"status": "authenticated", "csrf_token": csrfToken, "redirect": "/admin/dashboard"})
		return
	}
	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}
