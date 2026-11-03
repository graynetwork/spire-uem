package web

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
)

// BasicAuthMiddleware enforces HTTP Basic Authentication on /admin/* routes
// using constant-time comparisons via crypto/subtle.ConstantTimeCompare.
func BasicAuthMiddleware(expectedUser, expectedPass string) func(http.Handler) http.Handler {
	expectedUserHash := sha256.Sum256([]byte(expectedUser))
	expectedPassHash := sha256.Sum256([]byte(expectedPass))

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()
			if !ok {
				unauthorized(w)
				return
			}

			userHash := sha256.Sum256([]byte(user))
			passHash := sha256.Sum256([]byte(pass))

			userMatch := subtle.ConstantTimeCompare(userHash[:], expectedUserHash[:]) == 1
			passMatch := subtle.ConstantTimeCompare(passHash[:], expectedPassHash[:]) == 1

			if !userMatch || !passMatch {
				unauthorized(w)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="SpireUEM Admin", charset="UTF-8"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}
