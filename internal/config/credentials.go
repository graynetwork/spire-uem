package config

import (
	"fmt"
	"strings"
)

// DefaultSeededAdminPassword is the password the 000016 migration seeds for the 'admin'
// account. spire-server refuses to run while any active local account still uses it.
const DefaultSeededAdminPassword = "changeme"

// MinBreakGlassPasswordLen is the minimum length for the static break-glass password.
const MinBreakGlassPasswordLen = 12

var knownWeakPasswords = map[string]struct{}{
	"changeme": {}, "admin": {}, "password": {}, "spire": {}, "spirepassword": {},
	"changeme123": {}, "administrator": {}, "password123": {},
}

// BreakGlassEnabled reports whether the static (config/env) admin account is enabled.
// It is opt-in: it exists only when an admin password is explicitly configured.
func (c ServerConfig) BreakGlassEnabled() bool {
	return c.AdminPassword != ""
}

// ValidateBreakGlassPassword rejects known default/weak values and short passwords.
// An empty password is valid and means the static break-glass account is disabled.
func ValidateBreakGlassPassword(pw string) error {
	if pw == "" {
		return nil
	}
	if _, weak := knownWeakPasswords[strings.ToLower(pw)]; weak {
		return fmt.Errorf("SPIRE_ADMIN_PASSWORD is a known default or weak value; choose a unique password of at least %d characters", MinBreakGlassPasswordLen)
	}
	if len(pw) < MinBreakGlassPasswordLen {
		return fmt.Errorf("SPIRE_ADMIN_PASSWORD must be at least %d characters (got %d)", MinBreakGlassPasswordLen, len(pw))
	}
	return nil
}
