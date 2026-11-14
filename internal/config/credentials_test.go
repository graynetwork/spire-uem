package config

import "testing"

func TestValidateBreakGlassPassword(t *testing.T) {
	for _, pw := range []string{"changeme", "ChangeMe", "admin", "password", "short-pw-1"} {
		if ValidateBreakGlassPassword(pw) == nil {
			t.Errorf("expected %q to be rejected", pw)
		}
	}
	for _, pw := range []string{"", "a-much-longer-unique-passphrase"} {
		if err := ValidateBreakGlassPassword(pw); err != nil {
			t.Errorf("expected %q to be accepted: %v", pw, err)
		}
	}
}

func TestDefaultConfigHasBreakGlassDisabled(t *testing.T) {
	t.Setenv("SPIRE_ADMIN_PASSWORD", "")
	if Load("").Server.BreakGlassEnabled() {
		t.Fatal("break-glass account must be disabled unless a password is configured")
	}
}
