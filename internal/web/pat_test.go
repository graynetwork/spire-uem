package web

import (
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

func TestGeneratePATFormatAndHash(t *testing.T) {
	raw, hash, prefix, err := GeneratePAT()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.HasPrefix(raw, PATPrefix) {
		t.Fatalf("raw %q missing prefix", raw)
	}
	if !LooksLikePAT(raw) {
		t.Fatal("LooksLikePAT should accept a freshly generated token")
	}
	if HashPAT(raw) != hash {
		t.Fatal("HashPAT must match the returned hash")
	}
	if len(hash) != 64 {
		t.Fatalf("hash should be 64 hex chars, got %d", len(hash))
	}
	if !strings.HasPrefix(prefix, PATPrefix) || len(prefix) >= len(raw) {
		t.Fatalf("display prefix %q should be a short prefix of the token", prefix)
	}
	// Two tokens never collide.
	raw2, _, _, _ := GeneratePAT()
	if raw == raw2 {
		t.Fatal("tokens must be unique")
	}
	// Non-PATs rejected.
	if LooksLikePAT("Bearer abc") || LooksLikePAT("spire_pat_") {
		t.Fatal("LooksLikePAT should reject non-token / empty-suffix values")
	}
}

func TestRoleCappingAndMin(t *testing.T) {
	// A token must not outrank its creator.
	if RoleAtMost(types.RoleSuperAdmin, types.RoleOperator) {
		t.Fatal("SUPER_ADMIN token must not be allowed for an OPERATOR creator")
	}
	if !RoleAtMost(types.RoleAuditor, types.RoleOperator) {
		t.Fatal("AUDITOR token should be allowed for an OPERATOR creator")
	}
	if !RoleAtMost(types.RoleOperator, types.RoleOperator) {
		t.Fatal("equal role should be allowed")
	}
	if RoleAtMost(types.AdminRole("GARBAGE"), types.RoleSuperAdmin) {
		t.Fatal("unknown role must never be allowed")
	}

	// Effective role is the minimum of token role and owner's current role: demoting the
	// owner weakens the token.
	if got := MinRole(types.RoleSuperAdmin, types.RoleOperator); got != types.RoleOperator {
		t.Fatalf("MinRole(SUPER, OPERATOR) = %q, want OPERATOR", got)
	}
	if got := MinRole(types.RoleAuditor, types.RoleSecurityAdmin); got != types.RoleAuditor {
		t.Fatalf("MinRole(AUDITOR, SECURITY) = %q, want AUDITOR", got)
	}
}
