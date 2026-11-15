package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
)

// PATPrefix is the fixed, human-recognisable prefix of every personal access token.
// The random suffix carries the entropy; the prefix only identifies the token scheme so a
// leaked value is obviously a SpireUEM credential (and secret scanners can match it).
const PATPrefix = "spire_pat_"

// patRandomBytes is the entropy of the random portion of a token (32 bytes = 256 bits,
// comfortably above the ">= 32 bytes entropy" requirement).
const patRandomBytes = 32

// GeneratePAT returns a new personal access token in the form `spire_pat_<hex>`, its
// SHA-256 hash (hex) for storage, and a short display prefix for listings. The raw token
// is shown to the user once and never stored.
func GeneratePAT() (raw, hash, displayPrefix string, err error) {
	b := make([]byte, patRandomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", "", fmt.Errorf("generate pat: %w", err)
	}
	raw = PATPrefix + hex.EncodeToString(b)
	hash = HashPAT(raw)
	// Display prefix: scheme + first 6 hex chars, enough to tell tokens apart in a list
	// without revealing anything usable.
	displayPrefix = raw[:len(PATPrefix)+6]
	return raw, hash, displayPrefix, nil
}

// HashPAT returns the hex SHA-256 digest of a raw token. Lookups compare hashes, so the
// plaintext is never needed server-side after creation.
func HashPAT(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

// LooksLikePAT reports whether a bearer credential has the PAT shape. Used to route a
// request to token auth before spending a hash/DB lookup on obviously-non-PAT values.
func LooksLikePAT(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, PATPrefix) && len(v) > len(PATPrefix)+16
}

// roleRank orders roles from most to least privileged. A higher number is more powerful.
func roleRank(r types.AdminRole) int {
	switch r {
	case types.RoleSuperAdmin:
		return 4
	case types.RoleSecurityAdmin:
		return 3
	case types.RoleOperator:
		return 2
	case types.RoleAuditor:
		return 1
	default:
		return 0
	}
}

// RoleAtMost reports whether candidate is no more privileged than ceiling. Used to cap a
// token's role at its creator's role at creation time.
func RoleAtMost(candidate, ceiling types.AdminRole) bool {
	return roleRank(candidate) > 0 && roleRank(candidate) <= roleRank(ceiling)
}

// MinRole returns the less privileged of two roles. A token's EFFECTIVE role is the
// minimum of its stored role and its owner's CURRENT role, so demoting the owner
// immediately weakens every token they hold.
func MinRole(a, b types.AdminRole) types.AdminRole {
	if roleRank(a) <= roleRank(b) {
		return a
	}
	return b
}

// GenerateRecoveryCode returns one human-friendly recovery code (base32, grouped) and its
// SHA-256 hash for storage. Codes are single-use and shown once.
func GenerateRecoveryCode() (code, hash string, err error) {
	b := make([]byte, 10) // 80 bits -> 16 base32 chars
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate recovery code: %w", err)
	}
	enc := base32NoPad.EncodeToString(b) // 16 chars
	code = enc[:4] + "-" + enc[4:8] + "-" + enc[8:12] + "-" + enc[12:16]
	hash = HashRecoveryCode(code)
	return code, hash, nil
}

// HashRecoveryCode normalises (strip dashes/spaces, upper-case) then SHA-256-hashes a
// recovery code so entry formatting does not matter.
func HashRecoveryCode(code string) string {
	norm := strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}
