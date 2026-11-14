package types

import "time"

// PersonalAccessToken is a scoped bearer credential owned by an admin user, used by
// scripts and API clients in place of a password. Only the SHA-256 hash is stored; the
// raw `spire_pat_...` value is shown once at creation.
type PersonalAccessToken struct {
	ID            string     `json:"id" db:"id"`
	TokenPrefix   string     `json:"token_prefix" db:"token_prefix"`
	Name          string     `json:"name" db:"name"`
	OwnerUserID   string     `json:"owner_user_id" db:"owner_user_id"`
	OwnerName     string     `json:"owner_name,omitempty" db:"owner_name"`
	OwnerUsername string     `json:"owner_username,omitempty" db:"owner_username"`
	Role          AdminRole  `json:"role" db:"role"`
	CreatedBy     string     `json:"created_by" db:"created_by"`
	ExpiresAt     time.Time  `json:"expires_at" db:"expires_at"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
	LastUsedIP    *string    `json:"last_used_ip,omitempty" db:"last_used_ip"`
	FirstUsedAt   *time.Time `json:"first_used_at,omitempty" db:"first_used_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty" db:"revoked_at"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`

	// OwnerActive and OwnerRole reflect the owner's CURRENT state, joined at read time so
	// a listing can show when a token is weakened or dead because its owner changed.
	OwnerActive bool      `json:"owner_active" db:"owner_active"`
	OwnerRole   AdminRole `json:"owner_role" db:"owner_role"`
}

// IsRevoked reports whether the token has been explicitly revoked.
func (p *PersonalAccessToken) IsRevoked() bool { return p.RevokedAt != nil }

// MFARecoveryStatus summarises how many single-use recovery codes remain for a user.
type MFARecoveryStatus struct {
	Total     int `json:"total"`
	Remaining int `json:"remaining"`
}
