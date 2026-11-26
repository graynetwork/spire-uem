package types

import "time"

// API scopes granted to a service account. A request is allowed only when the principal
// holds the endpoint's scope AND its role cap permits the action AND, for device/group/
// campaign objects, the object is inside the principal's tag scope.
const (
	ScopeDevicesRead    = "devices:read"
	ScopeDevicesActions = "devices:actions"
	ScopeGroupsRead     = "groups:read"
	ScopeGroupsWrite    = "groups:write" // reserved: no v1 endpoint uses it yet
	ScopePoliciesRead   = "policies:read"
	ScopeCampaignsRead  = "campaigns:read"
	ScopeCampaignsWrite = "campaigns:write"
	ScopeAuditRead      = "audit:read"
	// ScopePostureRead lets a conditional-access connector read device access posture.
	ScopePostureRead = "posture:read"
)

// AllAPIScopes lists every scope a service account may hold.
var AllAPIScopes = []string{
	ScopeDevicesRead, ScopeDevicesActions, ScopeGroupsRead, ScopeGroupsWrite,
	ScopePoliciesRead, ScopeCampaignsRead, ScopeCampaignsWrite, ScopeAuditRead,
	ScopePostureRead,
}

// ValidAPIScope reports whether s is a known scope.
func ValidAPIScope(s string) bool {
	for _, v := range AllAPIScopes {
		if v == s {
			return true
		}
	}
	return false
}

// ServiceAccount is a non-human admin API principal.
type ServiceAccount struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Role        AdminRole  `json:"role"`
	AllowedTags []string   `json:"allowed_tags"`
	Scopes      []string   `json:"scopes"`
	Enabled     bool       `json:"enabled"`
	CreatedBy   string     `json:"created_by"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP  string     `json:"last_used_ip,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// ServiceAccountToken is one credential of a service account. The secret is never stored
// or returned here; only its hash lives in the database.
type ServiceAccountToken struct {
	ID               string     `json:"id"`
	ServiceAccountID string     `json:"service_account_id"`
	TokenID          string     `json:"token_id"` // public id embedded in the token
	Label            string     `json:"label"`
	CreatedBy        string     `json:"created_by"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt       *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP       string     `json:"last_used_ip,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	// SecretHash is populated only by the authentication lookup.
	SecretHash string `json:"-"`
}

// Active reports whether the token is usable at now (not revoked, not expired).
func (t ServiceAccountToken) Active(now time.Time) bool {
	if t.RevokedAt != nil {
		return false
	}
	return t.ExpiresAt == nil || now.Before(*t.ExpiresAt)
}
