package db

// DeviceScope limits fleet-wide read queries (dashboard, vulnerabilities, audit log) to the
// devices carrying at least one of Tags. The zero value is unrestricted. It mirrors the
// tag scoping enforced on device routes in internal/web/scoping.go, so a tag-limited admin
// sees totals for their own devices only.
type DeviceScope struct {
	Scoped bool
	Tags   []string
	// Actor is the admin's username. The scoped audit log also includes this admin's own
	// actions that have no device target (logins, token changes).
	Actor string
}

// Unscoped is the unrestricted scope used by SUPER_ADMIN, AUDITOR and unscoped admins.
var Unscoped = DeviceScope{}

// sqlArgs returns the (scoped, tags) pair for the `(NOT $n::bool OR d.tags && $m::text[])`
// predicate. Tags is never nil, so the array parameter is never NULL.
func (s DeviceScope) sqlArgs() (bool, []string) {
	tags := s.Tags
	if tags == nil {
		tags = []string{}
	}
	return s.Scoped, tags
}
