package web

import (
	"fmt"
	"net/http"

	"github.com/spire-uem/spire-uem/internal/types"
)

// Policy targets decide which devices receive a policy, including root-run scripts and
// network secrets. A tag-scoped admin must therefore only be able to create or change
// policies whose reach stays inside their tags:
//   - target tags must be non-empty and every tag must be one of the admin's tags (a policy
//     matches devices carrying ANY of its tags, so one foreign tag would reach that team);
//   - every target group must be one the admin may edit (groups created in their scope carry
//     an implicit filter to their tags; fleet-wide groups do not).
// Unscoped admins are not restricted.

// tagsSubset reports whether tags is non-empty and every element is in allowed.
func tagsSubset(tags, allowed []string) bool {
	if len(tags) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		set[a] = struct{}{}
	}
	for _, t := range tags {
		if _, ok := set[t]; !ok {
			return false
		}
	}
	return true
}

// policyTargetsAllowed checks proposed targets for the requesting admin. It returns a
// message suitable for a 403 when refused.
func (h *Handler) policyTargetsAllowed(r *http.Request, tags, groupIDs []string) (bool, string) {
	u := AdminUserObjFromContext(r.Context())
	if !userIsTagScoped(u) {
		return true, ""
	}
	if !tagsSubset(tags, u.AllowedTags) {
		return false, fmt.Sprintf("A tag-scoped admin must target only their own tags (%v); fleet-wide or other teams' tags are not allowed", u.AllowedTags)
	}
	for _, id := range groupIDs {
		g, err := h.repo.GetGroupByID(r.Context(), id)
		if err != nil || g == nil {
			return false, "Unknown target group " + id
		}
		if !GroupEditAllowed(u, g) {
			return false, fmt.Sprintf("Group %q is outside your tag scope", g.Name)
		}
	}
	return true, ""
}

// policyManageAllowed checks whether the requesting admin may change an existing policy.
func (h *Handler) policyManageAllowed(r *http.Request, pol *types.Policy) (bool, string) {
	if pol == nil {
		return true, "" // the caller reports not-found
	}
	return h.policyTargetsAllowed(r, pol.TargetTags, pol.TargetGroupIDs)
}

// denyPolicyScope writes the 403 for a refused scope check.
func denyPolicyScope(w http.ResponseWriter, msg string) {
	http.Error(w, msg, http.StatusForbidden)
}
