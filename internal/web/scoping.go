package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
)

// Operator scoping by device tag.
//
// OPERATOR and SECURITY_ADMIN admins may be limited to the devices carrying any of a set of
// allowed tags. An empty allowed-tag set means unrestricted. SUPER_ADMIN is never scoped
// (full access); AUDITOR is read-only and is likewise never scoped here. Enforcement lives
// in ONE place — the helpers below — and every device-targeted admin route goes through
// DeviceScopeMiddleware so a new route cannot silently bypass scoping. A test
// (scoping_routes_test.go) enumerates the device routes and fails if one is unscoped.

// userIsTagScoped reports whether the given user's actions must be filtered by allowed_tags.
func userIsTagScoped(u *types.AdminUser) bool {
	if u == nil {
		// No DB-backed user object (e.g. the static break-glass SUPER_ADMIN via Basic Auth).
		// The break-glass account is unrestricted by design.
		return false
	}
	if len(u.AllowedTags) == 0 {
		return false
	}
	switch u.Role {
	case types.RoleOperator, types.RoleSecurityAdmin:
		return true
	default:
		// SUPER_ADMIN and AUDITOR are never scoped.
		return false
	}
}

// tagsIntersect reports whether any device tag is in the allowed set (case-sensitive match,
// tags are already normalized lowercase on write).
func tagsIntersect(deviceTags, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		set[a] = struct{}{}
	}
	for _, t := range deviceTags {
		if _, ok := set[t]; ok {
			return true
		}
	}
	return false
}

// AdminMayAccessDeviceTags is the single authority deciding whether an admin may act on a
// device with the given tags. Used by the middleware and by any handler that already holds
// the device (so it need not refetch).
func AdminMayAccessDeviceTags(u *types.AdminUser, deviceTags []string) bool {
	if !userIsTagScoped(u) {
		return true
	}
	return tagsIntersect(deviceTags, u.AllowedTags)
}

// AllowedTagsForContext returns the scoping tags in force for the request, and whether the
// request is scoped at all. Used to filter list views.
func AllowedTagsForContext(r *http.Request) (tags []string, scoped bool) {
	u := AdminUserObjFromContext(r.Context())
	if !userIsTagScoped(u) {
		return nil, false
	}
	return u.AllowedTags, true
}

// DeviceScopeMiddleware enforces operator tag scoping on every device-targeted admin route.
// It resolves the {id} URL param to a device, and if the authenticated admin is tag-scoped
// and the device carries none of their allowed tags, it denies the request as 404 (the
// device is invisible to this operator — a 403 would confirm the device exists). Routes
// without an {id} param are passed through unchanged (list views filter themselves).
func (h *Handler) DeviceScopeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This middleware runs at the /admin GROUP level, BEFORE chi has resolved the final
		// route, so chi.URLParam(r,"id") and RouteContext.RoutePattern() are not yet
		// populated reliably here. Derive the target device id straight from the URL path
		// instead: device routes are exactly /admin/devices/{id} and
		// /admin/devices/{id}/<action>. /admin/devices (the list) has no id segment.
		deviceID, isDeviceRoute := deviceIDFromPath(r.URL.Path)
		if !isDeviceRoute {
			next.ServeHTTP(w, r)
			return
		}
		u := AdminUserObjFromContext(r.Context())
		if !userIsTagScoped(u) {
			next.ServeHTTP(w, r)
			return
		}
		dev, err := h.repo.GetDeviceByID(r.Context(), deviceID)
		if err != nil {
			http.Error(w, "Failed to resolve device", http.StatusInternalServerError)
			return
		}
		if dev == nil || !tagsIntersect(dev.Tags, u.AllowedTags) {
			denyOutOfScope(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// deviceIDFromPath extracts the device id from a device-targeted admin URL path. It returns
// (id, true) for /admin/devices/{id} and /admin/devices/{id}/<anything>, and ("", false)
// for the list page /admin/devices (no id) and any non-device path. Keying off the URL path
// makes scoping independent of chi's post-routing state, which is not yet populated when
// this middleware runs at the /admin group level.
func deviceIDFromPath(p string) (string, bool) {
	const prefix = "/admin/devices/"
	if !strings.HasPrefix(p, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(p, prefix)
	// The id is the first path segment; anything after a '/' is the action.
	id := rest
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		id = rest[:i]
	}
	if id == "" {
		return "", false
	}
	return id, true
}

// denyOutOfScope writes a 404 for an out-of-scope device (hides existence).
func denyOutOfScope(w http.ResponseWriter, r *http.Request) {
	isAPIOrHTMX := r.Header.Get("HX-Request") == "true" ||
		strings.Contains(r.Header.Get("Accept"), "application/json") ||
		r.Method != http.MethodGet
	if isAPIOrHTMX {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":   "not_found",
			"message": "device not found or outside your assigned tag scope",
		})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, `<!DOCTYPE html><html><body style="background:#0a0e17;color:#f87171;font-family:sans-serif;padding:40px;text-align:center;"><h2>404 Not Found</h2><p>This device does not exist or is outside your assigned tag scope.</p><p><a href="/admin/devices" style="color:#60a5fa;">Return to Devices</a></p></body></html>`)
}

// ScopedUpdatedTagsAllowed guards tag edits so a scoped operator cannot move a device out of
// their own scope (tag escape). A scoped operator may set any tags as long as the result
// still carries at least one of their allowed tags; an empty or out-of-scope result is
// refused. Unscoped admins may set any tags. Returns an error message when refused.
func ScopedUpdatedTagsAllowed(u *types.AdminUser, newTags []string) (ok bool, reason string) {
	if !userIsTagScoped(u) {
		return true, ""
	}
	if tagsIntersect(newTags, u.AllowedTags) {
		return true, ""
	}
	return false, "you may not remove all of your in-scope tags from a device; the new tag set must keep at least one of your assigned tags"
}
