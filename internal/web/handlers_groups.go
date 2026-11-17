package web

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/grouprule"
	"github.com/spire-uem/spire-uem/internal/types"
)

// groupFormInput is the shape accepted by the create/update endpoints (JSON or form).
type groupFormInput struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Kind        string          `json:"kind"`
	Rule        json.RawMessage `json:"rule"`
	Include     []string        `json:"include_device_ids"`
	Exclude     []string        `json:"exclude_device_ids"`
}

// ListGroupsPage renders the groups index (AUDITOR+). Counts and visible groups are scoped.
func (h *Handler) ListGroupsPage(w http.ResponseWriter, r *http.Request) {
	groups, err := h.repo.ListGroups(r.Context(), h.deviceScope(r))
	if err != nil {
		log.Printf("[web] list groups error: %v", err)
		http.Error(w, "Failed to load groups", http.StatusInternalServerError)
		return
	}
	devices, _ := h.repo.ListDevices(r.Context())
	devices = scopeDevices(r, devices)

	data := map[string]any{
		"Title":     "Groups",
		"ActiveNav": "groups",
		"CSRFToken": CSRFTokenFromContext(r.Context()),
		"AdminUser": AdminUserObjFromContext(r.Context()),
		"Groups":    groups,
		"Devices":   devices,
		"Fields":    grouprule.Fields(),
		"CanEdit":   roleCanEditGroups(r),
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(groups)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render groups template error: %v", err)
	}
}

func roleCanEditGroups(r *http.Request) bool {
	role := AdminRoleFromContext(r.Context())
	return role == types.RoleSuperAdmin || role == types.RoleSecurityAdmin
}

// parseGroupInput reads the create/update body (JSON or form).
func parseGroupInput(r *http.Request) (groupFormInput, error) {
	var in groupFormInput
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(&in); err != nil {
			return in, err
		}
		return in, nil
	}
	if err := r.ParseForm(); err != nil {
		return in, err
	}
	in.Name = r.FormValue("name")
	in.Description = r.FormValue("description")
	in.Kind = r.FormValue("kind")
	if rule := strings.TrimSpace(r.FormValue("rule")); rule != "" {
		in.Rule = json.RawMessage(rule)
	}
	in.Include = splitCSVIDs(r.FormValue("include_device_ids"))
	in.Exclude = splitCSVIDs(r.FormValue("exclude_device_ids"))
	return in, nil
}

func splitCSVIDs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// validateAndNormalizeRule parses + validates the rule with a Postgres-backed regex check,
// returning the canonical JSON (nil for no rule). A validation error maps to 400.
func (h *Handler) validateAndNormalizeRule(r *http.Request, raw json.RawMessage) (json.RawMessage, error) {
	rule, err := grouprule.Parse(raw, func(pattern string) error {
		return h.repo.ValidatePostgresRegex(r.Context(), pattern)
	})
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, nil
	}
	return rule.Normalized()
}

// CreateGroup handles POST /admin/groups (SECURITY_ADMIN+). A scoped admin's group is tagged
// with their scope so only they can edit it, and its membership is implicitly ANDed with
// their tags at materialisation time.
func (h *Handler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	in, err := parseGroupInput(r)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	kind := types.GroupKind(strings.ToLower(strings.TrimSpace(in.Kind)))
	if kind == "" {
		kind = types.GroupKindTarget
	}
	if !types.ValidGroupKind(kind) {
		http.Error(w, "kind must be 'target' or 'query'", http.StatusBadRequest)
		return
	}
	rule, err := h.validateAndNormalizeRule(r, in.Rule)
	if err != nil {
		if grouprule.IsValidationError(err) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		log.Printf("[web] group rule validation error: %v", err)
		http.Error(w, "invalid rule", http.StatusBadRequest)
		return
	}

	creatorTags, _ := AllowedTagsForContext(r)
	g, err := h.repo.CreateGroup(r.Context(), db.CreateGroupInput{
		Name:              name,
		Description:       strings.TrimSpace(in.Description),
		Kind:              kind,
		Rule:              rule,
		IncludeDeviceIDs:  in.Include,
		ExcludeDeviceIDs:  in.Exclude,
		CreatedBy:         AdminUserFromContext(r.Context()),
		CreatorScopedTags: creatorTags,
	})
	if err != nil {
		log.Printf("[web] create group error: %v", err)
		http.Error(w, "failed to create group (name may already exist)", http.StatusBadRequest)
		return
	}
	if _, _, err := h.repo.RecomputeGroupMembership(r.Context(), g.ID); err != nil {
		log.Printf("[web] warning: initial membership recompute for group %s failed: %v", g.ID, err)
	}
	h.auditGroup(r, "GROUP_CREATE", g.ID, map[string]any{"name": g.Name, "kind": string(g.Kind)})
	h.writeGroupResponse(w, r, g, http.StatusCreated)
}

// UpdateGroup handles POST /admin/groups/{id} (SECURITY_ADMIN+). A scoped admin may not edit
// a group created by an unscoped admin, and may only edit their own scoped groups.
func (h *Handler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := h.repo.GetGroupByID(r.Context(), id)
	if err != nil {
		http.Error(w, "failed to load group", http.StatusInternalServerError)
		return
	}
	if existing == nil {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	if !h.mayEditGroup(r, existing) {
		http.Error(w, "you may not edit this group (created by an administrator outside your tag scope)", http.StatusForbidden)
		return
	}

	in, err := parseGroupInput(r)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = existing.Name
	}
	kind := types.GroupKind(strings.ToLower(strings.TrimSpace(in.Kind)))
	if kind == "" {
		kind = existing.Kind
	}
	if !types.ValidGroupKind(kind) {
		http.Error(w, "kind must be 'target' or 'query'", http.StatusBadRequest)
		return
	}
	rule, err := h.validateAndNormalizeRule(r, in.Rule)
	if err != nil {
		if grouprule.IsValidationError(err) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, "invalid rule", http.StatusBadRequest)
		return
	}
	g, err := h.repo.UpdateGroup(r.Context(), id, db.CreateGroupInput{
		Name:             name,
		Description:      strings.TrimSpace(in.Description),
		Kind:             kind,
		Rule:             rule,
		IncludeDeviceIDs: in.Include,
		ExcludeDeviceIDs: in.Exclude,
	})
	if err != nil {
		log.Printf("[web] update group error: %v", err)
		http.Error(w, "failed to update group", http.StatusBadRequest)
		return
	}
	if g == nil {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	if _, _, err := h.repo.RecomputeGroupMembership(r.Context(), g.ID); err != nil {
		log.Printf("[web] warning: membership recompute after update of group %s failed: %v", g.ID, err)
	}
	h.auditGroup(r, "GROUP_UPDATE", g.ID, map[string]any{"name": g.Name, "kind": string(g.Kind)})
	h.writeGroupResponse(w, r, g, http.StatusOK)
}

// DeleteGroup handles DELETE/POST /admin/groups/{id}/delete (SECURITY_ADMIN+). Refused when
// any policy references the group; the referencing policy names are returned.
func (h *Handler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := h.repo.GetGroupByID(r.Context(), id)
	if err != nil || existing == nil {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	if !h.mayEditGroup(r, existing) {
		http.Error(w, "you may not delete this group", http.StatusForbidden)
		return
	}
	if err := h.repo.DeleteGroup(r.Context(), id); err != nil {
		if ref, ok := err.(*db.ErrGroupReferenced); ok {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":    "group_referenced",
				"message":  "This group is referenced by policies and cannot be deleted.",
				"policies": ref.PolicyNames,
			})
			return
		}
		log.Printf("[web] delete group error: %v", err)
		http.Error(w, "failed to delete group", http.StatusInternalServerError)
		return
	}
	h.auditGroup(r, "GROUP_DELETE", id, map[string]any{"name": existing.Name})
	if strings.Contains(r.Header.Get("Accept"), "application/json") || r.Header.Get("HX-Request") == "true" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/admin/groups", http.StatusSeeOther)
}

// PreviewGroup handles POST /admin/groups/preview (SECURITY_ADMIN+): evaluate an unsaved
// rule and return count + first 50 devices, scoped to the requesting admin.
func (h *Handler) PreviewGroup(w http.ResponseWriter, r *http.Request) {
	in, err := parseGroupInput(r)
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	rule, err := h.validateAndNormalizeRule(r, in.Rule)
	if err != nil {
		if grouprule.IsValidationError(err) {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_rule", "message": err.Error()})
			return
		}
		http.Error(w, "invalid rule", http.StatusBadRequest)
		return
	}
	res, err := h.repo.PreviewGroupRule(r.Context(), rule, in.Include, in.Exclude, h.deviceScope(r))
	if err != nil {
		log.Printf("[web] preview group rule error: %v", err)
		http.Error(w, "failed to evaluate rule", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(res)
}

// GroupMembers handles GET /admin/groups/{id}/members (AUDITOR+), scoped.
func (h *Handler) GroupMembers(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	members, err := h.repo.ListGroupMembers(r.Context(), id, h.deviceScope(r))
	if err != nil {
		http.Error(w, "failed to load members", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(members)
}

// GroupHistory handles GET /admin/groups/{id}/history (AUDITOR+).
func (h *Handler) GroupHistory(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	events, err := h.repo.ListGroupHistory(r.Context(), id, 100)
	if err != nil {
		http.Error(w, "failed to load history", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(events)
}

// mayEditGroup enforces the group-edit authority for the request's admin.
func (h *Handler) mayEditGroup(r *http.Request, g *types.DeviceGroup) bool {
	return GroupEditAllowed(AdminUserObjFromContext(r.Context()), g)
}

func (h *Handler) writeGroupResponse(w http.ResponseWriter, r *http.Request, g *types.DeviceGroup, status int) {
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") || strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(g)
		return
	}
	http.Redirect(w, r, "/admin/groups", http.StatusSeeOther)
}

func (h *Handler) auditGroup(r *http.Request, action, target string, details map[string]any) {
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), AdminUserFromContext(r.Context()), action, target, r.RemoteAddr, details)
	}
}
