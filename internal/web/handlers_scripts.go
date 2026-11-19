package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// Admin JSON API for reusable scripts, custom sensors and SCRIPT_POLICY runs.
//
// RBAC is enforced by the route groups in router.go: create/edit/delete are SECURITY_ADMIN+,
// running a script is OPERATOR+. Tag scoping is enforced here for run targeting (a scoped
// admin can only reach devices carrying their tags). Every mutation is audited with the acting
// admin via h.auditor.

func (h *Handler) audit(r *http.Request, action, targetID string, details map[string]any) {
	if h.auditor == nil {
		return
	}
	actor := AdminUserFromContext(r.Context())
	if actor == "" {
		actor = "admin"
	}
	_, _, _ = h.auditor.Emit(r.Context(), actor, action, targetID, r.RemoteAddr, details)
}

func writeJSONResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, status int, msg string) {
	writeJSONResp(w, status, map[string]string{"error": msg})
}

// redactScript and redactVersions strip secret parameter defaults from API responses. The
// list/detail reads are AUDITOR+, and a secret default is as sensitive as a secret run value.
func redactScript(s *types.Script) *types.Script {
	if s == nil || s.CurrentVersion == nil {
		return s
	}
	cp := *s
	v := *s.CurrentVersion
	v.Params = types.RedactSecretDefaults(v.Params)
	cp.CurrentVersion = &v
	return &cp
}

func redactVersion(v *types.ScriptVersion) *types.ScriptVersion {
	if v == nil {
		return nil
	}
	cp := *v
	cp.Params = types.RedactSecretDefaults(v.Params)
	return &cp
}

func redactVersions(vs []types.ScriptVersion) []types.ScriptVersion {
	out := make([]types.ScriptVersion, len(vs))
	for i := range vs {
		out[i] = *redactVersion(&vs[i])
	}
	return out
}

// clearDefaultSet drops the response-only flag if a client echoes it back in a request.
func clearDefaultSet(params []types.ScriptParam) {
	for i := range params {
		params[i].DefaultSet = false
	}
}

// scriptCreateRequest is the body for creating or updating a script (+ its first/next version).
type scriptCreateRequest struct {
	Name           string               `json:"name"`
	Description    string               `json:"description"`
	Interpreter    types.ScriptInterpreter `json:"interpreter"`
	RunAs          types.ScriptRunAs    `json:"run_as"`
	TimeoutSeconds int                  `json:"timeout_seconds"`
	MaxOutputBytes int                  `json:"max_output_bytes"`
	Content        string               `json:"content"`
	Params         []types.ScriptParam  `json:"params"`
}

// ListScripts GET /admin/scripts — all scripts with current versions.
func (h *Handler) ListScripts(w http.ResponseWriter, r *http.Request) {
	if wantsHTML(r) {
		h.renderScriptsListPage(w, r)
		return
	}
	scripts, err := h.repo.ListScripts(r.Context())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to list scripts")
		return
	}
	out := make([]*types.Script, len(scripts))
	for i, sc := range scripts {
		out[i] = redactScript(sc)
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"scripts": out})
}

// GetScript GET /admin/scripts/{id} — one script + version history.
func (h *Handler) GetScript(w http.ResponseWriter, r *http.Request) {
	if wantsHTML(r) {
		h.renderScriptDetailPage(w, r)
		return
	}
	id := chi.URLParam(r, "id")
	s, err := h.repo.GetScript(r.Context(), id)
	if err != nil || s == nil {
		jsonErr(w, http.StatusNotFound, "script not found")
		return
	}
	versions, _ := h.repo.ListScriptVersions(r.Context(), id)
	writeJSONResp(w, http.StatusOK, map[string]any{"script": redactScript(s), "versions": redactVersions(versions)})
}

// CreateScript POST /admin/scripts — SECURITY_ADMIN+.
func (h *Handler) CreateScript(w http.ResponseWriter, r *http.Request) {
	var req scriptCreateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	s := &types.Script{
		Name: strings.TrimSpace(req.Name), Description: req.Description,
		Interpreter: req.Interpreter, RunAs: req.RunAs,
		TimeoutSeconds: req.TimeoutSeconds, MaxOutputBytes: req.MaxOutputBytes,
	}
	clearDefaultSet(req.Params)
	actor := AdminUserFromContext(r.Context())
	created, err := h.repo.CreateScript(r.Context(), s, req.Content, req.Params, actor)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "SCRIPT_CREATE", created.ID, map[string]any{"name": created.Name, "interpreter": string(created.Interpreter), "run_as": string(created.RunAs)})
	writeJSONResp(w, http.StatusCreated, map[string]any{"script": redactScript(created)})
}

// UpdateScriptMeta POST /admin/scripts/{id} — change metadata only. SECURITY_ADMIN+.
func (h *Handler) UpdateScriptMeta(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := h.repo.GetScript(r.Context(), id)
	if err != nil || existing == nil {
		jsonErr(w, http.StatusNotFound, "script not found")
		return
	}
	var req scriptCreateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	existing.Name = strings.TrimSpace(req.Name)
	existing.Description = req.Description
	existing.Interpreter = req.Interpreter
	existing.RunAs = req.RunAs
	existing.TimeoutSeconds = req.TimeoutSeconds
	existing.MaxOutputBytes = req.MaxOutputBytes
	if err := h.repo.UpdateScriptMeta(r.Context(), existing); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "SCRIPT_UPDATE", id, map[string]any{"name": existing.Name})
	writeJSONResp(w, http.StatusOK, map[string]any{"script": redactScript(existing)})
}

// AddScriptVersion POST /admin/scripts/{id}/versions — immutable new version. SECURITY_ADMIN+.
func (h *Handler) AddScriptVersion(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req scriptCreateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	clearDefaultSet(req.Params)
	actor := AdminUserFromContext(r.Context())
	v, err := h.repo.AddScriptVersion(r.Context(), id, req.Content, req.Params, actor)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "SCRIPT_VERSION_ADD", id, map[string]any{"version": v.Version, "sha256": v.SHA256})
	writeJSONResp(w, http.StatusCreated, map[string]any{"version": redactVersion(v)})
}

// SetCurrentScriptVersion POST /admin/scripts/{id}/versions/{versionID}/current — SECURITY_ADMIN+.
func (h *Handler) SetCurrentScriptVersion(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	versionID := chi.URLParam(r, "versionID")
	if err := h.repo.SetCurrentScriptVersion(r.Context(), id, versionID); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "SCRIPT_VERSION_CURRENT", id, map[string]any{"version_id": versionID})
	writeJSONResp(w, http.StatusOK, map[string]any{"status": "ok"})
}

// DeleteScript DELETE /admin/scripts/{id} — SECURITY_ADMIN+.
func (h *Handler) DeleteScript(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.repo.DeleteScript(r.Context(), id); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "SCRIPT_DELETE", id, nil)
	writeJSONResp(w, http.StatusOK, map[string]any{"status": "deleted"})
}

// runScriptRequest targets a script version at devices/tags/ring with parameter values.
type runScriptRequest struct {
	VersionID string            `json:"version_id"` // optional; defaults to the script's current version
	DeviceIDs []string          `json:"device_ids,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
	Ring      string            `json:"ring,omitempty"`
	GroupID   string            `json:"group_id,omitempty"`
	Params    map[string]string `json:"params,omitempty"`
}

// RunScript POST /admin/scripts/{id}/run — OPERATOR+. Queues a run per in-scope target device.
func (h *Handler) RunScript(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req runScriptRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	script, err := h.repo.GetScript(r.Context(), id)
	if err != nil || script == nil {
		jsonErr(w, http.StatusNotFound, "script not found")
		return
	}
	versionID := strings.TrimSpace(req.VersionID)
	if versionID == "" {
		if script.CurrentVersionID == nil {
			jsonErr(w, http.StatusBadRequest, "script has no current version")
			return
		}
		versionID = *script.CurrentVersionID
	}
	v, err := h.repo.GetScriptVersion(r.Context(), versionID)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, "script version not found")
		return
	}
	plain, secret, perr := db.ResolveScriptParams(v, req.Params)
	if perr != nil {
		jsonErr(w, http.StatusBadRequest, perr.Error())
		return
	}

	// Build the target, intersected with the admin's tag scope (nil = unscoped).
	allowed, scoped := AllowedTagsForContext(r)
	target := buildScriptTarget(req, allowed, scoped)
	deviceIDs, err := h.repo.ResolveScriptTargetDevices(r.Context(), target)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(deviceIDs) == 0 {
		jsonErr(w, http.StatusBadRequest, "no in-scope approved devices matched this target")
		return
	}

	actor := AdminUserFromContext(r.Context())
	runIDs := make([]string, 0, len(deviceIDs))
	for _, dID := range deviceIDs {
		runID, qerr := h.repo.QueueScriptRun(r.Context(), dID, v, types.TriggerOnDemand, plain, secret, actor)
		if qerr != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to queue run: "+qerr.Error())
			return
		}
		runIDs = append(runIDs, runID)
		if h.hub != nil && h.hub.IsConnected(dID) {
			_ = h.hub.TriggerCheckin(dID)
		}
	}
	h.audit(r, "SCRIPT_RUN", id, map[string]any{
		"version": v.Version, "devices": len(deviceIDs), "secret_params": len(secret),
	})
	writeJSONResp(w, http.StatusCreated, map[string]any{"queued": len(runIDs), "run_ids": runIDs})
}

// buildScriptTarget constructs a db.ScriptTarget from the request + scope.
func buildScriptTarget(req runScriptRequest, allowed []string, scoped bool) db.ScriptTarget {
	t := db.ScriptTarget{DeviceIDs: req.DeviceIDs, Tags: req.Tags, GroupID: strings.TrimSpace(req.GroupID)}
	if ring := strings.TrimSpace(req.Ring); ring != "" {
		dr := types.DeploymentRing(strings.ToUpper(ring))
		t.Ring = &dr
	}
	if scoped {
		if allowed == nil {
			allowed = []string{}
		}
		t.ScopeTags = allowed
	}
	return t
}

// ListDeviceScriptRuns GET /admin/devices/{id}/script-runs — recent runs for a device.
// Device scoping is enforced by DeviceScopeMiddleware on the /admin/devices/{id} path.
func (h *Handler) ListDeviceScriptRuns(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	runs, err := h.repo.ListScriptRunsForDevice(r.Context(), id, 50)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to list runs")
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"runs": runs})
}
