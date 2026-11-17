package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/grouprule"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

// workflowRequest is the JSON body for creating/updating a workflow. It mirrors the stored
// shape but keeps trigger/schedule/condition/actions as the engine's own types.
type workflowRequest struct {
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Enabled     bool                 `json:"enabled"`
	Trigger     *workflows.Trigger   `json:"trigger,omitempty"`
	Schedule    *workflows.Schedule  `json:"schedule,omitempty"`
	Condition   json.RawMessage      `json:"condition,omitempty"`
	ThenActions []workflows.Action   `json:"then_actions,omitempty"`
	ElseActions []workflows.Action   `json:"else_actions,omitempty"`
	DryRun      bool                 `json:"dry_run"`
	CooldownSeconds int              `json:"cooldown_seconds"`
}

func (h *Handler) toWorkflow(r *http.Request, req *workflowRequest) *workflows.Workflow {
	w := &workflows.Workflow{
		Name:            strings.TrimSpace(req.Name),
		Description:     strings.TrimSpace(req.Description),
		Enabled:         req.Enabled,
		Trigger:         req.Trigger,
		Schedule:        req.Schedule,
		Condition:       req.Condition,
		ThenActions:     req.ThenActions,
		ElseActions:     req.ElseActions,
		DryRun:          req.DryRun,
		CooldownSeconds: req.CooldownSeconds,
		CreatedBy:       AdminUserFromContext(r.Context()),
	}
	// Stamp the creator's tag scope so the engine enforces it at run time.
	if tags, scoped := AllowedTagsForContext(r); scoped {
		w.CreatorScopedTags = tags
	}
	return w
}

// validateWorkflow validates a definition against the rule language and the engine's
// registered action set.
func (h *Handler) validateWorkflow(r *http.Request, w *workflows.Workflow) error {
	ruleValidator := func(raw json.RawMessage) error {
		_, err := grouprule.Parse(raw, func(pattern string) error {
			return h.repo.ValidatePostgresRegex(r.Context(), pattern)
		})
		return err
	}
	var known func(workflows.ActionType) bool
	if h.wfEngine != nil {
		reg := h.wfEngine.Registry()
		known = func(t workflows.ActionType) bool { return reg.Known(t) }
	}
	return workflows.ValidateDefinition(w, ruleValidator, known)
}

// CreateWorkflow handles POST /admin/workflows. SECURITY_ADMIN+.
func (h *Handler) CreateWorkflow(w http.ResponseWriter, r *http.Request) {
	var req workflowRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&req); err != nil {
		writeWFError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	wf := h.toWorkflow(r, &req)
	if err := h.validateWorkflow(r, wf); err != nil {
		writeWFError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := h.repo.CreateWorkflow(r.Context(), wf)
	if err != nil {
		writeWFError(w, http.StatusInternalServerError, "create failed: "+err.Error())
		return
	}
	h.auditWorkflow(r, "WORKFLOW_CREATE", id, wf.Name)
	writeJSONWF(w, http.StatusCreated, map[string]any{"id": id})
}

// UpdateWorkflow handles POST /admin/workflows/{id}. SECURITY_ADMIN+. A scoped admin may edit
// only a workflow whose creator scope overlaps theirs.
func (h *Handler) UpdateWorkflow(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := h.repo.GetWorkflow(r.Context(), id)
	if err != nil || existing == nil {
		writeWFError(w, http.StatusNotFound, "workflow not found")
		return
	}
	if !h.workflowEditAllowed(r, existing) {
		writeWFError(w, http.StatusNotFound, "workflow not found or outside your scope")
		return
	}
	var req workflowRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&req); err != nil {
		writeWFError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	wf := h.toWorkflow(r, &req)
	// Preserve the original creator scope: an edit never widens or changes who owns it.
	wf.CreatorScopedTags = existing.CreatorScopedTags
	if err := h.validateWorkflow(r, wf); err != nil {
		writeWFError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.repo.UpdateWorkflow(r.Context(), id, wf); err != nil {
		writeWFError(w, http.StatusInternalServerError, "update failed: "+err.Error())
		return
	}
	h.auditWorkflow(r, "WORKFLOW_UPDATE", id, wf.Name)
	writeJSONWF(w, http.StatusOK, map[string]any{"id": id})
}

// ToggleWorkflow handles POST /admin/workflows/{id}/toggle. SECURITY_ADMIN+.
func (h *Handler) ToggleWorkflow(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := h.repo.GetWorkflow(r.Context(), id)
	if err != nil || existing == nil || !h.workflowEditAllowed(r, existing) {
		writeWFError(w, http.StatusNotFound, "workflow not found or outside your scope")
		return
	}
	if err := h.repo.SetWorkflowEnabled(r.Context(), id, !existing.Enabled); err != nil {
		writeWFError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.auditWorkflow(r, "WORKFLOW_TOGGLE", id, existing.Name)
	writeJSONWF(w, http.StatusOK, map[string]any{"id": id, "enabled": !existing.Enabled})
}

// DeleteWorkflow handles DELETE/POST /admin/workflows/{id}/delete. SECURITY_ADMIN+.
func (h *Handler) DeleteWorkflow(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := h.repo.GetWorkflow(r.Context(), id)
	if err != nil || existing == nil || !h.workflowEditAllowed(r, existing) {
		writeWFError(w, http.StatusNotFound, "workflow not found or outside your scope")
		return
	}
	if err := h.repo.DeleteWorkflow(r.Context(), id); err != nil {
		writeWFError(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.auditWorkflow(r, "WORKFLOW_DELETE", id, existing.Name)
	writeJSONWF(w, http.StatusOK, map[string]any{"deleted": id})
}

// ListWorkflows handles GET /admin/workflows (AUDITOR+). Scoped to the admin's tags.
func (h *Handler) ListWorkflows(w http.ResponseWriter, r *http.Request) {
	wfs, err := h.repo.ListWorkflows(r.Context(), h.deviceScope(r))
	if err != nil {
		writeWFError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSONWF(w, http.StatusOK, map[string]any{"workflows": wfs})
}

// ListWorkflowRuns handles GET /admin/workflows/runs (AUDITOR+). Optional ?workflow_id=.
func (h *Handler) ListWorkflowRuns(w http.ResponseWriter, r *http.Request) {
	runs, err := h.repo.ListWorkflowRuns(r.Context(), r.URL.Query().Get("workflow_id"), 100)
	if err != nil {
		writeWFError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSONWF(w, http.StatusOK, map[string]any{"runs": runs})
}

// ListPendingApprovals handles GET /admin/workflows/approvals (SECURITY_ADMIN+ via route group).
func (h *Handler) ListPendingApprovals(w http.ResponseWriter, r *http.Request) {
	aps, err := h.repo.ListPendingApprovals(r.Context(), h.deviceScope(r))
	if err != nil {
		writeWFError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSONWF(w, http.StatusOK, map[string]any{"approvals": aps})
}

// DecideWorkflowApproval handles POST /admin/workflows/approvals/{id}/{decision} where
// decision is approve|reject. SECURITY_ADMIN+. On approve the engine resumes the parked
// actions (re-enforcing the creator's scope); on reject the run is finalized.
func (h *Handler) DecideWorkflowApproval(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	decision := strings.ToLower(chi.URLParam(r, "decision"))
	approve := decision == "approve"
	if decision != "approve" && decision != "reject" {
		writeWFError(w, http.StatusBadRequest, "decision must be approve or reject")
		return
	}
	// Scope: a scoped admin may only decide approvals whose creator scope overlaps theirs.
	pending, err := h.repo.GetPendingApproval(r.Context(), id)
	if err != nil {
		writeWFError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if pending == nil {
		writeWFError(w, http.StatusNotFound, "approval not found or already decided")
		return
	}
	if !h.approvalInScope(r, pending) {
		writeWFError(w, http.StatusNotFound, "approval not found or outside your scope")
		return
	}
	actor := AdminUserFromContext(r.Context())
	ap, err := h.repo.DecideApproval(r.Context(), id, approve, actor)
	if err != nil {
		writeWFError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if ap == nil {
		writeWFError(w, http.StatusConflict, "approval already decided or expired")
		return
	}
	h.auditWorkflow(r, "WORKFLOW_APPROVAL_"+strings.ToUpper(decision), ap.RunID, ap.WorkflowName)
	if h.wfEngine != nil {
		wf, _ := h.repo.GetWorkflow(r.Context(), ap.WorkflowID)
		if approve {
			if wf == nil {
				// Workflow deleted while paused: finalize the run without resuming.
				_ = h.repo.FinishWorkflowRun(r.Context(), ap.RunID, "FAILED", "workflow deleted before approval")
			} else {
				_ = h.wfEngine.ResumeApproved(r.Context(), *ap, wf)
			}
		} else {
			_ = h.wfEngine.RejectApproval(r.Context(), *ap, actor)
		}	}
	writeJSONWF(w, http.StatusOK, map[string]any{"run_id": ap.RunID, "decision": decision})
}

// workflowEditAllowed enforces that a scoped admin may edit only their own-scope workflows.
func (h *Handler) workflowEditAllowed(r *http.Request, wf *workflows.Workflow) bool {
	u := AdminUserObjFromContext(r.Context())
	if !userIsTagScoped(u) {
		return true
	}
	if len(wf.CreatorScopedTags) == 0 {
		return false // created by an unscoped admin; a scoped admin may not touch it
	}
	return tagsIntersect(wf.CreatorScopedTags, u.AllowedTags)
}

func (h *Handler) approvalInScope(r *http.Request, ap *workflows.Approval) bool {
	u := AdminUserObjFromContext(r.Context())
	if !userIsTagScoped(u) {
		return true
	}
	if len(ap.CreatorScopedTags) == 0 {
		return false
	}
	return tagsIntersect(ap.CreatorScopedTags, u.AllowedTags)
}

func (h *Handler) auditWorkflow(r *http.Request, action, id, name string) {
	if h.auditor == nil {
		return
	}
	_, _, _ = h.auditor.Emit(r.Context(), AdminUserFromContext(r.Context()), action, id, r.RemoteAddr,
		map[string]any{"workflow": name})
}

func writeWFError(w http.ResponseWriter, code int, msg string) {
	writeJSONWF(w, code, map[string]any{"error": msg})
}

func writeJSONWF(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
