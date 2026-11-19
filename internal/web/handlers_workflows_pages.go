package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/grouprule"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

// The HTML pages for workflows are served at the SAME URLs as the JSON API and use the same
// repo calls with the same scope. Content negotiation: HTML only when the client's Accept
// header asks for text/html; everything else (curl's */*, application/json, no header) gets
// exactly the JSON the API always returned.
func wantsHTML(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

// roleCanEditWorkflows mirrors the router: mutations and approvals are SECURITY_ADMIN+.
func roleCanEditWorkflows(r *http.Request) bool {
	role := AdminRoleFromContext(r.Context())
	return role == types.RoleSuperAdmin || role == types.RoleSecurityAdmin
}

// eventFieldHints documents the payload fields each event kind carries (the trigger filter
// matches on equality against these keys).
var eventFieldHints = map[workflows.EventKind]string{
	workflows.EventAttributeChanged:    "key, old, new, source",
	workflows.EventComplianceChanged:   "policy, from, to",
	workflows.EventCVEMatched:          "id, urgency",
	workflows.EventDeviceOffline:       "offline_minutes",
	workflows.EventPatchFailed:         "last_patch_status",
	workflows.EventAgentUpdateFailed:   "status, target_version",
	workflows.EventAttestationFailed:   "reason",
	workflows.EventBaselineMismatch:    "reason",
	workflows.EventActiveSessionChange: "old, new",
	workflows.EventPrimaryAddrChange:   "old, new",
}

// workflowActionOrder is the order the editor offers action types in.
var workflowActionOrder = []workflows.ActionType{
	workflows.ActionAddTag, workflows.ActionRemoveTag, workflows.ActionSetRing,
	workflows.ActionGroupInclude, workflows.ActionGroupExclude, workflows.ActionRunScript,
	workflows.ActionSendAlert, workflows.ActionLock, workflows.ActionQuarantine,
	workflows.ActionRequireApproval, db.ActionStartCampaign,
}

type wfIDName struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type wfKindInfo struct {
	Kind   string `json:"kind"`
	Fields string `json:"fields"`
}

// wfEditView is a workflow in the exact request shape the create/update endpoints accept, so
// the editor round-trips a stored definition without translation.
type wfEditView struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	Description     string              `json:"description"`
	Enabled         bool                `json:"enabled"`
	Trigger         *workflows.Trigger  `json:"trigger,omitempty"`
	Schedule        *workflows.Schedule `json:"schedule,omitempty"`
	Condition       json.RawMessage     `json:"condition,omitempty"`
	ThenActions     []workflows.Action  `json:"then_actions"`
	ElseActions     []workflows.Action  `json:"else_actions"`
	DryRun          bool                `json:"dry_run"`
	CooldownSeconds int                 `json:"cooldown_seconds"`
}

// wfConfig is the data the editor script needs. Everything the scoped admin may pick from
// (groups, campaigns) is already scoped.
type wfConfig struct {
	EventKinds  []wfKindInfo          `json:"event_kinds"`
	ActionTypes []string              `json:"action_types"`
	Rings       []string              `json:"rings"`
	Severities  []string              `json:"severities"`
	Groups      []wfIDName            `json:"groups"`
	Scripts     []wfIDName            `json:"scripts"`
	Campaigns   []wfIDName            `json:"campaigns"`
	Fields      []grouprule.FieldInfo `json:"fields"`
	Workflows   []wfEditView          `json:"workflows"`
}

func (h *Handler) workflowActionTypes() []string {
	var out []string
	for _, t := range workflowActionOrder {
		if h.wfEngine != nil {
			if t != workflows.ActionRequireApproval && !h.wfEngine.Registry().Known(t) {
				continue
			}
		} else if t == db.ActionStartCampaign {
			continue // not registered without an engine
		}
		out = append(out, string(t))
	}
	return out
}

type wfListRow struct {
	ID          string
	Name        string
	Description string
	Enabled     bool
	DryRun      bool
	TriggerText string
	IsSchedule  bool
	ActionCount int
	Editable    bool
	HasLast     bool
	LastStatus  string
	LastDryRun  bool
	LastAt      time.Time
}

func (h *Handler) wfPageBase(r *http.Request, tab string) map[string]any {
	return map[string]any{
		"Title":     "Workflows",
		"ActiveNav": "workflows",
		"WFTab":     tab,
		"CSRFToken": CSRFTokenFromContext(r.Context()),
		"AdminUser": AdminUserFromContext(r.Context()),
		"CanEdit":   roleCanEditWorkflows(r),
	}
}

func (h *Handler) renderWF(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render workflows template error: %v", err)
	}
}

func triggerText(wf *workflows.Workflow) (string, bool) {
	if wf.Trigger != nil {
		t := string(wf.Trigger.Kind)
		if len(wf.Trigger.Filter) > 0 {
			t += " where " + kvText(wf.Trigger.Filter)
		}
		return t, false
	}
	if wf.Schedule != nil {
		s := wf.Schedule
		t := "cron " + s.Cron + " over "
		switch s.TargetKind {
		case workflows.TargetGroup:
			t += "group " + s.TargetGroup
		case workflows.TargetTags:
			t += "tags " + strings.Join(s.TargetTags, ", ")
		case workflows.TargetRing:
			t += "ring " + s.TargetRing
		}
		return t, true
	}
	return "", false
}

// kvText renders a map as sorted "k=v" pairs.
func kvText(m map[string]any) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+clip(fmt.Sprint(m[k]), 200))
	}
	return strings.Join(parts, ", ")
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func (h *Handler) renderWorkflowsList(w http.ResponseWriter, r *http.Request, wfs []workflows.Workflow) {
	ctx := r.Context()
	canEdit := roleCanEditWorkflows(r)
	ids := make([]string, len(wfs))
	for i := range wfs {
		ids[i] = wfs[i].ID
	}
	last, err := h.repo.LastWorkflowRuns(ctx, ids)
	if err != nil {
		log.Printf("[web] workflows last runs: %v", err)
	}
	rows := make([]wfListRow, 0, len(wfs))
	edits := make([]wfEditView, 0, len(wfs))
	for i := range wfs {
		wf := &wfs[i]
		tt, isSched := triggerText(wf)
		row := wfListRow{
			ID: wf.ID, Name: wf.Name, Description: wf.Description, Enabled: wf.Enabled, DryRun: wf.DryRun,
			TriggerText: tt, IsSchedule: isSched,
			ActionCount: len(wf.ThenActions) + len(wf.ElseActions),
			Editable:    canEdit && h.workflowEditAllowed(r, wf),
		}
		if l, ok := last[wf.ID]; ok {
			row.HasLast, row.LastStatus, row.LastDryRun, row.LastAt = true, l.Status, l.DryRun, l.At
		}
		rows = append(rows, row)
		if row.Editable {
			edits = append(edits, wfEditView{
				ID: wf.ID, Name: wf.Name, Description: wf.Description, Enabled: wf.Enabled,
				Trigger: wf.Trigger, Schedule: wf.Schedule, Condition: wf.Condition,
				ThenActions: nonNilActions(wf.ThenActions), ElseActions: nonNilActions(wf.ElseActions),
				DryRun: wf.DryRun, CooldownSeconds: wf.CooldownSeconds,
			})
		}
	}

	data := h.wfPageBase(r, "list")
	data["Workflows"] = rows
	if canEdit {
		data["WFConfig"] = h.buildWFConfig(r, edits)
	}
	h.renderWF(w, data)
}

func nonNilActions(a []workflows.Action) []workflows.Action {
	if a == nil {
		return []workflows.Action{}
	}
	return a
}

func (h *Handler) buildWFConfig(r *http.Request, edits []wfEditView) wfConfig {
	ctx := r.Context()
	scope := h.deviceScope(r)
	cfg := wfConfig{
		ActionTypes: h.workflowActionTypes(),
		Rings:       []string{"CANARY", "PILOT", "PRODUCTION"},
		Severities:  []string{"INFO", "WARNING", "CRITICAL"},
		Groups:      []wfIDName{}, Scripts: []wfIDName{}, Campaigns: []wfIDName{},
		Workflows: edits,
	}
	for _, k := range workflows.AllEventKinds {
		cfg.EventKinds = append(cfg.EventKinds, wfKindInfo{Kind: string(k), Fields: eventFieldHints[k]})
	}
	fields := grouprule.Fields()
	for i := range fields {
		sort.Strings(fields[i].Ops)
	}
	cfg.Fields = fields
	if gs, err := h.repo.ListGroups(ctx, scope); err == nil {
		for _, g := range gs {
			cfg.Groups = append(cfg.Groups, wfIDName{ID: g.ID, Name: g.Name})
		}
	}
	if ss, err := h.repo.ListScripts(ctx); err == nil {
		for _, s := range ss {
			cfg.Scripts = append(cfg.Scripts, wfIDName{ID: s.ID, Name: s.Name})
		}
	}
	if cs, err := h.repo.ListCampaigns(ctx, scope); err == nil {
		for _, c := range cs {
			cfg.Campaigns = append(cfg.Campaigns, wfIDName{ID: c.ID, Name: c.Name})
		}
	}
	return cfg
}

type wfRunActionRow struct {
	Seq        int
	ActionType string
	Result     string
	Detail     string
	Args       string
}

type wfRunRow struct {
	ID              string
	WorkflowName    string
	WorkflowVersion int
	DeviceID        string
	Hostname        string
	Trigger         string
	EventText       string
	HasCondition    bool
	ConditionResult bool
	Branch          string
	Status          string
	DryRun          bool
	Detail          string
	CreatedAt       time.Time
	Actions         []wfRunActionRow
}

func (h *Handler) renderWorkflowRuns(w http.ResponseWriter, r *http.Request, runs []db.WorkflowRunView) {
	ctx := r.Context()
	// The runs are already scoped by the repo call; hydrating their action rows is by run id.
	if err := h.repo.LoadWorkflowRunActions(ctx, runs); err != nil {
		log.Printf("[web] workflow run actions: %v", err)
	}
	rows := make([]wfRunRow, 0, len(runs))
	for _, v := range runs {
		row := wfRunRow{
			ID: v.ID, WorkflowName: v.WorkflowName, WorkflowVersion: v.WorkflowVersion,
			DeviceID: v.DeviceID, Hostname: v.DeviceHostname, Trigger: v.Trigger,
			Branch: v.Branch, Status: v.Status, DryRun: v.DryRun, Detail: v.Detail, CreatedAt: v.CreatedAt,
		}
		if v.ConditionResult != nil {
			row.HasCondition, row.ConditionResult = true, *v.ConditionResult
		}
		if len(v.EventFields) > 0 {
			var m map[string]any
			if json.Unmarshal(v.EventFields, &m) == nil && len(m) > 0 {
				row.EventText = kvText(m)
			}
		}
		for _, a := range v.Actions {
			row.Actions = append(row.Actions, wfRunActionRow{
				Seq: a.Seq, ActionType: a.ActionType, Result: a.Result, Detail: a.Detail,
				Args: clip(string(a.Args), 300),
			})
		}
		rows = append(rows, row)
	}

	// Filter dropdown: the workflows this admin may see (same scoped call as the list page).
	wfs, _ := h.repo.ListWorkflows(ctx, h.deviceScope(r))
	opts := make([]wfIDName, 0, len(wfs))
	for _, wf := range wfs {
		opts = append(opts, wfIDName{ID: wf.ID, Name: wf.Name})
	}
	data := h.wfPageBase(r, "runs")
	data["Runs"] = rows
	data["WorkflowOptions"] = opts
	data["FilterWorkflow"] = strings.TrimSpace(r.URL.Query().Get("workflow_id"))
	h.renderWF(w, data)
}

type wfApprovalRow struct {
	ID           string
	RunID        string
	WorkflowName string
	DeviceID     string
	Hostname     string
	ExpiresAt    time.Time
	Steps        []string
}

func (h *Handler) renderWorkflowApprovals(w http.ResponseWriter, r *http.Request, aps []workflows.Approval) {
	ids := make([]string, 0, len(aps))
	for _, a := range aps {
		if a.DeviceID != "" {
			ids = append(ids, a.DeviceID)
		}
	}
	names, _ := h.repo.DeviceHostnames(r.Context(), ids)
	rows := make([]wfApprovalRow, 0, len(aps))
	for _, a := range aps {
		row := wfApprovalRow{
			ID: a.ID, RunID: a.RunID, WorkflowName: a.WorkflowName, DeviceID: a.DeviceID,
			Hostname: names[a.DeviceID], ExpiresAt: a.ExpiresAt,
		}
		for _, act := range a.ResumeActions {
			row.Steps = append(row.Steps, describeWorkflowAction(act))
		}
		rows = append(rows, row)
	}
	data := h.wfPageBase(r, "approvals")
	data["Approvals"] = rows
	h.renderWF(w, data)
}

// describeWorkflowAction renders what an action will do, for the approval screen.
func describeWorkflowAction(a workflows.Action) string {
	switch a.Type {
	case workflows.ActionAddTag:
		return fmt.Sprintf("Add tag %q", a.Tag)
	case workflows.ActionRemoveTag:
		return fmt.Sprintf("Remove tag %q", a.Tag)
	case workflows.ActionSetRing:
		return fmt.Sprintf("Set patch ring to %s", a.Ring)
	case workflows.ActionGroupInclude:
		return "Add the device to the include list of group " + a.GroupID
	case workflows.ActionGroupExclude:
		return "Remove the device from the include list of group " + a.GroupID
	case workflows.ActionRunScript:
		v := "latest version"
		if a.ScriptVersion > 0 {
			v = fmt.Sprintf("version %d", a.ScriptVersion)
		}
		return fmt.Sprintf("Run script %s (%s)", a.ScriptID, v)
	case workflows.ActionSendAlert:
		return fmt.Sprintf("Send %s alert %q", strings.ToUpper(a.Severity), a.Subject)
	case workflows.ActionLock:
		return "Lock the device's sessions"
	case workflows.ActionQuarantine:
		return "Quarantine the device (add the quarantine tag)"
	case workflows.ActionRequireApproval:
		return "Pause for another approval"
	case db.ActionStartCampaign:
		return "Start patch campaign " + a.Params["campaign_id"]
	}
	return "Run action " + string(a.Type)
}
