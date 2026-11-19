package web

import (
	"context"
	"fmt"
	"sort"

	"github.com/spire-uem/spire-uem/internal/workflows"
)

// Workflow definitions are stored as plain JSON and are readable by AUDITORs, so a run_script
// action must never carry a value for a secret script parameter. Secret values belong in the
// script's own (sealed at run time, redacted in responses) default, or in an on-demand run.
//
// A parameter counts as secret if ANY version of the script declares it secret, so a later
// version that marks an existing parameter secret is covered too.

// secretScriptParams returns the parameter names declared secret by any version of a script.
func (h *Handler) secretScriptParams(ctx context.Context, scriptID string, cache map[string]map[string]bool) map[string]bool {
	if set, ok := cache[scriptID]; ok {
		return set
	}
	set := map[string]bool{}
	versions, err := h.repo.ListScriptVersions(ctx, scriptID)
	if err == nil {
		for _, v := range versions {
			for _, p := range v.Params {
				if p.Secret {
					set[p.Name] = true
				}
			}
		}
	}
	cache[scriptID] = set
	return set
}

// checkWorkflowScriptSecrets refuses a definition that sets a secret script parameter.
func (h *Handler) checkWorkflowScriptSecrets(ctx context.Context, wf *workflows.Workflow) error {
	cache := map[string]map[string]bool{}
	for _, list := range [][]workflows.Action{wf.ThenActions, wf.ElseActions} {
		for _, a := range list {
			if a.Type != workflows.ActionRunScript || len(a.Params) == 0 {
				continue
			}
			secret := h.secretScriptParams(ctx, a.ScriptID, cache)
			var bad []string
			for name := range a.Params {
				if secret[name] {
					bad = append(bad, name)
				}
			}
			if len(bad) > 0 {
				sort.Strings(bad)
				return fmt.Errorf("run_script: secret parameters cannot be set in a workflow (%v); set a default on the script instead, which is stored sealed per run and never returned", bad)
			}
		}
	}
	return nil
}

// redactWorkflowActions returns a copy of actions with values for secret script parameters
// removed. It covers definitions saved before checkWorkflowScriptSecrets existed, and
// parameters a later script version marked secret.
func (h *Handler) redactWorkflowActions(ctx context.Context, actions []workflows.Action, cache map[string]map[string]bool) []workflows.Action {
	if actions == nil {
		return nil
	}
	out := make([]workflows.Action, len(actions))
	for i, a := range actions {
		if a.Type == workflows.ActionRunScript && len(a.Params) > 0 {
			secret := h.secretScriptParams(ctx, a.ScriptID, cache)
			params := make(map[string]string, len(a.Params))
			for k, v := range a.Params {
				if !secret[k] {
					params[k] = v
				}
			}
			a.Params = params
		}
		out[i] = a
	}
	return out
}

func (h *Handler) redactWorkflows(ctx context.Context, wfs []workflows.Workflow) []workflows.Workflow {
	cache := map[string]map[string]bool{}
	out := make([]workflows.Workflow, len(wfs))
	for i, wf := range wfs {
		wf.ThenActions = h.redactWorkflowActions(ctx, wf.ThenActions, cache)
		wf.ElseActions = h.redactWorkflowActions(ctx, wf.ElseActions, cache)
		out[i] = wf
	}
	return out
}

func (h *Handler) redactApprovals(ctx context.Context, aps []workflows.Approval) []workflows.Approval {
	cache := map[string]map[string]bool{}
	out := make([]workflows.Approval, len(aps))
	for i, ap := range aps {
		ap.ResumeActions = h.redactWorkflowActions(ctx, ap.ResumeActions, cache)
		out[i] = ap
	}
	return out
}
