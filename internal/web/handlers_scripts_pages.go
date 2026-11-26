package web

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/types"
)

// HTML admin pages for reusable scripts and custom sensors.
//
// The pages live at the same URLs as the JSON API and are chosen by content negotiation:
// HTML is rendered ONLY when the Accept header names text/html. Every other request
// (curl's "*/*", an empty Accept, application/json, PAT clients, the E2E suite) gets exactly
// the JSON it always got. Buttons rendered here call the existing JSON mutation routes, whose
// RBAC and CSRF checks remain the authority; the Can* flags only decide what is drawn.

// wantsHTML reports whether the client explicitly asked for an HTML page.
func wantsHTML(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

func roleCanEditScripts(r *http.Request) bool {
	role := AdminRoleFromContext(r.Context())
	return role == types.RoleSuperAdmin || role == types.RoleSecurityAdmin
}

func roleCanRunScripts(r *http.Request) bool {
	role := AdminRoleFromContext(r.Context())
	return role == types.RoleSuperAdmin || role == types.RoleSecurityAdmin || role == types.RoleOperator
}

// scriptParamView is a parameter as rendered. A secret parameter never carries a default
// value into the page: only the fact that one is set.
type scriptParamView struct {
	Name       string
	Type       types.ScriptParamType
	Required   bool
	Secret     bool
	Default    string // empty for secret parameters
	HasDefault bool
	Help       string
}

type scriptVersionView struct {
	types.ScriptVersion
	IsCurrent bool
	ParamView []scriptParamView
}

func paramViews(params []types.ScriptParam) []scriptParamView {
	out := make([]scriptParamView, 0, len(params))
	for _, p := range params {
		v := scriptParamView{Name: p.Name, Type: p.Type, Required: p.Required, Secret: p.Secret,
			HasDefault: p.Default != "", Help: p.Help}
		if !p.Secret {
			v.Default = p.Default
		}
		out = append(out, v)
	}
	return out
}

// sensorView adds a plain-string ring to a sensor for template comparisons.
type sensorView struct {
	*types.Sensor
	Ring string
}

func (h *Handler) baseScriptsData(r *http.Request, view string) map[string]any {
	return map[string]any{
		"Title":     "Scripts",
		"ActiveNav": "scripts",
		"View":      view,
		"CSRFToken": CSRFTokenFromContext(r.Context()),
		"AdminUser": AdminUserFromContext(r.Context()),
		"CanEdit":   roleCanEditScripts(r),
		"CanRun":    roleCanRunScripts(r),
	}
}

func (h *Handler) renderScriptsPage(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render scripts template error: %v", err)
	}
}

// renderScriptsListPage renders GET /admin/scripts as HTML.
func (h *Handler) renderScriptsListPage(w http.ResponseWriter, r *http.Request) {
	scripts, err := h.repo.ListScripts(r.Context())
	if err != nil {
		log.Printf("[web] list scripts error: %v", err)
		http.Error(w, "Failed to load scripts", http.StatusInternalServerError)
		return
	}
	data := h.baseScriptsData(r, "list")
	data["Scripts"] = scripts
	h.renderScriptsPage(w, data)
}

// renderScriptDetailPage renders GET /admin/scripts/{id} as HTML.
func (h *Handler) renderScriptDetailPage(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s, err := h.repo.GetScript(r.Context(), id)
	if err != nil || s == nil {
		http.Error(w, "Script not found", http.StatusNotFound)
		return
	}
	versions, err := h.repo.ListScriptVersions(r.Context(), id)
	if err != nil {
		log.Printf("[web] list script versions error: %v", err)
		http.Error(w, "Failed to load script versions", http.StatusInternalServerError)
		return
	}
	vviews := make([]scriptVersionView, 0, len(versions))
	for _, v := range versions {
		vviews = append(vviews, scriptVersionView{
			ScriptVersion: v,
			IsCurrent:     s.CurrentVersionID != nil && *s.CurrentVersionID == v.ID,
			ParamView:     paramViews(v.Params),
		})
	}
	data := h.baseScriptsData(r, "detail")
	data["Script"] = s
	data["Versions"] = vviews
	if s.CurrentVersion != nil {
		data["CurrentParams"] = paramViews(s.CurrentVersion.Params)
	}

	// Recent runs: only devices inside the viewer's tag scope. A failure here degrades to
	// an empty table rather than hiding the script itself.
	runs, rerr := h.repo.ListScriptRunsForScript(r.Context(), id, 50, h.deviceScope(r))
	if rerr != nil {
		log.Printf("[web] list script runs error: %v", rerr)
		runs = nil
	}
	data["Runs"] = runs

	if data["CanRun"].(bool) {
		devices, _ := h.repo.ListDevices(r.Context())
		devices = scopeDevices(r, devices)
		approved := make([]types.Device, 0, len(devices))
		for _, d := range devices {
			if d.Status == types.StatusApproved {
				approved = append(approved, d)
			}
		}
		data["Devices"] = approved
		groups, _ := h.repo.ListGroups(r.Context(), h.deviceScope(r))
		data["Groups"] = groups
		data["Rings"] = []types.DeploymentRing{types.RingCanary, types.RingBeta, types.RingPilot, types.RingProduction}
	}
	h.renderScriptsPage(w, data)
}

// renderSensorsPage renders GET /admin/sensors as HTML.
func (h *Handler) renderSensorsPage(w http.ResponseWriter, r *http.Request) {
	sensors, err := h.repo.ListSensors(r.Context())
	if err != nil {
		log.Printf("[web] list sensors error: %v", err)
		http.Error(w, "Failed to load sensors", http.StatusInternalServerError)
		return
	}
	scripts, _ := h.repo.ListScripts(r.Context())
	names := map[string]string{}
	type opt struct {
		VersionID string
		Label     string
	}
	opts := make([]opt, 0, len(scripts))
	for _, s := range scripts {
		names[s.ID] = s.Name
		if s.CurrentVersion == nil {
			continue
		}
		label := s.Name + " v" + strconv.Itoa(s.CurrentVersion.Version)
		opts = append(opts, opt{VersionID: s.CurrentVersion.ID, Label: label})
	}
	devices, _ := h.repo.ListDevices(r.Context())
	devices = scopeDevices(r, devices)

	data := h.baseScriptsData(r, "sensors")
	views := make([]sensorView, 0, len(sensors))
	for _, sn := range sensors {
		v := sensorView{Sensor: sn}
		if sn.TargetRing != nil {
			v.Ring = string(*sn.TargetRing)
		}
		views = append(views, v)
	}
	data["Sensors"] = views
	data["ScriptOptions"] = opts
	data["Devices"] = devices
	data["Rings"] = []types.DeploymentRing{types.RingCanary, types.RingBeta, types.RingPilot, types.RingProduction}
	data["ReturnTypes"] = []types.SensorReturnType{types.SensorString, types.SensorInteger, types.SensorBoolean, types.SensorDatetime, types.SensorJSON}
	data["ScriptNames"] = names
	h.renderScriptsPage(w, data)
}
