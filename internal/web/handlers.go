package web

import (
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

//go:embed templates/*
var templatesFS embed.FS

// Handler serves the embedded Admin Web UI.
type Handler struct {
	repo *db.Repository
	tmpl *template.Template
}

// NewHandler parses the embedded HTML templates and creates a Web UI Handler.
func NewHandler(repo *db.Repository) (*Handler, error) {
	funcMap := template.FuncMap{
		"joinTags": func(tags []string) string {
			return strings.Join(tags, ", ")
		},
		"derefInt": func(p *int) int {
			if p == nil {
				return 0
			}
			return *p
		},
	}
	tmpl, err := template.New("").Funcs(funcMap).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Handler{
		repo: repo,
		tmpl: tmpl,
	}, nil
}

// RegisterRoutes mounts the public onboarding endpoints (/install.sh, /dist/*)
// and the Admin Web UI routes (/admin/* with HTTP Basic Auth) onto a chi.Router.
func (h *Handler) RegisterRoutes(r chi.Router, adminUser, adminPass string) {
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/devices", http.StatusFound)
	})

	// Publicly accessible single-command onboarding endpoints (no Basic Auth required)
	r.Get("/install.sh", h.ServeBootstrapScript)
	r.Head("/install.sh", h.ServeBootstrapScript)
	r.Get("/dist/{filename}", h.ServeDebPackage)
	r.Head("/dist/{filename}", h.ServeDebPackage)

	r.Route("/admin", func(r chi.Router) {
		r.Use(BasicAuthMiddleware(adminUser, adminPass))
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/admin/devices", http.StatusFound)
		})
		r.Get("/devices", h.ListDevicesPage)
		r.Get("/devices/{id}", h.DeviceDetail)
		r.Post("/devices/{id}/approve", h.ApproveDevice)
		r.Post("/devices/{id}/revoke", h.RevokeDevice)
		r.Post("/devices/{id}/tags", h.UpdateDeviceTags)
		r.Post("/devices/{id}/commands", h.CreateDeviceCommand)
		r.Get("/policies", h.ListPoliciesPage)
		r.Post("/policies", h.CreatePolicy)
		r.Post("/policies/from-template", h.CreatePolicyFromTemplate)
		r.Post("/policies/{id}/toggle", h.TogglePolicy)
		r.Get("/compliance/export", h.ExportComplianceAudit)
		r.Head("/compliance/export", h.ExportComplianceAudit)
	})
}

// ExportComplianceAudit handles GET /admin/compliance/export?format=csv|json.
func (h *Handler) ExportComplianceAudit(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "csv"
	}

	records, err := h.repo.GetComplianceAuditSnapshot(r.Context())
	if err != nil {
		log.Printf("[web] get compliance audit snapshot error: %v", err)
		http.Error(w, "Failed to generate compliance audit snapshot", http.StatusInternalServerError)
		return
	}

	ts := time.Now().UTC().Format("20060102-150405")

	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="spire-compliance-audit-%s.json"`, ts))
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(records)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="spire-compliance-audit-%s.csv"`, ts))
	w.WriteHeader(http.StatusOK)

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"hostname",
		"hardware_uuid",
		"device_status",
		"device_tags",
		"policy_name",
		"policy_type",
		"target_tags",
		"compliance_status",
		"last_enforced_at",
		"error_message",
	})

	for _, rec := range records {
		enforcedAtStr := ""
		if rec.LastEnforcedAt != nil {
			enforcedAtStr = rec.LastEnforcedAt.UTC().Format(time.RFC3339)
		}
		_ = cw.Write([]string{
			rec.Hostname,
			rec.HardwareUUID,
			string(rec.DeviceStatus),
			strings.Join(rec.DeviceTags, ";"),
			rec.PolicyName,
			string(rec.PolicyType),
			strings.Join(rec.TargetTags, ";"),
			string(rec.ComplianceStatus),
			enforcedAtStr,
			rec.ErrorMessage,
		})
	}
	cw.Flush()
}

// ServeBootstrapScript handles GET /install.sh, dynamically replacing __SERVER_URL__ with the incoming Host header.
func (h *Handler) ServeBootstrapScript(w http.ResponseWriter, r *http.Request) {
	scriptBytes, err := os.ReadFile("packaging/bootstrap.sh")
	if err != nil {
		scriptBytes, err = templatesFS.ReadFile("templates/bootstrap.sh")
		if err != nil {
			log.Printf("[web] failed to read bootstrap.sh: %v", err)
			http.Error(w, "Bootstrap script not found", http.StatusNotFound)
			return
		}
	}

	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = "localhost:8080"
	}
	serverURL := fmt.Sprintf("%s://%s", scheme, host)

	rendered := strings.ReplaceAll(string(scriptBytes), "__SERVER_URL__", serverURL)
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(rendered))
	}
}

// ServeDebPackage handles GET/HEAD /dist/{filename}, serving dist/*.deb from the filesystem.
func (h *Handler) ServeDebPackage(w http.ResponseWriter, r *http.Request) {
	filename := filepath.Base(chi.URLParam(r, "filename"))
	if filename == "" || filename == "." || filename == ".." || !strings.HasSuffix(filename, ".deb") {
		http.Error(w, "Invalid package filename", http.StatusBadRequest)
		return
	}

	debPath := filepath.Join("dist", filename)
	info, err := os.Stat(debPath)
	if err != nil || info.IsDir() {
		http.Error(w, "Package not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/vnd.debian.binary-package")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	http.ServeFile(w, r, debPath)
}

// ListDevicesPage renders /admin/devices with fleet compliance analytics and search/tag/status filtering.
func (h *Handler) ListDevicesPage(w http.ResponseWriter, r *http.Request) {
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	tag := strings.TrimSpace(r.URL.Query().Get("tag"))
	status := strings.TrimSpace(r.URL.Query().Get("status"))

	summary, err := h.repo.GetFleetSummary(r.Context())
	if err != nil {
		log.Printf("[web] get fleet summary error: %v", err)
		summary = &types.FleetSummary{CompliancePercent: 100}
	}

	devices, err := h.repo.ListDevicesFiltered(r.Context(), search, tag, status)
	if err != nil {
		log.Printf("[web] list devices filtered error: %v", err)
		http.Error(w, "Failed to load devices", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"Title":        "Devices",
		"ActiveNav":    "devices",
		"Devices":      devices,
		"Summary":      summary,
		"FilterSearch": search,
		"FilterTag":    tag,
		"FilterStatus": status,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Header.Get("HX-Target") == "devices-table" {
		if err := h.tmpl.ExecuteTemplate(w, "devices_table", data); err != nil {
			log.Printf("[web] render devices_table fragment error: %v", err)
		}
		return
	}

	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render devices template error: %v", err)
	}
}

// DeviceDetail handles GET /admin/devices/{id} and returns an HTMX inspection drawer fragment.
func (h *Handler) DeviceDetail(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	h.renderDeviceDetail(w, r, id)
}

func (h *Handler) renderDeviceDetail(w http.ResponseWriter, r *http.Request, id string) {
	dev, err := h.repo.GetDeviceByID(r.Context(), id)
	if err != nil {
		log.Printf("[web] get device detail %s error: %v", id, err)
		http.Error(w, "Failed to load device details", http.StatusInternalServerError)
		return
	}
	if dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	var reported types.ReportedState
	if len(dev.ReportedState) > 0 {
		_ = json.Unmarshal(dev.ReportedState, &reported)
	}

	policies, err := h.repo.GetDevicePolicyDetails(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[web] get device policy details %s error: %v", id, err)
		http.Error(w, "Failed to load device policy compliance", http.StatusInternalServerError)
		return
	}

	commands, err := h.repo.ListDeviceCommands(r.Context(), dev.ID)
	if err != nil {
		log.Printf("[web] list device commands %s error: %v", id, err)
	}

	compliantCount := 0
	pendingCount := 0
	failedCount := 0
	for _, p := range policies {
		switch p.ComplianceStatus {
		case types.ComplianceCompliant:
			compliantCount++
		case types.CompliancePending:
			pendingCount++
		case types.ComplianceRevoked:
			// Revoked policies are historical/inactive
		default:
			failedCount++
		}
	}

	activeSession := strings.TrimSpace(reported.ActiveSession)
	if activeSession == "" {
		activeSession = "none (headless / no seat0 session)"
	}

	data := map[string]any{
		"Device":         dev,
		"PackageCount":   len(reported.Packages),
		"Packages":       reported.Packages,
		"ActiveSession":  activeSession,
		"CheckedInAt":    reported.CheckedInAt,
		"PolicyDetails":  policies,
		"Commands":       commands,
		"CompliantCount": compliantCount,
		"PendingCount":   pendingCount,
		"FailedCount":    failedCount,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "device_detail_drawer", data); err != nil {
		log.Printf("[web] render device_detail_drawer error: %v", err)
	}
}

// CreateDeviceCommand handles POST /admin/devices/{id}/commands.
func (h *Handler) CreateDeviceCommand(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var commandStr string

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Command string `json:"command"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		commandStr = strings.TrimSpace(body.Command)
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		commandStr = strings.TrimSpace(r.FormValue("command"))
	}

	if commandStr == "" {
		http.Error(w, "command is required", http.StatusBadRequest)
		return
	}

	cmd, err := h.repo.EnqueueDeviceCommand(r.Context(), id, commandStr)
	if err != nil {
		log.Printf("[web] enqueue device command for %s error: %v", id, err)
		http.Error(w, "Failed to enqueue command", http.StatusInternalServerError)
		return
	}

	log.Printf("[web] queued diagnostic command id=%s device=%s cmd=%q", cmd.ID, id, cmd.Command)
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(cmd)
		return
	}

	h.renderDeviceDetail(w, r, id)
}

// ApproveDevice handles POST /admin/devices/{id}/approve.
func (h *Handler) ApproveDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	dev, _, err := h.repo.ApproveDevice(r.Context(), id)
	if err != nil {
		log.Printf("[web] approve device %s error: %v", id, err)
		http.Error(w, "Failed to approve device", http.StatusInternalServerError)
		return
	}
	if dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	log.Printf("[web] device approved id=%s hostname=%s hw=%s", dev.ID, dev.Hostname, dev.HardwareUUID)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "device_row", dev); err != nil {
		log.Printf("[web] render device_row error: %v", err)
	}
}

// RevokeDevice handles POST /admin/devices/{id}/revoke.
func (h *Handler) RevokeDevice(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	dev, err := h.repo.RevokeDevice(r.Context(), id)
	if err != nil {
		log.Printf("[web] revoke device %s error: %v", id, err)
		http.Error(w, "Failed to revoke device", http.StatusInternalServerError)
		return
	}
	if dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	log.Printf("[web] device revoked id=%s hostname=%s hw=%s", dev.ID, dev.Hostname, dev.HardwareUUID)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "device_row", dev); err != nil {
		log.Printf("[web] render device_row error: %v", err)
	}
}

// UpdateDeviceTags handles POST /admin/devices/{id}/tags.
func (h *Handler) UpdateDeviceTags(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var tags []string

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Tags []string `json:"tags"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		tags = normalizeTagSlice(body.Tags)
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		tags = parseCommaSeparatedTags(r.FormValue("tags"))
	}

	dev, err := h.repo.UpdateDeviceTags(r.Context(), id, tags)
	if err != nil {
		log.Printf("[web] update device tags %s error: %v", id, err)
		http.Error(w, "Failed to update device tags", http.StatusInternalServerError)
		return
	}
	if dev == nil {
		http.Error(w, "Device not found", http.StatusNotFound)
		return
	}

	log.Printf("[web] updated tags for device id=%s hostname=%s tags=%v", dev.ID, dev.Hostname, dev.Tags)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "device_row", dev); err != nil {
		log.Printf("[web] render device_row error: %v", err)
	}
}

// ListPoliciesPage renders /admin/policies.
func (h *Handler) ListPoliciesPage(w http.ResponseWriter, r *http.Request) {
	policies, err := h.repo.ListPolicies(r.Context())
	if err != nil {
		log.Printf("[web] list policies error: %v", err)
		http.Error(w, "Failed to load policies", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"Title":     "Policies",
		"ActiveNav": "policies",
		"Policies":  policies,
		"Templates": types.EnterprisePolicyTemplates,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render policies template error: %v", err)
	}
}

// TogglePolicy handles POST /admin/policies/{id}/toggle.
func (h *Handler) TogglePolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	pol, err := h.repo.TogglePolicyActive(r.Context(), id)
	if err != nil {
		log.Printf("[web] toggle policy %s error: %v", id, err)
		http.Error(w, "Failed to toggle policy", http.StatusInternalServerError)
		return
	}
	if pol == nil {
		http.Error(w, "Policy not found", http.StatusNotFound)
		return
	}

	log.Printf("[web] policy toggled id=%s name=%q is_active=%v", pol.ID, pol.Name, pol.IsActive)
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(pol)
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := h.tmpl.ExecuteTemplate(w, "policy_row", pol); err != nil {
			log.Printf("[web] render policy_row error: %v", err)
		}
		return
	}
	http.Redirect(w, r, "/admin/policies", http.StatusSeeOther)
}

// CreatePolicyFromTemplate handles POST /admin/policies/from-template.
func (h *Handler) CreatePolicyFromTemplate(w http.ResponseWriter, r *http.Request) {
	var (
		templateID string
		targetTags []string
	)

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			TemplateID string   `json:"template_id"`
			TargetTags []string `json:"target_tags"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		templateID = strings.TrimSpace(body.TemplateID)
		targetTags = normalizeTagSlice(body.TargetTags)
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		templateID = strings.TrimSpace(r.FormValue("template_id"))
		targetTags = parseCommaSeparatedTags(r.FormValue("target_tags"))
	}

	preset, ok := types.GetPolicyTemplateByID(templateID)
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown enterprise policy template_id: %q", templateID), http.StatusBadRequest)
		return
	}

	pol, err := h.repo.CreatePolicy(
		r.Context(),
		preset.Name,
		preset.Description,
		preset.PolicyType,
		preset.Payload,
		targetTags,
	)
	if err != nil {
		log.Printf("[web] create policy from template %s error: %v", templateID, err)
		http.Error(w, "Failed to create policy from template", http.StatusInternalServerError)
		return
	}

	log.Printf("[web] deployed enterprise preset template_id=%s policy_id=%s name=%q", templateID, pol.ID, pol.Name)
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(pol)
		return
	}
	http.Redirect(w, r, "/admin/policies", http.StatusSeeOther)
}

// CreatePolicy handles POST /admin/policies.
func (h *Handler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	var (
		name        string
		description string
		policyType  types.PolicyType
		payloadRaw  json.RawMessage
		targetTags  []string
	)

	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Name        string           `json:"name"`
			Description string           `json:"description"`
			PolicyType  types.PolicyType `json:"policy_type"`
			Payload     json.RawMessage  `json:"payload"`
			TargetTags  []string         `json:"target_tags"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}
		name = strings.TrimSpace(body.Name)
		description = strings.TrimSpace(body.Description)
		policyType = body.PolicyType
		payloadRaw = body.Payload
		targetTags = normalizeTagSlice(body.TargetTags)
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}
		name = strings.TrimSpace(r.FormValue("name"))
		description = strings.TrimSpace(r.FormValue("description"))
		policyType = types.PolicyType(strings.TrimSpace(r.FormValue("policy_type")))
		targetTags = parseCommaSeparatedTags(r.FormValue("target_tags"))
		rawField := strings.TrimSpace(r.FormValue("payload"))
		if rawField != "" {
			payloadRaw = json.RawMessage(rawField)
		} else {
			built, err := buildStructuredPolicyPayload(r, policyType)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			payloadRaw = built
		}
	}

	if name == "" || policyType == "" || len(payloadRaw) == 0 || !json.Valid(payloadRaw) {
		http.Error(w, "name, policy_type, and valid policy fields/JSON payload are required", http.StatusBadRequest)
		return
	}

	pol, err := h.repo.CreatePolicy(r.Context(), name, description, policyType, payloadRaw, targetTags)
	if err != nil {
		log.Printf("[web] create policy error: %v", err)
		http.Error(w, "Failed to create policy", http.StatusInternalServerError)
		return
	}

	log.Printf("[web] policy created id=%s name=%q type=%s target_tags=%v", pol.ID, pol.Name, pol.PolicyType, pol.TargetTags)
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(pol)
		return
	}
	http.Redirect(w, r, "/admin/policies", http.StatusSeeOther)
}

func parseCommaSeparatedTags(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	parts := strings.Split(raw, ",")
	return normalizeTagSlice(parts)
}

func normalizeTagSlice(raw []string) []string {
	seen := make(map[string]bool, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		t := strings.ToLower(strings.TrimSpace(item))
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

func buildStructuredPolicyPayload(r *http.Request, policyType types.PolicyType) (json.RawMessage, error) {
	switch policyType {
	case types.PolicyTypePackageAbsence, types.PolicyTypePackagePresence:
		pkg := strings.TrimSpace(r.FormValue("package_name"))
		if pkg == "" {
			return nil, fmt.Errorf("package_name is required for %s", policyType)
		}
		b, err := json.Marshal(types.PackageAbsencePayload{PackageName: pkg})
		return b, err

	case types.PolicyTypeDconfSetting:
		schemaPath := strings.TrimSpace(r.FormValue("schema_path"))
		key := strings.TrimSpace(r.FormValue("dconf_key"))
		if key == "" {
			key = strings.TrimSpace(r.FormValue("key"))
		}
		val := strings.TrimSpace(r.FormValue("dconf_value"))
		if val == "" {
			val = strings.TrimSpace(r.FormValue("value"))
		}
		lockedStr := strings.ToLower(strings.TrimSpace(r.FormValue("dconf_locked")))
		if lockedStr == "" {
			lockedStr = strings.ToLower(strings.TrimSpace(r.FormValue("locked")))
		}
		locked := lockedStr == "true" || lockedStr == "1" || lockedStr == "on"
		if schemaPath == "" || key == "" || val == "" {
			return nil, fmt.Errorf("schema_path, key, and value are required for DCONF_SETTING")
		}
		b, err := json.Marshal(types.DconfSettingPayload{
			SchemaPath: schemaPath,
			Key:        key,
			Value:      val,
			Locked:     locked,
		})
		return b, err

	case types.PolicyTypeSystemdService:
		svc := strings.TrimSpace(r.FormValue("service_name"))
		state := strings.TrimSpace(r.FormValue("service_state"))
		if state == "" {
			state = strings.TrimSpace(r.FormValue("state"))
		}
		enabledStr := strings.ToLower(strings.TrimSpace(r.FormValue("service_enabled")))
		if enabledStr == "" {
			enabledStr = strings.ToLower(strings.TrimSpace(r.FormValue("enabled")))
		}
		enabled := enabledStr == "true" || enabledStr == "1" || enabledStr == "on"
		if svc == "" || state == "" {
			return nil, fmt.Errorf("service_name and service_state are required for SYSTEMD_SERVICE")
		}
		b, err := json.Marshal(types.SystemdServicePayload{
			ServiceName: svc,
			State:       state,
			Enabled:     enabled,
		})
		return b, err

	default:
		return nil, fmt.Errorf("unsupported policy_type: %s", policyType)
	}
}
