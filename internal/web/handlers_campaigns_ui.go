package web

import (
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/db"
)

// maxCampaignRowsRendered bounds the per-device table on the detail page. The export link and
// the JSON endpoint return every row.
const maxCampaignRowsRendered = 500

// isFormPost reports whether the request is a browser form submission.
func isFormPost(r *http.Request) bool {
	return r.Method == http.MethodPost &&
		strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded")
}

// campaignStageForm is one row of the stage editor.
type campaignStageForm struct {
	Index      int
	Name       string
	Enabled    bool
	MinDevices string
	SuccessPct string
	SoakMin    string
	HaltPct    string
	HaltCount  string
	Promotion  string
}

// campaignFormValues are the raw form values, kept as strings so a rejected submission
// re-renders exactly what the admin typed.
type campaignFormValues struct {
	Name, Description, TargetKind, GroupID   string
	CVEIDs, Packages, TargetTags, TargetRing string
	PackageExclusions, RebootPolicy          string
	MaxDeferrals, DeadlineAt                 string
	BlackoutCron, BlackoutDuration           string
	RespectMaintenanceWindow                 bool
	Stages                                   []campaignStageForm
}

func defaultCampaignForm() campaignFormValues {
	v := campaignFormValues{
		TargetKind: "packages", RebootPolicy: "notify", MaxDeferrals: "3",
		RespectMaintenanceWindow: true,
	}
	for i, s := range campaign.DefaultStages() {
		v.Stages = append(v.Stages, campaignStageForm{
			Index: i, Name: s.Name, Enabled: true,
			MinDevices: strconv.Itoa(s.MinDevices), SuccessPct: strconv.Itoa(s.SuccessThresholdPct),
			SoakMin: strconv.Itoa(s.SoakMinutes), HaltPct: strconv.Itoa(s.FailureHaltPct),
			HaltCount: strconv.Itoa(s.FailureHaltCount), Promotion: string(s.Promotion),
		})
	}
	return v
}

// splitFormList splits a comma/space/newline separated list, dropping blanks and duplicates.
func splitFormList(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ';' })
	seen := map[string]bool{}
	out := make([]string, 0, len(f))
	for _, x := range f {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// parseCampaignForm turns the posted form into the API input. Parse problems are returned as
// field errors; semantic validation stays in buildCampaign so the API and the form agree.
func parseCampaignForm(r *http.Request) (campaignCreateInput, campaignFormValues, map[string]string) {
	errs := map[string]string{}
	v := campaignFormValues{
		Name: r.PostFormValue("name"), Description: r.PostFormValue("description"),
		TargetKind: r.PostFormValue("target_kind"), GroupID: r.PostFormValue("group_id"),
		CVEIDs: r.PostFormValue("cve_ids"), Packages: r.PostFormValue("packages"),
		TargetTags: r.PostFormValue("target_tags"), TargetRing: r.PostFormValue("target_ring"),
		PackageExclusions: r.PostFormValue("package_exclusions"), RebootPolicy: r.PostFormValue("reboot_policy"),
		MaxDeferrals: r.PostFormValue("max_deferrals"), DeadlineAt: r.PostFormValue("deadline_at"),
		BlackoutCron: r.PostFormValue("blackout_cron"), BlackoutDuration: r.PostFormValue("blackout_duration_minutes"),
		RespectMaintenanceWindow: r.PostFormValue("respect_maintenance_window") != "",
	}
	in := campaignCreateInput{
		Name: v.Name, Description: v.Description, TargetKind: v.TargetKind, GroupID: v.GroupID,
		CVEIDs: splitFormList(v.CVEIDs), Packages: splitFormList(v.Packages), TargetTags: splitFormList(v.TargetTags),
		TargetRing: v.TargetRing, PackageExclusions: splitFormList(v.PackageExclusions),
		RebootPolicy: v.RebootPolicy, BlackoutCron: v.BlackoutCron,
		RespectMaintenanceWindow: v.RespectMaintenanceWindow,
	}
	num := func(field, label, raw string) int {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return 0
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > 1_000_000 {
			if _, dup := errs[field]; !dup {
				errs[field] = label + " must be a whole number of 0 or more"
			}
			return 0
		}
		return n
	}
	in.MaxDeferrals = num("max_deferrals", "Deferral limit", v.MaxDeferrals)
	in.BlackoutDurationMinutes = num("blackout_duration_minutes", "Blackout duration", v.BlackoutDuration)
	if d := strings.TrimSpace(v.DeadlineAt); d != "" {
		t, err := time.Parse("2006-01-02T15:04", d)
		if err != nil {
			errs["deadline_at"] = "Deadline must be a date and time"
		} else {
			t = t.UTC()
			in.DeadlineAt = &t
		}
	}
	order := 0
	for i := 0; i < 3; i++ {
		p := "stage_" + strconv.Itoa(i) + "_"
		sf := campaignStageForm{
			Index: i, Name: r.PostFormValue(p + "name"), Enabled: r.PostFormValue(p+"enabled") != "",
			MinDevices: r.PostFormValue(p + "min_devices"), SuccessPct: r.PostFormValue(p + "success_pct"),
			SoakMin: r.PostFormValue(p + "soak_minutes"), HaltPct: r.PostFormValue(p + "halt_pct"),
			HaltCount: r.PostFormValue(p + "halt_count"), Promotion: r.PostFormValue(p + "promotion"),
		}
		v.Stages = append(v.Stages, sf)
		if !sf.Enabled {
			continue
		}
		name := strings.ToUpper(strings.TrimSpace(sf.Name))
		if name != "CANARY" && name != "PILOT" && name != "PRODUCTION" {
			errs["stages"] = "Stage names must be CANARY, PILOT or PRODUCTION"
			continue
		}
		in.Stages = append(in.Stages, campaign.Stage{
			Order: order, Name: name,
			MinDevices:          num("stages", "Stage "+name+" minimum devices", sf.MinDevices),
			SuccessThresholdPct: num("stages", "Stage "+name+" success threshold", sf.SuccessPct),
			SoakMinutes:         num("stages", "Stage "+name+" soak time", sf.SoakMin),
			FailureHaltPct:      num("stages", "Stage "+name+" halt percentage", sf.HaltPct),
			FailureHaltCount:    num("stages", "Stage "+name+" halt count", sf.HaltCount),
			Promotion:           campaign.PromotionMode(sf.Promotion),
		})
		order++
	}
	if len(in.Stages) == 0 {
		if _, dup := errs["stages"]; !dup {
			errs["stages"] = "Enable at least one stage"
		}
	}
	return in, v, errs
}

// validateCampaignTarget holds the form-level check that the chosen target actually names
// something (the JSON API historically accepted an empty target).
func validateCampaignTarget(in campaignCreateInput) (string, string) {
	switch strings.ToLower(strings.TrimSpace(in.TargetKind)) {
	case "group":
		if strings.TrimSpace(in.GroupID) == "" {
			return "group_id", "Choose a group"
		}
	case "cve":
		if len(in.CVEIDs) == 0 {
			return "cve_ids", "Enter at least one CVE id"
		}
	case "packages":
		if len(in.Packages) == 0 {
			return "packages", "Enter at least one package name"
		}
	}
	return "", ""
}

// createCampaignForm handles a browser POST /admin/campaigns: validate through the shared
// builder, re-render the list page with errors beside the form on failure, redirect to the new
// campaign on success.
func (h *Handler) createCampaignForm(w http.ResponseWriter, r *http.Request) {
	in, vals, errs := parseCampaignForm(r)
	status := http.StatusBadRequest
	if len(errs) == 0 {
		if f, msg := validateCampaignTarget(in); f != "" {
			errs[f] = msg
		}
	}
	var c *campaign.Campaign
	if len(errs) == 0 {
		var ferr *campaignFieldError
		c, ferr = h.buildCampaign(r, in)
		if ferr != nil {
			errs[ferr.Field] = ferr.Msg
			status = ferr.Status
		}
	}
	if len(errs) > 0 {
		h.renderCampaignListForm(w, r, status, &vals, errs)
		return
	}
	created, err := h.repo.CreateCampaign(r.Context(), c)
	if err != nil {
		log.Printf("[web] create campaign: %v", err)
		h.renderCampaignListForm(w, r, http.StatusInternalServerError, &vals, map[string]string{"_": "Failed to create the campaign"})
		return
	}
	h.auditCampaign(r, "CAMPAIGN_CREATE", created.ID, map[string]any{"name": created.Name, "target_kind": string(created.TargetKind)})
	http.Redirect(w, r, "/admin/campaigns/"+created.ID, http.StatusSeeOther)
}

// campaignListRow is one row of the list page.
type campaignListRow struct {
	C        campaign.Campaign
	Target   string
	Stage    string
	Progress db.CampaignProgress
}

func campaignTargetSummary(c *campaign.Campaign, groupNames map[string]string) string {
	switch c.TargetKind {
	case campaign.TargetGroup:
		if n, ok := groupNames[c.GroupID]; ok {
			return "Group: " + n
		}
		return "Group: " + c.GroupID
	case campaign.TargetCVE:
		return "CVEs: " + strings.Join(c.CVEIDs, ", ")
	case campaign.TargetPackages:
		return "Packages: " + strings.Join(c.Packages, ", ")
	}
	return string(c.TargetKind)
}

func campaignStageLabel(c *campaign.Campaign) string {
	if st, ok := c.CurrentStageDef(); ok {
		return strconv.Itoa(c.CurrentStage+1) + "/" + strconv.Itoa(len(c.Stages)) + " " + st.Name
	}
	return "-"
}

func (h *Handler) pageBase(r *http.Request, title, nav string) map[string]any {
	return map[string]any{
		"Title":     title,
		"ActiveNav": nav,
		"CSRFToken": CSRFTokenFromContext(r.Context()),
		"AdminUser": AdminUserFromContext(r.Context()),
	}
}

func (h *Handler) renderPage(w http.ResponseWriter, status int, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render %v template error: %v", data["ActiveNav"], err)
	}
}

func (h *Handler) groupNames(r *http.Request) (map[string]string, []map[string]string) {
	names := map[string]string{}
	var opts []map[string]string
	groups, err := h.repo.ListGroups(r.Context(), h.deviceScope(r))
	if err != nil {
		return names, opts
	}
	for _, g := range groups {
		names[g.ID] = g.Name
		opts = append(opts, map[string]string{"ID": g.ID, "Name": g.Name})
	}
	return names, opts
}

// renderCampaignListForm renders the list page. vals/errs are set when re-rendering a rejected
// create submission.
func (h *Handler) renderCampaignListForm(w http.ResponseWriter, r *http.Request, status int, vals *campaignFormValues, errs map[string]string) {
	scope := h.deviceScope(r)
	list, err := h.repo.ListCampaigns(r.Context(), scope)
	if err != nil {
		http.Error(w, "failed to list campaigns", http.StatusInternalServerError)
		return
	}
	ids := make([]string, 0, len(list))
	for _, c := range list {
		ids = append(ids, c.ID)
	}
	prog, err := h.repo.CampaignProgressFor(r.Context(), ids, scope)
	if err != nil {
		http.Error(w, "failed to load campaign progress", http.StatusInternalServerError)
		return
	}
	names, groupOpts := h.groupNames(r)
	rows := make([]campaignListRow, 0, len(list))
	for i := range list {
		c := list[i]
		rows = append(rows, campaignListRow{C: c, Target: campaignTargetSummary(&c, names), Stage: campaignStageLabel(&c), Progress: prog[c.ID]})
	}
	form := defaultCampaignForm()
	if vals != nil {
		form = *vals
	}
	data := h.pageBase(r, "Patch Campaigns", "campaigns")
	data["View"] = "list"
	data["Rows"] = rows
	data["Form"] = form
	data["Errors"] = errs
	data["Groups"] = groupOpts
	data["Scoped"] = scope.Scoped
	data["Rings"] = []string{"CANARY", "BETA", "PILOT", "PRODUCTION"}
	h.renderPage(w, status, data)
}

// stageCounts is the per-stage tally for the detail timeline.
type stageCounts struct {
	Pending, Dispatched, Succeeded, Failed, Other, Total int
}

// campaignStageView is one step of the stage timeline.
type campaignStageView struct {
	Stage  campaign.Stage
	Status string // done, active, halted, upcoming, cancelled
	Counts stageCounts
}

type campaignWorkView struct {
	Row      campaign.DeviceWorkRow
	Packages []db.CampaignPackageResultRow
}

func (h *Handler) renderCampaignDetail(w http.ResponseWriter, r *http.Request, status int, flashErr string) {
	c, ok := h.getScopedCampaign(w, r, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	scope := h.deviceScope(r)
	// Same scoped repo calls the JSON handler uses; the page filters nothing by itself.
	work, err := h.repo.ListCampaignWork(r.Context(), c.ID, scope)
	if err != nil {
		http.Error(w, "failed to load work", http.StatusInternalServerError)
		return
	}
	pkgRes, err := h.repo.ListCampaignPackageResults(r.Context(), c.ID, scope)
	if err != nil {
		http.Error(w, "failed to load results", http.StatusInternalServerError)
		return
	}
	events, _ := h.repo.ListCampaignEvents(r.Context(), c.ID, 100)
	prog, err := h.repo.CampaignProgressFor(r.Context(), []string{c.ID}, scope)
	if err != nil {
		http.Error(w, "failed to load progress", http.StatusInternalServerError)
		return
	}
	names, _ := h.groupNames(r)

	// Stage timeline and failure classes are computed from the scoped rows so a scoped admin
	// never sees counts that include devices outside their tags.
	counts := map[int]*stageCounts{}
	classes := map[campaign.FailureClass]int{}
	for _, row := range work {
		sc := counts[row.Stage]
		if sc == nil {
			sc = &stageCounts{}
			counts[row.Stage] = sc
		}
		sc.Total++
		switch row.State {
		case campaign.WorkPending:
			sc.Pending++
		case campaign.WorkDispatched:
			sc.Dispatched++
		case campaign.WorkSucceeded:
			sc.Succeeded++
		case campaign.WorkFailed, campaign.WorkInterrupted, campaign.WorkUnsupported:
			sc.Failed++
			if row.FailureClass != campaign.FailNone {
				classes[row.FailureClass]++
			}
		default:
			sc.Other++
		}
	}
	stages := make([]campaignStageView, 0, len(c.Stages))
	for i, st := range c.Stages {
		v := campaignStageView{Stage: st, Status: "upcoming"}
		switch {
		case c.State == campaign.StateCompleted || i < c.CurrentStage:
			v.Status = "done"
		case i == c.CurrentStage && c.State == campaign.StateHalted:
			v.Status = "halted"
		case i == c.CurrentStage && c.State == campaign.StateCancelled:
			v.Status = "cancelled"
		case i == c.CurrentStage && c.State != campaign.StateDraft:
			v.Status = "active"
		case i == c.CurrentStage:
			v.Status = "next"
		}
		if sc := counts[i]; sc != nil {
			v.Counts = *sc
		}
		stages = append(stages, v)
	}

	byDevice := map[string][]db.CampaignPackageResultRow{}
	for _, p := range pkgRes {
		byDevice[p.DeviceID] = append(byDevice[p.DeviceID], p)
	}
	truncated := false
	shown := work
	if len(shown) > maxCampaignRowsRendered {
		shown = shown[:maxCampaignRowsRendered]
		truncated = true
	}
	rows := make([]campaignWorkView, 0, len(shown))
	for _, row := range shown {
		rows = append(rows, campaignWorkView{Row: row, Packages: byDevice[row.DeviceID]})
	}
	type classCount struct {
		Class string
		Count int
	}
	var classList []classCount
	for k, n := range classes {
		classList = append(classList, classCount{string(k), n})
	}
	sort.Slice(classList, func(i, j int) bool { return classList[i].Class < classList[j].Class })

	data := h.pageBase(r, c.Name, "campaigns")
	data["View"] = "detail"
	data["Campaign"] = c
	data["Target"] = campaignTargetSummary(c, names)
	data["Stages"] = stages
	data["Work"] = rows
	data["WorkTotal"] = len(work)
	data["Truncated"] = truncated
	data["Events"] = events
	data["Progress"] = prog[c.ID]
	data["FailureClasses"] = classList
	data["Actions"] = campaign.AllowedControls(c.State)
	data["Flash"] = flashErr
	data["Scoped"] = scope.Scoped
	h.renderPage(w, status, data)
}
