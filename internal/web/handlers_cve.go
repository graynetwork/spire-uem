package web

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/spire-uem/spire-uem/internal/cvefeed"
	"github.com/spire-uem/spire-uem/internal/types"
)

// maxCVEUploadBytes caps an admin offline feed upload (the real feed is ~60-90MB).
const maxCVEUploadBytes = 512 * 1024 * 1024

// VulnerabilitiesPage renders /admin/vulnerabilities: the fleet CVE list (CVE -> affected
// host count) plus feed freshness.
func (h *Handler) VulnerabilitiesPage(w http.ResponseWriter, r *http.Request) {
	cves, err := h.repo.ListFleetCVEsScoped(r.Context(), h.deviceScope(r))
	if err != nil {
		log.Printf("[web] list fleet CVEs: %v", err)
		http.Error(w, "Failed to load vulnerabilities", http.StatusInternalServerError)
		return
	}
	feedState, err := h.repo.GetCVEFeedState(r.Context())
	if err != nil {
		log.Printf("[web] get cve feed state: %v", err)
		feedState = &types.CVEFeedState{}
	}
	summary, _ := h.repo.GetFleetSummaryScoped(r.Context(), h.deviceScope(r))
	if summary == nil {
		summary = &types.FleetSummary{}
	}
	scope := h.deviceScope(r)
	feedCfg := cvefeed.LoadConfig(r.Context(), h.repo)

	data := map[string]any{
		"Title":            "Fleet Vulnerabilities",
		"ActiveNav":        "vulnerabilities",
		"CSRFToken":        CSRFTokenFromContext(r.Context()),
		"AdminUser":        AdminUserFromContext(r.Context()),
		"FleetCVEs":        cves,
		"FeedState":        feedState,
		"FlashMessage":     r.URL.Query().Get("msg"),
		"TotalHostsCount":  summary.TotalDevices,
		"Scoped":           scope.Scoped,
		"ScopeTags":        scope.Tags,
		"AutoImport":       feedCfg.Enabled,
		"AutoImportEnv":    feedCfg.EnabledFromEnv,
		"CanSetAutoImport": AdminRoleFromContext(r.Context()) == types.RoleSuperAdmin,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render vulnerabilities page: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// SetCVEAutoImport handles POST /admin/vulnerabilities/auto-import (SUPER_ADMIN): turns
// the automatic periodic feed import on or off by writing cve.feed_enabled. The running
// scheduler picks the change up within a minute. Audited.
func (h *Handler) SetCVEAutoImport(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Failed to parse form", http.StatusBadRequest)
		return
	}
	enabled := r.FormValue("enabled") == "true"
	actor := AdminUserFromContext(r.Context())
	if err := h.repo.UpdateSettingsCategory(r.Context(), "cve", map[string]interface{}{"cve.feed_enabled": enabled}, actor); err != nil {
		log.Printf("[web] set cve.feed_enabled: %v", err)
		http.Error(w, "Failed to save setting", http.StatusInternalServerError)
		return
	}
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), actor, "SETTINGS_UPDATE", "cve", r.RemoteAddr, map[string]any{"category": "cve", "updates": map[string]any{"cve.feed_enabled": enabled}})
	}
	msg := "Automatic import turned off."
	if enabled {
		msg = "Automatic import turned on. The first download starts within a minute."
	}
	if cvefeed.LoadConfig(r.Context(), h.repo).EnabledFromEnv {
		msg += " Note: SPIRE_CVE_FEED_ENABLED is set on the server and overrides this setting."
	}
	http.Redirect(w, r, "/admin/vulnerabilities?msg="+url.QueryEscape(msg), http.StatusSeeOther)
}

// TriggerCVEFeedImport handles POST /admin/vulnerabilities/import — runs an online feed
// import now (SUPER_ADMIN/SECURITY_ADMIN). Audited.
func (h *Handler) TriggerCVEFeedImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg := cvefeed.LoadConfig(ctx, h.repo)
	cfg.FilePath = "" // force the online URL path for a manual import
	imp := cvefeed.New(h.repo)

	records, cves, err := imp.RunOnce(ctx, cfg)
	actor := AdminUserFromContext(ctx)
	if err != nil {
		if h.auditor != nil {
			_, _, _ = h.auditor.Emit(ctx, actor, "cve.feed.import.failed", "", r.RemoteAddr, map[string]any{"error": err.Error(), "url": cfg.URL})
		}
		http.Redirect(w, r, "/admin/vulnerabilities?msg="+url.QueryEscape("Import failed: "+err.Error()), http.StatusSeeOther)
		return
	}
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(ctx, actor, "cve.feed.import", "", r.RemoteAddr, map[string]any{"records": records, "cves": cves, "url": cfg.URL})
	}
	http.Redirect(w, r, "/admin/vulnerabilities?msg="+url.QueryEscape(fmt.Sprintf("Imported %d records / %d CVEs", records, cves)), http.StatusSeeOther)
}

// UploadCVEFeed handles POST /admin/vulnerabilities/upload — the air-gapped offline path:
// an admin uploads the Debian Security Tracker JSON file directly. Streams the multipart
// file into the importer (no full in-memory copy). Audited.
func (h *Handler) UploadCVEFeed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	actor := AdminUserFromContext(ctx)
	r.Body = http.MaxBytesReader(w, r.Body, maxCVEUploadBytes+1024)
	// 10MB in-memory part buffer; the large file part spills to a temp file the multipart
	// reader streams, so the whole upload is never held in memory.
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Redirect(w, r, "/admin/vulnerabilities?msg="+url.QueryEscape("Upload rejected: "+err.Error()), http.StatusSeeOther)
		return
	}
	file, header, err := r.FormFile("feed")
	if err != nil {
		http.Redirect(w, r, "/admin/vulnerabilities?msg="+url.QueryEscape("No file provided"), http.StatusSeeOther)
		return
	}
	defer file.Close()

	imp := cvefeed.New(h.repo)
	source := "upload:" + sanitizeFilename(header.Filename)
	records, cves, err := imp.ImportFromReader(ctx, file, source)
	if err != nil {
		if h.auditor != nil {
			_, _, _ = h.auditor.Emit(ctx, actor, "cve.feed.upload.failed", "", r.RemoteAddr, map[string]any{"error": err.Error(), "file": header.Filename})
		}
		http.Redirect(w, r, "/admin/vulnerabilities?msg="+url.QueryEscape("Import failed: "+err.Error()), http.StatusSeeOther)
		return
	}
	if _, rerr := h.repo.RecomputeAllDeviceCVEs(ctx); rerr != nil {
		log.Printf("[web] offline upload: fleet rematch failed: %v", rerr)
	}
	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(ctx, actor, "cve.feed.upload", "", r.RemoteAddr, map[string]any{"records": records, "cves": cves, "file": header.Filename})
	}
	http.Redirect(w, r, "/admin/vulnerabilities?msg="+url.QueryEscape(fmt.Sprintf("Offline import: %d records / %d CVEs", records, cves)), http.StatusSeeOther)
}

func sanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 {
		name = name[i+1:]
	}
	if len(name) > 128 {
		name = name[:128]
	}
	if name == "" {
		return "feed.json"
	}
	return name
}
