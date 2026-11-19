package web

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// parseInventorySearch builds InventorySearchParams from the request query string. It accepts
// repeated attr_key/attr_op/attr_val triples plus pkg, port and admin filters.
func parseInventorySearch(r *http.Request) db.InventorySearchParams {
	q := r.URL.Query()
	params := db.InventorySearchParams{
		PackageName: strings.TrimSpace(q.Get("pkg")),
		LocalAdmin:  strings.TrimSpace(q.Get("admin")),
	}
	if p := strings.TrimSpace(q.Get("port")); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
			params.ListeningPort = n
		}
	}
	keys := q["attr_key"]
	ops := q["attr_op"]
	vals := q["attr_val"]
	for i := range keys {
		key := strings.TrimSpace(keys[i])
		if key == "" {
			continue
		}
		op := "eq"
		if i < len(ops) && strings.TrimSpace(ops[i]) != "" {
			op = strings.TrimSpace(ops[i])
		}
		val := ""
		if i < len(vals) {
			val = strings.TrimSpace(vals[i])
		}
		params.AttrFilters = append(params.AttrFilters, db.InventoryFilter{Key: key, Op: op, Value: val})
	}
	return params
}

// InventorySearchPage handles GET /admin/inventory — the fleet inventory search page.
// Results and counts respect the admin's tag scope. Any authenticated role may view.
func (h *Handler) InventorySearchPage(w http.ResponseWriter, r *http.Request) {
	params := parseInventorySearch(r)

	var results []db.InventorySearchResult
	var searchErr string
	hasQuery := len(params.AttrFilters) > 0 || params.PackageName != "" || params.ListeningPort > 0 || params.LocalAdmin != ""
	if hasQuery {
		res, err := h.repo.SearchInventory(r.Context(), params, h.deviceScope(r))
		if err != nil {
			log.Printf("[web] inventory search error: %v", err)
			searchErr = "Invalid search: " + err.Error()
		} else {
			results = res
		}
	}

	keys, _ := h.repo.ListInventoryAttributeKeys(r.Context())

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(results)
		return
	}

	data := map[string]any{
		"Title":        "Inventory",
		"ActiveNav":    "inventory",
		"CSRFToken":    CSRFTokenFromContext(r.Context()),
		"AdminUser":    AdminUserFromContext(r.Context()),
		"AdminRole":    string(AdminRoleFromContext(r.Context())),
		"Results":      results,
		"ResultCount":  len(results),
		"AttributeKeys": keys,
		"HasQuery":     hasQuery,
		"SearchError":  searchErr,
		"FilterPkg":    params.PackageName,
		"FilterPort":   r.URL.Query().Get("port"),
		"FilterAdmin":  params.LocalAdmin,
		"RawQuery":     r.URL.RawQuery,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Header.Get("HX-Request") == "true" {
		if err := h.tmpl.ExecuteTemplate(w, "inventory_results", data); err != nil {
			log.Printf("[web] render inventory_results error: %v", err)
		}
		return
	}
	if err := h.tmpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		log.Printf("[web] render inventory page error: %v", err)
	}
}

// ExportInventory handles GET /admin/inventory/export — CSV or JSON of the current filter,
// tag-scoped, AUDITOR+. The scope is applied in SearchInventory, so an operator cannot export
// a device outside their tags.
func (h *Handler) ExportInventory(w http.ResponseWriter, r *http.Request) {
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "csv"
	}
	params := parseInventorySearch(r)
	results, err := h.repo.SearchInventory(r.Context(), params, h.deviceScope(r))
	if err != nil {
		http.Error(w, "Invalid search: "+err.Error(), http.StatusBadRequest)
		return
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), AdminUserFromContext(r.Context()), "INVENTORY_EXPORT", "", r.RemoteAddr, map[string]any{
			"format":      format,
			"result_count": len(results),
			"query":       r.URL.RawQuery,
		})
	}

	ts := time.Now().UTC().Format("20060102-150405")
	if format == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="spire-inventory-%s.json"`, ts))
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return
	}

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="spire-inventory-%s.csv"`, ts))
	w.WriteHeader(http.StatusOK)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"hostname", "device_tags", "status", "cpu_model", "memory_mb", "os_name", "primary_ipv4", "package_count", "inventory_collected_at"})
	for _, res := range results {
		collected := ""
		if res.CollectedAt != nil {
			collected = res.CollectedAt.UTC().Format(time.RFC3339)
		}
		_ = cw.Write([]string{
			res.Hostname,
			strings.Join(res.Tags, ";"),
			res.Status,
			res.CPUModel,
			strconv.FormatInt(res.MemoryMB, 10),
			res.OSName,
			res.PrimaryIPv4,
			strconv.Itoa(res.PackageCount),
			collected,
		})
	}
	cw.Flush()
}

// RequestInventoryRefresh handles POST /admin/devices/{id}/inventory/refresh — asks the
// device to collect and send a fresh inventory report now, over the existing command queue.
// OPERATOR+, tag-scoped (the id is on the path, so DeviceScopeMiddleware already enforced
// scope; deviceInScope is a defensive re-check), audited.
func (h *Handler) RequestInventoryRefresh(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if !h.deviceInScope(r, id) {
		denyOutOfScope(w, r)
		return
	}

	cmd, err := h.repo.EnqueueDeviceCommand(r.Context(), id, types.InventoryRefreshCommand)
	if err != nil {
		log.Printf("[web] enqueue inventory refresh for %s error: %v", id, err)
		http.Error(w, "Failed to request inventory refresh", http.StatusInternalServerError)
		return
	}

	pushedLive := false
	if h.hub != nil && h.hub.IsConnected(id) {
		pushedLive = h.hub.PushCommand(r.Context(), id, types.CommandDTO{ID: cmd.ID, Command: cmd.Command})
	}

	if h.auditor != nil {
		_, _, _ = h.auditor.Emit(r.Context(), AdminUserFromContext(r.Context()), "INVENTORY_REFRESH", id, r.RemoteAddr, map[string]any{
			"command_id":  cmd.ID,
			"pushed_live": pushedLive,
		})
	}

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "requested", "command_id": cmd.ID, "pushed_live": pushedLive})
		return
	}
	h.renderDeviceDetail(w, r, id)
}
