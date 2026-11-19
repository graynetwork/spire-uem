package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// ---------------------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------------------

// apiCursor is the decoded form of the opaque next_cursor: the sort key and id of the last
// row returned, plus a fingerprint of the filters so a cursor cannot be replayed against a
// different query.
type apiCursor struct {
	K string `json:"k"`
	I string `json:"i"`
	F string `json:"f"`
}

func encodeCursor(key, id, filterSig string) string {
	b, _ := json.Marshal(apiCursor{K: key, I: id, F: filterSig})
	return base64.RawURLEncoding.EncodeToString(b)
}

// parsePageParams reads `limit` and `cursor`. It writes the 400 itself and returns ok=false
// on a bad value.
func parsePageParams(w http.ResponseWriter, r *http.Request, filterSig string) (limit int, cur *apiCursor, ok bool) {
	limit = apiDefaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > apiMaxLimit {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_limit", fmt.Sprintf("limit must be an integer between 1 and %d", apiMaxLimit))
			return 0, nil, false
		}
		limit = n
	}
	if v := r.URL.Query().Get("cursor"); v != "" {
		raw, err := base64.RawURLEncoding.DecodeString(v)
		var c apiCursor
		if err != nil || json.Unmarshal(raw, &c) != nil || c.I == "" {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_cursor", "cursor is not valid")
			return 0, nil, false
		}
		if c.F != filterSig {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_cursor", "cursor was issued for a different set of filters")
			return 0, nil, false
		}
		cur = &c
	}
	return limit, cur, true
}

func filterSignature(parts ...string) string {
	return sha256Hex(strings.Join(parts, "\x00"))[:12]
}

type pageEnvelope struct {
	Data       any     `json:"data"`
	NextCursor *string `json:"next_cursor"`
	HasMore    bool    `json:"has_more"`
}

func writePage(w http.ResponseWriter, data any, next string) {
	env := pageEnvelope{Data: data, HasMore: next != ""}
	if next != "" {
		env.NextCursor = &next
	}
	writeAPIJSON(w, http.StatusOK, env)
}

// timeSortKey is a fixed-width key that sorts NEWEST first in ascending string order.
func timeSortKey(t time.Time) string {
	return fmt.Sprintf("%020d", int64(1)<<62-t.UnixNano())
}

// pageSlice sorts items ascending by (key,id), skips everything up to and including the
// cursor position, and returns at most limit items plus the next cursor ("" on the last page).
func pageSlice[T any](items []T, keyID func(T) (string, string), cur *apiCursor, limit int, filterSig string) ([]T, string) {
	sort.SliceStable(items, func(a, b int) bool {
		ka, ia := keyID(items[a])
		kb, ib := keyID(items[b])
		if ka != kb {
			return ka < kb
		}
		return ia < ib
	})
	start := 0
	if cur != nil {
		start = len(items)
		for i, it := range items {
			k, id := keyID(it)
			if k > cur.K || (k == cur.K && id > cur.I) {
				start = i
				break
			}
		}
	}
	items = items[start:]
	if len(items) <= limit {
		return items, ""
	}
	items = items[:limit]
	k, id := keyID(items[len(items)-1])
	return items, encodeCursor(k, id, filterSig)
}

// ---------------------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------------------

type apiDevice struct {
	ID                   string     `json:"id"`
	HardwareUUID         string     `json:"hardware_uuid"`
	Hostname             string     `json:"hostname"`
	Status               string     `json:"status"`
	Tags                 []string   `json:"tags"`
	PatchRing            string     `json:"patch_ring"`
	RebootRequired       bool       `json:"reboot_required"`
	LastCheckinAt        *time.Time `json:"last_checkin_at"`
	WSConnected          bool       `json:"ws_connected"`
	AttestationStatus    string     `json:"attestation_status"`
	AgentVersion         string     `json:"agent_version"`
	PendingUpdatesCount  int        `json:"pending_updates_count"`
	SecurityUpdatesCount int        `json:"security_updates_count"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

func toAPIDevice(d types.Device) apiDevice {
	tags := d.Tags
	if tags == nil {
		tags = []string{}
	}
	return apiDevice{
		ID: d.ID, HardwareUUID: d.HardwareUUID, Hostname: d.Hostname, Status: string(d.Status), Tags: tags,
		PatchRing: string(d.PatchRing), RebootRequired: d.RebootRequired, LastCheckinAt: d.LastCheckinAt,
		WSConnected: d.WSConnected, AttestationStatus: string(d.AttestationStatus), AgentVersion: d.AgentVersion,
		PendingUpdatesCount: d.PendingUpdatesCount, SecurityUpdatesCount: d.SecurityUpdatesCount,
		CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	}
}

// ---------------------------------------------------------------------------------------
// /me
// ---------------------------------------------------------------------------------------

func (h *Handler) apiMe(w http.ResponseWriter, r *http.Request) {
	p := apiPrincipalFrom(r.Context())
	u := AdminUserObjFromContext(r.Context())
	tags := []string{}
	if u != nil && len(u.AllowedTags) > 0 {
		tags = u.AllowedTags
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"kind": p.Kind, "actor": p.Actor, "role": string(p.Role), "scopes": p.scopeList(), "allowed_tags": tags,
	}})
}

// ---------------------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------------------

func (h *Handler) apiListDevices(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	tag, ring, status, prefix := q.Get("tag"), q.Get("ring"), q.Get("status"), q.Get("hostname_prefix")
	if st := strings.ToUpper(strings.TrimSpace(status)); st == "PENDING" {
		status = "PENDING_APPROVAL"
	}
	if st := strings.ToUpper(strings.TrimSpace(status)); st != "" {
		switch types.DeviceStatus(st) {
		case types.StatusPendingApproval, types.StatusApproved, types.StatusRejected, types.StatusRevoked:
		default:
			writeAPIError(w, r, http.StatusBadRequest, "invalid_filter", "status must be one of PENDING_APPROVAL, APPROVED, REJECTED, REVOKED")
			return
		}
	}
	if rg := strings.ToUpper(strings.TrimSpace(ring)); rg != "" {
		if !validRing(rg) {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_filter", "unknown deployment ring")
			return
		}
	}
	sig := filterSignature("devices", tag, ring, status, prefix)
	limit, cur, ok := parsePageParams(w, r, sig)
	if !ok {
		return
	}
	f := db.DevicePageFilter{Tag: tag, Ring: ring, Status: status, HostnamePrefix: prefix, Scope: h.deviceScope(r), Limit: limit + 1}
	if cur != nil {
		t, err := time.Parse(time.RFC3339Nano, cur.K)
		if err != nil || !isUUID(cur.I) {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_cursor", "cursor is not valid")
			return
		}
		f.After = &db.PageAfter{CreatedAt: t, ID: cur.I}
	}
	devs, err := h.repo.ListDevicesPage(r.Context(), f)
	if err != nil {
		log.Printf("[admin-api] list devices: %v", err)
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	next := ""
	if len(devs) > limit {
		devs = devs[:limit]
		last := devs[len(devs)-1]
		next = encodeCursor(last.CreatedAt.UTC().Format(time.RFC3339Nano), last.ID, sig)
	}
	out := make([]apiDevice, 0, len(devs))
	for _, d := range devs {
		out = append(out, toAPIDevice(d))
	}
	writePage(w, out, next)
}

func validRing(r string) bool {
	switch types.DeploymentRing(r) {
	case types.RingCanary, types.RingBeta, types.RingPilot, types.RingProduction:
		return true
	}
	return false
}

// loadScopedDevice loads a device and enforces the tag scope with the same authority the
// /admin routes use. An absent or out-of-scope device is a 404 (existence is not revealed).
func (h *Handler) loadScopedDevice(w http.ResponseWriter, r *http.Request) (*types.Device, bool) {
	id := chi.URLParam(r, "id")
	if !isUUID(id) {
		writeAPIError(w, r, http.StatusNotFound, "not_found", "device not found")
		return nil, false
	}
	dev, err := h.repo.GetDeviceByID(r.Context(), id)
	if err != nil {
		log.Printf("[admin-api] get device: %v", err)
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return nil, false
	}
	if dev == nil || !AdminMayAccessDeviceTags(AdminUserObjFromContext(r.Context()), dev.Tags) {
		writeAPIError(w, r, http.StatusNotFound, "not_found", "device not found")
		return nil, false
	}
	return dev, true
}

func (h *Handler) apiGetDevice(w http.ResponseWriter, r *http.Request) {
	dev, ok := h.loadScopedDevice(w, r)
	if !ok {
		return
	}
	summary := map[string]any{"has_inventory": false}
	if inv, err := h.repo.GetDeviceInventory(r.Context(), dev.ID); err == nil && inv != nil {
		summary = map[string]any{
			"has_inventory": inv.HasInventory, "collected_at": inv.CollectedAt,
			"package_count": len(inv.Packages), "kernel_module_count": len(inv.Modules),
			"listening_socket_count": len(inv.Listening), "local_account_count": len(inv.Accounts),
			"ca_certificate_count": len(inv.CACerts), "usb_device_count": len(inv.USBDevices),
		}
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"device": toAPIDevice(*dev), "inventory_summary": summary,
	}})
}

// auditAPI records a mutation with the principal as actor.
func (h *Handler) auditAPI(r *http.Request, action, target string, details map[string]any) {
	if h.auditor == nil {
		return
	}
	if details == nil {
		details = map[string]any{}
	}
	p := apiPrincipalFrom(r.Context())
	details["via"] = "admin-api-v1"
	details["request_id"] = apiRequestID(r.Context())
	if p != nil {
		details["principal_kind"] = p.Kind
	}
	_, _, _ = h.auditor.Emit(r.Context(), AdminUserFromContext(r.Context()), action, target, r.RemoteAddr, details)
}

func (h *Handler) apiDeviceSync(w http.ResponseWriter, r *http.Request) {
	var body struct{}
	if !decodeAPIBody(w, r, &body) {
		return
	}
	dev, ok := h.loadScopedDevice(w, r)
	if !ok {
		return
	}
	connected := false
	if h.hub != nil {
		connected = h.hub.IsConnected(dev.ID)
		if connected {
			_ = h.hub.TriggerCheckin(dev.ID)
		}
	}
	h.auditAPI(r, "DEVICE_SYNC_REQUEST", dev.ID, map[string]any{"hostname": dev.Hostname, "connected": connected})
	writeAPIJSON(w, http.StatusAccepted, map[string]any{"data": map[string]any{
		"status": "sync_requested", "device_id": dev.ID, "connected": connected,
	}})
}

func (h *Handler) apiDeviceLock(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Message string `json:"message"`
	}
	if !decodeAPIBody(w, r, &body) {
		return
	}
	dev, ok := h.loadScopedDevice(w, r)
	if !ok {
		return
	}
	message := strings.TrimSpace(body.Message)
	if len(message) > 500 {
		writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "message must be at most 500 characters")
		return
	}
	directive := types.ActionDirective{Kind: types.ActionLock, ActorID: dev.ID, Message: message}
	raw, _ := json.Marshal(directive)
	cmd, err := h.repo.EnqueueDeviceCommand(r.Context(), dev.ID, types.ActionDirectivePrefix+string(raw))
	if err != nil {
		log.Printf("[admin-api] queue lock: %v", err)
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	pushed := false
	if h.hub != nil && h.hub.IsConnected(dev.ID) {
		pushed = h.hub.PushCommand(r.Context(), dev.ID, types.CommandDTO{ID: cmd.ID, Command: cmd.Command})
	}
	h.auditAPI(r, "DEVICE_LOCK", dev.ID, map[string]any{"hostname": dev.Hostname, "command_id": cmd.ID, "has_message": message != "", "pushed_live": pushed})
	writeAPIJSON(w, http.StatusAccepted, map[string]any{"data": map[string]any{
		"status": "lock_queued", "device_id": dev.ID, "command_id": cmd.ID, "pushed_live": pushed,
	}})
}

func (h *Handler) apiDeviceReboot(w http.ResponseWriter, r *http.Request) {
	var body struct{}
	if !decodeAPIBody(w, r, &body) {
		return
	}
	dev, ok := h.loadScopedDevice(w, r)
	if !ok {
		return
	}
	cmd, err := h.repo.EnqueueDeviceCommand(r.Context(), dev.ID, "/usr/sbin/reboot")
	if err != nil {
		log.Printf("[admin-api] queue reboot: %v", err)
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	pushed := false
	if h.hub != nil && h.hub.IsConnected(dev.ID) {
		pushed = h.hub.PushCommand(r.Context(), dev.ID, types.CommandDTO{ID: cmd.ID, Command: cmd.Command})
	}
	h.auditAPI(r, "DEVICE_REBOOT", dev.ID, map[string]any{"hostname": dev.Hostname, "command_id": cmd.ID, "pushed_live": pushed})
	writeAPIJSON(w, http.StatusAccepted, map[string]any{"data": map[string]any{
		"status": "reboot_queued", "device_id": dev.ID, "command_id": cmd.ID, "pushed_live": pushed,
	}})
}

// ---------------------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------------------

// visibleGroups returns the groups the principal may see: everything for an unscoped
// principal; for a scoped one, groups with at least one in-scope member or created within
// their scope (member counts are already limited to in-scope devices by ListGroups).
func (h *Handler) visibleGroups(r *http.Request) ([]types.DeviceGroup, error) {
	groups, err := h.repo.ListGroups(r.Context(), h.deviceScope(r))
	if err != nil {
		return nil, err
	}
	allowed, scoped := AllowedTagsForContext(r)
	if !scoped {
		return groups, nil
	}
	out := groups[:0]
	for _, g := range groups {
		if g.MemberCount > 0 || (g.CreatedByScoped() && tagsIntersect(g.CreatorScopedTags, allowed)) {
			out = append(out, g)
		}
	}
	return out, nil
}

func (h *Handler) apiListGroups(w http.ResponseWriter, r *http.Request) {
	sig := filterSignature("groups")
	limit, cur, ok := parsePageParams(w, r, sig)
	if !ok {
		return
	}
	groups, err := h.visibleGroups(r)
	if err != nil {
		log.Printf("[admin-api] list groups: %v", err)
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	page, next := pageSlice(groups, func(g types.DeviceGroup) (string, string) { return g.Name, g.ID }, cur, limit, sig)
	writePage(w, page, next)
}

func (h *Handler) findVisibleGroup(w http.ResponseWriter, r *http.Request) (*types.DeviceGroup, bool) {
	id := chi.URLParam(r, "id")
	if isUUID(id) {
		groups, err := h.visibleGroups(r)
		if err != nil {
			log.Printf("[admin-api] groups: %v", err)
			writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
			return nil, false
		}
		for i := range groups {
			if groups[i].ID == id {
				return &groups[i], true
			}
		}
	}
	writeAPIError(w, r, http.StatusNotFound, "not_found", "group not found")
	return nil, false
}

func (h *Handler) apiGetGroup(w http.ResponseWriter, r *http.Request) {
	g, ok := h.findVisibleGroup(w, r)
	if !ok {
		return
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"data": g})
}

func (h *Handler) apiGroupMembers(w http.ResponseWriter, r *http.Request) {
	g, ok := h.findVisibleGroup(w, r)
	if !ok {
		return
	}
	sig := filterSignature("members", g.ID)
	limit, cur, ok := parsePageParams(w, r, sig)
	if !ok {
		return
	}
	members, err := h.repo.ListGroupMembers(r.Context(), g.ID, h.deviceScope(r))
	if err != nil {
		log.Printf("[admin-api] group members: %v", err)
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	page, next := pageSlice(members, func(m types.DeviceGroupMember) (string, string) { return m.DeviceID, m.DeviceID }, cur, limit, sig)
	writePage(w, page, next)
}

// ---------------------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------------------

// secretFieldNames are payload keys whose values are credentials. Any value under one of
// these keys is replaced by a {"set": bool} marker, whatever its shape (a sealed envelope or
// a legacy plain string).
var secretFieldNames = map[string]bool{
	"psk": true, "password": true, "client_key": true, "private_key": true, "secret": true,
	"token": true, "api_key": true, "preshared_key": true, "presharedkey": true, "passphrase": true,
}

// envelopeKeys identify a sealed/plaintext SecretEnvelope object wherever it appears.
var envelopeKeys = []string{"ciphertext", "encrypted_dek", "nonce", "plaintext"}

func secretMarker(v any) map[string]any {
	set := false
	switch t := v.(type) {
	case string:
		set = t != ""
	case map[string]any:
		for _, k := range envelopeKeys {
			if s, ok := t[k].(string); ok && s != "" {
				set = true
			}
		}
		if !set && len(t) > 0 {
			set = true
		}
	case nil:
	default:
		set = true
	}
	return map[string]any{"set": set}
}

func redactSecrets(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for _, k := range envelopeKeys {
			if _, has := t[k]; has {
				return secretMarker(t)
			}
		}
		out := make(map[string]any, len(t))
		for k, val := range t {
			lk := strings.ToLower(k)
			switch {
			case lk == "peer_psks":
				if m, ok := val.(map[string]any); ok {
					red := make(map[string]any, len(m))
					for pk, pv := range m {
						red[pk] = secretMarker(pv)
					}
					out[k] = red
				} else {
					out[k] = secretMarker(val)
				}
			case secretFieldNames[lk]:
				out[k] = secretMarker(val)
			default:
				out[k] = redactSecrets(val)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = redactSecrets(e)
		}
		return out
	}
	return v
}

// sanitizePolicyPayload returns the payload with every credential replaced by a "set"
// marker. It fails closed: a payload that cannot be parsed is withheld entirely.
func sanitizePolicyPayload(raw json.RawMessage) (json.RawMessage, bool) {
	if len(raw) == 0 {
		return json.RawMessage("null"), false
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return json.RawMessage("null"), true
	}
	out, err := json.Marshal(redactSecrets(v))
	if err != nil {
		return json.RawMessage("null"), true
	}
	return out, false
}

type apiPolicy struct {
	ID              string                          `json:"id"`
	Name            string                          `json:"name"`
	Description     string                          `json:"description"`
	PolicyType      types.PolicyType                `json:"policy_type"`
	Payload         json.RawMessage                 `json:"payload"`
	PayloadRedacted bool                            `json:"payload_withheld"`
	TargetTags      []string                        `json:"target_tags"`
	TargetRing      *types.DeploymentRing           `json:"target_ring,omitempty"`
	TargetGroupIDs  []string                        `json:"target_group_ids"`
	RequiresReboot  bool                            `json:"requires_reboot"`
	IsSelfService   bool                            `json:"is_self_service"`
	AssignmentType  types.ApplicationAssignmentType `json:"assignment_type"`
	IsActive        bool                            `json:"is_active"`
	Version         int                             `json:"version"`
	CreatedAt       time.Time                       `json:"created_at"`
	UpdatedAt       time.Time                       `json:"updated_at"`
}

func toAPIPolicy(p types.Policy) apiPolicy {
	payload, withheld := sanitizePolicyPayload(p.Payload)
	tags, groups := p.TargetTags, p.TargetGroupIDs
	if tags == nil {
		tags = []string{}
	}
	if groups == nil {
		groups = []string{}
	}
	return apiPolicy{ID: p.ID, Name: p.Name, Description: p.Description, PolicyType: p.PolicyType, Payload: payload,
		PayloadRedacted: withheld, TargetTags: tags, TargetRing: p.TargetRing, TargetGroupIDs: groups,
		RequiresReboot: p.RequiresReboot, IsSelfService: p.IsSelfService, AssignmentType: p.AssignmentType,
		IsActive: p.IsActive, Version: p.Version, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
}

// policyVisible applies the scoped-admin policy rule (policy_scope.go): a scoped principal
// sees only policies whose reach stays inside its tags and groups.
func (h *Handler) policyVisible(r *http.Request, p *types.Policy) bool {
	ok, _ := h.policyManageAllowed(r, p)
	return ok
}

func (h *Handler) apiListPolicies(w http.ResponseWriter, r *http.Request) {
	sig := filterSignature("policies")
	limit, cur, ok := parsePageParams(w, r, sig)
	if !ok {
		return
	}
	all, err := h.repo.ListPolicies(r.Context())
	if err != nil {
		log.Printf("[admin-api] list policies: %v", err)
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	vis := make([]apiPolicyRow, 0, len(all))
	for i := range all {
		if h.policyVisible(r, &all[i]) {
			vis = append(vis, apiPolicyRow{key: timeSortKey(all[i].CreatedAt), p: all[i]})
		}
	}
	page, next := pageSlice(vis, func(x apiPolicyRow) (string, string) { return x.key, x.p.ID }, cur, limit, sig)
	out := make([]apiPolicy, 0, len(page))
	for _, x := range page {
		out = append(out, toAPIPolicy(x.p))
	}
	writePage(w, out, next)
}

type apiPolicyRow struct {
	key string
	p   types.Policy
}

func (h *Handler) apiGetPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var pol *types.Policy
	if isUUID(id) {
		var err error
		pol, err = h.repo.GetPolicyByID(r.Context(), id)
		if err != nil {
			log.Printf("[admin-api] get policy: %v", err)
			writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
			return
		}
	}
	if pol == nil || !h.policyVisible(r, pol) {
		writeAPIError(w, r, http.StatusNotFound, "not_found", "policy not found")
		return
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"data": toAPIPolicy(*pol)})
}

// ---------------------------------------------------------------------------------------
// Campaigns
// ---------------------------------------------------------------------------------------

func (h *Handler) apiListCampaigns(w http.ResponseWriter, r *http.Request) {
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	sig := filterSignature("campaigns", state)
	limit, cur, ok := parsePageParams(w, r, sig)
	if !ok {
		return
	}
	list, err := h.repo.ListCampaigns(r.Context(), h.deviceScope(r))
	if err != nil {
		log.Printf("[admin-api] list campaigns: %v", err)
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	rows := make([]apiCampaignRow, 0, len(list))
	for _, c := range list {
		if state != "" && !strings.EqualFold(string(c.State), state) {
			continue
		}
		rows = append(rows, apiCampaignRow{key: timeSortKey(c.CreatedAt), c: c})
	}
	page, next := pageSlice(rows, func(x apiCampaignRow) (string, string) { return x.key, x.c.ID }, cur, limit, sig)
	out := make([]campaign.Campaign, 0, len(page))
	for _, x := range page {
		out = append(out, x.c)
	}
	writePage(w, out, next)
}

type apiCampaignRow struct {
	key string
	c   campaign.Campaign
}

func (h *Handler) loadScopedCampaign(w http.ResponseWriter, r *http.Request) (*campaign.Campaign, bool) {
	id := chi.URLParam(r, "id")
	if !isUUID(id) {
		writeAPIError(w, r, http.StatusNotFound, "not_found", "campaign not found")
		return nil, false
	}
	c, err := h.repo.GetCampaign(r.Context(), id)
	if err != nil {
		log.Printf("[admin-api] get campaign: %v", err)
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return nil, false
	}
	if c == nil || !db.CampaignVisibleToScope(c, h.deviceScope(r)) {
		writeAPIError(w, r, http.StatusNotFound, "not_found", "campaign not found")
		return nil, false
	}
	return c, true
}

func (h *Handler) apiGetCampaign(w http.ResponseWriter, r *http.Request) {
	c, ok := h.loadScopedCampaign(w, r)
	if !ok {
		return
	}
	report, _ := h.repo.CampaignReport(r.Context(), c.ID)
	events, _ := h.repo.ListCampaignEvents(r.Context(), c.ID, 100)
	writeAPIJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"campaign": c, "report": report, "events": events}})
}

func (h *Handler) apiCampaignControl(w http.ResponseWriter, r *http.Request, action string) {
	var body struct{}
	if !decodeAPIBody(w, r, &body) {
		return
	}
	c, ok := h.loadScopedCampaign(w, r)
	if !ok {
		return
	}
	from := c.State
	newState, status, msg := h.applyCampaignControl(r.Context(), c, action, AdminUserFromContext(r.Context()))
	if status == http.StatusInternalServerError {
		log.Printf("[admin-api] campaign %s: %s", action, msg)
		writeAPIError(w, r, status, "internal_error", "internal server error")
		return
	}
	if status != 0 {
		writeAPIError(w, r, http.StatusConflict, "invalid_state", msg)
		return
	}
	h.auditAPI(r, "CAMPAIGN_"+strings.ToUpper(action), c.ID, map[string]any{"from": string(from), "to": string(newState)})
	writeAPIJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"id": c.ID, "state": string(newState)}})
}

// ---------------------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------------------

func (h *Handler) apiListAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	action, actor := strings.TrimSpace(q.Get("action")), strings.TrimSpace(q.Get("actor"))
	sig := filterSignature("audit", action, actor)
	limit, cur, ok := parsePageParams(w, r, sig)
	if !ok {
		return
	}
	var after *db.PageAfter
	if cur != nil {
		t, err := time.Parse(time.RFC3339Nano, cur.K)
		if err != nil || !isUUID(cur.I) {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_cursor", "cursor is not valid")
			return
		}
		after = &db.PageAfter{CreatedAt: t, ID: cur.I}
	}
	evs, err := h.repo.ListSystemAuditEventsPage(r.Context(), h.deviceScope(r), action, actor, after, limit+1)
	if err != nil {
		log.Printf("[admin-api] list audit: %v", err)
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	next := ""
	if len(evs) > limit {
		evs = evs[:limit]
		last := evs[len(evs)-1]
		next = encodeCursor(last.CreatedAt.UTC().Format(time.RFC3339Nano), last.ID, sig)
	}
	writePage(w, evs, next)
}
