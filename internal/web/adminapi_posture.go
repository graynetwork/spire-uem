package web

import (
	"context"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// Posture read API and shared identity resolution for conditional-access connectors.
//
// These handlers only READ device_posture. They never compute a verdict: the verdict is
// whatever DevicePosture.EffectiveState says, which maps a missing or stale row to UNKNOWN.

const peerAddrCtxKey contextKey = "spirePeerAddr"

// peerAddr returns the TCP peer of the request. TrustedProxyRealIPMiddleware may already
// have replaced r.RemoteAddr with a header value; it stashes the real peer first.
func peerAddr(r *http.Request) (netip.Addr, bool) {
	raw := r.RemoteAddr
	if s, ok := r.Context().Value(peerAddrCtxKey).(string); ok && s != "" {
		raw = s
	}
	raw = strings.TrimSpace(raw)
	if ap, err := netip.ParseAddrPort(raw); err == nil {
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(raw); err == nil {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

// Resolution outcomes.
const (
	resolveOK        = "ok"
	resolveUnknown   = "unknown"
	resolveAmbiguous = "ambiguous"
)

type accessResolution struct {
	Outcome  string
	DeviceID string
	Hostname string
}

// matchedBy names the identity field that decided a lookup.
func matchedBy(id types.AccessIdentity) string {
	switch {
	case id.CertSerial != "":
		return "cert_serial"
	case id.CertFingerprint != "":
		return "cert_fingerprint"
	case id.MAC != "":
		return "mac"
	case id.IP != "":
		return "ip"
	case id.User != "":
		return "user"
	}
	return ""
}

func strengthOf(id types.AccessIdentity) string {
	if id.Weak() {
		return "weak"
	}
	return "strong"
}

// resolveAccess maps an identity to at most one device inside the caller's tag scope. The
// scope is applied BEFORE counting matches, so a device the caller may not see is
// indistinguishable from one that does not exist, and cannot make an identity ambiguous.
func (h *Handler) resolveAccess(ctx context.Context, caller *types.AdminUser, id types.AccessIdentity, needHostname bool) (accessResolution, error) {
	ids, err := h.repo.ResolveAccessIdentity(ctx, id)
	if err != nil {
		return accessResolution{}, err
	}
	if len(ids) == 0 {
		return accessResolution{Outcome: resolveUnknown}, nil
	}
	var infos []db.AccessDeviceInfo
	if userIsTagScoped(caller) || (needHostname && len(ids) == 1) {
		all, err := h.repo.AccessDeviceInfos(ctx, ids)
		if err != nil {
			return accessResolution{}, err
		}
		for _, d := range all {
			if AdminMayAccessDeviceTags(caller, d.Tags) {
				infos = append(infos, d)
			}
		}
		switch len(infos) {
		case 0:
			return accessResolution{Outcome: resolveUnknown}, nil
		case 1:
			return accessResolution{Outcome: resolveOK, DeviceID: infos[0].ID, Hostname: infos[0].Hostname}, nil
		}
		return accessResolution{Outcome: resolveAmbiguous}, nil
	}
	if len(ids) == 1 {
		return accessResolution{Outcome: resolveOK, DeviceID: ids[0]}, nil
	}
	return accessResolution{Outcome: resolveAmbiguous}, nil
}

// postureVerdict reads the stored verdict and reduces it to what a connector may act on.
// stale is true when a stored verdict exists but has expired.
func (h *Handler) postureVerdict(ctx context.Context, deviceID string, now time.Time) (state types.PostureState, p *types.DevicePosture, stale bool, err error) {
	p, err = h.repo.GetDevicePosture(ctx, deviceID)
	if err != nil {
		return types.PostureUnknown, nil, false, err
	}
	state = p.EffectiveState(now)
	stale = p != nil && state == types.PostureUnknown && p.State != types.PostureUnknown
	return state, p, stale, nil
}

func verdictReasons(state types.PostureState, p *types.DevicePosture, stale bool) []string {
	switch {
	case p == nil:
		return []string{"no posture verdict"}
	case stale:
		return []string{"posture verdict is stale"}
	case len(p.Reasons) == 0 && state == types.PostureUnknown:
		return []string{"posture is unknown"}
	}
	return append([]string{}, p.Reasons...)
}

// ---------------------------------------------------------------------------------------
// GET /api/admin/v1/devices/{id}/posture
// ---------------------------------------------------------------------------------------

func (h *Handler) apiGetDevicePosture(w http.ResponseWriter, r *http.Request) {
	dev, ok := h.loadScopedDevice(w, r)
	if !ok {
		return
	}
	state, p, stale, err := h.postureVerdict(r.Context(), dev.ID, time.Now())
	if err != nil {
		log.Printf("[admin-api] get posture: %v", err)
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	out := map[string]any{
		"device_id":        dev.ID,
		"state":            state,
		"allowed":          state == types.PostureCompliant,
		"stale":            stale,
		"stored_state":     nil,
		"reasons":          verdictReasons(state, p, stale),
		"checks":           []types.PostureCheck{},
		"rule_set_version": nil,
		"evaluated_at":     nil,
		"valid_until":      nil,
		"state_changed_at": nil,
	}
	if p != nil {
		out["stored_state"] = p.State
		if p.Checks != nil {
			out["checks"] = p.Checks
		}
		out["rule_set_version"] = p.RuleSetVersion
		out["evaluated_at"] = p.EvaluatedAt
		out["valid_until"] = p.ValidUntil
		out["state_changed_at"] = p.StateChangedAt
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"data": out})
}

// ---------------------------------------------------------------------------------------
// GET /api/admin/v1/posture/lookup
// ---------------------------------------------------------------------------------------

type postureLookupData struct {
	Allowed          bool               `json:"allowed"`
	State            types.PostureState `json:"state"`
	DeviceID         *string            `json:"device_id"`
	Hostname         *string            `json:"hostname"`
	IdentityStrength string             `json:"identity_strength"`
	MatchedBy        string             `json:"matched_by"`
	Reasons          []string           `json:"reasons"`
}

const lookupParamMax = 256

func (h *Handler) apiPostureLookup(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var (
		id      types.AccessIdentity
		set     int
		other   bool
		purpose types.CertPurpose
	)
	for k, v := range q {
		if len(v) != 1 || len(v[0]) > lookupParamMax || strings.TrimSpace(v[0]) == "" {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "each parameter must be given once with a non-empty value of at most 256 characters")
			return
		}
		val := strings.TrimSpace(v[0])
		if k == "purpose" {
			// Optional, and only with serial or fingerprint: limits the certificate lookup to
			// one kind of certificate, so a connector that wants a browser certificate is
			// never answered for an agent or network certificate.
			purpose = types.CertPurpose(strings.ToLower(val))
			continue
		}
		switch k {
		case "serial":
			id.CertSerial = val
		case "fingerprint":
			id.CertFingerprint = val
		case "mac":
			id.MAC = val
		case "ip":
			id.IP = val
		case "user":
			id.User = val
		default:
			other = true
		}
		set++
	}
	if other || set != 1 {
		writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "give exactly one of: serial, fingerprint, mac, ip, user (serial and fingerprint also accept purpose)")
		return
	}
	if purpose != "" {
		switch purpose {
		case types.CertPurposeAgent, types.CertPurposeNetwork, types.CertPurposeBrowser:
		default:
			writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "purpose must be agent, network or browser")
			return
		}
		if id.CertSerial == "" && id.CertFingerprint == "" {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "purpose can only be combined with serial or fingerprint")
			return
		}
		id.CertPurposes = []types.CertPurpose{purpose}
	}
	if id.MAC != "" && db.NormalizeMAC(id.MAC) == "" {
		writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "mac is not a valid MAC address")
		return
	}
	if id.IP != "" {
		if _, err := netip.ParseAddr(id.IP); err != nil {
			writeAPIError(w, r, http.StatusBadRequest, "invalid_request", "ip is not a valid IP address")
			return
		}
	}

	out := postureLookupData{State: types.PostureUnknown, IdentityStrength: strengthOf(id), MatchedBy: matchedBy(id), Reasons: []string{"unknown device"}}
	caller := AdminUserObjFromContext(r.Context())
	res, err := h.resolveAccess(r.Context(), caller, id, true)
	if err != nil {
		log.Printf("[admin-api] posture lookup: %v", err)
		writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	switch res.Outcome {
	case resolveAmbiguous:
		out.Reasons = []string{"ambiguous identity"}
	case resolveOK:
		state, p, stale, err := h.postureVerdict(r.Context(), res.DeviceID, time.Now())
		if err != nil {
			log.Printf("[admin-api] posture lookup: %v", err)
			writeAPIError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
			return
		}
		devID, host := res.DeviceID, res.Hostname
		out.DeviceID, out.Hostname = &devID, &host
		out.State = state
		out.Allowed = state == types.PostureCompliant
		out.Reasons = verdictReasons(state, p, stale)
	}
	writeAPIJSON(w, http.StatusOK, map[string]any{"data": out})
}
