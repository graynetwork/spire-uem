package web

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/types"
)

// sensorRequest is the body for creating/updating a sensor.
type sensorRequest struct {
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	ScriptVersionID string                 `json:"script_version_id"`
	ReturnType      types.SensorReturnType `json:"return_type"`
	IntervalSeconds int                    `json:"interval_seconds"`
	TargetTags      []string               `json:"target_tags"`
	Ring            string                 `json:"ring,omitempty"`
	Enabled         *bool                  `json:"enabled,omitempty"`
}

func (req sensorRequest) toSensor() *types.Sensor {
	s := &types.Sensor{
		Name: strings.TrimSpace(req.Name), Description: req.Description,
		ScriptVersionID: strings.TrimSpace(req.ScriptVersionID), ReturnType: req.ReturnType,
		IntervalSeconds: req.IntervalSeconds, TargetTags: req.TargetTags, Enabled: true,
	}
	if req.Enabled != nil {
		s.Enabled = *req.Enabled
	}
	if ring := strings.TrimSpace(req.Ring); ring != "" {
		dr := types.DeploymentRing(strings.ToUpper(ring))
		s.TargetRing = &dr
	}
	return s
}

// ListSensors GET /admin/sensors — SECURITY_ADMIN+ (read via the group).
func (h *Handler) ListSensors(w http.ResponseWriter, r *http.Request) {
	sensors, err := h.repo.ListSensors(r.Context())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to list sensors")
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"sensors": sensors})
}

// CreateSensor POST /admin/sensors — SECURITY_ADMIN+.
func (h *Handler) CreateSensor(w http.ResponseWriter, r *http.Request) {
	var req sensorRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	actor := AdminUserFromContext(r.Context())
	s, err := h.repo.CreateSensor(r.Context(), req.toSensor(), actor)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "SENSOR_CREATE", s.ID, map[string]any{"name": s.Name, "return_type": string(s.ReturnType), "interval_seconds": s.IntervalSeconds})
	writeJSONResp(w, http.StatusCreated, map[string]any{"sensor": s})
}

// UpdateSensor POST /admin/sensors/{id} — SECURITY_ADMIN+. Name is immutable.
func (h *Handler) UpdateSensor(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	existing, err := h.repo.GetSensor(r.Context(), id)
	if err != nil || existing == nil {
		jsonErr(w, http.StatusNotFound, "sensor not found")
		return
	}
	var req sensorRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	s := req.toSensor()
	s.ID = existing.ID
	s.Name = existing.Name // name is the attribute key; immutable
	if err := h.repo.UpdateSensor(r.Context(), s); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "SENSOR_UPDATE", id, map[string]any{"name": s.Name, "enabled": s.Enabled})
	writeJSONResp(w, http.StatusOK, map[string]any{"sensor": s})
}

// DeleteSensor DELETE /admin/sensors/{id} — SECURITY_ADMIN+. Devices clear its attribute at
// their next check-in via ClearStaleSensorAttributesForDevice.
func (h *Handler) DeleteSensor(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.repo.DeleteSensor(r.Context(), id); err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h.audit(r, "SENSOR_DELETE", id, nil)
	writeJSONResp(w, http.StatusOK, map[string]any{"status": "deleted"})
}

// ListDeviceSensorResults GET /admin/devices/{id}/sensors/{name} — reading history for a
// device+sensor. Device scoping is enforced by DeviceScopeMiddleware on the path.
func (h *Handler) ListDeviceSensorResults(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	name := chi.URLParam(r, "name")
	if !types.ValidSensorName(name) {
		jsonErr(w, http.StatusBadRequest, "invalid sensor name")
		return
	}
	results, err := h.repo.ListSensorResults(r.Context(), id, name, types.SensorResultHistoryPerDevice)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to list sensor results")
		return
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"results": results})
}
