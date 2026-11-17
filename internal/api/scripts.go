package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
)

// ReportScriptRuns handles POST /api/v1/desktop/scripts/report: the agent reports the outcome
// of each script run it executed this cycle. Each result is matched to a run the server queued
// for this device; a run already finalized is ignored (so a duplicate report is harmless).
func (h *Handler) ReportScriptRuns(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLargeBodyBytes)
	var req types.ScriptRunReport
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid script run report"})
		return
	}
	accepted := 0
	for _, res := range req.Runs {
		res.RunID = strings.TrimSpace(res.RunID)
		if res.RunID == "" {
			continue
		}
		if res.Status == "" {
			res.Status = types.ScriptRunCompleted
		}
		if err := h.repo.RecordScriptRunResult(r.Context(), dev.ID, res); err != nil {
			log.Printf("[api] script run report device=%s run=%s not recorded: %v", dev.ID, res.RunID, err)
			continue
		}
		accepted++
	}
	log.Printf("[api] HTTP 200 script run report device=%s accepted=%d/%d", dev.ID, accepted, len(req.Runs))
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "accepted": accepted})
}

// ReportSensors handles POST /api/v1/desktop/sensors/report: the agent reports each sensor's
// reading. The server parses each value to the sensor's declared type and writes it as the
// device attribute sensor.<name>; a parse failure or non-zero exit records an error and keeps
// the last good value. An unknown sensor name is ignored (it may have just been deleted).
func (h *Handler) ReportSensors(w http.ResponseWriter, r *http.Request) {
	dev := h.authenticateBearer(r)
	if dev == nil || dev.Status != types.StatusApproved {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "unauthorized or unapproved device"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxLargeBodyBytes)
	var req types.SensorReport
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid sensor report"})
		return
	}
	updated := 0
	for _, res := range req.Results {
		res.SensorName = strings.TrimSpace(res.SensorName)
		if !types.ValidSensorName(res.SensorName) {
			continue
		}
		sensor, err := h.repo.GetSensorByName(r.Context(), res.SensorName)
		if err != nil || sensor == nil {
			continue // unknown/deleted sensor; ignore
		}
		ok, rerr := h.repo.RecordSensorResult(r.Context(), dev.ID, sensor, res)
		if rerr != nil {
			log.Printf("[api] sensor report device=%s sensor=%s failed: %v", dev.ID, res.SensorName, rerr)
			continue
		}
		if ok {
			updated++
		}
	}
	log.Printf("[api] HTTP 200 sensor report device=%s results=%d updated=%d", dev.ID, len(req.Results), updated)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "updated": updated})
}
