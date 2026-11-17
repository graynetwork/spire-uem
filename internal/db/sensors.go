package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/types"
)

// CreateSensor inserts a sensor definition. The referenced script version must exist.
func (r *Repository) CreateSensor(ctx context.Context, s *types.Sensor, createdBy string) (*types.Sensor, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	v, err := r.GetScriptVersion(ctx, s.ScriptVersionID)
	if err != nil {
		return nil, fmt.Errorf("sensor script version: %w", err)
	}
	s.ScriptID = v.ScriptID
	if s.TargetTags == nil {
		s.TargetTags = []string{}
	}
	var ring *string
	if s.TargetRing != nil {
		rv := string(*s.TargetRing)
		ring = &rv
	}
	err = r.pool.QueryRow(ctx, `
		INSERT INTO sensors (name, description, script_id, script_version_id, return_type, interval_seconds, target_tags, target_ring, enabled, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING id, created_at, updated_at`,
		s.Name, s.Description, s.ScriptID, s.ScriptVersionID, string(s.ReturnType), s.IntervalSeconds,
		s.TargetTags, ring, s.Enabled, createdBy,
	).Scan(&s.ID, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert sensor: %w", err)
	}
	s.CreatedBy = createdBy
	return s, nil
}

// UpdateSensor changes a sensor's mutable fields (version, return type, interval, targets,
// enabled). Name is immutable because it is the attribute key.
func (r *Repository) UpdateSensor(ctx context.Context, s *types.Sensor) error {
	if err := s.Validate(); err != nil {
		return err
	}
	v, err := r.GetScriptVersion(ctx, s.ScriptVersionID)
	if err != nil {
		return fmt.Errorf("sensor script version: %w", err)
	}
	s.ScriptID = v.ScriptID
	if s.TargetTags == nil {
		s.TargetTags = []string{}
	}
	var ring *string
	if s.TargetRing != nil {
		rv := string(*s.TargetRing)
		ring = &rv
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE sensors
		SET description=$2, script_id=$3, script_version_id=$4, return_type=$5, interval_seconds=$6,
		    target_tags=$7, target_ring=$8, enabled=$9, updated_at=NOW()
		WHERE id=$1`,
		s.ID, s.Description, s.ScriptID, s.ScriptVersionID, string(s.ReturnType), s.IntervalSeconds,
		s.TargetTags, ring, s.Enabled)
	if err != nil {
		return fmt.Errorf("update sensor: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("sensor %s not found", s.ID)
	}
	return nil
}

// DeleteSensor removes a sensor. The attribute each targeted device carries for it is removed
// lazily: SensorsToClearForDevice reports the sensor as gone so the agent / server clears it.
func (r *Repository) DeleteSensor(ctx context.Context, sensorID string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM sensors WHERE id=$1`, sensorID)
	if err != nil {
		return fmt.Errorf("delete sensor: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("sensor %s not found", sensorID)
	}
	return nil
}

// GetSensor loads one sensor by id.
func (r *Repository) GetSensor(ctx context.Context, sensorID string) (*types.Sensor, error) {
	s, err := r.scanSensors(ctx, `WHERE id=$1`, sensorID)
	if err != nil || len(s) == 0 {
		return nil, err
	}
	return s[0], nil
}

// GetSensorByName loads one sensor by its unique name.
func (r *Repository) GetSensorByName(ctx context.Context, name string) (*types.Sensor, error) {
	s, err := r.scanSensors(ctx, `WHERE name=$1`, name)
	if err != nil || len(s) == 0 {
		return nil, err
	}
	return s[0], nil
}

// ListSensors returns all sensors ordered by name.
func (r *Repository) ListSensors(ctx context.Context) ([]*types.Sensor, error) {
	return r.scanSensors(ctx, `ORDER BY name`)
}

func (r *Repository) scanSensors(ctx context.Context, where string, args ...any) ([]*types.Sensor, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, name, description, script_id, script_version_id, return_type, interval_seconds,
		       target_tags, target_ring, enabled, created_by, created_at, updated_at
		FROM sensors `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("query sensors: %w", err)
	}
	defer rows.Close()
	out := make([]*types.Sensor, 0)
	for rows.Next() {
		var s types.Sensor
		var rt string
		var ring *string
		if err := rows.Scan(&s.ID, &s.Name, &s.Description, &s.ScriptID, &s.ScriptVersionID, &rt,
			&s.IntervalSeconds, &s.TargetTags, &ring, &s.Enabled, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan sensor: %w", err)
		}
		s.ReturnType = types.SensorReturnType(rt)
		if ring != nil {
			dr := types.DeploymentRing(*ring)
			s.TargetRing = &dr
		}
		out = append(out, &s)
	}
	return out, rows.Err()
}

// ClaimDueSensorDirectivesForDevice returns the enabled sensors that both target this device
// (tags/ring) and are due (interval elapsed since last dispatch to this device), as resolved
// directives, and records the dispatch time. The whole thing is one transaction so two server
// instances do not both dispatch the same sensor in the same window. A sensor whose version
// was deleted is skipped.
func (r *Repository) ClaimDueSensorDirectivesForDevice(ctx context.Context, deviceID string, deviceTags []string, ring types.DeploymentRing, now time.Time) ([]types.SensorDirective, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin claim sensors: %w", err)
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		SELECT s.id, s.name, s.script_version_id, s.return_type, s.interval_seconds, s.target_ring
		FROM sensors s
		LEFT JOIN sensor_device_state st ON st.sensor_id = s.id AND st.device_id = $1
		WHERE s.enabled = TRUE
		  AND (s.target_tags = '{}' OR s.target_tags && $2::text[])
		  AND (s.target_ring IS NULL OR s.target_ring = $3)
		  AND (st.last_dispatched_at IS NULL OR st.last_dispatched_at <= $4::timestamptz - make_interval(secs => s.interval_seconds))
		FOR UPDATE OF s SKIP LOCKED`,
		deviceID, deviceTags, string(ring), now)
	if err != nil {
		return nil, fmt.Errorf("query due sensors: %w", err)
	}
	type due struct {
		id, name, versionID, returnType string
		interval                        int
	}
	var dues []due
	for rows.Next() {
		var d due
		var tr *string
		if err := rows.Scan(&d.id, &d.name, &d.versionID, &d.returnType, &d.interval, &tr); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan due sensor: %w", err)
		}
		dues = append(dues, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]types.SensorDirective, 0, len(dues))
	for _, d := range dues {
		v, err := r.GetScriptVersion(ctx, d.versionID)
		if err != nil {
			continue // version deleted; skip (sensor cleanup handles the attribute)
		}
		s, err := r.GetScript(ctx, v.ScriptID)
		if err != nil || s == nil {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO sensor_device_state (device_id, sensor_id, last_dispatched_at)
			VALUES ($1,$2,$3)
			ON CONFLICT (device_id, sensor_id) DO UPDATE SET last_dispatched_at = EXCLUDED.last_dispatched_at`,
			deviceID, d.id, now); err != nil {
			return nil, fmt.Errorf("record sensor dispatch: %w", err)
		}
		out = append(out, types.SensorDirective{
			SensorName:   d.name,
			ReturnType:   types.SensorReturnType(d.returnType),
			VersionID:    v.ID,
			Version:      v.Version,
			Interpreter:  s.Interpreter,
			RunAs:        s.RunAs,
			Content:      v.Content,
			SHA256:       v.SHA256,
			TimeoutSecs:  s.TimeoutSeconds,
			MaxOutput:    s.MaxOutputBytes,
			IntervalSecs: d.interval,
		})
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit claim sensors: %w", err)
	}
	return out, nil
}

// ErrSensorNotDispatched means a device reported a reading for a sensor that is disabled,
// does not target it, or was never dispatched to it. The reading is refused.
var ErrSensorNotDispatched = errors.New("sensor is not active for this device")

// RecordSensorResult parses a reported sensor reading to its declared type and writes it as
// the device attribute sensor.<name> (source sensor:<name>), keeping a bounded history. A
// non-zero exit or a parse failure records an error row and leaves the last good attribute
// value untouched. Returns true if the attribute value was updated.
func (r *Repository) RecordSensorResult(ctx context.Context, deviceID string, sensor *types.Sensor, rep types.SensorResultReport) (updated bool, err error) {
	// Only accept a reading for a sensor that is enabled, currently targets this device, and
	// was dispatched to it. Without this a device could write sensor.<name> attributes for
	// sensors that never ran on it, and those attributes feed group rules and reports.
	var accepted bool
	if err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM sensors s
			JOIN devices d ON d.id = $1
			JOIN sensor_device_state st ON st.sensor_id = s.id AND st.device_id = d.id
			WHERE s.id = $2
			  AND s.enabled = TRUE
			  AND (s.target_tags = '{}' OR s.target_tags && d.tags)
			  AND (s.target_ring IS NULL OR s.target_ring = d.patch_ring::text)
			  AND st.last_dispatched_at IS NOT NULL
		)`, deviceID, sensor.ID).Scan(&accepted); err != nil {
		return false, fmt.Errorf("check sensor dispatch: %w", err)
	}
	if !accepted {
		return false, ErrSensorNotDispatched
	}
	if rep.Error != "" || rep.ExitCode != 0 {
		msg := rep.Error
		if msg == "" {
			msg = fmt.Sprintf("sensor exited %d", rep.ExitCode)
		}
		_ = r.insertSensorResult(ctx, deviceID, sensor.Name, false, nil, msg, rep.ExitCode)
		return false, nil
	}
	attr, perr := types.ParseSensorValue(sensor.Name, sensor.ReturnType, rep.RawValue)
	if perr != nil {
		_ = r.insertSensorResult(ctx, deviceID, sensor.Name, false, nil, perr.Error(), rep.ExitCode)
		return false, nil
	}
	// Write the attribute under the sensor's own source; never touches inventory keys.
	if _, err := r.ReplaceDeviceAttributes(ctx, deviceID, types.SensorSource(sensor.Name), []types.DeviceAttribute{attr}); err != nil {
		return false, fmt.Errorf("write sensor attribute: %w", err)
	}
	_ = r.insertSensorResult(ctx, deviceID, sensor.Name, true, attr.Value, "", rep.ExitCode)
	return true, nil
}

func (r *Repository) insertSensorResult(ctx context.Context, deviceID, sensorName string, ok bool, value json.RawMessage, errMsg string, exitCode int) error {
	var v any
	if value != nil {
		v = string(value)
	}
	if _, err := r.pool.Exec(ctx, `
		INSERT INTO sensor_results (device_id, sensor_name, ok, value, error_msg, exit_code)
		VALUES ($1,$2,$3,$4::jsonb,$5,$6)`,
		deviceID, sensorName, ok, v, errMsg, exitCode); err != nil {
		return err
	}
	// Trim history to the newest N rows for this device+sensor.
	_, _ = r.pool.Exec(ctx, `
		DELETE FROM sensor_results
		WHERE device_id=$1 AND sensor_name=$2
		  AND id NOT IN (
		      SELECT id FROM sensor_results
		      WHERE device_id=$1 AND sensor_name=$2
		      ORDER BY created_at DESC LIMIT $3
		  )`, deviceID, sensorName, types.SensorResultHistoryPerDevice)
	return nil
}

// ClearStaleSensorAttributesForDevice removes sensor attributes for sensors that no longer
// apply to this device: the sensor was deleted or disabled, or the device left the sensor's
// targets. It compares the device's existing sensor: sources against the set of sensors that
// currently target it, and replaces each stale source with an empty set (deleting its key).
// Returns the sensor names cleared.
func (r *Repository) ClearStaleSensorAttributesForDevice(ctx context.Context, deviceID string, deviceTags []string, ring types.DeploymentRing) ([]string, error) {
	// Sensor names currently applying to this device.
	activeRows, err := r.pool.Query(ctx, `
		SELECT name FROM sensors
		WHERE enabled = TRUE
		  AND (target_tags = '{}' OR target_tags && $1::text[])
		  AND (target_ring IS NULL OR target_ring = $2)`, deviceTags, string(ring))
	if err != nil {
		return nil, fmt.Errorf("list active sensors: %w", err)
	}
	active := map[string]bool{}
	for activeRows.Next() {
		var n string
		if err := activeRows.Scan(&n); err != nil {
			activeRows.Close()
			return nil, err
		}
		active[n] = true
	}
	activeRows.Close()
	if err := activeRows.Err(); err != nil {
		return nil, err
	}

	// Sensor sources the device currently carries.
	attrs, err := r.GetDeviceAttributes(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	var cleared []string
	seen := map[string]bool{}
	for _, a := range attrs {
		name, ok := sensorNameFromSource(a.Source)
		if !ok || seen[name] {
			continue
		}
		seen[name] = true
		if !active[name] {
			if _, err := r.ReplaceDeviceAttributes(ctx, deviceID, types.SensorSource(name), nil); err != nil {
				return cleared, fmt.Errorf("clear sensor %s: %w", name, err)
			}
			// Also drop its state row so a re-enabled sensor dispatches immediately.
			_, _ = r.pool.Exec(ctx, `DELETE FROM sensor_device_state st USING sensors s WHERE st.sensor_id=s.id AND s.name=$1 AND st.device_id=$2`, name, deviceID)
			cleared = append(cleared, name)
		}
	}
	return cleared, nil
}

// sensorNameFromSource extracts the sensor name from an attribute source "sensor:<name>".
func sensorNameFromSource(source string) (string, bool) {
	const pfx = types.AttrSourceSensorPfx
	if len(source) <= len(pfx) || source[:len(pfx)] != pfx {
		return "", false
	}
	return source[len(pfx):], true
}

// ListSensorResults returns recent readings for one device+sensor, newest first.
func (r *Repository) ListSensorResults(ctx context.Context, deviceID, sensorName string, limit int) ([]types.SensorResult, error) {
	if limit <= 0 || limit > types.SensorResultHistoryPerDevice {
		limit = types.SensorResultHistoryPerDevice
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, device_id, sensor_name, ok, value, error_msg, exit_code, created_at
		FROM sensor_results WHERE device_id=$1 AND sensor_name=$2 ORDER BY created_at DESC LIMIT $3`,
		deviceID, sensorName, limit)
	if err != nil {
		return nil, fmt.Errorf("list sensor results: %w", err)
	}
	defer rows.Close()
	out := make([]types.SensorResult, 0)
	for rows.Next() {
		var res types.SensorResult
		var val []byte
		if err := rows.Scan(&res.ID, &res.DeviceID, &res.SensorName, &res.OK, &val, &res.ErrorMsg, &res.ExitCode, &res.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan sensor result: %w", err)
		}
		if val != nil {
			res.Value = json.RawMessage(val)
		}
		out = append(out, res)
	}
	return out, rows.Err()
}

var errNoSensor = errors.New("sensor not found")

// sentinel to satisfy pgx import if unused elsewhere
var _ = pgx.ErrNoRows
var _ = errNoSensor
