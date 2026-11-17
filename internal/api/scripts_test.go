package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

func scriptsTestHandler(t *testing.T) (*Handler, *db.Repository, context.Context) {
	t.Helper()
	connStr := os.Getenv("SPIRE_TEST_DB_URL")
	if connStr == "" {
		t.Skip("SPIRE_TEST_DB_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Skipf("cannot connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("ping failed: %v", err)
	}
	if err := db.RunMigrations(ctx, pool, "../../migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	kek := filepath.Join(t.TempDir(), "kek.pem")
	repo := db.NewRepositoryWithKEK(pool, kek)
	return &Handler{repo: repo}, repo, ctx
}

func approvedDevice(t *testing.T, repo *db.Repository, ctx context.Context) (*types.Device, string) {
	t.Helper()
	hw := "scr-api-" + time.Now().Format("150405.000000000")
	dev, _, err := repo.GetOrCreateDevice(ctx, hw, hw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.ApproveDevice(ctx, dev.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}
	d, _ := repo.GetDeviceByID(ctx, dev.ID)
	token, err := repo.ClaimApprovedToken(ctx, d)
	if err != nil {
		t.Fatalf("claim token: %v", err)
	}
	d, _ = repo.GetDeviceByID(ctx, dev.ID)
	return d, token
}

func postCheckin(t *testing.T, h *Handler, token string, body types.CheckinRequest) types.CheckinResponse {
	t.Helper()
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/desktop/checkin", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.Checkin(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("checkin HTTP %d: %s", w.Code, w.Body.String())
	}
	var resp types.CheckinResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode checkin resp: %v", err)
	}
	return resp
}

func TestCheckin_DispatchesScriptAndSensorThenReports(t *testing.T) {
	h, repo, ctx := scriptsTestHandler(t)
	dev, token := approvedDevice(t, repo, ctx)

	// A script with one secret param, queued for this device.
	params := []types.ScriptParam{{Name: "SECRET", Type: types.ScriptParamString, Secret: true, Required: true}}
	s := &types.Script{Name: "api s " + time.Now().Format("150405.000000000"), Interpreter: types.InterpreterBash, RunAs: types.RunAsRoot}
	script, err := repo.CreateScript(ctx, s, `echo "$SPIRE_PARAM_SECRET"`, params, "admin")
	if err != nil {
		t.Fatal(err)
	}
	v, _ := repo.GetScriptVersion(ctx, *script.CurrentVersionID)
	plain, secret, err := db.ResolveScriptParams(v, map[string]string{"SECRET": "s3cr3t"})
	if err != nil {
		t.Fatal(err)
	}
	runID, err := repo.QueueScriptRun(ctx, dev.ID, v, types.TriggerOnDemand, plain, secret, "admin")
	if err != nil {
		t.Fatal(err)
	}

	// A sensor targeting all devices.
	sn := &types.Sensor{Name: "apisensor" + time.Now().Format("05000000"), ScriptVersionID: *script.CurrentVersionID, ReturnType: types.SensorInteger, IntervalSeconds: types.SensorMinIntervalSeconds, Enabled: true}
	sensor, err := repo.CreateSensor(ctx, sn, "admin")
	if err != nil {
		t.Fatal(err)
	}

	// Check-in: the response carries the resolved script + sensor directives.
	resp := postCheckin(t, h, token, types.CheckinRequest{HardwareUUID: dev.HardwareUUID, AgentVersion: "9.9.9"})
	if len(resp.ScriptDirectives) != 1 || resp.ScriptDirectives[0].RunID != runID {
		t.Fatalf("expected 1 script directive for run %s, got %+v", runID, resp.ScriptDirectives)
	}
	if resp.ScriptDirectives[0].Params["SECRET"] != "s3cr3t" {
		t.Fatalf("secret not opened for the device: %q", resp.ScriptDirectives[0].Params["SECRET"])
	}
	if resp.ScriptDirectives[0].SHA256 != v.SHA256 {
		t.Fatal("directive sha256 mismatch")
	}
	if len(resp.SensorDirectives) < 1 {
		t.Fatalf("expected at least our sensor directive, got %+v", resp.SensorDirectives)
	}
	foundSensor := false
	for _, sd := range resp.SensorDirectives {
		if sd.SensorName == sensor.Name {
			foundSensor = true
		}
	}
	if !foundSensor {
		t.Fatalf("our sensor %s not dispatched: %+v", sensor.Name, resp.SensorDirectives)
	}

	// Agent reports the run result.
	postJSONTo(t, h.ReportScriptRuns, token, types.ScriptRunReport{Runs: []types.ScriptRunResult{
		{RunID: runID, Status: types.ScriptRunCompleted, ExitCode: 0, Stdout: "s3cr3t", DurationMS: 3},
	}})
	runs, _ := repo.ListScriptRunsForDevice(ctx, dev.ID, 10)
	if len(runs) != 1 || runs[0].Status != types.ScriptRunCompleted {
		t.Fatalf("run not finalized: %+v", runs)
	}

	// Agent reports a sensor reading -> device attribute written.
	postJSONTo(t, h.ReportSensors, token, types.SensorReport{Results: []types.SensorResultReport{
		{SensorName: sensor.Name, ExitCode: 0, RawValue: "7"},
	}})
	attrs, _ := repo.GetDeviceAttributes(ctx, dev.ID)
	found := false
	for _, a := range attrs {
		if a.Key == "sensor."+sensor.Name {
			found = true
			if string(a.Value) != "7" {
				t.Fatalf("sensor attr value = %s, want 7", a.Value)
			}
		}
	}
	if !found {
		t.Fatal("sensor attribute not written from report")
	}

	// A second check-in should NOT re-dispatch the finished run or the not-yet-due sensor.
	resp2 := postCheckin(t, h, token, types.CheckinRequest{HardwareUUID: dev.HardwareUUID})
	if len(resp2.ScriptDirectives) != 0 {
		t.Fatalf("finished run re-dispatched: %+v", resp2.ScriptDirectives)
	}
	if len(resp2.SensorDirectives) != 0 {
		t.Fatalf("sensor re-dispatched before its interval: %+v", resp2.SensorDirectives)
	}
}

// TestCheckin_OldAgentSafe covers the upgrade case: an agent built before this feature sends
// a check-in with none of the new fields and ignores the new response fields. The server must
// still respond 200 and must not error when no scripts/sensors apply.
func TestCheckin_OldAgentSafe(t *testing.T) {
	h, repo, ctx := scriptsTestHandler(t)
	dev, token := approvedDevice(t, repo, ctx)
	// This device has no QUEUED script runs, so no script directives regardless of what other
	// tests left in the shared DB. (Fleet-wide sensors from other tests may legitimately apply.)
	resp := postCheckin(t, h, token, types.CheckinRequest{HardwareUUID: dev.HardwareUUID})
	if len(resp.ScriptDirectives) != 0 {
		t.Fatalf("a device with no queued runs must get no script directives: %+v", resp.ScriptDirectives)
	}

	// The omitempty fields must be absent from the JSON of a response with empty slices, so an
	// old client that does not know these fields is never handed them.
	bare := types.CheckinResponse{DeviceID: dev.ID, Status: types.StatusApproved}
	raw := mustMarshal(t, bare)
	if bytes.Contains(raw, []byte("script_directives")) || bytes.Contains(raw, []byte("sensor_directives")) {
		t.Fatalf("empty directive fields should be omitted from the response JSON: %s", raw)
	}
}

func postJSONTo(t *testing.T, fn http.HandlerFunc, token string, body any) {
	t.Helper()
	payload, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	fn(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("report HTTP %d: %s", w.Code, w.Body.String())
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
