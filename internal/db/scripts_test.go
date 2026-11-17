package db_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// repoWithKEK builds a repository against the test pool with a freshly generated KEK (needed
// for sealing secret script parameters).
func repoWithKEK(t *testing.T, pool *pgxpool.Pool) *db.Repository {
	t.Helper()
	kek := filepath.Join(t.TempDir(), "kek.pem")
	return db.NewRepositoryWithKEK(pool, kek)
}

func mkDevice(t *testing.T, repo *db.Repository, ctx context.Context, tags []string, ring types.DeploymentRing) *types.Device {
	t.Helper()
	hw := "scr-dev-" + time.Now().Format("150405.000000000")
	dev, _, err := repo.GetOrCreateDevice(ctx, hw, hw)
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if _, _, err := repo.ApproveDevice(ctx, dev.ID); err != nil {
		t.Fatalf("approve device: %v", err)
	}
	if len(tags) > 0 {
		if _, err := repo.UpdateDeviceTags(ctx, dev.ID, tags); err != nil {
			t.Fatalf("set tags: %v", err)
		}
	}
	if ring != "" {
		if _, err := repo.UpdateDevicePatchRing(ctx, dev.ID, ring); err != nil {
			t.Fatalf("set ring: %v", err)
		}
	}
	d, _ := repo.GetDeviceByID(ctx, dev.ID)
	return d
}

func mkScript(t *testing.T, repo *db.Repository, ctx context.Context, content string, params []types.ScriptParam) *types.Script {
	t.Helper()
	s := &types.Script{Name: "s " + time.Now().Format("150405.000000000"), Interpreter: types.InterpreterBash, RunAs: types.RunAsRoot}
	created, err := repo.CreateScript(ctx, s, content, params, "admin")
	if err != nil {
		t.Fatalf("create script: %v", err)
	}
	return created
}

func TestScriptVersionsAreImmutable(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	s := mkScript(t, repo, ctx, "echo v1", nil)
	v1 := *s.CurrentVersionID
	gotV1, err := repo.GetScriptVersion(ctx, v1)
	if err != nil || gotV1.Version != 1 || gotV1.SHA256 != types.ComputeScriptSHA256("echo v1") {
		t.Fatalf("v1 wrong: %+v err=%v", gotV1, err)
	}

	v2, err := repo.AddScriptVersion(ctx, s.ID, "echo v2", nil, "admin")
	if err != nil {
		t.Fatalf("add version: %v", err)
	}
	if v2.Version != 2 {
		t.Fatalf("version number = %d, want 2", v2.Version)
	}
	// v1 content is unchanged (immutable).
	stillV1, _ := repo.GetScriptVersion(ctx, v1)
	if stillV1.Content != "echo v1" {
		t.Fatalf("v1 content mutated: %q", stillV1.Content)
	}
	// current points at v2 now.
	reloaded, _ := repo.GetScript(ctx, s.ID)
	if reloaded.CurrentVersionID == nil || *reloaded.CurrentVersionID != v2.ID {
		t.Fatal("current version not advanced to v2")
	}
	// Marking v1 current again works.
	if err := repo.SetCurrentScriptVersion(ctx, s.ID, v1); err != nil {
		t.Fatalf("set current v1: %v", err)
	}
}

func TestQueueClaimRun_SecretNeverStoredPlain(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := repoWithKEK(t, pool)

	params := []types.ScriptParam{
		{Name: "USERNAME", Type: types.ScriptParamString, Required: true},
		{Name: "TOKEN", Type: types.ScriptParamString, Required: true, Secret: true},
	}
	s := mkScript(t, repo, ctx, `echo "$SPIRE_PARAM_USERNAME"`, params)
	v, _ := repo.GetScriptVersion(ctx, *s.CurrentVersionID)
	dev := mkDevice(t, repo, ctx, nil, "")

	secretVal := "super-secret-token-value"
	plain, secret, err := db.ResolveScriptParams(v, map[string]string{"USERNAME": "alice", "TOKEN": secretVal})
	if err != nil {
		t.Fatalf("resolve params: %v", err)
	}
	if _, ok := plain["TOKEN"]; ok {
		t.Fatal("secret param leaked into plain set")
	}
	runID, err := repo.QueueScriptRun(ctx, dev.ID, v, types.TriggerOnDemand, plain, secret, "admin")
	if err != nil {
		t.Fatalf("queue run: %v", err)
	}

	// The stored params column must NOT contain the secret value.
	var paramsCol string
	if err := pool.QueryRow(ctx, `SELECT params::text FROM script_runs WHERE id=$1`, runID).Scan(&paramsCol); err != nil {
		t.Fatal(err)
	}
	if containsStr(paramsCol, secretVal) {
		t.Fatalf("secret value stored in plain params column: %s", paramsCol)
	}
	// The sealed secret row must not hold the plaintext either.
	var ct string
	if err := pool.QueryRow(ctx, `SELECT ciphertext FROM script_run_secrets WHERE run_id=$1 AND param_name='TOKEN'`, runID).Scan(&ct); err != nil {
		t.Fatalf("sealed secret row missing: %v", err)
	}
	if containsStr(ct, secretVal) {
		t.Fatal("sealed ciphertext contains plaintext")
	}

	// Claiming the directive opens the secret for the target device only.
	dirs, err := repo.ClaimScriptDirectivesForDevice(ctx, dev.ID)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if len(dirs) != 1 {
		t.Fatalf("claimed %d directives, want 1", len(dirs))
	}
	if dirs[0].Params["TOKEN"] != secretVal {
		t.Fatalf("opened secret = %q, want %q", dirs[0].Params["TOKEN"], secretVal)
	}
	if dirs[0].Params["USERNAME"] != "alice" {
		t.Fatalf("plain param wrong: %q", dirs[0].Params["USERNAME"])
	}
	if dirs[0].SHA256 != v.SHA256 {
		t.Fatal("directive sha256 mismatch")
	}

	// A second claim returns nothing (claimed exactly once -> RUNNING).
	dirs2, _ := repo.ClaimScriptDirectivesForDevice(ctx, dev.ID)
	if len(dirs2) != 0 {
		t.Fatalf("run claimed twice: %d", len(dirs2))
	}

	// Reporting a result finalizes it; stdout/stderr never contain the secret because the
	// agent only ever gets it as an env var — here we just confirm result recording works.
	if err := repo.RecordScriptRunResult(ctx, dev.ID, types.ScriptRunResult{
		RunID: runID, Status: types.ScriptRunCompleted, ExitCode: 0, Stdout: "alice", DurationMS: 5,
	}); err != nil {
		t.Fatalf("record result: %v", err)
	}
}

func TestResolveScriptParams_MissingRequiredAndUnknown(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	params := []types.ScriptParam{{Name: "REQ", Type: types.ScriptParamString, Required: true}}
	s := mkScript(t, repo, ctx, "echo hi", params)
	v, _ := repo.GetScriptVersion(ctx, *s.CurrentVersionID)

	if _, _, err := db.ResolveScriptParams(v, map[string]string{}); err == nil {
		t.Fatal("missing required param must error")
	}
	if _, _, err := db.ResolveScriptParams(v, map[string]string{"REQ": "x", "BOGUS": "y"}); err == nil {
		t.Fatal("unknown param must error")
	}
	if _, _, err := db.ResolveScriptParams(v, map[string]string{"REQ": "x"}); err != nil {
		t.Fatalf("valid params should resolve: %v", err)
	}
}

func TestScopedTargetingExcludesOutOfScope(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	suffix := time.Now().Format("150405.000000000")
	inScopeTag := "team-a-" + suffix
	outScopeTag := "team-b-" + suffix
	inDev := mkDevice(t, repo, ctx, []string{inScopeTag}, "")
	outDev := mkDevice(t, repo, ctx, []string{outScopeTag}, "")

	// A scoped admin limited to inScopeTag targets by the broad tag set but must only reach inDev.
	ids, err := repo.ResolveScriptTargetDevices(ctx, db.ScriptTarget{
		Tags:      []string{inScopeTag, outScopeTag},
		ScopeTags: []string{inScopeTag},
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(ids) != 1 || ids[0] != inDev.ID {
		t.Fatalf("scoped target reached out-of-scope devices: %v (in=%s out=%s)", ids, inDev.ID, outDev.ID)
	}

	// Scoped admin explicitly naming the out-of-scope device id gets nothing.
	ids2, _ := repo.ResolveScriptTargetDevices(ctx, db.ScriptTarget{
		DeviceIDs: []string{outDev.ID},
		ScopeTags: []string{inScopeTag},
	})
	if len(ids2) != 0 {
		t.Fatalf("scoped admin targeted out-of-scope device by id: %v", ids2)
	}

	// Unscoped admin (ScopeTags nil) reaches both by the shared tag.
	ids3, _ := repo.ResolveScriptTargetDevices(ctx, db.ScriptTarget{Tags: []string{inScopeTag, outScopeTag}})
	if len(ids3) != 2 {
		t.Fatalf("unscoped target = %v, want both", ids3)
	}
}

func TestSensorTypingOwnershipAndCleanup(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	suffix := time.Now().Format("150405.000000000")
	tag := "sensortag-" + suffix
	dev := mkDevice(t, repo, ctx, []string{tag}, "")

	// Inventory writes an hw.* key first; a sensor must never be able to overwrite it.
	if _, err := repo.ReplaceDeviceAttributes(ctx, dev.ID, types.AttrSourceInventory, []types.DeviceAttribute{types.IntAttr("hw.cores", 8)}); err != nil {
		t.Fatal(err)
	}

	script := mkScript(t, repo, ctx, "echo 42", nil)
	// sensor names are globally unique and must be lowercase ^[a-z][a-z0-9_]{0,47}$
	sensorName := "cpu_sensor_" + onlyAlnumLower(suffix)
	sn := &types.Sensor{
		Name: sensorName, ScriptVersionID: *script.CurrentVersionID,
		ReturnType: types.SensorInteger, IntervalSeconds: types.SensorMinIntervalSeconds,
		TargetTags: []string{tag}, Enabled: true,
	}
	sensor, err := repo.CreateSensor(ctx, sn, "admin")
	if err != nil {
		t.Fatalf("create sensor: %v", err)
	}

	// Record a good integer reading -> writes sensor.<name> under source sensor:<name>.
	updated, err := repo.RecordSensorResult(ctx, dev.ID, sensor, types.SensorResultReport{SensorName: sensorName, ExitCode: 0, RawValue: "42"})
	if err != nil || !updated {
		t.Fatalf("record good reading: updated=%v err=%v", updated, err)
	}
	// A parse failure keeps the last good value (no update) and records an error row.
	updated, err = repo.RecordSensorResult(ctx, dev.ID, sensor, types.SensorResultReport{SensorName: sensorName, ExitCode: 0, RawValue: "not-an-int"})
	if err != nil || updated {
		t.Fatalf("parse failure must not update: updated=%v err=%v", updated, err)
	}
	// A non-zero exit also keeps the last good value.
	updated, _ = repo.RecordSensorResult(ctx, dev.ID, sensor, types.SensorResultReport{SensorName: sensorName, ExitCode: 2, RawValue: "99"})
	if updated {
		t.Fatal("non-zero exit must not update the value")
	}

	attrs, _ := repo.GetDeviceAttributes(ctx, dev.ID)
	got := map[string]string{}
	for _, a := range attrs {
		got[a.Key] = a.Source + "=" + string(a.Value)
	}
	if got["sensor."+sensorName] != types.SensorSource(sensorName)+"=42" {
		t.Fatalf("sensor value = %q, want 42 from last good reading", got["sensor."+sensorName])
	}
	if got["hw.cores"] != "inventory=8" {
		t.Fatalf("sensor overwrote or lost inventory key: %q", got["hw.cores"])
	}

	// History is kept (good + the two error rows).
	hist, _ := repo.ListSensorResults(ctx, dev.ID, sensorName, 10)
	if len(hist) < 3 {
		t.Fatalf("expected >=3 history rows, got %d", len(hist))
	}

	// Disabling the sensor and running cleanup removes the device's sensor attribute.
	sensor.Enabled = false
	if err := repo.UpdateSensor(ctx, sensor); err != nil {
		t.Fatalf("disable sensor: %v", err)
	}
	cleared, err := repo.ClearStaleSensorAttributesForDevice(ctx, dev.ID, dev.Tags, dev.PatchRing)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if len(cleared) != 1 || cleared[0] != sensorName {
		t.Fatalf("cleanup cleared %v, want [%s]", cleared, sensorName)
	}
	attrs2, _ := repo.GetDeviceAttributes(ctx, dev.ID)
	for _, a := range attrs2 {
		if a.Key == "sensor."+sensorName {
			t.Fatal("sensor attribute not cleared after disable")
		}
		if a.Key == "hw.cores" && string(a.Value) != "8" {
			t.Fatal("cleanup disturbed an inventory key")
		}
	}
}

func TestSensorDueDispatchRespectsIntervalAndTargets(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	suffix := time.Now().Format("150405.000000000")
	tag := "duetag-" + suffix
	dev := mkDevice(t, repo, ctx, []string{tag}, "")
	other := mkDevice(t, repo, ctx, []string{"unrelated-" + suffix}, "")

	script := mkScript(t, repo, ctx, "echo 1", nil)
	dueName := "due_sensor_" + onlyAlnumLower(suffix)
	sn := &types.Sensor{Name: dueName, ScriptVersionID: *script.CurrentVersionID, ReturnType: types.SensorInteger, IntervalSeconds: types.SensorMinIntervalSeconds, TargetTags: []string{tag}, Enabled: true}
	if _, err := repo.CreateSensor(ctx, sn, "admin"); err != nil {
		t.Fatalf("create sensor: %v", err)
	}

	now := time.Now().UTC()
	countMine := func(dirs []types.SensorDirective) int {
		n := 0
		for _, d := range dirs {
			if d.SensorName == dueName {
				n++
			}
		}
		return n
	}
	// In-target device: our sensor is due on first check-in.
	dirs, err := repo.ClaimDueSensorDirectivesForDevice(ctx, dev.ID, dev.Tags, dev.PatchRing, now)
	if err != nil || countMine(dirs) != 1 {
		t.Fatalf("first dispatch: mine=%d err=%v, want 1", countMine(dirs), err)
	}
	// Immediately again: our sensor is not due (interval not elapsed).
	dirs2, _ := repo.ClaimDueSensorDirectivesForDevice(ctx, dev.ID, dev.Tags, dev.PatchRing, now.Add(time.Minute))
	if countMine(dirs2) != 0 {
		t.Fatalf("our sensor re-dispatched before interval elapsed: mine=%d", countMine(dirs2))
	}
	// After the interval: due again.
	dirs3, _ := repo.ClaimDueSensorDirectivesForDevice(ctx, dev.ID, dev.Tags, dev.PatchRing, now.Add(types.SensorMinIntervalSeconds*time.Second+time.Minute))
	if countMine(dirs3) != 1 {
		t.Fatalf("our sensor not re-dispatched after interval: mine=%d", countMine(dirs3))
	}
	// Out-of-target device never gets OUR sensor (it may get other fleet-wide ones).
	od, _ := repo.ClaimDueSensorDirectivesForDevice(ctx, other.ID, other.Tags, other.PatchRing, now)
	if countMine(od) != 0 {
		t.Fatalf("out-of-target device received our sensor: mine=%d", countMine(od))
	}
}

func TestScriptPolicyResolution_AndDeletedVersion(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	detectScript := mkScript(t, repo, ctx, "exit 0", nil)
	remScript := mkScript(t, repo, ctx, "echo fix", nil)
	payload := types.ScriptPolicyPayload{
		DetectVersionID:    *detectScript.CurrentVersionID,
		RemediateVersionID: *remScript.CurrentVersionID,
	}
	raw := mustJSONB(t, payload)

	policies := []types.AssignedPolicy{{ID: "p1", PolicyType: types.PolicyTypeScriptPolicy, Payload: raw}}
	resolved, err := repo.ResolveScriptPolicyPayloads(ctx, policies)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	var dir types.ScriptPolicyDirective
	mustUnJSON(t, resolved[0].Payload, &dir)
	if dir.Detect == nil || dir.Detect.Content != "exit 0" || dir.Detect.SHA256 != types.ComputeScriptSHA256("exit 0") {
		t.Fatalf("detect step not resolved: %+v", dir.Detect)
	}
	if dir.Remediate == nil || dir.Remediate.Content != "echo fix" {
		t.Fatalf("remediate step not resolved: %+v", dir.Remediate)
	}
	if dir.Missing != "" {
		t.Fatalf("unexpected missing: %s", dir.Missing)
	}

	// Delete the detect script; resolution must mark the policy Missing, not error.
	if err := repo.DeleteScript(ctx, detectScript.ID); err != nil {
		t.Fatalf("delete script: %v", err)
	}
	policies2 := []types.AssignedPolicy{{ID: "p1", PolicyType: types.PolicyTypeScriptPolicy, Payload: raw}}
	resolved2, err := repo.ResolveScriptPolicyPayloads(ctx, policies2)
	if err != nil {
		t.Fatalf("resolve after delete: %v", err)
	}
	var dir2 types.ScriptPolicyDirective
	mustUnJSON(t, resolved2[0].Payload, &dir2)
	if dir2.Missing == "" {
		t.Fatal("deleted detect version must set Missing")
	}
}

func TestStaleRunningRunMarkedInterrupted(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := repoWithKEK(t, pool)

	s := mkScript(t, repo, ctx, "echo hi", nil)
	v, _ := repo.GetScriptVersion(ctx, *s.CurrentVersionID)
	dev := mkDevice(t, repo, ctx, nil, "")
	runID, _ := repo.QueueScriptRun(ctx, dev.ID, v, types.TriggerOnDemand, map[string]string{}, nil, "admin")
	// Claim moves it to RUNNING.
	if _, err := repo.ClaimScriptDirectivesForDevice(ctx, dev.ID); err != nil {
		t.Fatal(err)
	}
	// Backdate created_at so the stale sweep catches it.
	if _, err := pool.Exec(ctx, `UPDATE script_runs SET created_at = NOW() - INTERVAL '3 hours' WHERE id=$1`, runID); err != nil {
		t.Fatal(err)
	}
	n, err := repo.RequeueStaleRunningScriptRuns(ctx, dev.ID, 2*time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("stale sweep n=%d err=%v, want 1", n, err)
	}
	runs, _ := repo.ListScriptRunsForDevice(ctx, dev.ID, 10)
	if len(runs) != 1 || runs[0].Status != types.ScriptRunInterrupted {
		t.Fatalf("stale run not marked INTERRUPTED: %+v", runs)
	}
}

// helpers
func containsStr(hay, needle string) bool { return len(needle) > 0 && stringsContains(hay, needle) }
