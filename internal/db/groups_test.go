package db_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// grpSetup creates an approved device with the given hostname + tags and returns its id.
func grpDevice(t *testing.T, ctx context.Context, pool *pgxpool.Pool, repo *db.Repository, hostname string, tags []string) string {
	t.Helper()
	hw := hostname + "-" + time.Now().Format("150405.000000000")
	dev, _, err := repo.GetOrCreateDevice(ctx, hw, hostname)
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if _, _, err := repo.ApproveDevice(ctx, dev.ID); err != nil {
		t.Fatalf("approve device: %v", err)
	}
	if len(tags) > 0 {
		if _, err := repo.UpdateDeviceTags(ctx, dev.ID, tags); err != nil {
			t.Fatalf("tag device: %v", err)
		}
	}
	return dev.ID
}

func TestGroups_MembershipRecompute_IncludeExcludeAndHistory(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	tagEng := "grpeng-" + time.Now().Format("150405.000000")
	devA := grpDevice(t, ctx, pool, repo, "grp-a", []string{tagEng})
	devB := grpDevice(t, ctx, pool, repo, "grp-b", []string{tagEng})
	devC := grpDevice(t, ctx, pool, repo, "grp-c", []string{"sales"})

	// Rule: tag contains_any [tagEng]. devA, devB match; devC does not. Exclude devB; include devC.
	g, err := repo.CreateGroup(ctx, db.CreateGroupInput{
		Name:             "eng-group-" + time.Now().Format("150405.000000"),
		Kind:             types.GroupKindTarget,
		Rule:             []byte(`{"field":"device.tags","op":"contains_any","value":["` + tagEng + `"]}`),
		ExcludeDeviceIDs: []string{devB},
		IncludeDeviceIDs: []string{devC},
	})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, _, err := repo.RecomputeGroupMembership(ctx, g.ID); err != nil {
		t.Fatalf("recompute: %v", err)
	}
	members, err := repo.DevicesInGroup(ctx, g.ID)
	if err != nil {
		t.Fatalf("devices in group: %v", err)
	}
	got := map[string]bool{}
	for _, m := range members {
		got[m] = true
	}
	// Expect devA (rule) and devC (included); NOT devB (excluded even though rule matches).
	if !got[devA] || !got[devC] || got[devB] || len(members) != 2 {
		t.Fatalf("membership = %v, want {devA,devC} (devA=%s devB=%s devC=%s)", members, devA, devB, devC)
	}

	// History should record two joins with a reason.
	hist, err := repo.ListGroupHistory(ctx, g.ID, 50)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	joins := 0
	for _, e := range hist {
		if e.Entered {
			joins++
			if e.Reason == "" {
				t.Fatalf("join event has empty reason")
			}
		}
	}
	if joins != 2 {
		t.Fatalf("expected 2 join events, got %d (%+v)", joins, hist)
	}

	// Now tag devA out of eng → it should leave on recompute, with a leave event.
	if _, err := repo.UpdateDeviceTags(ctx, devA, []string{"other"}); err != nil {
		t.Fatalf("retag: %v", err)
	}
	if _, left, err := repo.RecomputeGroupMembership(ctx, g.ID); err != nil || left != 1 {
		t.Fatalf("recompute after retag: left=%d err=%v, want 1", left, err)
	}
	members, _ = repo.DevicesInGroup(ctx, g.ID)
	for _, m := range members {
		if m == devA {
			t.Fatalf("devA should have left the group")
		}
	}
}

func TestGroups_OperatorFamiliesAgainstRealData(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	dev := grpDevice(t, ctx, pool, repo, "grp-ops", []string{"prod"})
	// Set agent_version, last_checkin_at, pending_updates, reported_state directly.
	if _, err := pool.Exec(ctx, `UPDATE devices SET agent_version='1.2.10', last_checkin_at=NOW() - INTERVAL '10 days', reported_state=$2::jsonb WHERE id=$1`,
		dev, `{"os_name":"Debian GNU/Linux 12","kernel_version":"6.1.0","release_codename":"bookworm"}`); err != nil {
		t.Fatalf("set device fields: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO device_patch_status (device_id, pending_updates_count, security_updates_count, reboot_required)
		VALUES ($1, 7, 3, true) ON CONFLICT (device_id) DO UPDATE SET pending_updates_count=7, security_updates_count=3, reboot_required=true`, dev); err != nil {
		t.Fatalf("set patch status: %v", err)
	}

	match := func(rule string) bool {
		t.Helper()
		res, err := repo.PreviewGroupRule(ctx, []byte(rule), nil, nil, db.Unscoped)
		if err != nil {
			t.Fatalf("preview %s: %v", rule, err)
		}
		for _, d := range res.Devices {
			if d.DeviceID == dev {
				return true
			}
		}
		return false
	}

	cases := []struct {
		rule string
		want bool
	}{
		{`{"field":"device.hostname","op":"starts_with","value":"grp-ops"}`, true},
		{`{"field":"device.hostname","op":"contains","value":"ops"}`, true},
		{`{"field":"device.hostname","op":"matches","value":"^grp-ops"}`, true},
		{`{"field":"device.tags","op":"contains_all","value":["prod"]}`, true},
		{`{"field":"device.tags","op":"contains_any","value":["x","prod"]}`, true},
		{`{"field":"device.tags","op":"contains_all","value":["prod","nope"]}`, false},
		{`{"field":"device.pending_updates","op":"gte","value":7}`, true},
		{`{"field":"device.pending_updates","op":"gt","value":7}`, false},
		{`{"field":"device.security_updates","op":"in","value":[1,3,5]}`, true},
		{`{"field":"device.reboot_required","op":"eq","value":true}`, true},
		{`{"field":"device.os_name","op":"contains","value":"Debian"}`, true},
		{`{"field":"device.release_codename","op":"eq","value":"bookworm"}`, true},
		{`{"field":"device.last_checkin_at","op":"older_than","value":"7d"}`, true},
		{`{"field":"device.last_checkin_at","op":"newer_than","value":"7d"}`, false},
		// version ordering: 1.2.10 >= 1.2.9 (numeric, not string).
		{`{"field":"device.agent_version","op":"gte","value":"1.2.9"}`, true},
		{`{"field":"device.agent_version","op":"lt","value":"1.2.9"}`, false},
		{`{"field":"device.agent_version","op":"gte","value":"1.3.0"}`, false},
		// combinators + not
		{`{"all":[{"field":"device.tags","op":"contains_any","value":["prod"]},{"field":"device.pending_updates","op":"gt","value":5}]}`, true},
		{`{"not":{"field":"device.tags","op":"contains_any","value":["prod"]}}`, false},
		{`{"any":[{"field":"device.tags","op":"contains_any","value":["nope"]},{"field":"device.reboot_required","op":"eq","value":true}]}`, true},
	}
	for _, c := range cases {
		if got := match(c.rule); got != c.want {
			t.Errorf("rule %s matched=%v, want %v", c.rule, got, c.want)
		}
	}
}

func TestGroups_AttributeRulesAcrossTypes(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	dev := grpDevice(t, ctx, pool, repo, "grp-attr", nil)
	attrs := []types.DeviceAttribute{
		types.StringAttr("hw.cpu_model", "Ryzen 7"),
		types.IntAttr("hw.mem_mb", 16384),
		types.BoolAttr("sensor.disk_ok", true),
		types.TimeAttr("sw.last_scan", time.Now().Add(-48*time.Hour)),
	}
	if _, err := repo.ReplaceDeviceAttributes(ctx, dev, types.AttrSourceInventory, attrs[:2]); err != nil {
		t.Fatalf("write inv attrs: %v", err)
	}
	if _, err := repo.ReplaceDeviceAttributes(ctx, dev, types.SensorSource("disk"), attrs[2:3]); err != nil {
		t.Fatalf("write sensor attr: %v", err)
	}
	if _, err := repo.ReplaceDeviceAttributes(ctx, dev, types.AttrSourceSystem, attrs[3:4]); err != nil {
		t.Fatalf("write system attr: %v", err)
	}

	match := func(rule string) bool {
		res, err := repo.PreviewGroupRule(ctx, []byte(rule), nil, nil, db.Unscoped)
		if err != nil {
			t.Fatalf("preview %s: %v", rule, err)
		}
		for _, d := range res.Devices {
			if d.DeviceID == dev {
				return true
			}
		}
		return false
	}
	cases := []struct {
		rule string
		want bool
	}{
		{`{"field":"attr.hw.cpu_model","op":"contains","value":"Ryzen"}`, true},
		{`{"field":"attr.hw.cpu_model","op":"eq","value":"Ryzen 7"}`, true},
		{`{"field":"attr.hw.mem_mb","op":"gte","value":16384}`, true},
		{`{"field":"attr.hw.mem_mb","op":"gt","value":16384}`, false},
		{`{"field":"attr.sensor.disk_ok","op":"eq","value":true}`, true},
		{`{"field":"attr.sensor.disk_ok","op":"eq","value":false}`, false},
		{`{"field":"attr.sw.last_scan","op":"older_than","value":"1d"}`, true},
		{`{"field":"attr.missing.key","op":"missing"}`, true},
		{`{"field":"attr.hw.cpu_model","op":"exists"}`, true},
		{`{"field":"attr.hw.cpu_model","op":"ne","value":"Intel"}`, true},
	}
	for _, c := range cases {
		if got := match(c.rule); got != c.want {
			t.Errorf("attr rule %s matched=%v, want %v", c.rule, got, c.want)
		}
	}
}

func TestGroups_SQLInjectionValueIsLiteral(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	dev := grpDevice(t, ctx, pool, repo, "grp-inj", nil)
	// A hostname eq with an injection-looking value must match nothing and must not error or
	// drop the table.
	res, err := repo.PreviewGroupRule(ctx, []byte(`{"field":"device.hostname","op":"eq","value":"'); DROP TABLE devices; --"}`), nil, nil, db.Unscoped)
	if err != nil {
		t.Fatalf("preview injection value errored (should be literal): %v", err)
	}
	if res.Count != 0 {
		t.Fatalf("injection value matched %d devices, want 0", res.Count)
	}
	// Table still exists and our device is still there.
	var n int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM devices WHERE id=$1`, dev).Scan(&n); err != nil || n != 1 {
		t.Fatalf("devices table damaged: n=%d err=%v", n, err)
	}
}

func TestGroups_PolicyTargeting_WithAndWithoutGroups(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	inGroup := grpDevice(t, ctx, pool, repo, "grp-tgt-in", []string{"eng"})
	outGroup := grpDevice(t, ctx, pool, repo, "grp-tgt-out", []string{"eng"})

	g, err := repo.CreateGroup(ctx, db.CreateGroupInput{
		Name:             "tgt-group-" + time.Now().Format("150405.000000"),
		Kind:             types.GroupKindTarget,
		IncludeDeviceIDs: []string{inGroup},
	})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, _, err := repo.RecomputeGroupMembership(ctx, g.ID); err != nil {
		t.Fatalf("recompute: %v", err)
	}

	// Old-style policy (no groups) targets BOTH eng devices (upgrade safety).
	polNoGroup, err := repo.CreatePolicy(ctx, "no-group-"+time.Now().Format("150405.000000"), "", types.PolicyTypePackagePresence, []byte(`{"package_name":"curl"}`), []string{"eng"})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	assertTargeted := func(policyID, deviceID string, want bool) {
		t.Helper()
		pols, err := repo.GetActivePoliciesForDevice(ctx, deviceID)
		if err != nil {
			t.Fatalf("active policies: %v", err)
		}
		found := false
		for _, p := range pols {
			if p.ID == policyID {
				found = true
			}
		}
		if found != want {
			t.Fatalf("policy %s targeted on device %s = %v, want %v", policyID, deviceID, found, want)
		}
	}
	assertTargeted(polNoGroup.ID, inGroup, true)
	assertTargeted(polNoGroup.ID, outGroup, true)

	// Group-targeted policy: only inGroup is targeted.
	polGroup, err := repo.CreatePolicy(ctx, "group-"+time.Now().Format("150405.000000"), "", types.PolicyTypePackagePresence, []byte(`{"package_name":"vim"}`), []string{"eng"})
	if err != nil {
		t.Fatalf("create group policy: %v", err)
	}
	if err := repo.SetPolicyTargetGroups(ctx, polGroup.ID, []string{g.ID}); err != nil {
		t.Fatalf("set target groups: %v", err)
	}
	assertTargeted(polGroup.ID, inGroup, true)
	assertTargeted(polGroup.ID, outGroup, false)
}

func TestGroups_LeaveGroupTriggersRevoke(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	dev := grpDevice(t, ctx, pool, repo, "grp-rev", []string{"eng"})
	g, err := repo.CreateGroup(ctx, db.CreateGroupInput{
		Name:             "rev-group-" + time.Now().Format("150405.000000"),
		Kind:             types.GroupKindTarget,
		IncludeDeviceIDs: []string{dev},
	})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, _, err := repo.RecomputeGroupMembership(ctx, g.ID); err != nil {
		t.Fatalf("recompute: %v", err)
	}
	pol, err := repo.CreatePolicy(ctx, "rev-pol-"+time.Now().Format("150405.000000"), "", types.PolicyTypePackagePresence, []byte(`{"package_name":"htop"}`), nil)
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if err := repo.SetPolicyTargetGroups(ctx, pol.ID, []string{g.ID}); err != nil {
		t.Fatalf("set target group: %v", err)
	}
	// Stage the policy on the device (as a check-in would).
	if _, err := repo.StagePolicyForTargetedDevices(ctx, mustPolicy(t, repo, ctx, pol.ID)); err != nil {
		t.Fatalf("stage: %v", err)
	}
	// Device is targeted now; not revoked.
	if rev := revokedIDs(t, repo, ctx, dev); rev[pol.ID] {
		t.Fatalf("policy should not be revoked while device is a group member")
	}

	// Remove device from the group (empty the include list) and recompute.
	if _, err := repo.UpdateGroup(ctx, g.ID, db.CreateGroupInput{Name: g.Name, Kind: types.GroupKindTarget}); err != nil {
		t.Fatalf("update group: %v", err)
	}
	if _, _, err := repo.RecomputeGroupMembership(ctx, g.ID); err != nil {
		t.Fatalf("recompute after empty: %v", err)
	}
	// The device is no longer a member → the staged policy appears in the revoke set.
	if rev := revokedIDs(t, repo, ctx, dev); !rev[pol.ID] {
		t.Fatalf("policy should be revoked after the device left the group")
	}
}

func mustPolicy(t *testing.T, repo *db.Repository, ctx context.Context, id string) *types.Policy {
	t.Helper()
	p, err := repo.GetPolicyByID(ctx, id)
	if err != nil || p == nil {
		t.Fatalf("get policy: %v", err)
	}
	return p
}

func revokedIDs(t *testing.T, repo *db.Repository, ctx context.Context, deviceID string) map[string]bool {
	t.Helper()
	revs, err := repo.GetRevokedPoliciesForDevice(ctx, deviceID)
	if err != nil {
		t.Fatalf("revoked policies: %v", err)
	}
	m := map[string]bool{}
	for _, r := range revs {
		m[r.ID] = true
	}
	return m
}

func TestGroups_DeletionRefusedWhenReferenced(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	g, err := repo.CreateGroup(ctx, db.CreateGroupInput{Name: "del-group-" + time.Now().Format("150405.000000"), Kind: types.GroupKindTarget})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	pol, err := repo.CreatePolicy(ctx, "del-pol-"+time.Now().Format("150405.000000"), "", types.PolicyTypePackagePresence, []byte(`{"package_name":"git"}`), nil)
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if err := repo.SetPolicyTargetGroups(ctx, pol.ID, []string{g.ID}); err != nil {
		t.Fatalf("set target: %v", err)
	}
	err = repo.DeleteGroup(ctx, g.ID)
	ref, ok := err.(*db.ErrGroupReferenced)
	if !ok {
		t.Fatalf("expected ErrGroupReferenced, got %v", err)
	}
	if len(ref.PolicyNames) != 1 || ref.PolicyNames[0] != pol.Name {
		t.Fatalf("referenced policies = %v, want [%s]", ref.PolicyNames, pol.Name)
	}
	// After clearing the reference, deletion succeeds.
	if err := repo.SetPolicyTargetGroups(ctx, pol.ID, nil); err != nil {
		t.Fatalf("clear target: %v", err)
	}
	if err := repo.DeleteGroup(ctx, g.ID); err != nil {
		t.Fatalf("delete after clearing reference: %v", err)
	}
}

func TestGroups_ScopedAdminImplicitTagFilter(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	suffix := time.Now().Format("150405.000000")
	inTag := "scopegrp-in-" + suffix
	outTag := "scopegrp-out-" + suffix
	devIn := grpDevice(t, ctx, pool, repo, "sg-in", []string{inTag})
	devOut := grpDevice(t, ctx, pool, repo, "sg-out", []string{outTag})

	// Rule matches BOTH devices (status APPROVED). A scoped admin limited to inTag should
	// only see devIn in a preview, via the implicit tag AND.
	rule := []byte(`{"field":"device.status","op":"eq","value":"APPROVED"}`)
	scope := db.DeviceScope{Scoped: true, Tags: []string{inTag}}
	res, err := repo.PreviewGroupRule(ctx, rule, nil, nil, scope)
	if err != nil {
		t.Fatalf("scoped preview: %v", err)
	}
	seenIn, seenOut := false, false
	for _, d := range res.Devices {
		if d.DeviceID == devIn {
			seenIn = true
		}
		if d.DeviceID == devOut {
			seenOut = true
		}
	}
	if !seenIn || seenOut {
		t.Fatalf("scoped preview saw in=%v out=%v, want in=true out=false", seenIn, seenOut)
	}
	_ = devOut
}

func TestGroups_EvaluationErrorKeepsLastMembership(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	dev := grpDevice(t, ctx, pool, repo, "grp-fail", []string{"eng"})
	g, err := repo.CreateGroup(ctx, db.CreateGroupInput{
		Name:             "fail-group-" + time.Now().Format("150405.000000"),
		Kind:             types.GroupKindTarget,
		IncludeDeviceIDs: []string{dev},
	})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if _, _, err := repo.RecomputeGroupMembership(ctx, g.ID); err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if ids, _ := repo.DevicesInGroup(ctx, g.ID); len(ids) != 1 {
		t.Fatalf("expected 1 member before corruption, got %d", len(ids))
	}

	// Corrupt the stored rule to something that fails to parse/compile.
	if _, err := pool.Exec(ctx, `UPDATE device_groups SET rule=$2::jsonb WHERE id=$1`, g.ID, `{"field":"device.not_real","op":"eq","value":"x"}`); err != nil {
		t.Fatalf("corrupt rule: %v", err)
	}
	// Recompute should fail-safe: return an error AND keep the last membership.
	if _, _, err := repo.RecomputeGroupMembership(ctx, g.ID); err == nil {
		t.Fatalf("expected recompute to report the bad rule")
	}
	if ids, _ := repo.DevicesInGroup(ctx, g.ID); len(ids) != 1 {
		t.Fatalf("membership must be preserved on evaluation error, got %d members", len(ids))
	}
	// The error is recorded on the group row.
	g2, _ := repo.GetGroupByID(ctx, g.ID)
	if g2 == nil || g2.LastRuleError == "" {
		t.Fatalf("group should record last_rule_error, got %+v", g2)
	}
}

// jsonEq is a tiny helper for comparing canonical JSON in a couple of assertions.
func jsonEq(a, b []byte) bool {
	var x, y any
	_ = json.Unmarshal(a, &x)
	_ = json.Unmarshal(b, &y)
	ab, _ := json.Marshal(x)
	bb, _ := json.Marshal(y)
	return string(ab) == string(bb)
}

var _ = jsonEq
