package db_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

func postureDevice(t *testing.T, repo *db.Repository, ctx context.Context) *types.Device {
	t.Helper()
	hw := "posture-dev-" + time.Now().Format("150405.000000000")
	dev, _, err := repo.GetOrCreateDevice(ctx, hw, hw)
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	if _, _, err := repo.ApproveDevice(ctx, dev.ID); err != nil {
		t.Fatalf("approve device: %v", err)
	}
	return dev
}

func TestDevicePosture_UpsertTracksTransitions(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	dev := postureDevice(t, repo, ctx)

	if p, err := repo.GetDevicePosture(ctx, dev.ID); err != nil || p != nil {
		t.Fatalf("unevaluated device: got %+v, %v; want nil, nil", p, err)
	}
	var nilPosture *types.DevicePosture
	if got := nilPosture.EffectiveState(time.Now()); got != types.PostureUnknown {
		t.Fatalf("nil posture effective state = %s, want UNKNOWN", got)
	}

	t0 := time.Now().UTC().Truncate(time.Millisecond)
	prev, err := repo.UpsertDevicePosture(ctx, &types.DevicePosture{
		DeviceID: dev.ID, State: types.PostureCompliant, EvaluatedAt: t0, ValidUntil: t0.Add(time.Hour),
	})
	if err != nil || prev != types.PostureUnknown {
		t.Fatalf("first upsert: prev=%s err=%v; want UNKNOWN, nil", prev, err)
	}
	first, _ := repo.GetDevicePosture(ctx, dev.ID)

	// Same state again: state_changed_at must not move.
	t1 := t0.Add(time.Minute)
	prev, err = repo.UpsertDevicePosture(ctx, &types.DevicePosture{
		DeviceID: dev.ID, State: types.PostureCompliant, EvaluatedAt: t1, ValidUntil: t1.Add(time.Hour),
	})
	if err != nil || prev != types.PostureCompliant {
		t.Fatalf("second upsert: prev=%s err=%v", prev, err)
	}
	second, _ := repo.GetDevicePosture(ctx, dev.ID)
	if !second.StateChangedAt.Equal(first.StateChangedAt) {
		t.Fatalf("state_changed_at moved without a state change: %v -> %v", first.StateChangedAt, second.StateChangedAt)
	}

	// A real transition moves it and is listed by ListPostureChangedSince.
	t2 := t1.Add(time.Minute)
	if _, err := repo.UpsertDevicePosture(ctx, &types.DevicePosture{
		DeviceID: dev.ID, State: types.PostureNoncompliant, Reasons: []string{"disk not encrypted"},
		Checks:      []types.PostureCheck{{ID: "disk_encrypted", Passed: false, Detail: "no LUKS root"}},
		EvaluatedAt: t2, ValidUntil: t2.Add(time.Hour),
	}); err != nil {
		t.Fatalf("third upsert: %v", err)
	}
	third, _ := repo.GetDevicePosture(ctx, dev.ID)
	if !third.StateChangedAt.Equal(t2) || third.Reasons[0] != "disk not encrypted" || third.Checks[0].ID != "disk_encrypted" {
		t.Fatalf("transition not stored: %+v", third)
	}
	changed, err := repo.ListPostureChangedSince(ctx, t1, 100)
	if err != nil {
		t.Fatalf("list changed: %v", err)
	}
	found := false
	for _, c := range changed {
		if c.DeviceID == dev.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("transitioned device missing from ListPostureChangedSince")
	}

	// A stale verdict reads as UNKNOWN.
	if got := third.EffectiveState(t2.Add(2 * time.Hour)); got != types.PostureUnknown {
		t.Fatalf("stale verdict effective state = %s, want UNKNOWN", got)
	}
	if third.Allowed(t2) {
		t.Fatalf("NONCOMPLIANT verdict reported as allowed")
	}

	if _, err := repo.UpsertDevicePosture(ctx, &types.DevicePosture{DeviceID: dev.ID, State: "BOGUS", ValidUntil: t2}); err == nil {
		t.Fatalf("invalid state accepted")
	}
	if _, err := repo.UpsertDevicePosture(ctx, &types.DevicePosture{DeviceID: dev.ID, State: types.PostureCompliant}); err == nil {
		t.Fatalf("missing valid_until accepted")
	}
}

func TestResolveAccessIdentity(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	dev := postureDevice(t, repo, ctx)
	other := postureDevice(t, repo, ctx)
	suffix := time.Now().Format("150405000000")
	serial := "9" + suffix
	fp := "ab" + suffix
	revokedSerial := "8" + suffix
	ip := fmt.Sprintf("10.250.%d.%d", time.Now().Nanosecond()%250, 7)
	user := "posture-user-" + suffix

	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	mustExec(`INSERT INTO device_certificates (device_id, serial, fingerprint_sha256, not_before, not_after)
		VALUES ($1, $2, $3, NOW() - interval '1 hour', NOW() + interval '1 day')`, dev.ID, serial, fp)
	mustExec(`INSERT INTO device_certificates (device_id, serial, fingerprint_sha256, not_before, not_after, revoked_at)
		VALUES ($1, $2, $3, NOW() - interval '1 hour', NOW() + interval '1 day', NOW())`, other.ID, revokedSerial, "cd"+suffix)
	mustExec(`UPDATE devices SET last_seen_ip = $2, last_active_user = $3 WHERE id = ANY($1)`,
		[]string{dev.ID, other.ID}, ip, user)
	mac := "02:" + suffix[0:2] + ":" + suffix[2:4] + ":" + suffix[4:6] + ":" + suffix[6:8] + ":" + suffix[8:10]
	mustExec(`INSERT INTO device_attributes (device_id, key, value_type, value, source)
		VALUES ($1, 'net.primary_mac', 'string', to_jsonb($2::text), 'inventory')`, dev.ID, mac)

	one := func(name string, id types.AccessIdentity, want ...string) {
		t.Helper()
		got, err := repo.ResolveAccessIdentity(ctx, id)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%s: got %v, want %v", name, got, want)
		}
		wantSet := map[string]bool{}
		for _, w := range want {
			wantSet[w] = true
		}
		for _, g := range got {
			if !wantSet[g] {
				t.Fatalf("%s: got %v, want %v", name, got, want)
			}
		}
	}
	one("serial", types.AccessIdentity{CertSerial: serial}, dev.ID)
	one("fingerprint with colons and caps", types.AccessIdentity{CertFingerprint: "AB:" + suffix}, dev.ID)
	one("revoked serial", types.AccessIdentity{CertSerial: revokedSerial})
	one("mac, hyphen notation", types.AccessIdentity{MAC: "02-" + suffix[0:2] + "-" + suffix[2:4] + "-" + suffix[4:6] + "-" + suffix[6:8] + "-" + suffix[8:10]}, dev.ID)
	one("bad mac", types.AccessIdentity{MAC: "not-a-mac"})
	one("ip shared by two devices", types.AccessIdentity{IP: ip}, dev.ID, other.ID)
	one("user, different case", types.AccessIdentity{User: "POSTURE-USER-" + suffix}, dev.ID, other.ID)
	one("empty identity", types.AccessIdentity{})
	// The strongest field decides: a valid serial wins over a shared IP.
	one("serial beats ip", types.AccessIdentity{CertSerial: serial, IP: ip}, dev.ID)

	// Lost and revoked devices never resolve.
	mustExec(`UPDATE devices SET is_lost = TRUE WHERE id = $1`, other.ID)
	one("lost device excluded", types.AccessIdentity{IP: ip}, dev.ID)
	mustExec(`UPDATE devices SET status = 'REVOKED' WHERE id = $1`, dev.ID)
	one("revoked device excluded", types.AccessIdentity{CertSerial: serial})
}

func TestNormalizeMAC(t *testing.T) {
	for in, want := range map[string]string{
		"AA:BB:CC:DD:EE:FF": "aa:bb:cc:dd:ee:ff",
		"aa-bb-cc-dd-ee-ff": "aa:bb:cc:dd:ee:ff",
		"aabb.ccdd.eeff":    "aa:bb:cc:dd:ee:ff",
		"AABBCCDDEEFF":      "aa:bb:cc:dd:ee:ff",
		"aa:bb:cc":          "",
		"":                  "",
		"zz:bb:cc:dd:ee:ff": "",
	} {
		if got := db.NormalizeMAC(in); got != want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
}
