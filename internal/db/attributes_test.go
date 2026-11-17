package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

func TestDeviceAttributes_ReplaceAndOwnership(t *testing.T) {
	pool := getTestPool(t)
	defer pool.Close()
	ctx := context.Background()
	if err := db.RunMigrations(ctx, pool, "../../migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	repo := db.NewRepository(pool)
	hw := "attr-dev-" + time.Now().Format("150405.000000000")
	dev, _, err := repo.GetOrCreateDevice(ctx, hw, hw)
	if err != nil {
		t.Fatal(err)
	}

	inv := []types.DeviceAttribute{types.StringAttr("hw.cpu.model", "Ryzen"), types.IntAttr("hw.memory_mb", 16384)}
	if skipped, err := repo.ReplaceDeviceAttributes(ctx, dev.ID, types.AttrSourceInventory, inv); err != nil || len(skipped) != 0 {
		t.Fatalf("inventory write: skipped=%v err=%v", skipped, err)
	}
	sensor := types.SensorSource("disk_health")
	if _, err := repo.ReplaceDeviceAttributes(ctx, dev.ID, sensor, []types.DeviceAttribute{types.BoolAttr("sensor.disk_health", true)}); err != nil {
		t.Fatal(err)
	}

	// A sensor trying to write an inventory key is skipped, and the inventory value survives.
	skipped, err := repo.ReplaceDeviceAttributes(ctx, dev.ID, sensor, []types.DeviceAttribute{
		types.BoolAttr("sensor.disk_health", false), types.IntAttr("hw.memory_mb", 1),
	})
	if err != nil || len(skipped) != 1 || skipped[0] != "hw.memory_mb" {
		t.Fatalf("cross-source write: skipped=%v err=%v, want [hw.memory_mb]", skipped, err)
	}

	// Replacing the inventory set removes keys it no longer reports, but not the sensor's.
	if _, err := repo.ReplaceDeviceAttributes(ctx, dev.ID, types.AttrSourceInventory, []types.DeviceAttribute{types.IntAttr("hw.memory_mb", 32768)}); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetDeviceAttributes(ctx, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, a := range got {
		m[a.Key] = a.Source + "=" + string(a.Value)
	}
	want := map[string]string{"hw.memory_mb": "inventory=32768", "sensor.disk_health": sensor + "=false"}
	if len(m) != len(want) {
		t.Fatalf("attributes = %v, want %v", m, want)
	}
	for k, v := range want {
		if m[k] != v {
			t.Fatalf("attribute %s = %q, want %q (all: %v)", k, m[k], v, m)
		}
	}

	// Invalid input is refused before anything is written.
	if _, err := repo.ReplaceDeviceAttributes(ctx, dev.ID, "Bad Source", nil); err == nil {
		t.Fatal("invalid source must be refused")
	}
	if _, err := repo.ReplaceDeviceAttributes(ctx, dev.ID, types.AttrSourceInventory, []types.DeviceAttribute{
		types.IntAttr("hw.memory_mb", 1), types.IntAttr("hw.memory_mb", 2),
	}); err == nil {
		t.Fatal("duplicate keys must be refused")
	}

	keys, err := repo.ListAttributeKeys(ctx, "hw.")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, k := range keys {
		if k.Key == "hw.memory_mb" && k.Type == types.AttrInteger && k.Source == types.AttrSourceInventory && k.DeviceCount >= 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("ListAttributeKeys did not report hw.memory_mb: %+v", keys)
	}
}
