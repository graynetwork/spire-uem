package db_test

import (
	"context"
	"testing"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// Text and numeric searches must both work, including on a key some devices hold as an
// integer and others do not, and with values that are not numbers.
func TestInventory_SearchTextAndNumericValues(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	dev := newInvDevice(t, repo, "searchtag")
	if _, err := repo.ReplaceDeviceAttributes(ctx, dev.ID, types.AttrSourceInventory, []types.DeviceAttribute{
		types.StringAttr("os.name", "Debian GNU/Linux 12"),
		types.StringAttr("os.version_id", "12"),
		types.IntAttr("hw.memory_mb", 16384),
	}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		f    db.InventoryFilter
		want bool
	}{
		{"text eq", db.InventoryFilter{Key: "os.name", Op: "eq", Value: "Debian GNU/Linux 12"}, true},
		{"text ne", db.InventoryFilter{Key: "os.name", Op: "ne", Value: "Ubuntu"}, true},
		{"number gt", db.InventoryFilter{Key: "hw.memory_mb", Op: "gt", Value: "8000"}, true},
		{"number lt", db.InventoryFilter{Key: "hw.memory_mb", Op: "lt", Value: "8000"}, false},
		{"text value on integer key", db.InventoryFilter{Key: "hw.memory_mb", Op: "eq", Value: "lots"}, false},
		{"numeric value on text key", db.InventoryFilter{Key: "os.version_id", Op: "eq", Value: "12"}, true},
		{"numeric value against mixed keys", db.InventoryFilter{Key: "os.name", Op: "eq", Value: "12"}, false},
	}
	for _, tc := range cases {
		ids, err := repo.SearchInventoryDeviceIDs(ctx, db.InventorySearchParams{AttrFilters: []db.InventoryFilter{tc.f}}, db.Unscoped)
		if err != nil {
			t.Errorf("%s: search failed: %v", tc.name, err)
			continue
		}
		found := false
		for _, id := range ids {
			found = found || id == dev.ID
		}
		if found != tc.want {
			t.Errorf("%s: found=%v want %v", tc.name, found, tc.want)
		}
	}
}
