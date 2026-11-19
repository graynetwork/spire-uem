package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// The application list has its own row scan; it broke when policies gained target_group_ids.
func TestListApplicationPoliciesWithAdoption_Scans(t *testing.T) {
	pool := getTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	name := "app-scan-" + time.Now().Format("150405.000000000")
	if _, err := repo.CreatePolicy(ctx, name, "test", types.PolicyTypePackagePresence, []byte(`{"package_name":"htop"}`), []string{}); err != nil {
		t.Fatal(err)
	}
	items, _, err := repo.ListApplicationPoliciesWithAdoption(ctx)
	if err != nil {
		t.Fatalf("list applications: %v", err)
	}
	found := false
	for _, it := range items {
		found = found || it.Name == name
	}
	if !found {
		t.Fatalf("created application %q not listed", name)
	}
}
