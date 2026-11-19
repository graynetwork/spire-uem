package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/api"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

func invCheckinPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connStr := os.Getenv("SPIRE_TEST_DB_URL")
	if connStr == "" {
		t.Skip("skipping inventory check-in test: SPIRE_TEST_DB_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Skipf("skipping: cannot connect to postgres: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("skipping: postgres ping failed: %v", err)
	}
	if err := db.RunMigrations(ctx, pool, "../../migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return pool
}

// approveAndClaim approves a device and returns its id and bearer token.
func approveAndClaim(t *testing.T, ctx context.Context, repo *db.Repository, hw string) (string, string) {
	t.Helper()
	dev, _, err := repo.GetOrCreateDevice(ctx, hw, hw+"-host")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.ApproveDevice(ctx, dev.ID); err != nil {
		t.Fatal(err)
	}
	dev, _ = repo.GetDeviceByID(ctx, dev.ID)
	token, err := repo.ClaimApprovedToken(ctx, dev)
	if err != nil {
		t.Fatalf("claim token: %v", err)
	}
	return dev.ID, token
}

func postCheckin(t *testing.T, router chi.Router, token string, req types.CheckinRequest) int {
	t.Helper()
	body, _ := json.Marshal(req)
	r := httptest.NewRequest(http.MethodPost, "http://x/api/v1/desktop/checkin", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w.Code
}

func TestCheckin_StoresInventory_AndOldAgentWorks(t *testing.T) {
	pool := invCheckinPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)

	router := chi.NewRouter()
	api.RegisterRoutes(router, repo, nil)

	uniq := time.Now().Format("150405.000000000")

	// Old agent: a check-in with NO inventory field must succeed and leave HasInventory false.
	oldID, oldToken := approveAndClaim(t, ctx, repo, "inv-old-"+uniq)
	if code := postCheckin(t, router, oldToken, types.CheckinRequest{HardwareUUID: "inv-old-" + uniq, Packages: []string{"bash\t5.2"}}); code != http.StatusOK {
		t.Fatalf("old-agent check-in returned %d, want 200", code)
	}
	oldInv, err := repo.GetDeviceInventory(ctx, oldID)
	if err != nil {
		t.Fatal(err)
	}
	if oldInv.HasInventory {
		t.Fatal("old agent sent no inventory; HasInventory must be false")
	}

	// New agent: a check-in carrying an inventory report stores it.
	newID, newToken := approveAndClaim(t, ctx, repo, "inv-new-"+uniq)
	rep := &types.InventoryReport{
		CollectedAt: time.Now().UTC(),
		HW:          types.HardwareInfo{CPUModel: "Ryzen 7", MemoryMB: 32000, TPMPresent: true, TPMVersion: "2.0"},
		Net:         types.NetworkInfo{PrimaryIPv4: "10.1.2.3"},
		SW: types.SoftwareInfo{
			PackageCount: 1,
			Packages:     []types.InventoryPackage{{Name: "openssl", Version: "3.0", Architecture: "amd64"}},
			Listening:    []types.ListeningSocket{{Protocol: "tcp", Port: 22, ProcessName: "sshd"}},
		},
		Sec: types.SecurityInfo{FirewallActive: true},
	}
	if code := postCheckin(t, router, newToken, types.CheckinRequest{HardwareUUID: "inv-new-" + uniq, Inventory: rep}); code != http.StatusOK {
		t.Fatalf("new-agent check-in returned %d, want 200", code)
	}
	newInv, err := repo.GetDeviceInventory(ctx, newID)
	if err != nil {
		t.Fatal(err)
	}
	if !newInv.HasInventory {
		t.Fatal("new agent sent inventory; HasInventory must be true")
	}
	var mem, ip, fw bool
	for _, a := range newInv.Attributes {
		switch a.Key {
		case db.KeyHWMemoryMB:
			mem = string(a.Value) == "32000"
		case db.KeyNetPrimaryIPv4:
			ip = string(a.Value) == `"10.1.2.3"`
		case db.KeySecFirewallActive:
			fw = string(a.Value) == "true"
		}
	}
	if !mem || !ip || !fw {
		t.Fatalf("flattened attrs missing: mem=%v ip=%v fw=%v", mem, ip, fw)
	}
	if len(newInv.Packages) != 1 || len(newInv.Listening) != 1 {
		t.Fatalf("list tables not populated: pkgs=%d listen=%d", len(newInv.Packages), len(newInv.Listening))
	}
}
