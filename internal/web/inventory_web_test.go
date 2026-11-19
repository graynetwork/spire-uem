package web_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/audit"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/web"
)

func invWebPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connStr := os.Getenv("SPIRE_TEST_DB_URL")
	if connStr == "" {
		t.Skip("skipping inventory web test: SPIRE_TEST_DB_URL not set")
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

func seedInvDevice(t *testing.T, ctx context.Context, repo *db.Repository, hw string, tags []string, mem int64) string {
	t.Helper()
	dev, _, err := repo.GetOrCreateDevice(ctx, hw, hw+"-host")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdateDeviceTags(ctx, dev.ID, tags); err != nil {
		t.Fatal(err)
	}
	rep := &types.InventoryReport{
		CollectedAt: time.Now().UTC(),
		HW:          types.HardwareInfo{MemoryMB: mem, CPUModel: "cpu"},
		SW:          types.SoftwareInfo{PackageCount: 1, Packages: []types.InventoryPackage{{Name: "openssl"}}},
	}
	clean, _ := db.SanitizeInventoryReport(rep)
	if err := repo.StoreInventoryReport(ctx, dev.ID, clean); err != nil {
		t.Fatal(err)
	}
	return dev.ID
}

// seedScopedCtx injects the admin-user context a scoped operator would carry.
func seedScopedCtx(r *http.Request, u *types.AdminUser) *http.Request {
	ctx := context.WithValue(r.Context(), web.AdminUserObjCtxKey, u)
	ctx = context.WithValue(ctx, web.AdminUserCtxKey, u.Username)
	ctx = context.WithValue(ctx, web.AdminRoleCtxKey, u.Role)
	return r.WithContext(ctx)
}

func TestInventorySearchPage_TagScoped(t *testing.T) {
	pool := invWebPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	h, err := web.NewHandler(repo, nil, &audit.Forwarder{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	uniq := time.Now().Format("150405.000000000")
	hrID := seedInvDevice(t, ctx, repo, "websearch-hr-"+uniq, []string{"hr"}, 16000)
	engID := seedInvDevice(t, ctx, repo, "websearch-eng-"+uniq, []string{"eng"}, 16000)

	// A scoped operator limited to "hr" searching memory >= 8000 must see only the hr device.
	op := &types.AdminUser{ID: "op", Username: "op", Role: types.RoleOperator, AllowedTags: []string{"hr"}}
	req := httptest.NewRequest(http.MethodGet, "http://x/admin/inventory?attr_key="+db.KeyHWMemoryMB+"&attr_op=ge&attr_val=8000", nil)
	req.Header.Set("Accept", "application/json")
	req = seedScopedCtx(req, op)
	w := httptest.NewRecorder()
	h.InventorySearchPage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var results []db.InventorySearchResult
	if err := json.Unmarshal(w.Body.Bytes(), &results); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, w.Body.String())
	}
	sawHR, sawENG := false, false
	for _, r := range results {
		if r.DeviceID == hrID {
			sawHR = true
		}
		if r.DeviceID == engID {
			sawENG = true
		}
	}
	if !sawHR {
		t.Error("scoped hr operator should see the hr device")
	}
	if sawENG {
		t.Error("scoped hr operator must NOT see the eng device in inventory search")
	}
}

func TestRequestInventoryRefresh_EnqueuesCommand(t *testing.T) {
	pool := invWebPool(t)
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	h, err := web.NewHandler(repo, nil, audit.NewForwarder(repo, ""))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	uniq := time.Now().Format("150405.000000000")
	dev, _, err := repo.GetOrCreateDevice(ctx, "refresh-"+uniq, "refresh-host")
	if err != nil {
		t.Fatal(err)
	}

	// An unscoped operator refreshing an in-scope device enqueues the refresh command.
	op := &types.AdminUser{ID: "op", Username: "op", Role: types.RoleOperator}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", dev.ID)
	req := httptest.NewRequest(http.MethodPost, "http://x/admin/devices/"+dev.ID+"/inventory/refresh", nil)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = seedScopedCtx(req, op)
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	h.RequestInventoryRefresh(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("status %d, want 202 (body=%s)", w.Code, w.Body.String())
	}
	cmds, err := repo.ListDeviceCommands(ctx, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range cmds {
		if strings.Contains(c.Command, types.InventoryRefreshCommand) {
			found = true
		}
	}
	if !found {
		t.Fatalf("inventory refresh command not enqueued: %+v", cmds)
	}
}
