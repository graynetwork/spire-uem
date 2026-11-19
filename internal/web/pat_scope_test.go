package web_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/spire-uem/spire-uem/internal/audit"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/web"
)

// TestPAT_OwnerTagScopeApplies: a personal access token owned by a tag-scoped admin must be
// held to that admin's tags on /admin routes. Before the fix the PAT path never loaded the
// owner's account into the request context, so every scoping check treated it as unscoped.
func TestPAT_OwnerTagScopeApplies(t *testing.T) {
	pool := tokenWebTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	ctx := context.Background()
	repo := db.NewRepository(pool)
	h, err := web.NewHandler(repo, nil, audit.NewForwarder(repo, ""))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	router := chi.NewRouter()
	h.RegisterRoutes(router, "breakglass", "")

	sfx := strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
	teamA, teamB := "pat-a-"+sfx, "pat-b-"+sfx
	owner, err := repo.CreateLocalAdminUser(ctx, types.CreateUserRequest{
		Username: "pat-scoped-" + sfx, Email: "pat-scoped-" + sfx + "@example.test",
		Password: "correct-horse-battery", Role: types.RoleOperator, AllowedTags: []string{teamA},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	inDev, _, err := repo.GetOrCreateDevice(ctx, "pat-in-"+sfx, "pat-in-"+sfx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdateDeviceTags(ctx, inDev.ID, []string{teamA}); err != nil {
		t.Fatal(err)
	}
	outDev, _, err := repo.GetOrCreateDevice(ctx, "pat-out-"+sfx, "pat-out-"+sfx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdateDeviceTags(ctx, outDev.ID, []string{teamB}); err != nil {
		t.Fatal(err)
	}

	raw, hash, prefix, err := web.GeneratePAT()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreatePersonalAccessToken(ctx, hash, prefix, "scoped", owner.ID, types.RoleOperator, owner.Username, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("create PAT: %v", err)
	}
	do := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(""))
		req.Header.Set("Authorization", "Bearer "+raw)
		req.Header.Set("Accept", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	if rec := do(http.MethodGet, "/admin/devices/"+outDev.ID); rec.Code != http.StatusNotFound {
		t.Errorf("out-of-scope device detail via PAT: got %d, want 404", rec.Code)
	}
	if rec := do(http.MethodPost, "/admin/devices/"+outDev.ID+"/sync"); rec.Code != http.StatusNotFound {
		t.Errorf("out-of-scope device action via PAT: got %d, want 404", rec.Code)
	}
	if rec := do(http.MethodGet, "/admin/devices/"+inDev.ID); rec.Code == http.StatusNotFound || rec.Code >= 500 {
		t.Errorf("in-scope device detail via PAT: got %d", rec.Code)
	}

	rec := do(http.MethodGet, "/admin/devices")
	if rec.Code != http.StatusOK {
		t.Fatalf("device list via PAT: %d %s", rec.Code, rec.Body.String())
	}
	var list []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err == nil {
		for _, d := range list {
			if d["id"] == outDev.ID {
				t.Errorf("device list via scoped PAT includes an out-of-scope device")
			}
		}
	} else if strings.Contains(rec.Body.String(), outDev.ID) {
		t.Errorf("device list via scoped PAT includes an out-of-scope device")
	}
}
