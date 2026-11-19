package web_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/audit"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/web"
)

func tokenWebTestPool(t *testing.T) *pgxpool.Pool {
	connStr := os.Getenv("SPIRE_TEST_DB_URL")
	if connStr == "" {
		t.Skip("skipping token web test: SPIRE_TEST_DB_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil {
		t.Skipf("skipping: cannot connect to postgres: %v", err)
		return nil
	}
	if err := pool.Ping(ctx); err != nil {
		t.Skipf("skipping: postgres ping failed: %v", err)
		return nil
	}
	if err := db.RunMigrations(ctx, pool, "../../migrations"); err != nil {
		t.Skipf("skipping: migrations failed: %v", err)
		return nil
	}
	return pool
}

// withAdmin seeds the request context the way the auth middleware would, for a given admin.
func withAdmin(r *http.Request, u *types.AdminUser) *http.Request {
	ctx := r.Context()
	ctx = context.WithValue(ctx, web.AdminUserCtxKey, u.Username)
	ctx = context.WithValue(ctx, web.AdminRoleCtxKey, u.Role)
	ctx = context.WithValue(ctx, web.AdminUserObjCtxKey, u)
	return r.WithContext(ctx)
}

func TestCreateToken_ScopedAdminCannotAssignOutOfScopeTags(t *testing.T) {
	pool := tokenWebTestPool(t)
	if pool == nil {
		return
	}
	defer pool.Close()
	repo := db.NewRepository(pool)
	h, err := web.NewHandler(repo, nil, audit.NewForwarder(repo, ""))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	scoped := &types.AdminUser{ID: "op1", Username: "op1", Role: types.RoleOperator, AllowedTags: []string{"eng"}}

	// Out-of-scope tag -> 403, no token created.
	form := url.Values{"description": {"bad"}, "target_ring": {"PRODUCTION"}, "target_tags": {"finance"}}
	req := httptest.NewRequest(http.MethodPost, "/admin/settings/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req = withAdmin(req, scoped)
	rec := httptest.NewRecorder()
	h.CreateToken(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("scoped admin assigning out-of-scope tag must be 403, got %d", rec.Code)
	}

	// In-scope tag -> allowed.
	form2 := url.Values{"description": {"ok"}, "target_ring": {"PRODUCTION"}, "target_tags": {"eng"}}
	req2 := httptest.NewRequest(http.MethodPost, "/admin/settings/tokens", strings.NewReader(form2.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2 = withAdmin(req2, scoped)
	rec2 := httptest.NewRecorder()
	h.CreateToken(rec2, req2)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("scoped admin assigning in-scope tag should succeed (201), got %d", rec2.Code)
	}
}

func TestCreateToken_RecordsCreatedByAndApprovalPolicy(t *testing.T) {
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
	super := &types.AdminUser{ID: "root", Username: "root", Role: types.RoleSuperAdmin}

	form := url.Values{
		"description":      {"policy-" + time.Now().Format("150405.000000")},
		"target_ring":      {"PRODUCTION"},
		"require_approval":  {"1"},
		"hostname_pattern": {"lab-*"},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/settings/tokens", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req = withAdmin(req, super)
	rec := httptest.NewRecorder()
	h.CreateToken(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("super admin create should be 201, got %d body=%s", rec.Code, rec.Body.String())
	}

	// Verify the stored token carries the policy and created_by.
	tokens, err := repo.ListEnrollmentTokens(ctx)
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	var found *types.EnrollmentToken
	for i := range tokens {
		if strings.HasPrefix(tokens[i].Description, "policy-") {
			found = &tokens[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("created token not found")
	}
	if !found.RequireApproval {
		t.Error("require_approval must be stored true")
	}
	if found.HostnamePattern != "lab-*" {
		t.Errorf("hostname_pattern must be stored, got %q", found.HostnamePattern)
	}
	if found.CreatedBy != "root" {
		t.Errorf("created_by must be the acting admin, got %q", found.CreatedBy)
	}
}
