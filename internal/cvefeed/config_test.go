package cvefeed

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/db"
)

func testRepo(t *testing.T) *db.Repository {
	t.Helper()
	connStr := os.Getenv("SPIRE_TEST_DB_URL")
	if connStr == "" {
		t.Skip("SPIRE_TEST_DB_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, connStr)
	if err != nil || pool.Ping(ctx) != nil {
		t.Skipf("postgres unavailable at %s", connStr)
	}
	t.Cleanup(pool.Close)
	if err := db.RunMigrations(context.Background(), pool, "../../migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	return db.NewRepository(pool)
}

// TestLoadConfig_AutoImportOffByDefault checks that the automatic feed download is off
// unless cve.feed_enabled is exactly true or SPIRE_CVE_FEED_ENABLED turns it on.
func TestLoadConfig_AutoImportOffByDefault(t *testing.T) {
	repo := testRepo(t)
	ctx := context.Background()
	t.Setenv("SPIRE_CVE_FEED_ENABLED", "")
	os.Unsetenv("SPIRE_CVE_FEED_ENABLED")

	// Restore the seeded value at the end so other tests see the default.
	t.Cleanup(func() {
		_ = repo.UpdateSettingsCategory(context.Background(), "cve", map[string]interface{}{"cve.feed_enabled": false}, "test")
	})

	// The migration seeds false.
	_ = repo.UpdateSettingsCategory(ctx, "cve", map[string]interface{}{"cve.feed_enabled": false}, "test")
	if cfg := LoadConfig(ctx, repo); cfg.Enabled || cfg.EnabledFromEnv {
		t.Fatalf("seeded config: Enabled=%v FromEnv=%v, want false/false", cfg.Enabled, cfg.EnabledFromEnv)
	}

	if err := repo.UpdateSettingsCategory(ctx, "cve", map[string]interface{}{"cve.feed_enabled": true}, "test"); err != nil {
		t.Fatalf("update setting: %v", err)
	}
	if cfg := LoadConfig(ctx, repo); !cfg.Enabled {
		t.Fatalf("cve.feed_enabled=true did not enable the import")
	}

	t.Setenv("SPIRE_CVE_FEED_ENABLED", "false")
	if cfg := LoadConfig(ctx, repo); cfg.Enabled || !cfg.EnabledFromEnv {
		t.Fatalf("env false: Enabled=%v FromEnv=%v, want false/true", cfg.Enabled, cfg.EnabledFromEnv)
	}
	t.Setenv("SPIRE_CVE_FEED_ENABLED", "yes")
	if cfg := LoadConfig(ctx, repo); cfg.Enabled {
		t.Fatalf("env 'yes' enabled the import; only true or 1 should")
	}
}
