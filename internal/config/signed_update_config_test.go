package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spire-uem/spire-uem/internal/config"
)

func TestLoad_RequireSignedUpdatesDefaultsTrue(t *testing.T) {
	// Ensure no env override leaks in from the host.
	t.Setenv("SPIRE_AGENT_REQUIRE_SIGNED_UPDATES", "")
	cfg := config.Load("")
	if !cfg.Agent.RequireSignedUpdates {
		t.Error("require_signed_updates should default to true for a fresh config")
	}
	if cfg.Agent.ReleaseKeysDir != config.DefaultReleaseKeysDir {
		t.Errorf("release_keys_dir = %q, want default %q", cfg.Agent.ReleaseKeysDir, config.DefaultReleaseKeysDir)
	}
}

func TestLoad_RequireSignedUpdatesEnvOverride(t *testing.T) {
	t.Setenv("SPIRE_AGENT_REQUIRE_SIGNED_UPDATES", "false")
	cfg := config.Load("")
	if cfg.Agent.RequireSignedUpdates {
		t.Error("env SPIRE_AGENT_REQUIRE_SIGNED_UPDATES=false should relax the default")
	}
}

func TestLoad_RequireSignedUpdatesYAMLOverride(t *testing.T) {
	t.Setenv("SPIRE_AGENT_REQUIRE_SIGNED_UPDATES", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := "agent:\n  require_signed_updates: false\n  release_keys_dir: /custom/keys\n"
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Load(path)
	if cfg.Agent.RequireSignedUpdates {
		t.Error("yaml require_signed_updates: false should relax the default")
	}
	if cfg.Agent.ReleaseKeysDir != "/custom/keys" {
		t.Errorf("release_keys_dir = %q, want /custom/keys", cfg.Agent.ReleaseKeysDir)
	}
}
