package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_EnrollmentTokenFromYAML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(`agent:
  server_url: "http://localhost:8080"
  enrollment_token_file: "/etc/spire/enrollment-token"
  enrollment_token: "spire_tok_fromconfig"
`), 0600); err != nil {
		t.Fatal(err)
	}
	// Ensure env does not interfere.
	os.Unsetenv("SPIRE_ENROLLMENT_TOKEN")
	os.Unsetenv("SPIRE_ENROLLMENT_TOKEN_FILE")

	cfg := Load(cfgPath)
	if cfg.Agent.EnrollmentTokenFile != "/etc/spire/enrollment-token" {
		t.Errorf("enrollment_token_file not parsed, got %q", cfg.Agent.EnrollmentTokenFile)
	}
	if cfg.Agent.EnrollmentToken != "spire_tok_fromconfig" {
		t.Errorf("enrollment_token not parsed, got %q", cfg.Agent.EnrollmentToken)
	}
}

func TestLoad_EnrollmentTokenEnvOverridesConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("agent:\n  enrollment_token: \"from-config\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SPIRE_ENROLLMENT_TOKEN", "from-env")
	t.Setenv("SPIRE_ENROLLMENT_TOKEN_FILE", "/env/path/token")

	cfg := Load(cfgPath)
	if cfg.Agent.EnrollmentToken != "from-env" {
		t.Errorf("env SPIRE_ENROLLMENT_TOKEN must override config value, got %q", cfg.Agent.EnrollmentToken)
	}
	if cfg.Agent.EnrollmentTokenFile != "/env/path/token" {
		t.Errorf("env SPIRE_ENROLLMENT_TOKEN_FILE must be applied, got %q", cfg.Agent.EnrollmentTokenFile)
	}
}
