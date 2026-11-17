package web

import (
	"os"
	"strings"
	"testing"
)

// TestBootstrapScripts_IdenticalAndTokenFlags asserts the two bootstrap copies
// (packaging/bootstrap.sh and the embedded templates/bootstrap.sh) are byte-identical and
// both carry the automated-enrollment token flags. The spec requires the copies never drift.
func TestBootstrapScripts_IdenticalAndTokenFlags(t *testing.T) {
	packaged, err := os.ReadFile("../../packaging/bootstrap.sh")
	if err != nil {
		t.Fatalf("read packaging/bootstrap.sh: %v", err)
	}
	embedded, err := templatesFS.ReadFile("templates/bootstrap.sh")
	if err != nil {
		t.Fatalf("read embedded templates/bootstrap.sh: %v", err)
	}
	if string(packaged) != string(embedded) {
		t.Fatalf("packaging/bootstrap.sh and templates/bootstrap.sh must be byte-identical")
	}
	s := string(packaged)
	for _, want := range []string{
		"--enrollment-token-file",
		"--enrollment-token",
		"enrollment_token_file:", // written into config.yaml (the PATH, not the secret)
		"visible in",             // the inline-token warning
		"AGENT_TOKEN_FILE=\"/etc/spire/enrollment-token\"",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("bootstrap.sh is missing expected content %q", want)
		}
	}
	// The secret must NEVER be written into config.yaml as an enrollment_token value.
	if strings.Contains(s, "enrollment_token:") {
		t.Errorf("bootstrap.sh must not write the token secret into config.yaml (enrollment_token:)")
	}
}
