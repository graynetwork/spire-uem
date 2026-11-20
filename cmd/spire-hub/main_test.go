package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestHubScript_ValidSyntax(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available in PATH")
	}

	cmd := exec.Command("python3", "-c", "import ast, sys; ast.parse(sys.stdin.read())")
	cmd.Stdin = strings.NewReader(hubScript)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python syntax error in embedded spire-hub.py: %v (output: %s)", err, string(out))
	}
}

func TestHubScript_ContainsMetadata(t *testing.T) {
	if !strings.Contains(hubScript, `APP_ID = "org.spire.hub"`) {
		t.Errorf("expected APP_ID = 'org.spire.hub', but not found in hubScript")
	}
	if !strings.Contains(hubScript, `title="Spire Hub"`) {
		t.Errorf("expected title='Spire Hub', but not found in hubScript")
	}
	if !strings.Contains(hubScript, `title="System &amp; Security Baseline"`) {
		t.Errorf("expected Group 1 'System & Security Baseline' in hubScript")
	}
	if !strings.Contains(hubScript, `title="Mandatory Applications"`) {
		t.Errorf("expected Group 2 'Mandatory Applications' in hubScript")
	}
	if !strings.Contains(hubScript, `"Action Required: Install"`) {
		t.Errorf("expected 'Action Required: Install' status tag in hubScript")
	}
	for _, btnLabel := range []string{`label="Install"`, `label="Open"`, `label="Remove"`} {
		if !strings.Contains(hubScript, btnLabel) {
			t.Errorf("expected %s button in App Catalog view", btnLabel)
		}
	}
}

// The browser certificate tests run the real certutil and pk12util against a temporary HOME.
// They are skipped when python3, certutil, pk12util or openssl is missing.
func TestHubBrowserCertEnrolment(t *testing.T) {
	for _, tool := range []string{"python3", "certutil", "pk12util", "openssl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available in PATH", tool)
		}
	}
	cmd := exec.Command("python3", "-m", "unittest", "-v", "test_browser_cert")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("browser certificate tests failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "OK") || strings.Contains(string(out), "skipped") {
		t.Fatalf("browser certificate tests did not all run:\n%s", out)
	}
}
