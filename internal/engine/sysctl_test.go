package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

func TestValidateSysctlKey(t *testing.T) {
	validKeys := []string{
		"net.ipv4.conf.all.rp_filter",
		"net.ipv4.conf.default.rp_filter",
		"net.ipv4.icmp_echo_ignore_broadcasts",
		"kernel.randomize_va_space",
		"fs.suid_dumpable",
	}
	for _, k := range validKeys {
		if err := ValidateSysctlKey(k); err != nil {
			t.Errorf("expected valid key %q, got error: %v", k, err)
		}
	}

	invalidKeys := []string{
		"",
		"   ",
		"net..ipv4",
		"net/ipv4/rp_filter",
		"../../etc/shadow",
		"net.ipv4; rm -rf /",
		"net.ipv4.conf.all.rp_filter`whoami`",
		"net.ipv4.conf.all.rp_filter$FOO",
		"net_single_segment",
		".leading_dot",
		"trailing_dot.",
	}
	for _, k := range invalidKeys {
		if err := ValidateSysctlKey(k); err == nil {
			t.Errorf("expected error for invalid key %q, got nil", k)
		}
	}
}

func TestValidateSysctlValue(t *testing.T) {
	validValues := []string{
		"0",
		"1",
		"2",
		"fq_codel",
		"bbr",
		"1024 65535",
		"utf-8",
	}
	for _, v := range validValues {
		if err := ValidateSysctlValue(v); err != nil {
			t.Errorf("expected valid value %q, got error: %v", v, err)
		}
	}

	invalidValues := []string{
		"",
		"   ",
		"1; cat /etc/passwd",
		"value\nwith\nnewlines",
		"`id`",
		"$(whoami)",
	}
	for _, v := range invalidValues {
		if err := ValidateSysctlValue(v); err == nil {
			t.Errorf("expected error for invalid value %q, got nil", v)
		}
	}
}

func TestSysctlPolicyReconciliationAndRemoval(t *testing.T) {
	// Use temporary directories for testing
	tmpDir, err := os.MkdirTemp("", "spire-sysctl-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	origBaseDir := sysctlBaseDir
	origProcBase := procSysBase
	origFind := findSysctlBin
	sysctlBaseDir = filepath.Join(tmpDir, "etc/sysctl.d")
	procSysBase = filepath.Join(tmpDir, "proc/sys")
	findSysctlBin = func() (string, error) { return "", nil }
	defer func() {
		sysctlBaseDir = origBaseDir
		procSysBase = origProcBase
		findSysctlBin = origFind
	}()

	policyID := "cis-net-test-01"
	settings := map[string]string{
		"net.ipv4.conf.all.rp_filter":     "1",
		"net.ipv4.conf.default.rp_filter": "1",
	}

	// Create mock /proc/sys values so verification succeeds
	for k, v := range settings {
		p := filepath.Join(procSysBase, strings.ReplaceAll(k, ".", "/"))
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatalf("mkdir proc path: %v", err)
		}
		if err := os.WriteFile(p, []byte(v+"\n"), 0644); err != nil {
			t.Fatalf("write proc val: %v", err)
		}
	}

	ctx := context.Background()

	// 1. Reconcile settings
	status := ReconcileSysctlSettings(ctx, policyID, settings)
	if status != types.ComplianceCompliant {
		t.Fatalf("expected compliance status COMPLIANT, got %v", status)
	}

	// 2. Verify file was created with correct permissions and contents
	confPath := SysctlConfPath(policyID)
	info, err := os.Stat(confPath)
	if err != nil {
		t.Fatalf("sysctl conf file not found: %v", err)
	}
	if info.Mode().Perm() != 0644 {
		t.Errorf("expected file mode 0644, got %v", info.Mode().Perm())
	}

	contentBytes, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("read conf file: %v", err)
	}
	content := string(contentBytes)
	if !strings.Contains(content, "net.ipv4.conf.all.rp_filter = 1") {
		t.Errorf("conf file missing net.ipv4.conf.all.rp_filter: %s", content)
	}
	if !strings.Contains(content, "net.ipv4.conf.default.rp_filter = 1") {
		t.Errorf("conf file missing net.ipv4.conf.default.rp_filter: %s", content)
	}

	// 3. Test EnforceSysctlPolicy wrapper
	assigned := types.AssignedPolicy{
		ID:         policyID,
		Name:       "Test Sysctl",
		PolicyType: types.PolicyTypeSysctlSetting,
		Payload:    []byte(`{"settings":{"net.ipv4.conf.all.rp_filter":"1","net.ipv4.conf.default.rp_filter":"1"}}`),
	}
	item := EnforceSysctlPolicy(ctx, assigned)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Errorf("EnforceSysctlPolicy status: expected COMPLIANT, got %v (err: %s)", item.ComplianceStatus, item.ErrorMessage)
	}

	// 4. Test Removal
	if err := RemoveSysctlSettings(ctx, policyID); err != nil {
		t.Fatalf("RemoveSysctlSettings failed: %v", err)
	}
	if _, err := os.Stat(confPath); !os.IsNotExist(err) {
		t.Errorf("expected conf file to be removed, but stat returned: %v", err)
	}
}
