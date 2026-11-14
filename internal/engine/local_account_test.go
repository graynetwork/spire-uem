package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/types"
)

func TestValidateLocalAccountPolicyPayload(t *testing.T) {
	ok := types.LocalAccountPolicyPayload{
		PwqualityMinLen:    14,
		PwqualityMinClass:  3,
		FaillockDeny:       5,
		FaillockUnlockTime: 900,
		PassMaxDays:        365,
		Sudoers:            &types.LocalAccountSudoersPayload{Groups: []string{"sudo", "admins"}, Users: []string{"ops"}},
	}
	if err := ValidateLocalAccountPolicyPayload(ok); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}

	bad := []types.LocalAccountPolicyPayload{
		{PwqualityMinClass: 9},
		{FaillockDeny: -1},
		{PassMaxDays: 100000},
		{Sudoers: &types.LocalAccountSudoersPayload{Groups: []string{"bad group"}}},
		{Sudoers: &types.LocalAccountSudoersPayload{Users: []string{"root; rm -rf /"}}},
	}
	for i, p := range bad {
		if err := ValidateLocalAccountPolicyPayload(p); err == nil {
			t.Errorf("case %d: expected error, got nil", i)
		}
	}
}

func TestRenderLocalAccountFiles(t *testing.T) {
	p := types.LocalAccountPolicyPayload{
		PwqualityMinLen:    14,
		PwqualityMinClass:  4,
		FaillockDeny:       5,
		FaillockUnlockTime: 1800,
		Sudoers:            &types.LocalAccountSudoersPayload{Groups: []string{"wheel", "admins"}, Users: []string{"ops"}, NoPasswd: false},
	}
	pw := RenderPwqualityConf(p)
	if !strings.Contains(pw, "minlen = 14") || !strings.Contains(pw, "minclass = 4") {
		t.Errorf("pwquality render wrong:\n%s", pw)
	}
	fl := RenderFaillockConf(p)
	if !strings.Contains(fl, "deny = 5") || !strings.Contains(fl, "unlock_time = 1800") {
		t.Errorf("faillock render wrong:\n%s", fl)
	}
	su := RenderSudoers(p.Sudoers)
	// Sorted groups then users.
	if !strings.Contains(su, "%admins ALL=(ALL:ALL) ALL") || !strings.Contains(su, "%wheel ALL=(ALL:ALL) ALL") || !strings.Contains(su, "ops ALL=(ALL:ALL) ALL") {
		t.Errorf("sudoers render wrong:\n%s", su)
	}

	// Empty renders.
	if RenderPwqualityConf(types.LocalAccountPolicyPayload{}) != "" {
		t.Error("expected empty pwquality render for empty payload")
	}
	if RenderSudoers(&types.LocalAccountSudoersPayload{NoPasswd: true}) != "" {
		t.Error("expected empty sudoers render when no principals")
	}
	// NOPASSWD tag.
	su2 := RenderSudoers(&types.LocalAccountSudoersPayload{Groups: []string{"ci"}, NoPasswd: true})
	if !strings.Contains(su2, "%ci ALL=(ALL:ALL) NOPASSWD: ALL") {
		t.Errorf("expected NOPASSWD tag:\n%s", su2)
	}
}

func TestEnforceLocalAccountPolicy_ApplyAndRemove(t *testing.T) {
	tmp := t.TempDir()
	origRoot := laRoot
	origVisudo := runVisudoCheck
	laRoot = tmp
	// Fake visudo accepts any file whose content has no "INVALID" marker.
	runVisudoCheck = func(ctx context.Context, path string) (string, error) {
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), "INVALID") {
			return "parse error near line 1", fmt.Errorf("invalid sudoers")
		}
		return "", nil
	}
	defer func() { laRoot = origRoot; runVisudoCheck = origVisudo }()

	// Seed a pre-existing login.defs to prove the managed block is additive and non-destructive.
	loginDefs := filepath.Join(tmp, loginDefsRel)
	_ = os.MkdirAll(filepath.Dir(loginDefs), 0755)
	_ = os.WriteFile(loginDefs, []byte("# distro login.defs\nUMASK\t022\nPASS_MIN_DAYS\t0\n"), 0644)

	ctx := context.Background()
	payload := types.LocalAccountPolicyPayload{
		PwqualityMinLen:    14,
		PwqualityMinClass:  3,
		FaillockDeny:       5,
		FaillockUnlockTime: 900,
		PassMaxDays:        365,
		Sudoers:            &types.LocalAccountSudoersPayload{Groups: []string{"sudo"}},
	}
	pb, _ := json.Marshal(payload)
	pol := types.AssignedPolicy{ID: "la-1", PolicyType: types.PolicyTypeLocalAccountPolicy, Payload: pb}

	item := EnforceLocalAccountPolicy(ctx, pol)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("expected COMPLIANT, got %v (err=%s)", item.ComplianceStatus, item.ErrorMessage)
	}

	// pwquality + faillock present.
	if b, _ := os.ReadFile(filepath.Join(tmp, pwqualityConfRel)); !strings.Contains(string(b), "minlen = 14") {
		t.Errorf("pwquality file missing/incorrect: %q", string(b))
	}
	if b, _ := os.ReadFile(filepath.Join(tmp, faillockConfRel)); !strings.Contains(string(b), "deny = 5") {
		t.Errorf("faillock file missing/incorrect: %q", string(b))
	}

	// login.defs: original content preserved + managed block added.
	ld, _ := os.ReadFile(loginDefs)
	lds := string(ld)
	if !strings.Contains(lds, "UMASK\t022") || !strings.Contains(lds, "PASS_MIN_DAYS\t0") {
		t.Errorf("login.defs lost original content:\n%s", lds)
	}
	if !strings.Contains(lds, loginDefsBegin) || !strings.Contains(lds, "PASS_MAX_DAYS\t365") {
		t.Errorf("login.defs missing managed block:\n%s", lds)
	}

	// sudoers installed with mode 0440 and validated.
	sudoersPath := filepath.Join(tmp, sudoersDropRel)
	si, err := os.Stat(sudoersPath)
	if err != nil {
		t.Fatalf("sudoers not installed: %v", err)
	}
	if si.Mode().Perm() != 0440 {
		t.Errorf("expected sudoers mode 0440, got %v", si.Mode().Perm())
	}

	// Idempotency: enforce again, managed block count stays 1.
	item = EnforceLocalAccountPolicy(ctx, pol)
	if item.ComplianceStatus != types.ComplianceCompliant {
		t.Fatalf("second enforce not COMPLIANT: %v", item.ComplianceStatus)
	}
	ld2, _ := os.ReadFile(loginDefs)
	if n := strings.Count(string(ld2), loginDefsBegin); n != 1 {
		t.Errorf("expected exactly 1 managed login.defs block, got %d", n)
	}

	// Removal strips everything and leaves original login.defs intact.
	if err := RemoveLocalAccountPolicy(ctx); err != nil {
		t.Fatalf("remove: %v", err)
	}
	for _, rel := range []string{pwqualityConfRel, faillockConfRel, sudoersDropRel} {
		if _, err := os.Stat(filepath.Join(tmp, rel)); !os.IsNotExist(err) {
			t.Errorf("expected %s removed, stat err=%v", rel, err)
		}
	}
	ld3, _ := os.ReadFile(loginDefs)
	if strings.Contains(string(ld3), loginDefsBegin) {
		t.Errorf("managed block not stripped on removal:\n%s", string(ld3))
	}
	if !strings.Contains(string(ld3), "UMASK\t022") {
		t.Errorf("removal damaged original login.defs:\n%s", string(ld3))
	}
}

func TestEnforceLocalAccountPolicy_SudoersRejected(t *testing.T) {
	tmp := t.TempDir()
	origRoot := laRoot
	origVisudo := runVisudoCheck
	laRoot = tmp
	// visudo rejects everything.
	runVisudoCheck = func(ctx context.Context, path string) (string, error) {
		return ">>> parse error", fmt.Errorf("syntax error")
	}
	defer func() { laRoot = origRoot; runVisudoCheck = origVisudo }()

	ctx := context.Background()
	payload := types.LocalAccountPolicyPayload{Sudoers: &types.LocalAccountSudoersPayload{Groups: []string{"sudo"}}}
	pb, _ := json.Marshal(payload)
	pol := types.AssignedPolicy{ID: "la-reject", PolicyType: types.PolicyTypeLocalAccountPolicy, Payload: pb}

	item := EnforceLocalAccountPolicy(ctx, pol)
	if item.ComplianceStatus != types.ComplianceFailed {
		t.Fatalf("expected FAILED when visudo rejects, got %v", item.ComplianceStatus)
	}
	// The real drop-in must NOT have been installed.
	if _, err := os.Stat(filepath.Join(tmp, sudoersDropRel)); !os.IsNotExist(err) {
		t.Errorf("sudoers drop-in must not be installed when visudo rejects it")
	}
}
