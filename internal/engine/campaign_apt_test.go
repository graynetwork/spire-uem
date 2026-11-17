package engine

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/spire-uem/spire-uem/internal/campaign"
)

type fakeAptRunner struct {
	gotArgv []string
	gotEnv  []string
	out     []byte
	err     error
}

func (f *fakeAptRunner) Run(_ context.Context, argv []string, env []string) ([]byte, error) {
	f.gotArgv = argv
	f.gotEnv = env
	return f.out, f.err
}

func TestBuildAptArgv_ExactAndNoShell(t *testing.T) {
	works := []campaign.PackageWork{
		{Package: "curl", Target: "7.88.1-10+deb12u7"},
		{Package: "git", Target: campaign.TargetLatest},
	}
	argv, specs, ok := BuildAptArgv(works)
	if !ok {
		t.Fatal("expected ok")
	}
	want := []string{
		"apt-get", "install", "--only-upgrade", "-y",
		"-o", "Dpkg::Options::=--force-confdef",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "Dpkg::Use-Pty=0",
		"curl=7.88.1-10+deb12u7", "git",
	}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv mismatch:\n got %q\nwant %q", argv, want)
	}
	if !reflect.DeepEqual(specs, []string{"curl=7.88.1-10+deb12u7", "git"}) {
		t.Errorf("specs mismatch: %q", specs)
	}
	// No argv element may contain a shell metacharacter.
	for _, a := range argv {
		if strings.ContainsAny(a, ";|&$`><\n") {
			t.Errorf("argv element %q contains a shell metacharacter", a)
		}
	}
}

func TestBuildAptArgv_RejectsUnsafe(t *testing.T) {
	if _, _, ok := BuildAptArgv([]campaign.PackageWork{{Package: "-rf", Target: campaign.TargetLatest}}); ok {
		t.Error("option-injection package name must be rejected")
	}
	if _, _, ok := BuildAptArgv([]campaign.PackageWork{{Package: "curl", Target: "1.0; rm -rf /"}}); ok {
		t.Error("unsafe version must be rejected")
	}
}

func TestExecuteCampaignInstall_UpgradedAndCurrent(t *testing.T) {
	runner := &fakeAptRunner{out: []byte(`Reading package lists... Done
Inst curl [7.88.1-10+deb12u5] (7.88.1-10+deb12u7 Debian-Security:12/bookworm-security [amd64])
Conf curl (7.88.1-10+deb12u7 ...)
`)}
	req := CampaignInstallRequest{CampaignID: "c1", Packages: []campaign.PackageWork{
		{Package: "curl", Target: "7.88.1-10+deb12u7"},
		{Package: "git", Target: campaign.TargetLatest}, // not in output -> already current
	}}
	res := ExecuteCampaignInstall(context.Background(), runner, req)

	// env must carry DEBIAN_FRONTEND=noninteractive.
	foundEnv := false
	for _, e := range runner.gotEnv {
		if e == "DEBIAN_FRONTEND=noninteractive" {
			foundEnv = true
		}
	}
	if !foundEnv {
		t.Error("expected DEBIAN_FRONTEND=noninteractive in env")
	}

	byPkg := map[string]campaign.PackageResult{}
	for _, p := range res.Packages {
		byPkg[p.Package] = p
	}
	if byPkg["curl"].State != campaign.PkgUpgraded || byPkg["curl"].ToVersion != "7.88.1-10+deb12u7" {
		t.Errorf("curl should be upgraded: %+v", byPkg["curl"])
	}
	if byPkg["git"].State != campaign.PkgAlreadyCurrent {
		t.Errorf("git should be already current: %+v", byPkg["git"])
	}
	state, _ := ClassifyDeviceResult(res)
	if state != campaign.WorkSucceeded {
		t.Errorf("expected overall success, got %v", state)
	}
}

func TestExecuteCampaignInstall_FailureClassification(t *testing.T) {
	cases := []struct {
		name  string
		out   string
		class campaign.FailureClass
	}{
		{"download", "E: Failed to fetch http://deb.debian.org/... Connection timed out", campaign.FailDownload},
		{"dependency", "The following packages have unmet dependencies:\n curl : Depends: libc6 but it is not going to be installed", campaign.FailDependency},
		{"dpkg", "dpkg: error processing package curl (--configure):", campaign.FailDpkg},
		{"held", "The following packages have been kept back:\n  curl", campaign.FailHeld},
		{"other", "E: Something unexpected happened", campaign.FailOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeAptRunner{out: []byte(tc.out), err: context.DeadlineExceeded}
			req := CampaignInstallRequest{CampaignID: "c1", Packages: []campaign.PackageWork{{Package: "curl", Target: campaign.TargetLatest}}}
			res := ExecuteCampaignInstall(context.Background(), runner, req)
			if got := classifyAptFailure(tc.out); got != tc.class {
				t.Errorf("classifyAptFailure = %v, want %v", got, tc.class)
			}
			state, cls := ClassifyDeviceResult(res)
			if state != campaign.WorkFailed {
				t.Errorf("expected FAILED, got %v", state)
			}
			if tc.class == campaign.FailHeld && cls != campaign.FailHeld {
				t.Errorf("held should classify as FailHeld, got %v", cls)
			}
		})
	}
}

func TestExecuteCampaignInstall_InterruptedNotSuccess(t *testing.T) {
	res := campaign.DeviceRunResult{CampaignID: "c1", Interrupted: true, Packages: []campaign.PackageResult{
		{Package: "curl", State: campaign.PkgUpgraded},
	}}
	state, _ := ClassifyDeviceResult(res)
	if state != campaign.WorkInterrupted {
		t.Errorf("an interrupted run must never classify as success, got %v", state)
	}
}

func TestExecuteCampaignInstall_UnsafeSpecRefuses(t *testing.T) {
	runner := &fakeAptRunner{}
	req := CampaignInstallRequest{CampaignID: "c1", Packages: []campaign.PackageWork{{Package: "curl; rm -rf /", Target: campaign.TargetLatest}}}
	res := ExecuteCampaignInstall(context.Background(), runner, req)
	if runner.gotArgv != nil {
		t.Errorf("runner must NOT be invoked for an unsafe spec; argv=%q", runner.gotArgv)
	}
	state, _ := ClassifyDeviceResult(res)
	if state != campaign.WorkFailed {
		t.Errorf("unsafe spec must classify as failed, not success, got %v", state)
	}
}
