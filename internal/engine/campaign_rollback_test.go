package engine

import (
	"context"
	"reflect"
	"testing"

	"github.com/spire-uem/spire-uem/internal/campaign"
)

func TestBuildRollbackArgv(t *testing.T) {
	items := []campaign.RollbackItem{
		{Package: "curl", ToVersion: "7.88.1-10+deb12u5", State: campaign.RollbackPlanned},
		{Package: "git", State: campaign.RollbackUnavailable}, // excluded from argv
	}
	argv, specs, ok := BuildRollbackArgv(items)
	if !ok {
		t.Fatal("expected ok")
	}
	want := []string{
		"apt-get", "install", "--allow-downgrades", "-y",
		"-o", "Dpkg::Options::=--force-confdef",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "Dpkg::Use-Pty=0",
		"curl=7.88.1-10+deb12u5",
	}
	if !reflect.DeepEqual(argv, want) {
		t.Fatalf("argv mismatch:\n got %q\nwant %q", argv, want)
	}
	if len(specs) != 1 {
		t.Errorf("only planned items should be in specs, got %q", specs)
	}
}

func TestBuildRollbackArgv_NothingPlanned(t *testing.T) {
	items := []campaign.RollbackItem{{Package: "git", State: campaign.RollbackUnavailable}}
	if _, _, ok := BuildRollbackArgv(items); ok {
		t.Error("no planned items should yield ok=false")
	}
}

func TestExecuteCampaignRollback_ReportsUnavailable(t *testing.T) {
	runner := &fakeAptRunner{out: []byte("Inst curl [7.88.1-10+deb12u7] (7.88.1-10+deb12u5 ...)")}
	items := []campaign.RollbackItem{
		{Package: "curl", FromVersion: "7.88.1-10+deb12u7", ToVersion: "7.88.1-10+deb12u5", State: campaign.RollbackPlanned},
		{Package: "git", State: campaign.RollbackUnavailable},
	}
	res := ExecuteCampaignRollback(context.Background(), runner, "c1", items)
	byPkg := map[string]campaign.PackageResult{}
	for _, p := range res.Packages {
		byPkg[p.Package] = p
	}
	if byPkg["curl"].State != campaign.PkgUpgraded {
		t.Errorf("curl rollback should be applied, got %+v", byPkg["curl"])
	}
	if byPkg["git"].State != campaign.PkgNotAvailable {
		t.Errorf("git should be reported rollback unavailable, got %+v", byPkg["git"])
	}
}

func TestAptCachePolicyHasVersion(t *testing.T) {
	out := `curl:
  Installed: 7.88.1-10+deb12u7
  Candidate: 7.88.1-10+deb12u7
  Version table:
 *** 7.88.1-10+deb12u7 500
        500 http://deb.debian.org/debian-security bookworm-security/main amd64 Packages
     7.88.1-10+deb12u5 500
        500 http://deb.debian.org/debian bookworm/main amd64 Packages
`
	if !AptCachePolicyHasVersion(out, "7.88.1-10+deb12u5") {
		t.Errorf("expected the older version to be found as available")
	}
	if AptCachePolicyHasVersion(out, "7.88.1-10+deb12u1") {
		t.Errorf("a version not listed must not be found")
	}
	// A bare version with no priority must not match (defends against partial lines).
	if AptCachePolicyHasVersion("  Installed: 7.88.1-10+deb12u5", "7.88.1-10+deb12u5") {
		t.Errorf("version without a trailing priority number must not match")
	}
}
