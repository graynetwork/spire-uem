package engine

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"github.com/spire-uem/spire-uem/internal/campaign"
)

// BuildRollbackArgv builds the exact argv to install the planned previous versions. Only
// items in state RollbackPlanned are included; the rest are reported without touching apt.
// It uses `apt-get install --allow-downgrades -y <pkg>=<prevver> ...` with the same
// noninteractive dpkg options and no shell. Returns ("", nil, false) if there is nothing to
// roll back or any spec is unsafe.
func BuildRollbackArgv(items []campaign.RollbackItem) (argv []string, specs []string, ok bool) {
	argv = []string{
		"apt-get", "install", "--allow-downgrades", "-y",
		"-o", "Dpkg::Options::=--force-confdef",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "Dpkg::Use-Pty=0",
	}
	any := false
	for _, it := range items {
		if it.State != campaign.RollbackPlanned {
			continue
		}
		spec, specOK := campaign.AptSpec(it.Package, it.ToVersion)
		if !specOK {
			return nil, nil, false
		}
		argv = append(argv, spec)
		specs = append(specs, spec)
		any = true
	}
	if !any {
		return nil, nil, false
	}
	return argv, specs, true
}

// ExecuteCampaignRollback runs the planned rollback for a device via the injected runner,
// returning the per-package result. Packages not in RollbackPlanned state are reported with
// their plan state (unavailable / no_previous / skipped) and never passed to apt. A nil
// runner uses DefaultAptRunner.
func ExecuteCampaignRollback(ctx context.Context, runner AptRunner, campaignID string, items []campaign.RollbackItem) campaign.DeviceRunResult {
	if runner == nil {
		runner = DefaultAptRunner
	}
	res := campaign.DeviceRunResult{CampaignID: campaignID}

	// Report the non-installable items first.
	for _, it := range items {
		switch it.State {
		case campaign.RollbackUnavailable:
			res.Packages = append(res.Packages, campaign.PackageResult{Package: it.Package, State: campaign.PkgNotAvailable, Output: "rollback unavailable"})
		case campaign.RollbackNoPrevious, campaign.RollbackSkippedNotUpgraded:
			// Not touched; nothing to report as a failure.
		}
	}

	argv, _, ok := BuildRollbackArgv(items)
	if !ok {
		return res
	}
	out, runErr := runner.Run(ctx, argv, CampaignAptEnv())
	output := string(out)
	res.RebootRequired = IsRebootRequired()

	installed := map[string]string{}
	for _, m := range instRe.FindAllStringSubmatch(output, -1) {
		name := m[1]
		if i := strings.IndexByte(name, ':'); i > 0 {
			name = name[:i]
		}
		installed[name] = m[2]
	}
	runClass := campaign.FailNone
	if runErr != nil {
		runClass = classifyAptFailure(output)
	}
	cappedOut := capOutput(output)

	for _, it := range items {
		if it.State != campaign.RollbackPlanned {
			continue
		}
		pr := campaign.PackageResult{Package: it.Package, ToVersion: it.ToVersion, FromVersion: it.FromVersion}
		if ver, did := installed[it.Package]; did {
			pr.State = campaign.PkgUpgraded // downgrade counts as a successful install of the target
			pr.ToVersion = ver
		} else if runErr == nil {
			pr.State = campaign.PkgAlreadyCurrent
		} else {
			pr.State = campaign.PkgDpkgError
			pr.Output = cappedOut
			_ = runClass
		}
		res.Packages = append(res.Packages, pr)
	}
	return res
}

// AptCachePolicyAvailable reports whether apt can install pkg=version from the device's
// repositories, by inspecting `apt-cache policy <pkg>` output for the exact version. It is
// the production `available` function for campaign.PlanRollback. The command runs with no
// shell; a lookup error is treated as "not available" (fail-closed for rollback safety).
func AptCachePolicyAvailable(ctx context.Context, pkg, version string) bool {
	if !campaign.ValidPackageName(pkg) || !campaign.ValidVersion(version) {
		return false
	}
	cmd := exec.CommandContext(ctx, "apt-cache", "policy", pkg)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return AptCachePolicyHasVersion(string(out), version)
}

// AptCachePolicyHasVersion reports whether `apt-cache policy` output lists the exact version
// as an installation candidate. Separated out so it is unit-testable without apt.
func AptCachePolicyHasVersion(policyOutput, version string) bool {
	for _, line := range strings.Split(policyOutput, "\n") {
		f := strings.Fields(line)
		// Version lines look like "*** 7.88.1-10+deb12u5 500" or "    7.88.1-10+deb12u5 500".
		for i, tok := range f {
			if tok == version && i+1 < len(f) {
				// Must be followed by a priority number (the archive priority).
				if _, err := parsePriority(f[i+1]); err == nil {
					return true
				}
			}
		}
	}
	return false
}

func parsePriority(s string) (int, error) {
	n := 0
	if s == "" {
		return 0, os.ErrInvalid
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, os.ErrInvalid
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
