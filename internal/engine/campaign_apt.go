package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/spire-uem/spire-uem/internal/campaign"
)

// campaignAptOutputCap bounds how much apt/dpkg output is kept per package result.
const campaignAptOutputCap = 4096

// AptRunner runs one apt-get invocation and returns its combined output and error. It is
// injected so tests can assert the exact argv and env with no real apt, and so there is one
// place that actually touches the package manager.
type AptRunner interface {
	Run(ctx context.Context, argv []string, env []string) (output []byte, err error)
}

// execAptRunner is the production runner: it execs apt-get directly (no shell) with a fixed
// interpreter and the campaign's noninteractive dpkg options.
type execAptRunner struct{}

// DefaultAptRunner is the production apt runner.
var DefaultAptRunner AptRunner = execAptRunner{}

func (execAptRunner) Run(ctx context.Context, argv []string, env []string) ([]byte, error) {
	if len(argv) == 0 {
		return nil, os.ErrInvalid
	}
	// argv[0] is always "apt-get" — resolve it from PATH, never a caller-supplied path.
	cmd := exec.CommandContext(ctx, "apt-get", argv[1:]...)
	cmd.Env = env
	return cmd.CombinedOutput()
}

// CampaignInstallRequest is the validated per-device install the agent executes.
type CampaignInstallRequest struct {
	CampaignID string
	Packages   []campaign.PackageWork
}

// BuildAptArgv builds the exact argv for a campaign install. It is pure and separated from
// execution so a test can assert argv byte-for-byte. It returns ("", nil, false) if any spec
// is unsafe — the caller must then refuse to run, never fall back to a shell.
//
// The invocation is:
//
//	apt-get install --only-upgrade -y
//	  -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold
//	  -o Dpkg::Use-Pty=0 <spec> [<spec> ...]
//
// with DEBIAN_FRONTEND=noninteractive in the environment. --only-upgrade guarantees the
// campaign never INSTALLS a package the device does not already have; each <spec> is either
// "<pkg>" (latest) or "<pkg>=<ver>" (pinned), both validated.
func BuildAptArgv(works []campaign.PackageWork) (argv []string, specs []string, ok bool) {
	if len(works) == 0 {
		return nil, nil, false
	}
	argv = []string{
		"apt-get", "install", "--only-upgrade", "-y",
		"-o", "Dpkg::Options::=--force-confdef",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "Dpkg::Use-Pty=0",
	}
	for _, w := range works {
		spec, specOK := campaign.AptSpec(w.Package, w.Target)
		if !specOK {
			return nil, nil, false
		}
		argv = append(argv, spec)
		specs = append(specs, spec)
	}
	return argv, specs, true
}

// CampaignAptEnv returns the environment for a campaign apt run (noninteractive, no
// interactive prompts). Exposed so tests can assert it.
func CampaignAptEnv() []string {
	return append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "APT_LISTCHANGES_FRONTEND=none")
}

var (
	// Per-package apt "Inst <pkg> (<ver> ...)" line, to detect what was upgraded.
	instRe = regexp.MustCompile(`(?m)^Inst\s+([^\s]+)\s+(?:\[[^\]]*\]\s+)?\(([^\s]+)`)
	// dpkg held-package markers.
	heldRe = regexp.MustCompile(`(?m)\bkept back\b|\bheld\b`)
)

// ExecuteCampaignInstall runs the campaign install for one device via the given runner and
// classifies the result per package. It NEVER uses a shell; argv is built by BuildAptArgv.
// A nil runner uses DefaultAptRunner.
//
// Classification rules:
//   - The run as a whole fails (returns a non-nil error from the runner) -> every package
//     that is not shown upgraded/current is attributed the run-level failure class and the
//     overall result is a failure. Output is capped.
//   - Download failure text -> FailDownload; dependency/conflict -> FailDependency; a dpkg
//     error -> FailDpkg; held package -> FailHeld. Unknown failure -> FailOther.
//   - A package shown "Inst <pkg>" is upgraded; one not mentioned and no error is
//     already-current.
func ExecuteCampaignInstall(ctx context.Context, runner AptRunner, req CampaignInstallRequest) campaign.DeviceRunResult {
	if runner == nil {
		runner = DefaultAptRunner
	}
	res := campaign.DeviceRunResult{CampaignID: req.CampaignID}

	argv, _, ok := BuildAptArgv(req.Packages)
	if !ok {
		// Unsafe spec: refuse to run. Report every package as a dpkg/other error so the
		// server never records a false success.
		for _, w := range req.Packages {
			res.Packages = append(res.Packages, campaign.PackageResult{
				Package: w.Package, State: campaign.PkgDpkgError,
				Output: "refused: package/version failed validation",
			})
		}
		return res
	}

	out, runErr := runner.Run(ctx, argv, CampaignAptEnv())
	output := string(out)
	res.RebootRequired = IsRebootRequired()

	upgraded := map[string]string{} // pkg -> new version
	for _, m := range instRe.FindAllStringSubmatch(output, -1) {
		name := m[1]
		if i := strings.IndexByte(name, ':'); i > 0 {
			name = name[:i] // strip :arch
		}
		upgraded[name] = m[2]
	}

	runClass := campaign.FailNone
	if runErr != nil {
		runClass = classifyAptFailure(output)
	}
	cappedOut := capOutput(output)

	for _, w := range req.Packages {
		pr := campaign.PackageResult{Package: w.Package}
		if ver, did := upgraded[w.Package]; did {
			pr.State = campaign.PkgUpgraded
			pr.ToVersion = ver
			res.Packages = append(res.Packages, pr)
			continue
		}
		if runErr == nil {
			// No error and not upgraded: already at target/current.
			pr.State = campaign.PkgAlreadyCurrent
			res.Packages = append(res.Packages, pr)
			continue
		}
		// Run failed and this package was not upgraded: attribute the run failure.
		switch runClass {
		case campaign.FailHeld:
			pr.State = campaign.PkgHeld
		case campaign.FailDownload, campaign.FailDependency, campaign.FailDpkg, campaign.FailOther:
			pr.State = campaign.PkgDpkgError
		default:
			pr.State = campaign.PkgDpkgError
		}
		pr.Output = cappedOut
		res.Packages = append(res.Packages, pr)
	}
	return res
}

// classifyAptFailure maps apt/dpkg output to a FailureClass. Order matters: a dpkg error
// line is the most specific, then dependency conflicts, then download problems, then held.
func classifyAptFailure(output string) campaign.FailureClass {
	lo := strings.ToLower(output)
	switch {
	case strings.Contains(lo, "dpkg: error") || strings.Contains(lo, "dpkg returned an error") || strings.Contains(lo, "error processing package"):
		return campaign.FailDpkg
	case strings.Contains(lo, "unmet dependencies") || strings.Contains(lo, "broken packages") || strings.Contains(lo, "conflicts:") || strings.Contains(lo, "but it is not going to be installed"):
		return campaign.FailDependency
	case strings.Contains(lo, "failed to fetch") || strings.Contains(lo, "could not resolve") || strings.Contains(lo, "connection timed out") || strings.Contains(lo, "temporary failure resolving") || strings.Contains(lo, "hash sum mismatch"):
		return campaign.FailDownload
	case heldRe.MatchString(output):
		return campaign.FailHeld
	default:
		return campaign.FailOther
	}
}

// ClassifyDeviceResult reduces a DeviceRunResult to an overall work state and failure class.
// Any dpkg/held/not-available/error package makes the device FAILED; an interrupted run is
// INTERRUPTED; otherwise SUCCEEDED (every package upgraded or already current).
func ClassifyDeviceResult(res campaign.DeviceRunResult) (campaign.DeviceWorkState, campaign.FailureClass) {
	if res.Interrupted {
		return campaign.WorkInterrupted, campaign.FailNone
	}
	worst := campaign.FailNone
	failed := false
	for _, p := range res.Packages {
		switch p.State {
		case campaign.PkgUpgraded, campaign.PkgAlreadyCurrent:
			// ok
		case campaign.PkgHeld:
			failed = true
			if worst == campaign.FailNone {
				worst = campaign.FailHeld
			}
		case campaign.PkgNotAvailable:
			failed = true
			if worst == campaign.FailNone {
				worst = campaign.FailOther
			}
		case campaign.PkgDpkgError:
			failed = true
			worst = campaign.FailDpkg
		}
	}
	if failed {
		return campaign.WorkFailed, worst
	}
	return campaign.WorkSucceeded, campaign.FailNone
}

func capOutput(s string) string {
	if len(s) <= campaignAptOutputCap {
		return s
	}
	return s[:campaignAptOutputCap] + "\n...[truncated]"
}

// ReconcileCampaignResult corrects a campaign result using the installed versions read from
// dpkg before and after the run, which are authoritative where apt's output is not:
//
//   - A package that was not installed before the run is reported not_available. apt-get
//     --only-upgrade skips it with exit status 0, which would otherwise read as success.
//   - A package whose installed version changed is reported upgraded, with both versions.
//     (A real, non-simulated apt run prints no "Inst" lines, so output parsing alone reports
//     every real upgrade as already current.)
//   - A work item with a MinVersion (a CVE fix) succeeds only when the package's installed
//     SOURCE version afterwards is at least that version. Otherwise, including when the
//     version cannot be read, it is reported not_available: the repository did not supply the
//     fix, so the device is still vulnerable.
//
// before, after and sourceAfter map package -> version; a missing or empty entry means the
// package is not installed (or could not be read).
func ReconcileCampaignResult(res campaign.DeviceRunResult, works []campaign.PackageWork, before, after, sourceAfter map[string]string) campaign.DeviceRunResult {
	minFor := make(map[string]string, len(works))
	for _, w := range works {
		minFor[w.Package] = w.MinVersion
	}
	for i := range res.Packages {
		pr := &res.Packages[i]
		b, a := before[pr.Package], after[pr.Package]
		switch {
		case b == "":
			pr.State = campaign.PkgNotAvailable
			pr.Output = "package is not installed on this device"
			continue
		case a != "" && a != b:
			pr.State = campaign.PkgUpgraded
			pr.FromVersion = b
			pr.ToVersion = a
			pr.Output = ""
		}
		if b != "" && pr.FromVersion == "" {
			pr.FromVersion = b
		}
		min := minFor[pr.Package]
		if min == "" || (pr.State != campaign.PkgUpgraded && pr.State != campaign.PkgAlreadyCurrent) {
			continue
		}
		if src := sourceAfter[pr.Package]; src == "" || !campaign.VersionAtLeast(src, min) {
			pr.State = campaign.PkgNotAvailable
			pr.Output = fmt.Sprintf("installed source version %q is below the required fixed version %q; the repository does not provide the fix yet", src, min)
		}
	}
	return res
}
