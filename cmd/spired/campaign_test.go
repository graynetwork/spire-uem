package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/ipc"
	"github.com/spire-uem/spire-uem/internal/types"
)

type fakeApt struct {
	mu     sync.Mutex
	calls  [][]string
	envs   [][]string
	output string
	err    error
	onRun  func()
}

func (f *fakeApt) Run(_ context.Context, argv []string, env []string) ([]byte, error) {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string(nil), argv...))
	f.envs = append(f.envs, env)
	f.mu.Unlock()
	if f.onRun != nil {
		f.onRun()
	}
	return []byte(f.output), f.err
}

type fakePending struct {
	set      []ipc.PendingCampaign
	cleared  []string
	deferred map[string]bool
}

func (p *fakePending) SetPendingCampaign(c ipc.PendingCampaign) { p.set = append(p.set, c) }
func (p *fakePending) ClearPendingCampaign(id string)           { p.cleared = append(p.cleared, id) }
func (p *fakePending) TakeCampaignDeferral(id string) bool {
	if p.deferred[id] {
		delete(p.deferred, id)
		return true
	}
	return false
}

type harness struct {
	deps     campaignDeps
	apt      *fakeApt
	pending  *fakePending
	posted   []campaign.DeviceRunResult
	postPath []string
	postErr  error
	notes    []string
	rebootN  []string
	forced   []time.Duration
	reboot   bool
	slept    []time.Duration
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{apt: &fakeApt{}, pending: &fakePending{deferred: map[string]bool{}}}
	h.deps = campaignDeps{
		Runner:         h.apt,
		Notify:         func(_ context.Context, summary, body string) { h.notes = append(h.notes, summary+": "+body) },
		RebootRequired: func() bool { return h.reboot },
		NotifyReboot:   func(_ context.Context, m string) { h.rebootN = append(h.rebootN, m) },
		ForceReboot: func(_ context.Context, _ string, d time.Duration) error {
			h.forced = append(h.forced, d)
			return nil
		},
		Post: func(_ context.Context, path string, body any) error {
			if h.postErr != nil {
				return h.postErr
			}
			h.postPath = append(h.postPath, path)
			h.posted = append(h.posted, body.(campaign.DeviceRunResult))
			return nil
		},
		Pending:   h.pending,
		StatePath: filepath.Join(t.TempDir(), "state", "campaign-inflight.json"),
		Grace:     time.Minute,
		Sleep:     func(_ context.Context, d time.Duration) bool { h.slept = append(h.slept, d); return true },
		InstalledVersion: func(_ context.Context, pkg string) string {
			return map[string]string{"openssl": "3.0.1-1", "curl": "7.0-1"}[pkg]
		},
	}
	return h
}

func directive(pkgs ...types.CampaignPackageWork) types.CampaignDirective {
	return types.CampaignDirective{CampaignID: "camp-1", Name: "Fix OpenSSL", Packages: pkgs, RebootPolicy: "never", MayDefer: true, DeferralsLeft: 2}
}

var wantArgvPrefix = []string{
	"apt-get", "install", "--only-upgrade", "-y",
	"-o", "Dpkg::Options::=--force-confdef",
	"-o", "Dpkg::Options::=--force-confold",
	"-o", "Dpkg::Use-Pty=0",
}

func TestCampaignDirective_RunsExactAptArgvAndReports(t *testing.T) {
	h := newHarness(t)
	h.apt.output = "Inst openssl [3.0.1-1] (3.0.2-1 Debian-Security:12/stable-security [amd64])\n"
	dir := directive(
		types.CampaignPackageWork{Package: "openssl", Target: "3.0.2-1", FromCVE: "CVE-1"},
		types.CampaignPackageWork{Package: "curl", Target: campaign.TargetLatest},
	)
	runCampaignDirectives(context.Background(), h.deps, []types.CampaignDirective{dir})

	if len(h.apt.calls) != 1 {
		t.Fatalf("apt runs = %d, want 1", len(h.apt.calls))
	}
	want := append(append([]string{}, wantArgvPrefix...), "openssl=3.0.2-1", "curl")
	if !reflect.DeepEqual(h.apt.calls[0], want) {
		t.Fatalf("argv =\n %q\nwant\n %q", h.apt.calls[0], want)
	}
	env := strings.Join(h.apt.envs[0], "\n")
	if !strings.Contains(env, "DEBIAN_FRONTEND=noninteractive") {
		t.Errorf("apt must run noninteractive")
	}
	if len(h.posted) != 1 || h.postPath[0] != "/api/v1/desktop/campaign/report" {
		t.Fatalf("expected one report to the campaign endpoint, got %v %v", len(h.posted), h.postPath)
	}
	r := h.posted[0]
	if r.CampaignID != "camp-1" || r.Interrupted {
		t.Errorf("bad report header: %+v", r)
	}
	got := map[string]campaign.PackageResult{}
	for _, p := range r.Packages {
		got[p.Package] = p
	}
	if got["openssl"].State != campaign.PkgUpgraded || got["openssl"].ToVersion != "3.0.2-1" || got["openssl"].FromVersion != "3.0.1-1" {
		t.Errorf("openssl result (previous version must be recorded for rollback): %+v", got["openssl"])
	}
	if got["curl"].State != campaign.PkgAlreadyCurrent {
		t.Errorf("curl should be already current: %+v", got["curl"])
	}
	// The user was told first; the in-flight entry is cleared once the report is accepted.
	if len(h.notes) == 0 || !strings.Contains(h.notes[0], "Fix OpenSSL") {
		t.Errorf("user must be notified before install: %v", h.notes)
	}
	if len(loadInflight(h.deps.StatePath)) != 0 {
		t.Errorf("in-flight state must be cleared after an accepted report")
	}
	// The state dir/file are root-only.
	if st, err := os.Stat(filepath.Dir(h.deps.StatePath)); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("state dir mode = %v err=%v, want 0700", st.Mode().Perm(), err)
	}
}

func TestCampaignDirective_FailureIsReportedAsFailureNotSuccess(t *testing.T) {
	h := newHarness(t)
	h.apt.err = errors.New("exit status 100")
	h.apt.output = "dpkg: error processing package openssl (--configure)"
	runCampaignDirectives(context.Background(), h.deps, []types.CampaignDirective{
		directive(types.CampaignPackageWork{Package: "openssl", Target: "3.0.2-1"})})
	if len(h.posted) != 1 {
		t.Fatalf("posted %d", len(h.posted))
	}
	if h.posted[0].Packages[0].State != campaign.PkgDpkgError {
		t.Fatalf("a failed apt run must be reported as an error, got %+v", h.posted[0].Packages[0])
	}
	st, class := classifyForTest(h.posted[0])
	if st != campaign.WorkFailed || class != campaign.FailDpkg {
		t.Errorf("server classification = %s/%s, want FAILED/dpkg", st, class)
	}
}

func TestCampaignDirective_UnsafeSpecNeverReachesApt(t *testing.T) {
	h := newHarness(t)
	for _, evil := range []string{"x; rm -rf /", "-oAPT::Update::Pre-Invoke::=id", "../../etc/passwd", "a b"} {
		runCampaignDirectives(context.Background(), h.deps, []types.CampaignDirective{
			directive(types.CampaignPackageWork{Package: evil, Target: campaign.TargetLatest})})
	}
	runCampaignDirectives(context.Background(), h.deps, []types.CampaignDirective{
		directive(types.CampaignPackageWork{Package: "curl", Target: "1.0 --allow-unauthenticated"})})
	if len(h.apt.calls) != 0 {
		t.Fatalf("unsafe package/version must never reach apt, got %q", h.apt.calls)
	}
	for _, r := range h.posted {
		if st, _ := classifyForTest(r); st == campaign.WorkSucceeded {
			t.Fatalf("a refused install must never be reported as success: %+v", r)
		}
	}
}

func TestCampaignDirective_DeferralSkipsInstallAndReportsNothing(t *testing.T) {
	h := newHarness(t)
	h.pending.deferred["camp-1"] = true // the SERVER granted a deferral via the IPC route
	runCampaignDirectives(context.Background(), h.deps, []types.CampaignDirective{
		directive(types.CampaignPackageWork{Package: "openssl", Target: "3.0.2-1"})})
	if len(h.apt.calls) != 0 || len(h.posted) != 0 {
		t.Fatalf("deferred install must not run or report: apt=%d posts=%d", len(h.apt.calls), len(h.posted))
	}
	if len(h.pending.set) != 1 || !h.pending.set[0].MayDefer || h.pending.set[0].DeferralsLeft != 2 {
		t.Errorf("Hub must be offered the Defer button: %+v", h.pending.set)
	}
	if len(h.slept) != 1 || h.slept[0] != time.Minute {
		t.Errorf("agent should wait the grace period for a deferral: %v", h.slept)
	}
	if len(loadInflight(h.deps.StatePath)) != 0 {
		t.Errorf("a deferred install must leave no in-flight state")
	}
}

func TestCampaignDirective_NoDeferralOfferedWhenServerForbids(t *testing.T) {
	h := newHarness(t)
	dir := directive(types.CampaignPackageWork{Package: "openssl", Target: "3.0.2-1"})
	dir.MayDefer = false // deadline passed or deferrals exhausted
	dir.DeadlinePassed = true
	h.pending.deferred["camp-1"] = true // even a stale local flag cannot defer
	runCampaignDirectives(context.Background(), h.deps, []types.CampaignDirective{dir})
	if len(h.apt.calls) != 1 || len(h.slept) != 0 || len(h.pending.set) != 0 {
		t.Fatalf("no grace/Defer when the server says no: apt=%d slept=%v set=%v", len(h.apt.calls), h.slept, h.pending.set)
	}
}

func TestCampaignDirective_RestartMidInstallReportedInterruptedExactlyOnce(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	// The agent is stopped (restart) while apt is running.
	h.apt.onRun = cancel
	h.apt.err = errors.New("signal: killed")
	runCampaignDirectives(ctx, h.deps, []types.CampaignDirective{
		directive(types.CampaignPackageWork{Package: "openssl", Target: "3.0.2-1"})})
	if len(h.posted) != 0 {
		t.Fatalf("a run killed by shutdown must not report a result, got %+v", h.posted)
	}
	if _, ok := loadInflight(h.deps.StatePath)["camp-1"]; !ok {
		t.Fatalf("in-flight entry must survive the restart")
	}

	// New process starts: the recovery report goes out ONCE as INTERRUPTED.
	fresh := context.Background()
	reportRecoveredCampaigns(fresh, h.deps)
	reportRecoveredCampaigns(fresh, h.deps)
	reportRecoveredCampaigns(fresh, h.deps)
	if len(h.posted) != 1 {
		t.Fatalf("INTERRUPTED must be reported exactly once, got %d", len(h.posted))
	}
	if !h.posted[0].Interrupted || h.posted[0].CampaignID != "camp-1" {
		t.Fatalf("expected an interrupted report, got %+v", h.posted[0])
	}
	if st, _ := classifyForTest(h.posted[0]); st != campaign.WorkInterrupted {
		t.Errorf("server must classify it INTERRUPTED, got %s", st)
	}
	if len(loadInflight(h.deps.StatePath)) != 0 {
		t.Errorf("entry must be cleared after the interrupted report landed")
	}
}

func TestCampaignDirective_FailedReportIsRetriedWithTheRealResult(t *testing.T) {
	h := newHarness(t)
	h.apt.output = "Inst openssl [3.0.1-1] (3.0.2-1 Debian-Security [amd64])\n"
	h.postErr = errors.New("server unreachable")
	runCampaignDirectives(context.Background(), h.deps, []types.CampaignDirective{
		directive(types.CampaignPackageWork{Package: "openssl", Target: "3.0.2-1"})})
	e, ok := loadInflight(h.deps.StatePath)["camp-1"]
	if !ok || e.Result == nil {
		t.Fatalf("an unreported finished run must keep its result: %+v", e)
	}
	// The server is back at the next check-in: the REAL result is sent, not INTERRUPTED.
	h.postErr = nil
	reportRecoveredCampaigns(context.Background(), h.deps)
	if len(h.posted) != 1 || h.posted[0].Interrupted || h.posted[0].Packages[0].State != campaign.PkgUpgraded {
		t.Fatalf("expected the original upgraded result, got %+v", h.posted)
	}
	reportRecoveredCampaigns(context.Background(), h.deps)
	if len(h.posted) != 1 {
		t.Fatalf("must not report twice, got %d", len(h.posted))
	}
}

func TestCampaignDirective_StateWriteFailureFailsClosed(t *testing.T) {
	h := newHarness(t)
	// A regular file where the state directory should be: it cannot be created.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.deps.StatePath = filepath.Join(blocker, "inflight.json")
	runCampaignDirectives(context.Background(), h.deps, []types.CampaignDirective{
		directive(types.CampaignPackageWork{Package: "openssl", Target: "3.0.2-1"})})
	if len(h.apt.calls) != 0 {
		t.Fatalf("without durable in-flight state the install must not start")
	}
}

func TestCampaignDirective_RebootPolicies(t *testing.T) {
	cases := []struct {
		name           string
		policy         string
		deadlinePassed bool
		rebootNeeded   bool
		wantNotice     bool
		wantForced     bool
	}{
		{"never", "never", true, true, false, false},
		{"notify", "notify", false, true, true, false},
		{"force before deadline only notifies", "force", false, true, true, false},
		{"force at deadline reboots with warning", "force", true, true, false, true},
		{"no reboot needed", "force", true, false, false, false},
		{"unknown policy never reboots", "bogus", true, true, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			h.reboot = c.rebootNeeded
			dir := directive(types.CampaignPackageWork{Package: "curl", Target: campaign.TargetLatest})
			dir.RebootPolicy = c.policy
			dir.DeadlinePassed = c.deadlinePassed
			dir.MayDefer = false
			runCampaignDirectives(context.Background(), h.deps, []types.CampaignDirective{dir})
			if (len(h.rebootN) > 0) != c.wantNotice {
				t.Errorf("reboot notice = %v, want %v", h.rebootN, c.wantNotice)
			}
			if (len(h.forced) > 0) != c.wantForced {
				t.Errorf("forced reboot = %v, want %v", h.forced, c.wantForced)
			}
			if c.wantForced {
				if h.forced[0] != campaignForcedRebootDelay {
					t.Errorf("forced reboot must give a warning delay, got %v", h.forced[0])
				}
				warned := false
				for _, n := range h.notes {
					if strings.Contains(n, "restart in") {
						warned = true
					}
				}
				if !warned {
					t.Errorf("user must be warned before a forced reboot: %v", h.notes)
				}
			}
			// The report is sent BEFORE any reboot can lose it.
			if len(h.posted) != 1 {
				t.Errorf("report must be posted, got %d", len(h.posted))
			}
		})
	}
}

func TestCampaignDirective_OldServerSendsNothing(t *testing.T) {
	h := newHarness(t)
	runCampaignDirectives(context.Background(), h.deps, nil)
	reportRecoveredCampaigns(context.Background(), h.deps)
	if len(h.apt.calls) != 0 || len(h.posted) != 0 || len(h.notes) != 0 {
		t.Fatalf("no directives must be a no-op")
	}
}

// classifyForTest applies the SERVER's classification to an agent report.
func classifyForTest(r campaign.DeviceRunResult) (campaign.DeviceWorkState, campaign.FailureClass) {
	return engine.ClassifyDeviceResult(r)
}
