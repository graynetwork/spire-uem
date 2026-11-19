package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/inventory"
	"github.com/spire-uem/spire-uem/internal/ipc"
	"github.com/spire-uem/spire-uem/internal/types"
)

const (
	// campaignStatePath persists in-flight campaign installs so a restart mid-install is
	// reported as INTERRUPTED (once) instead of being lost or mistaken for success.
	campaignStatePath = "/var/lib/spire/campaign-inflight.json"
	// campaignDeferGrace is how long the user has to press Defer after being notified.
	campaignDeferGrace = 60 * time.Second
	// campaignReportPath is the control-plane endpoint for campaign results.
	campaignReportPath = "/api/v1/desktop/campaign/report"
	// campaignForcedRebootDelay is the warning period before a forced reboot.
	campaignForcedRebootDelay = 5 * time.Minute
)

// campaignPending is the slice of the IPC server the runner uses: it publishes the pending
// install for Spire Hub and learns whether the server granted a deferral.
type campaignPending interface {
	SetPendingCampaign(p ipc.PendingCampaign)
	ClearPendingCampaign(campaignID string)
	TakeCampaignDeferral(campaignID string) bool
}

// campaignDeps injects every system interaction so tests run with no apt, no desktop, no
// reboot and no network.
type campaignDeps struct {
	Runner         engine.AptRunner                                // apt-get runner (real in production)
	Notify         func(ctx context.Context, summary, body string) // desktop notification to the active user
	RebootRequired func() bool                                     // is a reboot pending after the install
	NotifyReboot   func(ctx context.Context, message string)       // "reboot needed" notice (reboot policy notify)
	ForceReboot    func(ctx context.Context, warning string, delay time.Duration) error
	Post           func(ctx context.Context, path string, body any) error // report to the control plane
	Pending        campaignPending
	StatePath      string
	Grace          time.Duration
	Sleep          func(ctx context.Context, d time.Duration) bool
	// InstalledVersion returns the currently installed version of a package ("" if unknown).
	// It is read BEFORE the install so the report carries the previous version for rollback.
	InstalledVersion func(ctx context.Context, pkg string) string
	// InstalledSourceVersion returns the installed package's SOURCE version ("" if unknown),
	// read after the install to confirm a CVE's fixed version was reached.
	InstalledSourceVersion func(ctx context.Context, pkg string) string
}

// inflightEntry is one persisted in-flight (or completed-but-unreported) campaign run.
type inflightEntry struct {
	StartedAt time.Time                 `json:"started_at"`
	Result    *campaign.DeviceRunResult `json:"result,omitempty"`
}

var inflightMu sync.Mutex

func loadInflight(path string) map[string]inflightEntry {
	out := map[string]inflightEntry{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(b, &out)
	return out
}

// saveInflight writes the state atomically (0600 file in a 0700 root-owned dir).
func saveInflight(path string, m map[string]inflightEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func updateInflight(path string, fn func(m map[string]inflightEntry)) error {
	inflightMu.Lock()
	defer inflightMu.Unlock()
	m := loadInflight(path)
	fn(m)
	return saveInflight(path, m)
}

// reportRecoveredCampaigns reports runs left in the state file by a previous process. A run
// with a stored result (the install finished but the report never landed) is re-reported with
// that result; a run with none was cut off mid-install and is reported INTERRUPTED. An entry is
// removed only after the report is accepted, so each is reported until it lands and a
// successful report is never repeated.
func reportRecoveredCampaigns(ctx context.Context, d campaignDeps) {
	inflightMu.Lock()
	entries := loadInflight(d.StatePath)
	inflightMu.Unlock()
	for id, e := range entries {
		res := campaign.DeviceRunResult{CampaignID: id, Interrupted: true}
		if e.Result != nil {
			res = *e.Result
		}
		if err := d.Post(ctx, campaignReportPath, res); err != nil {
			log.Printf("[spired] campaign %s: could not report recovered run: %v", id, err)
			continue
		}
		if err := updateInflight(d.StatePath, func(m map[string]inflightEntry) { delete(m, id) }); err != nil {
			log.Printf("[spired] campaign %s: could not clear in-flight state: %v", id, err)
		}
		log.Printf("[spired] campaign %s: reported recovered run (interrupted=%v)", id, res.Interrupted)
	}
}

// runCampaignDirectives executes each campaign directive the server claimed for this device.
// Older servers never send directives, so an empty slice is a no-op.
func runCampaignDirectives(ctx context.Context, d campaignDeps, directives []types.CampaignDirective) {
	for _, dir := range directives {
		if ctx.Err() != nil {
			return
		}
		runCampaignDirective(ctx, d, dir)
	}
}

func runCampaignDirective(ctx context.Context, d campaignDeps, dir types.CampaignDirective) {
	id := strings.TrimSpace(dir.CampaignID)
	if id == "" || len(dir.Packages) == 0 {
		return
	}
	works := make([]campaign.PackageWork, 0, len(dir.Packages))
	for _, p := range dir.Packages {
		works = append(works, campaign.PackageWork{Package: p.Package, Target: p.Target, MinVersion: p.MinVersion, FromCVE: p.FromCVE})
	}

	// 1. Tell the active user, and give them a chance to defer when the server allows it.
	name := dir.Name
	if name == "" {
		name = "security updates"
	}
	summary := "SpireUEM: updates scheduled"
	body := fmt.Sprintf("%s will be installed on this computer.", name)
	if dir.MayDefer && d.Grace > 0 && dir.DeferralsLeft > 0 {
		graceSecs := int(d.Grace / time.Second)
		if graceSecs >= 60 {
			body = fmt.Sprintf("%s will be installed in %d minute(s). Open Spire Hub to review or defer (%d deferral(s) remaining).", name, graceSecs/60, dir.DeferralsLeft)
		} else {
			body = fmt.Sprintf("%s will be installed in %d second(s). Open Spire Hub to review or defer (%d deferral(s) remaining).", name, graceSecs, dir.DeferralsLeft)
		}
	} else if dir.DeadlinePassed {
		body = fmt.Sprintf("%s deadline has passed and will be installed now.", name)
	}
	d.Notify(ctx, summary, body)
	if dir.MayDefer && d.Grace > 0 {
		var pkgItems []ipc.PendingPackageItem
		var pkgNames []string
		for _, p := range dir.Packages {
			pkgItems = append(pkgItems, ipc.PendingPackageItem{
				Package: p.Package,
				Target:  p.Target,
				FromCVE: p.FromCVE,
			})
			pkgNames = append(pkgNames, p.Package)
		}
		d.Pending.SetPendingCampaign(ipc.PendingCampaign{
			CampaignID:     id,
			Name:           dir.Name,
			Packages:       pkgItems,
			PackageNames:   pkgNames,
			MayDefer:       true,
			DeferralsLeft:  dir.DeferralsLeft,
			DeadlinePassed: dir.DeadlinePassed,
			GraceSeconds:   int(d.Grace / time.Second),
		})
		d.Sleep(ctx, d.Grace)
		d.Pending.ClearPendingCampaign(id)
		if d.Pending.TakeCampaignDeferral(id) {
			// The SERVER granted the deferral and already returned the work to PENDING.
			log.Printf("[spired] campaign %s deferred by user; install skipped", id)
			d.Notify(ctx, "SpireUEM: updates deferred", fmt.Sprintf("%s deferred. Updates will be rescheduled.", name))
			return
		}
	}
	if ctx.Err() != nil {
		return
	}

	// 2. Persist "in flight" BEFORE touching apt so a crash is reported INTERRUPTED.
	if err := updateInflight(d.StatePath, func(m map[string]inflightEntry) {
		m[id] = inflightEntry{StartedAt: time.Now().UTC()}
	}); err != nil {
		// Fail closed: without durable state a restart could not be reported, so do not install.
		log.Printf("[spired] campaign %s: cannot persist in-flight state, not installing: %v", id, err)
		return
	}

	// 3. Record each package's current version (for rollback), then run the install (exact apt
	// argv built and validated by the engine; never a shell).
	prev := map[string]string{}
	if d.InstalledVersion != nil {
		for _, w := range works {
			if campaign.ValidPackageName(w.Package) {
				prev[w.Package] = d.InstalledVersion(ctx, w.Package)
			}
		}
	}
	res := engine.ExecuteCampaignInstall(ctx, d.Runner, engine.CampaignInstallRequest{CampaignID: id, Packages: works})
	if d.InstalledVersion != nil {
		// Re-read dpkg after the run: the before/after versions, not apt's output, decide
		// what was upgraded, what was never installed, and whether a CVE fix was reached.
		after := map[string]string{}
		srcAfter := map[string]string{}
		for _, w := range works {
			if campaign.ValidPackageName(w.Package) {
				after[w.Package] = d.InstalledVersion(ctx, w.Package)
				if d.InstalledSourceVersion != nil {
					srcAfter[w.Package] = d.InstalledSourceVersion(ctx, w.Package)
				}
			}
		}
		res = engine.ReconcileCampaignResult(res, works, prev, after, srcAfter)
	}
	for i := range res.Packages {
		if res.Packages[i].FromVersion == "" {
			res.Packages[i].FromVersion = prev[res.Packages[i].Package]
		}
	}
	res.RebootRequired = d.RebootRequired()
	if ctx.Err() != nil {
		// Shutting down mid-install: leave the in-flight entry so the next start reports it
		// INTERRUPTED rather than reporting a result produced by a killed apt.
		return
	}

	// 4. Record the result durably, then report; the entry is cleared only once accepted.
	_ = updateInflight(d.StatePath, func(m map[string]inflightEntry) {
		e := m[id]
		r := res
		e.Result = &r
		m[id] = e
	})
	if err := d.Post(ctx, campaignReportPath, res); err != nil {
		log.Printf("[spired] campaign %s: report failed, will retry at next check-in: %v", id, err)
	} else {
		_ = updateInflight(d.StatePath, func(m map[string]inflightEntry) { delete(m, id) })
	}

	// 5. Reboot policy (after the report so a reboot can never lose it).
	applyCampaignRebootPolicy(ctx, d, dir, res)
}

func applyCampaignRebootPolicy(ctx context.Context, d campaignDeps, dir types.CampaignDirective, res campaign.DeviceRunResult) {
	if !res.RebootRequired {
		return
	}
	switch campaign.RebootPolicy(dir.RebootPolicy) {
	case campaign.RebootNotify:
		d.NotifyReboot(ctx, "Updates were installed and a restart is required. Please restart when convenient.")
	case campaign.RebootForce:
		if !dir.DeadlinePassed {
			// Before the deadline a force policy only notifies.
			d.NotifyReboot(ctx, "Updates were installed and a restart is required. It will be forced after the deadline.")
			return
		}
		warn := fmt.Sprintf("This computer will restart in %d minutes to finish installing updates. Save your work.", int(campaignForcedRebootDelay/time.Minute))
		d.Notify(ctx, "SpireUEM: restart scheduled", warn)
		if err := d.ForceReboot(ctx, warn, campaignForcedRebootDelay); err != nil {
			log.Printf("[spired] campaign %s: forced reboot could not be scheduled: %v", dir.CampaignID, err)
		}
	default: // RebootNever and anything unrecognised: never reboot.
	}
}

// newCampaignDeps builds the production dependencies.
func newCampaignDeps(client *http.Client, serverURL, token string, pending campaignPending) campaignDeps {
	return campaignDeps{
		Runner:         engine.DefaultAptRunner,
		Notify:         notifyActiveUser,
		RebootRequired: engine.IsRebootRequired,
		NotifyReboot: func(ctx context.Context, msg string) {
			_ = engine.MarkRebootRequired(ctx, msg)
		},
		ForceReboot: func(ctx context.Context, warning string, delay time.Duration) error {
			// A scheduled (cancellable) reboot via shutdown(8); no shell involved.
			mins := int(delay / time.Minute)
			if mins < 1 {
				mins = 1
			}
			return exec.CommandContext(ctx, "shutdown", "-r", fmt.Sprintf("+%d", mins), warning).Run()
		},
		Post: func(ctx context.Context, path string, body any) error {
			return postJSON(ctx, client, serverURL+path, token, body)
		},
		InstalledVersion:       dpkgInstalledVersion,
		InstalledSourceVersion: dpkgInstalledSourceVersion,
		Pending:                pending,
		StatePath:              campaignStatePath,
		Grace:                  campaignDeferGrace,
		Sleep:                  sleepContext,
	}
}

// notifyActiveUser best-effort shows a desktop notification to the active seat0 user.
// It tries notify-send first, falling back to gdbus and dbus-send on the user's session bus.
func notifyActiveUser(ctx context.Context, summary, body string) {
	username, uid, err := inventory.GetActiveSessionDetails()
	if err != nil || username == "" || uid == "" {
		return
	}
	dbus := fmt.Sprintf("DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/%s/bus", uid)

	// 1. Try notify-send
	if _, err := exec.LookPath("notify-send"); err == nil {
		cmd := exec.CommandContext(ctx, "runuser", "-u", username, "--",
			"env", dbus, "notify-send", "-u", "normal", "-a", "SpireUEM", summary, body)
		if err := cmd.Run(); err == nil {
			return
		}
	}

	// 2. Fallback to gdbus
	if _, err := exec.LookPath("gdbus"); err == nil {
		cmd := exec.CommandContext(ctx, "runuser", "-u", username, "--",
			"env", dbus,
			"gdbus", "call", "--session",
			"--dest", "org.freedesktop.Notifications",
			"--object-path", "/org/freedesktop/Notifications",
			"--method", "org.freedesktop.Notifications.Notify",
			"SpireUEM", "0", "dialog-information", summary, body, "[]", "{}", "10000",
		)
		if err := cmd.Run(); err == nil {
			return
		}
	}

	// 3. Fallback to dbus-send
	if _, err := exec.LookPath("dbus-send"); err == nil {
		cmd := exec.CommandContext(ctx, "runuser", "-u", username, "--",
			"env", dbus,
			"dbus-send", "--session",
			"--dest=org.freedesktop.Notifications",
			"--type=method_call",
			"/org/freedesktop/Notifications",
			"org.freedesktop.Notifications.Notify",
			"string:SpireUEM", "uint32:0", "string:dialog-information",
			fmt.Sprintf("string:%s", summary), fmt.Sprintf("string:%s", body),
			"array:string:", "dict:string:string:", "int32:10000",
		)
		_ = cmd.Run()
	}
}

// dpkgInstalledVersion returns the installed version of a binary package via dpkg-query, or ""
// when it is not installed or unknown. The name is validated first and passed as one argv
// element after "--", so it can never be read as an option or reach a shell.
func dpkgInstalledVersion(ctx context.Context, pkg string) string {
	return dpkgQueryField(ctx, pkg, "${Version}")
}

// dpkgInstalledSourceVersion returns the installed package's source version, which is what
// CVE fixed versions are expressed in ("" if not installed).
func dpkgInstalledSourceVersion(ctx context.Context, pkg string) string {
	return dpkgQueryField(ctx, pkg, "${source:Version}")
}

// dpkgQueryField reads one dpkg-query field for an installed package. A package that is
// known to dpkg but not installed (removed, config files only) reports "".
func dpkgQueryField(ctx context.Context, pkg, field string) string {
	if !campaign.ValidPackageName(pkg) {
		return ""
	}
	out, err := exec.CommandContext(ctx, "dpkg-query", "--show", "--showformat=${db:Status-Status}\t"+field, "--", pkg).Output()
	if err != nil {
		return ""
	}
	status, val, ok := strings.Cut(strings.TrimSpace(string(out)), "\t")
	if !ok || status != "installed" {
		return ""
	}
	return strings.TrimSpace(val)
}
