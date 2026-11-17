package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/campaignsync"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// e2eEnv is a group-targeted campaign over real Postgres with CANARY and PRODUCTION devices.
type e2eEnv struct {
	t      *testing.T
	h      *Handler
	repo   *db.Repository
	pool   *pgxpool.Pool
	ctx    context.Context
	pkg    string
	cve    string
	group  *types.DeviceGroup
	camp   *campaign.Campaign
	clock  time.Time
	mu     sync.Mutex
	canary devTok
	prod   []devTok
}

type devTok struct {
	dev   *types.Device
	token string
}

func (e *e2eEnv) now() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.clock }
func (e *e2eEnv) advance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.clock = e.clock.Add(d)
}

func e2eStages() []campaign.Stage {
	return []campaign.Stage{
		{Order: 0, Name: "CANARY", MinDevices: 1, SuccessThresholdPct: 95, SoakMinutes: 60, FailureHaltPct: 10, Promotion: campaign.PromotionAuto},
		{Order: 1, Name: "PRODUCTION", MinDevices: 0, SuccessThresholdPct: 95, SoakMinutes: 0, FailureHaltPct: 10, Promotion: campaign.PromotionAuto},
	}
}

// newE2E builds: 1 CANARY device + nProd PRODUCTION devices, each with an open fixable CVE on
// a unique package, all in a static group, and a RUNNING campaign targeting that group.
func newE2E(t *testing.T, nProd int, mutate func(*campaign.Campaign)) *e2eEnv {
	t.Helper()
	h, repo, ctx := scriptsTestHandler(t)
	pool, err := pgxpool.New(ctx, os.Getenv("SPIRE_TEST_DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	sfx := strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "")
	e := &e2eEnv{t: t, h: h, repo: repo, pool: pool, ctx: ctx, pkg: "e2epkg" + sfx, cve: "CVE-2099-" + sfx, clock: time.Now().UTC()}

	mk := func(ring types.DeploymentRing) devTok {
		d, tok := approvedDevice(t, repo, ctx)
		if _, err := repo.UpdateDevicePatchRing(ctx, d.ID, ring); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO device_cve_matches (device_id, cve_id, source_package, installed_version, fixed_version, urgency, no_fix_available)
			VALUES ($1,$2,$3,'1.0-1','1.0-2','high',false)`, d.ID, e.cve, e.pkg); err != nil {
			t.Fatal(err)
		}
		d, _ = repo.GetDeviceByID(ctx, d.ID)
		return devTok{dev: d, token: tok}
	}
	e.canary = mk(types.RingCanary)
	ids := []string{e.canary.dev.ID}
	for i := 0; i < nProd; i++ {
		p := mk(types.RingProduction)
		e.prod = append(e.prod, p)
		ids = append(ids, p.dev.ID)
	}
	g, err := repo.CreateGroup(ctx, db.CreateGroupInput{Name: "e2e-" + sfx, Kind: types.GroupKindTarget, IncludeDeviceIDs: ids, CreatedBy: "test"})
	if err != nil {
		t.Fatal(err)
	}
	e.group = g
	if _, _, err := repo.RecomputeGroupMembership(ctx, g.ID); err != nil {
		t.Fatal(err)
	}

	c := &campaign.Campaign{
		Name: "e2e " + sfx, TargetKind: campaign.TargetGroup, GroupID: g.ID,
		Stages: e2eStages(), RebootPolicy: campaign.RebootNotify, MaxDeferrals: 2, CreatedBy: "test",
	}
	if mutate != nil {
		mutate(c)
	}
	created, err := repo.CreateCampaign(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.SetCampaignState(ctx, created.ID, campaign.StateRunning); err != nil {
		t.Fatal(err)
	}
	e.camp, _ = repo.GetCampaign(ctx, created.ID)
	return e
}

func (e *e2eEnv) loop() *campaignsync.Loop {
	return campaignsync.NewWithStore(e.repo, nil, time.Minute, e.now)
}

func (e *e2eEnv) checkin(d devTok) []types.CampaignDirective {
	e.t.Helper()
	return postCheckin(e.t, e.h, d.token, types.CheckinRequest{HardwareUUID: d.dev.HardwareUUID, AgentVersion: "9.9.9"}).CampaignDirectives
}

func (e *e2eEnv) report(d devTok, res campaign.DeviceRunResult) {
	e.t.Helper()
	b, _ := json.Marshal(res)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/desktop/campaign/report", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+d.token)
	w := httptest.NewRecorder()
	e.h.ReportCampaignResult(w, req)
	if w.Code != http.StatusOK {
		e.t.Fatalf("report HTTP %d: %s", w.Code, w.Body.String())
	}
}

func (e *e2eEnv) upgraded() campaign.DeviceRunResult {
	return campaign.DeviceRunResult{CampaignID: e.camp.ID, Packages: []campaign.PackageResult{
		{Package: e.pkg, State: campaign.PkgUpgraded, FromVersion: "1.0-1", ToVersion: "1.0-2"}}}
}

func (e *e2eEnv) failed() campaign.DeviceRunResult {
	return campaign.DeviceRunResult{CampaignID: e.camp.ID, Packages: []campaign.PackageResult{
		{Package: e.pkg, State: campaign.PkgDpkgError, Output: "dpkg: error processing package"}}}
}

func (e *e2eEnv) eval() engineEval {
	e.t.Helper()
	ev, err := e.loop().EvaluateOne(e.ctx, e.camp.ID)
	if err != nil {
		e.t.Fatalf("evaluate: %v", err)
	}
	return engineEval{Promoted: ev.Promoted, Halted: ev.Halted, Completed: ev.Completed}
}

type engineEval struct{ Promoted, Halted, Completed bool }

func (e *e2eEnv) state() *campaign.Campaign {
	c, err := e.repo.GetCampaign(e.ctx, e.camp.ID)
	if err != nil || c == nil {
		e.t.Fatalf("get campaign: %v", err)
	}
	return c
}

func (e *e2eEnv) workState(d devTok) campaign.DeviceWorkState {
	s, ok, err := e.repo.GetCampaignWorkState(e.ctx, e.camp.ID, d.dev.ID)
	if err != nil {
		e.t.Fatal(err)
	}
	if !ok {
		return ""
	}
	return s
}

func (e *e2eEnv) countEvents(kind string) int {
	evs, err := e.repo.ListCampaignEvents(e.ctx, e.camp.ID, 100)
	if err != nil {
		e.t.Fatal(err)
	}
	n := 0
	for _, ev := range evs {
		if ev.Kind == kind {
			n++
		}
	}
	return n
}

// TestCampaignE2E_CanaryPromoteThenHalt is the full lifecycle: CANARY directive, success
// report, soak (fake clock), promotion, PRODUCTION directive, failures beyond the halt
// threshold, halt, and nothing more dispatched afterwards.
func TestCampaignE2E_CanaryPromoteThenHalt(t *testing.T) {
	e := newE2E(t, 3, nil)

	// A PRODUCTION device gets nothing while the campaign is still in its CANARY stage.
	if d := e.checkin(e.prod[0]); len(d) != 0 {
		t.Fatalf("PRODUCTION device must get no directive during CANARY, got %+v", d)
	}

	// The CANARY device gets exactly the validated work, claimed once.
	dirs := e.checkin(e.canary)
	if len(dirs) != 1 || dirs[0].CampaignID != e.camp.ID {
		t.Fatalf("CANARY device should get one directive, got %+v", dirs)
	}
	if len(dirs[0].Packages) != 1 || dirs[0].Packages[0].Package != e.pkg || dirs[0].Packages[0].Target != "1.0-2" {
		t.Fatalf("unexpected work: %+v", dirs[0].Packages)
	}
	if dirs[0].RebootPolicy != "notify" || !dirs[0].MayDefer || dirs[0].DeferralsLeft != 2 {
		t.Errorf("directive should carry reboot policy and deferral allowance: %+v", dirs[0])
	}
	if again := e.checkin(e.canary); len(again) != 0 {
		t.Fatalf("an already-claimed install must not be dispatched twice, got %+v", again)
	}
	if got := e.workState(e.canary); got != campaign.WorkDispatched {
		t.Fatalf("canary state = %s, want DISPATCHED", got)
	}

	// Before the canary reports, evaluation must not promote (pending device).
	if ev := e.eval(); ev.Promoted || ev.Halted || ev.Completed {
		t.Fatalf("no transition before the canary reports: %+v", ev)
	}

	// Canary succeeds. Soak (60m) must elapse on the FAKE clock before promotion.
	e.report(e.canary, e.upgraded())
	if got := e.workState(e.canary); got != campaign.WorkSucceeded {
		t.Fatalf("canary state = %s, want SUCCEEDED", got)
	}
	if ev := e.eval(); ev.Promoted {
		t.Fatalf("must not promote at soak start")
	}
	e.advance(30 * time.Minute)
	if ev := e.eval(); ev.Promoted {
		t.Fatalf("must not promote within soak")
	}
	if d := e.checkin(e.prod[0]); len(d) != 0 {
		t.Fatalf("still CANARY stage: PRODUCTION device must get nothing, got %+v", d)
	}
	e.advance(31 * time.Minute)
	if ev := e.eval(); !ev.Promoted {
		t.Fatalf("expected promotion after soak")
	}
	if c := e.state(); c.CurrentStage != 1 || c.State != campaign.StateRunning {
		t.Fatalf("after promotion: stage=%d state=%s", c.CurrentStage, c.State)
	}
	if e.countEvents("promoted") != 1 {
		t.Errorf("expected exactly one promoted event, got %d", e.countEvents("promoted"))
	}

	// The next cycle builds the PRODUCTION stage for ALL its devices (even ones that have not
	// checked in) and must NOT complete the campaign over them.
	if ev := e.eval(); ev.Completed {
		t.Fatalf("campaign must not complete while PRODUCTION devices are unpatched")
	}
	for i, p := range e.prod {
		if got := e.workState(p); got != campaign.WorkPending {
			t.Fatalf("prod[%d] should be materialized PENDING before check-in, got %q", i, got)
		}
	}

	// PRODUCTION device now gets work.
	pd := e.checkin(e.prod[0])
	if len(pd) != 1 {
		t.Fatalf("PRODUCTION device should now get a directive, got %+v", pd)
	}

	// It fails: 1/1 = 100% > 10% halt threshold. HALT wins; nothing further is dispatched.
	e.report(e.prod[0], e.failed())
	ev := e.eval()
	if !ev.Halted || ev.Promoted || ev.Completed {
		t.Fatalf("expected halt only, got %+v", ev)
	}
	if c := e.state(); c.State != campaign.StateHalted || c.HaltedReason == "" {
		t.Fatalf("campaign should be HALTED with a reason: state=%s reason=%q", c.State, c.HaltedReason)
	}
	for i := 1; i < len(e.prod); i++ {
		if d := e.checkin(e.prod[i]); len(d) != 0 {
			t.Fatalf("halted campaign must dispatch nothing, prod[%d] got %+v", i, d)
		}
		if got := e.workState(e.prod[i]); got == campaign.WorkDispatched {
			t.Fatalf("prod[%d] must not be DISPATCHED after halt", i)
		}
	}
	if e.countEvents("halted") != 1 {
		t.Errorf("expected one halted event, got %d", e.countEvents("halted"))
	}
	// A further evaluation of a halted campaign is a no-op (no second halt, no promotion).
	if ev := e.eval(); ev.Halted || ev.Promoted || ev.Completed {
		t.Fatalf("halted campaign must not transition: %+v", ev)
	}
}

// TestCampaignE2E_BlackoutDispatchesNothing: a device inside a blackout window gets no
// directive, and the work stays unclaimed (PENDING) so nothing is lost.
func TestCampaignE2E_BlackoutDispatchesNothing(t *testing.T) {
	e := newE2E(t, 0, func(c *campaign.Campaign) {
		c.BlackoutCron = "* * * * *" // every minute...
		c.BlackoutDurationMinutes = 60
	})
	if d := e.checkin(e.canary); len(d) != 0 {
		t.Fatalf("blackout window active: expected no directive, got %+v", d)
	}
	if got := e.workState(e.canary); got == campaign.WorkDispatched {
		t.Fatalf("work must not be claimed during blackout, state=%s", got)
	}
}

// TestCampaignE2E_DeviceLeavesGroupStopsDispatch: removing a device from the target group
// stops dispatch to it and retires its row.
func TestCampaignE2E_DeviceLeavesGroupStopsDispatch(t *testing.T) {
	e := newE2E(t, 0, nil)
	// Remove the canary from the group (explicit exclude) and recompute membership.
	if _, err := e.repo.UpdateGroup(e.ctx, e.group.ID, db.CreateGroupInput{
		Name: e.group.Name, Kind: types.GroupKindTarget, IncludeDeviceIDs: []string{e.canary.dev.ID},
		ExcludeDeviceIDs: []string{e.canary.dev.ID}, CreatedBy: "test",
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.repo.RecomputeGroupMembership(e.ctx, e.group.ID); err != nil {
		t.Fatal(err)
	}
	if d := e.checkin(e.canary); len(d) != 0 {
		t.Fatalf("device that left the target must get nothing, got %+v", d)
	}
}

// TestCampaignE2E_TwoInstancesPromoteExactlyOnce: two loops (two server instances) racing
// at the soak boundary produce exactly one promotion and never complete the campaign early.
func TestCampaignE2E_TwoInstancesPromoteExactlyOnce(t *testing.T) {
	e := newE2E(t, 2, nil)
	if d := e.checkin(e.canary); len(d) != 1 {
		t.Fatalf("canary directive: %+v", d)
	}
	e.report(e.canary, e.upgraded())
	e.eval() // start soak
	e.advance(61 * time.Minute)

	var wg sync.WaitGroup
	results := make([]engineEval, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ev, err := e.loop().EvaluateOne(e.ctx, e.camp.ID)
			if err != nil {
				t.Errorf("evaluate: %v", err)
				return
			}
			results[i] = engineEval{Promoted: ev.Promoted, Completed: ev.Completed}
		}(i)
	}
	wg.Wait()
	promoted := 0
	for _, r := range results {
		if r.Promoted {
			promoted++
		}
		if r.Completed {
			t.Errorf("campaign must not complete during the race")
		}
	}
	if promoted != 1 || e.countEvents("promoted") != 1 {
		t.Fatalf("exactly one promotion expected, got evals=%d events=%d", promoted, e.countEvents("promoted"))
	}
	if c := e.state(); c.CurrentStage != 1 {
		t.Fatalf("stage = %d, want 1 (never skipped or double-advanced)", c.CurrentStage)
	}
}

// TestCampaignE2E_OldAgentIsUnsupportedNotSuccess: an agent that ignores the directive and
// never reports is marked UNSUPPORTED after the timeout, counted as a failure, never success.
func TestCampaignE2E_OldAgentIsUnsupportedNotSuccess(t *testing.T) {
	e := newE2E(t, 0, nil)
	if d := e.checkin(e.canary); len(d) != 1 {
		t.Fatalf("expected directive, got %+v", d)
	}
	// Pretend it was dispatched 25h ago (past the 24h unsupported timeout).
	if _, err := e.pool.Exec(e.ctx, `UPDATE campaign_device_work SET dispatched_at = NOW() - interval '25 hours' WHERE campaign_id=$1`, e.camp.ID); err != nil {
		t.Fatal(err)
	}
	ev := e.eval()
	if got := e.workState(e.canary); got != campaign.WorkUnsupported {
		t.Fatalf("silent agent should be UNSUPPORTED, got %s", got)
	}
	if ev.Completed || ev.Promoted {
		t.Fatalf("an unsupported agent must never advance the campaign: %+v", ev)
	}
	if !ev.Halted {
		t.Errorf("1/1 unsupported counts as a failure and exceeds the halt threshold")
	}
}

// TestCheckinResponse_OldAgentWireCompat: a check-in with no campaign work serialises with no
// campaign_directives key at all, so old agents see a byte-identical response.
func TestCheckinResponse_OldAgentWireCompat(t *testing.T) {
	b, _ := json.Marshal(types.CheckinResponse{DeviceID: "x", Status: types.StatusApproved})
	if strings.Contains(string(b), "campaign_directives") {
		t.Fatalf("empty campaign directives must be omitted: %s", b)
	}
	// And an old agent's request (no new fields) still checks in fine with a RUNNING campaign.
	e := newE2E(t, 0, nil)
	resp := postCheckin(t, e.h, e.canary.token, types.CheckinRequest{HardwareUUID: e.canary.dev.HardwareUUID})
	if len(resp.CampaignDirectives) != 1 {
		t.Fatalf("server should still dispatch to an agent that sends no new fields: %+v", resp.CampaignDirectives)
	}
}

// TestCampaignE2E_PartialStageDoesNotComplete: the last stage must not complete while some of
// its devices (offline, never checked in) have no result, even when every REPORTED device
// succeeded.
func TestCampaignE2E_PartialStageDoesNotComplete(t *testing.T) {
	e := newE2E(t, 3, nil)
	e.checkin(e.canary)
	e.report(e.canary, e.upgraded())
	e.eval()
	e.advance(61 * time.Minute)
	if ev := e.eval(); !ev.Promoted {
		t.Fatalf("expected promotion")
	}
	e.eval() // materialize PRODUCTION
	// Only prod[0] is online and succeeds; prod[1] and prod[2] stay offline the whole time.
	if d := e.checkin(e.prod[0]); len(d) != 1 {
		t.Fatalf("prod[0] directive: %+v", d)
	}
	e.report(e.prod[0], e.upgraded())
	e.advance(10 * time.Minute)
	for i := 0; i < 3; i++ {
		if ev := e.eval(); ev.Completed || ev.Halted {
			t.Fatalf("cycle %d: campaign must stay RUNNING while devices are still pending: %+v", i, ev)
		}
	}
	if c := e.state(); c.State != campaign.StateRunning {
		t.Fatalf("state = %s, want RUNNING", c.State)
	}
	// Once the stragglers come online and succeed, it completes.
	for _, p := range e.prod[1:] {
		if d := e.checkin(p); len(d) != 1 {
			t.Fatalf("straggler directive: %+v", d)
		}
		e.report(p, e.upgraded())
	}
	if ev := e.eval(); !ev.Completed {
		t.Fatalf("expected completion once every device reported")
	}
}
