package db_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/webhooks"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

type whReceiver struct {
	srv    *httptest.Server
	secret string
	mu     sync.Mutex
	events []whReceived
	// failFirst makes the first N requests answer 500.
	failFirst int32
	// alwaysFail answers 500 to everything.
	alwaysFail bool
	seen       int32
}

type whReceived struct {
	EventID  string
	Env      webhooks.Envelope
	SigError error
	Raw      []byte
}

func newReceiver(t *testing.T) *whReceiver {
	rc := &whReceiver{}
	rc.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0, 4096)
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			body = append(body, buf[:n]...)
			if err != nil {
				break
			}
		}
		n := atomic.AddInt32(&rc.seen, 1)
		if rc.alwaysFail || n <= atomic.LoadInt32(&rc.failFirst) {
			http.Error(w, "boom", 500)
			return
		}
		rc.mu.Lock()
		rc.mu.Unlock()
		var env webhooks.Envelope
		_ = json.Unmarshal(body, &env)
		rc.mu.Lock()
		rc.events = append(rc.events, whReceived{
			EventID: r.Header.Get(webhooks.HeaderEventID), Env: env, Raw: body,
			SigError: webhooks.Verify(rc.secret, r.Header.Get(webhooks.HeaderSignature), body, time.Now(), 5*time.Minute),
		})
		rc.mu.Unlock()
		w.WriteHeader(200)
	}))
	t.Cleanup(rc.srv.Close)
	return rc
}

func (rc *whReceiver) byDevice(deviceID, typ string) []whReceived {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	var out []whReceived
	for _, e := range rc.events {
		if e.Env.Type == typ && e.Env.Device != nil && e.Env.Device.ID == deviceID {
			out = append(out, e)
		}
	}
	return out
}

func (rc *whReceiver) byType(typ string) []whReceived {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	var out []whReceived
	for _, e := range rc.events {
		if e.Env.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func whRepo(t *testing.T) (*db.Repository, context.Context) {
	pool := getTestPool(t)
	if pool == nil {
		t.SkipNow()
	}
	t.Cleanup(pool.Close)
	return db.NewRepositoryWithKEK(pool, filepath.Join(t.TempDir(), "kek.pem")), context.Background()
}

// subFor creates a subscription pointed at the receiver and wires the receiver's secret.
func subFor(t *testing.T, repo *db.Repository, ctx context.Context, rc *whReceiver, types_ []string, tagScope []string) *db.WebhookSubscription {
	t.Helper()
	sub, secret, err := repo.WebhookStore().CreateSubscription(ctx, db.WebhookInput{
		Name: "t-" + uniqueHW("sub"), URL: "https://hooks.example.com/spire", EventTypes: types_, TagScope: tagScope,
		Enabled: true, AllowPrivateNetwork: true, // http test receiver; loopback allowed only via the test sender
	}, "test")
	if err != nil {
		t.Fatalf("create subscription: %v", err)
	}
	rc.secret = secret
	// Save-time validation (correctly) refuses a loopback URL, so point the row at the local
	// test receiver directly; only the test sender may connect to it.
	if _, err := repo.Pool().Exec(ctx, `UPDATE webhook_subscriptions SET url=$2 WHERE id=$1`, sub.ID, rc.srv.URL); err != nil {
		t.Fatal(err)
	}
	sub.URL = rc.srv.URL
	t.Cleanup(func() { _ = repo.WebhookStore().DeleteSubscription(context.Background(), sub.ID) })
	return sub
}

func testWorker(repo *db.Repository, subIDs ...string) *webhooks.Worker {
	return webhooks.NewWorker(repo.WebhookStore().RestrictedTo(subIDs...), webhooks.NewSender(webhooks.UnsafeAllowLoopbackForTests()))
}

func drainWebhooks(w *webhooks.Worker) {
	for i := 0; i < 10; i++ {
		if w.DrainOnce(context.Background()) == 0 {
			return
		}
	}
}

func tagFor(prefix string) string {
	return prefix + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "")
}

// End to end: a real action (device approval) -> outbox -> worker -> receiver that verifies
// the signature. The secret was sealed in the DB and is not the stored value.
func TestWebhook_EndToEnd_ApproveDevice(t *testing.T) {
	repo, ctx := whRepo(t)
	rc := newReceiver(t)
	tag := tagFor("e2e")
	sub := subFor(t, repo, ctx, rc, []string{"device_approved"}, []string{tag})

	dev, _, err := repo.GetOrCreateDevice(ctx, uniqueHW("whe2e"), "e2e-host")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpdateDeviceTags(ctx, dev.ID, []string{tag}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.ApproveDevice(ctx, dev.ID); err != nil {
		t.Fatal(err)
	}
	drainWebhooks(testWorker(repo, sub.ID))

	got := rc.byDevice(dev.ID, "device_approved")
	if len(got) != 1 {
		t.Fatalf("want exactly 1 delivery, got %d", len(got))
	}
	e := got[0]
	if e.SigError != nil {
		t.Fatalf("signature did not verify: %v", e.SigError)
	}
	if e.Env.SpecVer != "spire.v1" || e.Env.ID == "" || e.Env.ID != e.EventID || e.Env.OccurredAt == "" {
		t.Errorf("bad envelope: %+v", e.Env)
	}
	if e.Env.Device == nil || e.Env.Device.Hostname != "e2e-host" || e.Env.Data["hostname"] != "e2e-host" {
		t.Errorf("bad device/data: %+v", e.Env)
	}
	if strings.Contains(string(e.Raw), rc.secret) {
		t.Error("body must not contain the secret")
	}
	rows, _ := repo.WebhookStore().ListDeliveries(ctx, sub.ID, 10)
	if len(rows) != 1 || rows[0].Status != "DELIVERED" {
		t.Fatalf("delivery row: %+v", rows)
	}
	atts, _ := repo.WebhookStore().ListAttempts(ctx, rows[0].ID)
	if len(atts) != 1 || atts[0].StatusCode == nil || *atts[0].StatusCode != 200 {
		t.Errorf("attempt log: %+v", atts)
	}
}

// Two workers (two servers) draining the same outbox send each delivery exactly once.
func TestWebhook_TwoWorkers_EachDeliverySentOnce(t *testing.T) {
	repo, ctx := whRepo(t)
	rc := newReceiver(t)
	tag := tagFor("two")
	sub := subFor(t, repo, ctx, rc, []string{"agent_started"}, []string{tag})
	const n = 40
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		d, _, err := repo.GetOrCreateDevice(ctx, uniqueHW("whtwo")+string(rune('a'+i%26))+string(rune('a'+i/26)), "two-host")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = repo.UpdateDeviceTags(ctx, d.ID, []string{tag})
		repo.EmitEvent(ctx, workflows.EventAgentStarted, d.ID, map[string]any{"agent_version": "1"}, false)
		ids = append(ids, d.ID)
	}
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wk := testWorker(repo, sub.ID)
			wk.Batch = 5
			drainWebhooks(wk)
		}()
	}
	wg.Wait()
	for _, id := range ids {
		if c := len(rc.byDevice(id, "agent_started")); c != 1 {
			t.Fatalf("device %s received %d deliveries, want exactly 1", id, c)
		}
	}
	rows, _ := repo.WebhookStore().ListDeliveries(ctx, sub.ID, 100)
	if len(rows) != n {
		t.Fatalf("outbox rows = %d, want %d (one per event)", len(rows), n)
	}
	for _, r := range rows {
		if r.Attempts != 1 || r.Status != "DELIVERED" {
			t.Fatalf("row %s attempts=%d status=%s", r.ID, r.Attempts, r.Status)
		}
	}
}

// An event emitted once creates one delivery per matching subscription, and re-emitting the
// same event id cannot create a second row (unique index).
func TestWebhook_FanOutOncePerSubscription(t *testing.T) {
	repo, ctx := whRepo(t)
	rc := newReceiver(t)
	tag := tagFor("fan")
	s1 := subFor(t, repo, ctx, rc, []string{"device_approved"}, []string{tag})
	s2 := subFor(t, repo, ctx, rc, []string{"device_approved", "agent_started"}, []string{tag})
	s3 := subFor(t, repo, ctx, rc, []string{"agent_started"}, []string{tag}) // different type
	dev := mkApprovedDevice(t, repo, ctx, []string{tag})
	for _, s := range []*db.WebhookSubscription{s1, s2, s3} {
		_ = s
	}
	// mkApprovedDevice approved before tagging, so emit explicitly with the tag in place.
	repo.EmitEvent(ctx, workflows.EventDeviceApproved, dev.ID, map[string]any{"hostname": "x"}, false)
	count := func(id string) int {
		rows, _ := repo.WebhookStore().ListDeliveries(ctx, id, 50)
		n := 0
		for _, r := range rows {
			if r.EventType == "device_approved" {
				n++
			}
		}
		return n
	}
	if count(s1.ID) != 1 || count(s2.ID) != 1 || count(s3.ID) != 0 {
		t.Fatalf("fan-out counts s1=%d s2=%d s3=%d, want 1/1/0", count(s1.ID), count(s2.ID), count(s3.ID))
	}
}

func TestWebhook_RetryThenSuccess(t *testing.T) {
	repo, ctx := whRepo(t)
	rc := newReceiver(t)
	rc.failFirst = 2
	tag := tagFor("retry")
	sub := subFor(t, repo, ctx, rc, []string{"agent_started"}, []string{tag})
	dev := mkApprovedDevice(t, repo, ctx, []string{tag})
	repo.EmitEvent(ctx, workflows.EventAgentStarted, dev.ID, nil, false)
	wk := testWorker(repo, sub.ID)

	makeDue := func() {
		_, err := repo.Pool().Exec(ctx, `UPDATE webhook_deliveries SET next_attempt_at=NOW() WHERE subscription_id=$1 AND status='PENDING'`, sub.ID)
		if err != nil {
			t.Fatal(err)
		}
	}
	wk.DrainOnce(ctx)
	rows, _ := repo.WebhookStore().ListDeliveries(ctx, sub.ID, 5)
	if rows[0].Status != "PENDING" || rows[0].Attempts != 1 || rows[0].NextAttemptAt.Before(time.Now().Add(15*time.Second)) {
		t.Fatalf("after first failure want PENDING w/ future retry, got %+v", rows[0])
	}
	// Not due yet: a drain must not resend.
	if wk.DrainOnce(ctx) != 0 {
		t.Fatal("delivery sent before its backoff elapsed")
	}
	makeDue()
	wk.DrainOnce(ctx)
	makeDue()
	wk.DrainOnce(ctx)
	rows, _ = repo.WebhookStore().ListDeliveries(ctx, sub.ID, 5)
	if rows[0].Status != "DELIVERED" || rows[0].Attempts != 3 {
		t.Fatalf("want DELIVERED after 3 attempts, got %+v", rows[0])
	}
	atts, _ := repo.WebhookStore().ListAttempts(ctx, rows[0].ID)
	if len(atts) != 3 || *atts[0].StatusCode != 500 || *atts[2].StatusCode != 200 || atts[0].ResponseSnippet == "" {
		t.Fatalf("attempt log wrong: %+v", atts)
	}
	if len(rc.byDevice(dev.ID, "agent_started")) != 1 {
		t.Fatal("receiver should have accepted exactly once")
	}
}

func TestWebhook_DeadAfterMaxAttempts_AndAutoDisable(t *testing.T) {
	repo, ctx := whRepo(t)
	rc := newReceiver(t)
	rc.alwaysFail = true
	tag := tagFor("dead")
	sub := subFor(t, repo, ctx, rc, []string{"agent_started"}, []string{tag})
	dev := mkApprovedDevice(t, repo, ctx, []string{tag})
	repo.EmitEvent(ctx, workflows.EventAgentStarted, dev.ID, nil, false)

	// Fast-forward: the row is on its last allowed attempt, and the subscription is one
	// dead delivery away from the auto-disable threshold.
	if _, err := repo.Pool().Exec(ctx, `UPDATE webhook_deliveries SET attempts=$2 WHERE subscription_id=$1`, sub.ID, webhooks.MaxAttempts-1); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Pool().Exec(ctx, `UPDATE webhook_subscriptions SET consecutive_dead=$2 WHERE id=$1`, sub.ID, webhooks.AutoDisableAfterDead-1); err != nil {
		t.Fatal(err)
	}
	var disabledName string
	wk := testWorker(repo, sub.ID)
	wk.OnAutoDisable = func(_ context.Context, name, _ string) { disabledName = name }
	wk.DrainOnce(ctx)

	rows, _ := repo.WebhookStore().ListDeliveries(ctx, sub.ID, 5)
	if rows[0].Status != "DEAD" || rows[0].FinishedAt == nil {
		t.Fatalf("want DEAD after max attempts, got %+v", rows[0])
	}
	got, _ := repo.WebhookStore().GetSubscription(ctx, sub.ID)
	if got.Enabled || got.DisabledReason == "" || disabledName != sub.Name {
		t.Fatalf("subscription must be auto-disabled and the hook called: %+v hook=%q", got, disabledName)
	}
	// Disabled subscriptions get no new deliveries.
	repo.EmitEvent(ctx, workflows.EventAgentStarted, dev.ID, nil, false)
	rows, _ = repo.WebhookStore().ListDeliveries(ctx, sub.ID, 5)
	if len(rows) != 1 {
		t.Fatalf("disabled subscription received a new delivery: %d rows", len(rows))
	}
	// Re-enabling clears the streak.
	in := db.WebhookInput{Name: sub.Name, URL: "https://hooks.example.com/spire", EventTypes: sub.EventTypes, TagScope: sub.TagScope, Enabled: true, AllowPrivateNetwork: true}
	if err := repo.WebhookStore().UpdateSubscription(ctx, sub.ID, in); err != nil {
		t.Fatal(err)
	}
	got, _ = repo.WebhookStore().GetSubscription(ctx, sub.ID)
	if !got.Enabled || got.ConsecutiveDead != 0 || got.DisabledReason != "" {
		t.Fatalf("re-enable should reset the streak: %+v", got)
	}
}

func TestWebhook_BackoffDeadlineMakesDeadEarly(t *testing.T) {
	repo, ctx := whRepo(t)
	rc := newReceiver(t)
	rc.alwaysFail = true
	tag := tagFor("age")
	sub := subFor(t, repo, ctx, rc, []string{"agent_started"}, []string{tag})
	dev := mkApprovedDevice(t, repo, ctx, []string{tag})
	repo.EmitEvent(ctx, workflows.EventAgentStarted, dev.ID, nil, false)
	// Created 23h59m ago: the next backoff would pass the 24h window.
	_, _ = repo.Pool().Exec(ctx, `UPDATE webhook_deliveries SET created_at = NOW() - interval '23 hours 59 minutes 50 seconds' WHERE subscription_id=$1`, sub.ID)
	testWorker(repo, sub.ID).DrainOnce(ctx)
	rows, _ := repo.WebhookStore().ListDeliveries(ctx, sub.ID, 5)
	if rows[0].Status != "DEAD" {
		t.Fatalf("a delivery past the 24h window must go DEAD, got %s", rows[0].Status)
	}
}

func TestWebhook_TagScope(t *testing.T) {
	repo, ctx := whRepo(t)
	rc := newReceiver(t)
	inTag, outTag := tagFor("in"), tagFor("out")
	scoped := subFor(t, repo, ctx, rc, []string{"agent_started", "policy_created"}, []string{inTag})
	inDev := mkApprovedDevice(t, repo, ctx, []string{inTag})
	outDev := mkApprovedDevice(t, repo, ctx, []string{outTag})
	noTagDev := mkApprovedDevice(t, repo, ctx, nil)
	for _, d := range []*types.Device{inDev, outDev, noTagDev} {
		repo.EmitEvent(ctx, workflows.EventAgentStarted, d.ID, nil, false)
	}
	// Device-less event: a scoped subscription must NOT receive it.
	repo.EmitEvent(ctx, workflows.EventPolicyCreated, "", map[string]any{"policy_id": "p", "name": "pol-" + inTag}, false)

	rows, _ := repo.WebhookStore().ListDeliveries(ctx, scoped.ID, 50)
	if len(rows) != 1 || rows[0].EventType != "agent_started" {
		t.Fatalf("scoped subscription should hold exactly the in-scope device event, got %d rows: %+v", len(rows), rows)
	}
	wk := testWorker(repo, scoped.ID)
	drainWebhooks(wk)
	if len(rc.byDevice(inDev.ID, "agent_started")) != 1 {
		t.Error("in-scope device event not delivered")
	}
	if len(rc.byDevice(outDev.ID, "agent_started"))+len(rc.byDevice(noTagDev.ID, "agent_started")) != 0 {
		t.Error("out-of-scope device events leaked to a tag-scoped subscription")
	}

	// An unscoped subscription does receive device-less events.
	rc2 := newReceiver(t)
	open := subFor(t, repo, ctx, rc2, []string{"policy_created"}, nil)
	repo.EmitEvent(ctx, workflows.EventPolicyCreated, "", map[string]any{"policy_id": "p2", "name": "pol2-" + inTag}, false)
	drainWebhooks(testWorker(repo, open.ID))
	if got := rc2.byType("policy_created"); len(got) != 1 || got[0].Env.Device != nil {
		t.Fatalf("unscoped subscription should get the device-less event with device=null, got %+v", got)
	}
}

func TestWebhook_SecretSealedAndNeverReadable(t *testing.T) {
	repo, ctx := whRepo(t)
	rc := newReceiver(t)
	sub := subFor(t, repo, ctx, rc, []string{"agent_started"}, nil)
	secret := rc.secret
	if !strings.HasPrefix(secret, "whsec_") || len(secret) < 40 {
		t.Fatalf("weak secret %q", secret)
	}
	var enc []byte
	if err := repo.Pool().QueryRow(ctx, `SELECT secret_enc FROM webhook_subscriptions WHERE id=$1`, sub.ID).Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if len(enc) == 0 || strings.Contains(string(enc), secret) {
		t.Fatal("secret must be stored sealed, not in plaintext")
	}
	// No read API returns it.
	list, _ := repo.WebhookStore().ListSubscriptions(ctx)
	b, _ := json.Marshal(list)
	if strings.Contains(string(b), secret) {
		t.Fatal("ListSubscriptions leaked the secret")
	}
	// Rotation changes it, and the old secret stops verifying.
	newSecret, err := repo.WebhookStore().RotateSecret(ctx, sub.ID)
	if err != nil || newSecret == secret {
		t.Fatalf("rotate: %v same=%v", err, newSecret == secret)
	}
	rc.secret = newSecret
	tag := tagFor("rot")
	_ = tag
	dev := mkApprovedDevice(t, repo, ctx, nil)
	repo.EmitEvent(ctx, workflows.EventAgentStarted, dev.ID, nil, false)
	drainWebhooks(testWorker(repo, sub.ID))
	got := rc.byDevice(dev.ID, "agent_started")
	if len(got) != 1 || got[0].SigError != nil {
		t.Fatalf("delivery after rotation must verify with the NEW secret: %+v", got)
	}
	if err := webhooks.Verify(secret, "t=1,v1=00", got[0].Raw, time.Now(), time.Hour); err == nil {
		t.Error("old secret must not verify")
	}
}

// New event kinds: emitted by the real producers, delivered to webhooks, and never written to
// the workflow event queue (so the engine cannot be triggered by them).
func TestWebhook_NewEventKinds_FromProducers(t *testing.T) {
	repo, ctx := whRepo(t)
	rc := newReceiver(t)
	all := []string{"policy_created", "policy_toggled", "campaign_started", "campaign_stage_promoted",
		"campaign_halted", "campaign_completed", "campaign_cancelled", "device_revoked", "device_marked_lost", "device_wiped"}
	sub := subFor(t, repo, ctx, rc, all, nil)
	sfx := tagFor("nk")

	// Policy create + toggle.
	pol, err := repo.CreatePolicy(ctx, "wh-pol-"+sfx, "d", types.PolicyTypePackagePresence, json.RawMessage(`{"package_name":"curl"}`), nil)
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	if _, err := repo.TogglePolicyActive(ctx, pol.ID); err != nil {
		t.Fatal(err)
	}
	// Campaign lifecycle through the one recorder every producer uses.
	c := mkCampaign(t, repo, ctx, "wh-camp-"+sfx, nil, nil)
	for _, k := range []string{"start", "pause", "promoted", "halted", "completed", "cancel"} {
		if err := repo.RecordCampaignEvent(ctx, c.ID, k, "tester", "detail-"+k, 1); err != nil {
			t.Fatal(err)
		}
	}
	// Device lifecycle.
	dev := mkApprovedDevice(t, repo, ctx, nil)
	if _, err := repo.SetDeviceLost(ctx, dev.ID, "admin1", "lock me", true); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.RevokeDevice(ctx, dev.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Pool().Exec(ctx, `
		INSERT INTO device_wipe_requests (device_id, status, confirm_hostname, reason, requested_by, approval_deadline)
		VALUES ($1,'DELIVERED','h','r','a',NOW()+interval '1 hour')`, dev.ID); err != nil {
		t.Skipf("cannot seed wipe request: %v", err)
	}
	var reqID string
	_ = repo.Pool().QueryRow(ctx, `SELECT id::text FROM device_wipe_requests WHERE device_id=$1`, dev.ID).Scan(&reqID)
	if err := repo.CompleteWipeRequest(ctx, reqID, "COMPLETED", "ok"); err != nil {
		t.Fatal(err)
	}

	drainWebhooks(testWorker(repo, sub.ID))
	want := map[string]int{"policy_created": 1, "policy_toggled": 1, "campaign_started": 1, "campaign_stage_promoted": 1,
		"campaign_halted": 1, "campaign_completed": 1, "campaign_cancelled": 1}
	for typ, n := range want {
		matches := 0
		for _, e := range rc.byType(typ) {
			if strings.Contains(string(e.Raw), sfx) {
				matches++
			}
		}
		if matches != n {
			t.Errorf("%s: got %d, want %d", typ, matches, n)
		}
	}
	for _, typ := range []string{"device_marked_lost", "device_revoked", "device_wiped"} {
		if len(rc.byDevice(dev.ID, typ)) != 1 {
			t.Errorf("%s not delivered exactly once for the device", typ)
		}
	}
	if len(rc.byType("campaign_paused")) != 0 {
		t.Error("pause is not a webhook event")
	}
	for _, e := range rc.byType("device_revoked") {
		if e.SigError != nil {
			t.Errorf("signature: %v", e.SigError)
		}
	}

	// None of the webhook-only kinds may sit in the workflow queue.
	var n int
	_ = repo.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM workflow_events WHERE device_id=$1 AND kind = ANY($2)`,
		dev.ID, []string{"device_revoked", "device_marked_lost", "device_wiped"}).Scan(&n)
	if n != 0 {
		t.Fatalf("webhook-only kinds leaked into workflow_events: %d rows", n)
	}
	_ = repo.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM workflow_events WHERE kind LIKE 'policy\_%' OR kind LIKE 'campaign\_%'`).Scan(&n)
	if n != 0 {
		t.Fatalf("policy/campaign kinds leaked into workflow_events: %d rows", n)
	}
}

// A workflow cannot be configured to trigger on a webhook-only kind.
func TestWebhook_OnlyKinds_AreNotWorkflowTriggers(t *testing.T) {
	for _, k := range workflows.WebhookOnlyKinds {
		if k.Valid() {
			t.Errorf("%s must not be a valid workflow trigger", k)
		}
		if !k.WebhookKind() {
			t.Errorf("%s must be a webhook kind", k)
		}
		if !webhooks.KnownType(string(k)) {
			t.Errorf("%s missing from the webhook catalog", k)
		}
	}
	for _, k := range workflows.AllEventKinds {
		if !webhooks.KnownType(string(k)) {
			t.Logf("note: workflow kind %s is not in the webhook catalog", k)
		}
	}
	w := &workflows.Workflow{Name: "x", Enabled: true, Trigger: &workflows.Trigger{Kind: workflows.EventPolicyToggled},
		ThenActions: []workflows.Action{{Type: workflows.ActionAddTag, Tag: "t"}}}
	if err := workflows.ValidateDefinition(w, nil, func(workflows.ActionType) bool { return true }); err == nil {
		t.Fatal("validation must reject a trigger on a webhook-only kind")
	}
}

func TestWebhook_RedeliverAndReaper(t *testing.T) {
	repo, ctx := whRepo(t)
	rc := newReceiver(t)
	tag := tagFor("red")
	sub := subFor(t, repo, ctx, rc, []string{"agent_started"}, []string{tag})
	dev := mkApprovedDevice(t, repo, ctx, []string{tag})
	repo.EmitEvent(ctx, workflows.EventAgentStarted, dev.ID, nil, false)
	wk := testWorker(repo, sub.ID)
	drainWebhooks(wk)
	rows, _ := repo.WebhookStore().ListDeliveries(ctx, sub.ID, 5)
	newID, err := repo.WebhookStore().Redeliver(ctx, rows[0].ID)
	if err != nil || newID == "" {
		t.Fatalf("redeliver: %v", err)
	}
	drainWebhooks(wk)
	got := rc.byDevice(dev.ID, "agent_started")
	if len(got) != 2 || got[0].EventID != got[1].EventID {
		t.Fatalf("redelivery must resend the same event id: %+v", got)
	}
	// Reaper deletes old finished rows (and their attempts) but keeps recent ones.
	_, _ = repo.Pool().Exec(ctx, `UPDATE webhook_deliveries SET finished_at = NOW() - interval '40 days' WHERE id=$1`, rows[0].ID)
	if _, err := repo.WebhookStore().Reap(ctx, webhooks.RetainFinished); err != nil {
		t.Fatal(err)
	}
	var left int
	_ = repo.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM webhook_deliveries WHERE subscription_id=$1`, sub.ID).Scan(&left)
	var attLeft int
	_ = repo.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM webhook_delivery_attempts WHERE delivery_id=$1`, rows[0].ID).Scan(&attLeft)
	if left != 1 || attLeft != 0 {
		t.Fatalf("reaper: deliveries left=%d (want 1), attempts of reaped=%d (want 0)", left, attLeft)
	}
}

func TestWebhook_InputValidation(t *testing.T) {
	repo, ctx := whRepo(t)
	st := repo.WebhookStore()
	bad := []db.WebhookInput{
		{Name: "a", URL: "http://example.com/x", EventTypes: []string{"device_approved"}},                                 // http without flag
		{Name: "a", URL: "https://127.0.0.1/x", EventTypes: []string{"device_approved"}, AllowPrivateNetwork: true},       // loopback
		{Name: "a", URL: "https://169.254.169.254/x", EventTypes: []string{"device_approved"}, AllowPrivateNetwork: true}, // metadata
		{Name: "a", URL: "https://example.com/x", EventTypes: nil},                                                        // no events
		{Name: "a", URL: "https://example.com/x", EventTypes: []string{"nope"}},                                           // unknown event
		{Name: "", URL: "https://example.com/x", EventTypes: []string{"device_approved"}},
	}
	for i, in := range bad {
		if _, _, err := st.CreateSubscription(ctx, in, "t"); err == nil {
			t.Errorf("case %d should be rejected: %+v", i, in)
		}
	}
}
