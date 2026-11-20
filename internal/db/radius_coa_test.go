package db_test

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/radius"
	"github.com/spire-uem/spire-uem/internal/types"
)

type coaNAS struct {
	addr string
	port int
	mu   sync.Mutex
	got  []*radius.Packet
	mode string // ack | nak | silent
}

func (n *coaNAS) count() int { n.mu.Lock(); defer n.mu.Unlock(); return len(n.got) }

// startCoANAS listens on a unique 127.0.0.N address so concurrently running tests cannot
// collide on the unique NAS address column.
func startCoANAS(t *testing.T, secret, mode string) *coaNAS {
	t.Helper()
	for try := 0; try < 50; try++ {
		host := fmt.Sprintf("127.%d.%d.%d", 20+rand.Intn(200), rand.Intn(250), 1+rand.Intn(250))
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host)})
		if err != nil {
			continue
		}
		n := &coaNAS{addr: host, port: c.LocalAddr().(*net.UDPAddr).Port, mode: mode}
		t.Cleanup(func() { c.Close() })
		go func() {
			buf := make([]byte, 4096)
			for {
				l, from, err := c.ReadFromUDP(buf)
				if err != nil {
					return
				}
				if radius.VerifyRequest(buf[:l], []byte(secret)) != nil {
					continue
				}
				p, _ := radius.Decode(buf[:l])
				n.mu.Lock()
				n.got = append(n.got, p)
				n.mu.Unlock()
				switch n.mode {
				case "ack":
					out, _ := radius.EncodeResponse(radius.CodeDisconnectACK, p.ID, p.Authenticator, []byte(secret), nil)
					_, _ = c.WriteToUDP(out, from)
				case "nak":
					out, _ := radius.EncodeResponse(radius.CodeDisconnectNAK, p.ID, p.Authenticator, []byte(secret),
						[]radius.Attr{radius.Uint32Attr(radius.AttrErrorCause, 404)})
					_, _ = c.WriteToUDP(out, from)
				}
			}
		}()
		return n
	}
	t.Fatal("no free loopback address")
	return nil
}

type coaFixture struct {
	t      *testing.T
	repo   *db.Repository
	store  *db.RadiusStore
	ctx    context.Context
	dev    *types.Device
	nas    *coaNAS
	nasID  string
	secret string
}

func newCoAFixture(t *testing.T, mode string) *coaFixture {
	pool := getTestPool(t)
	if pool == nil {
		t.SkipNow()
	}
	t.Cleanup(pool.Close)
	ctx := context.Background()
	repo := db.NewRepositoryWithKEK(pool, filepath.Join(t.TempDir(), "kek.pem"))
	f := &coaFixture{t: t, repo: repo, store: repo.RadiusStore(), ctx: ctx, secret: "coa-shared-secret"}
	f.nas = startCoANAS(t, f.secret, mode)
	n, _, _, err := f.store.CreateNAS(ctx, db.RadiusNASInput{Name: fmt.Sprintf("coa-%d", time.Now().UnixNano()),
		Address: "10.1.1.1", CoAPort: f.nas.port, Enabled: true, Secret: f.secret}, "test")
	if err != nil {
		t.Fatal(err)
	}
	f.nasID = n.ID
	// Point the stored NAS at the loopback listener (the API refuses loopback by design).
	if _, err := pool.Exec(ctx, `UPDATE radius_nas_clients SET address=$2 WHERE id=$1`, n.ID, f.nas.addr); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM radius_nas_clients WHERE id=$1`, n.ID) })

	hw := fmt.Sprintf("coa-%d", time.Now().UnixNano())
	f.dev, _, err = repo.GetOrCreateDevice(ctx, hw, hw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.ApproveDevice(ctx, f.dev.ID); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *coaFixture) posture(st types.PostureState) {
	f.t.Helper()
	now := time.Now().UTC()
	if _, err := f.repo.UpsertDevicePosture(f.ctx, &types.DevicePosture{DeviceID: f.dev.ID, State: st, EvaluatedAt: now, ValidUntil: now.Add(time.Hour)}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *coaFixture) session(granted types.PostureState) {
	f.t.Helper()
	ok, err := f.store.RecordSession(f.ctx, db.RadiusSession{DeviceID: f.dev.ID, NASAddress: f.nas.addr, NASIdentifier: "sw1",
		CallingStationID: "aa:bb:cc:00:11:22", UserName: "aabbcc001122", GrantedState: granted}, radius.SessionTTL)
	if err != nil || !ok {
		f.t.Fatalf("record session: ok=%v err=%v", ok, err)
	}
}

func (f *coaFixture) loop() *radius.Loop {
	l := radius.NewLoop(f.store, radius.NewSender(radius.UnsafeAllowLoopbackForTests(), radius.WithTiming(300*time.Millisecond, 2)))
	return l
}

func (f *coaFixture) deliveries() []db.RadiusDelivery {
	d, err := f.store.ListDeliveries(f.ctx, 200, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	var mine []db.RadiusDelivery
	for _, x := range d {
		if x.DeviceID == f.dev.ID {
			mine = append(mine, x)
		}
	}
	return mine
}

func TestRadiusCoA_PostureChangeSendsSignedDisconnect(t *testing.T) {
	f := newCoAFixture(t, "ack")
	f.posture(types.PostureCompliant)
	f.session(types.PostureCompliant)
	l := f.loop()
	l.RunOnce(f.ctx) // same state as admitted: nothing to do
	if f.nas.count() != 0 {
		t.Fatal("a session still in its admitted state must not be disconnected")
	}
	f.posture(types.PostureNoncompliant)
	l.RunOnce(f.ctx)
	if f.nas.count() != 1 {
		t.Fatalf("want exactly 1 Disconnect-Request, NAS saw %d", f.nas.count())
	}
	p := f.nas.got[0]
	if p.Code != radius.CodeDisconnectRequest {
		t.Fatalf("code %d", p.Code)
	}
	for attr, want := range map[byte]string{radius.AttrUserName: "aabbcc001122", radius.AttrCallingStationID: "aa:bb:cc:00:11:22", radius.AttrNASIdentifier: "sw1"} {
		if v, _ := p.Get(attr); string(v) != want {
			t.Errorf("attr %d = %q, want %q", attr, v, want)
		}
	}
	if v, _ := p.Get(radius.AttrNASIPAddress); net.IP(v).String() != f.nas.addr {
		t.Errorf("NAS-IP-Address = %v", net.IP(v))
	}
	d := f.deliveries()
	if len(d) != 1 || d[0].Status != "ACKED" || d[0].PostureState != "NONCOMPLIANT" {
		t.Fatalf("delivery log: %+v", d)
	}
	// Re-running (and re-scanning the lookback window) must not send again.
	l.RunOnce(f.ctx)
	l.RunOnce(f.ctx)
	if f.nas.count() != 1 {
		t.Fatalf("duplicate disconnect: NAS saw %d", f.nas.count())
	}
	// A device that reconnects compliant and then degrades again gets a new disconnect.
	f.session(types.PostureCompliant)
	time.Sleep(20 * time.Millisecond)
	f.posture(types.PostureCompliant)
	l.RunOnce(f.ctx)
	time.Sleep(20 * time.Millisecond)
	f.posture(types.PostureQuarantined)
	l.RunOnce(f.ctx)
	if f.nas.count() != 2 {
		t.Fatalf("second state change: NAS saw %d, want 2", f.nas.count())
	}
}

func TestRadiusCoA_TwoServersSendOnce(t *testing.T) {
	f := newCoAFixture(t, "ack")
	f.posture(types.PostureCompliant)
	f.session(types.PostureCompliant)
	f.posture(types.PostureQuarantined)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ { // four "servers" racing on the same database
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.loop().RunOnce(f.ctx)
		}()
	}
	wg.Wait()
	f.loop().RunOnce(f.ctx)
	if f.nas.count() != 1 {
		t.Fatalf("4 concurrent loops sent %d Disconnect-Requests, want exactly 1", f.nas.count())
	}
	if d := f.deliveries(); len(d) != 1 {
		t.Fatalf("want 1 delivery row, got %+v", d)
	}
}

func TestRadiusCoA_NAKAndUnreachableAndNoNAS(t *testing.T) {
	// NAK: recorded, not retried.
	f := newCoAFixture(t, "nak")
	f.posture(types.PostureCompliant)
	f.session(types.PostureCompliant)
	f.posture(types.PostureNoncompliant)
	f.loop().RunOnce(f.ctx)
	if d := f.deliveries(); len(d) != 1 || d[0].Status != "NAKED" || d[0].ErrorCause != 404 {
		t.Fatalf("NAK: %+v", d)
	}
	if f.nas.count() != 1 {
		t.Fatalf("a NAK must not be retried, NAS saw %d", f.nas.count())
	}

	// Silent NAS: bounded retries inside the claim, then a later claim, then FAILED.
	g := newCoAFixture(t, "silent")
	g.posture(types.PostureCompliant)
	g.session(types.PostureCompliant)
	g.posture(types.PostureNoncompliant)
	g.loop().RunOnce(g.ctx)
	d := g.deliveries()
	if len(d) != 1 || d[0].Status != "PENDING" || d[0].Attempts != 1 {
		t.Fatalf("after first failure the delivery must wait for a retry: %+v", d)
	}
	if g.nas.count() != 2 {
		t.Fatalf("one claim sends at most 2 packets here, NAS saw %d", g.nas.count())
	}

	// NAS client disabled after the session was recorded: no packet, delivery FAILED.
	h := newCoAFixture(t, "ack")
	h.posture(types.PostureCompliant)
	h.session(types.PostureCompliant)
	if _, err := h.store.UpdateNAS(h.ctx, h.nasID, db.RadiusNASInput{Name: fmt.Sprintf("dis-%d", time.Now().UnixNano()), Address: "10.1.1.2", CoAPort: h.nas.port, Enabled: false}); err != nil {
		t.Fatal(err)
	}
	h.posture(types.PostureQuarantined)
	h.loop().RunOnce(h.ctx)
	if h.nas.count() != 0 {
		t.Fatal("no Disconnect may be sent to a disabled NAS client")
	}
	if d := h.deliveries(); len(d) != 1 || d[0].Status != "FAILED" {
		t.Fatalf("disabled NAS: %+v", d)
	}
}

func TestRadiusCoA_ExpiredSessionsAreNotDisconnected(t *testing.T) {
	f := newCoAFixture(t, "ack")
	f.posture(types.PostureCompliant)
	f.session(types.PostureCompliant)
	if _, err := f.repo.RadiusStore().CountSessions(f.ctx, f.dev.ID); err != nil {
		t.Fatal(err)
	}
	pool := getTestPool(t)
	defer pool.Close()
	if _, err := pool.Exec(f.ctx, `UPDATE radius_sessions SET expires_at = NOW() - interval '1 minute' WHERE device_id=$1`, f.dev.ID); err != nil {
		t.Fatal(err)
	}
	f.posture(types.PostureNoncompliant)
	f.loop().RunOnce(f.ctx)
	if f.nas.count() != 0 {
		t.Fatal("an expired session must not be disconnected")
	}
}

// One unreadable posture row elsewhere must not stall disconnects for everyone else.
func TestRadiusCoA_PoisonPostureRowDoesNotBlockOthers(t *testing.T) {
	poison := newCoAFixture(t, "ack")
	poison.posture(types.PostureCompliant)
	pool := getTestPool(t)
	defer pool.Close()
	if _, err := pool.Exec(poison.ctx, `UPDATE device_posture SET reasons='"corrupt"'::jsonb WHERE device_id=$1`, poison.dev.ID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `UPDATE device_posture SET reasons='[]'::jsonb WHERE device_id=$1`, poison.dev.ID)
	})
	f := newCoAFixture(t, "ack")
	f.posture(types.PostureCompliant)
	f.session(types.PostureCompliant)
	f.posture(types.PostureNoncompliant)
	f.loop().RunOnce(f.ctx)
	if f.nas.count() != 1 {
		t.Fatalf("a corrupt row for another device blocked the loop: NAS saw %d", f.nas.count())
	}
}
