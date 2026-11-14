package engine

import (
	"context"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/types"
)

// signedDirective builds a signed wipe directive for the given order using a test signer.
func signedDirective(t *testing.T, signer *crypto.WipeSigner, order types.WipeOrder) types.ActionDirective {
	t.Helper()
	b, err := order.MarshalCanonical()
	if err != nil {
		t.Fatalf("marshal order: %v", err)
	}
	return types.ActionDirective{
		Kind:           types.ActionWipe,
		SignedOrder:    b,
		OrderSignature: signer.Sign(b),
	}
}

// recordingRunner records every command invocation for assertions.
type recordingRunner struct{ calls [][]string }

func (rr *recordingRunner) run(_ context.Context, name string, args ...string) (string, error) {
	rr.calls = append(rr.calls, append([]string{name}, args...))
	return "", nil
}

func newTestSigner(t *testing.T) *crypto.WipeSigner {
	t.Helper()
	s, err := crypto.NewWipeSigner(t.TempDir() + "/wipe.pem")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return s
}

func baseOrder() types.WipeOrder {
	now := time.Now().UTC()
	return types.WipeOrder{
		Version: 1, RequestID: "req-1", DeviceID: "dev-1", HardwareUUID: "HW-1",
		Hostname: "host-1", VolumeUUIDs: []string{"vol-a", "vol-b"},
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

func escrowFunc(vols ...string) func() map[string]DiscoveredLUKSVolume {
	return func() map[string]DiscoveredLUKSVolume {
		m := map[string]DiscoveredLUKSVolume{}
		for _, v := range vols {
			m[v] = DiscoveredLUKSVolume{Name: v, VolumeUUID: v, DevicePath: "/dev/mapper/" + v}
		}
		return m
	}
}

func TestPerformWipe_ValidSignature_ErasesOnlyOwnEscrowed(t *testing.T) {
	signer := newTestSigner(t)
	rr := &recordingRunner{}
	poweredOff := false
	we := &WipeEngine{
		Runner:          rr.run,
		PowerOff:        func(context.Context) error { poweredOff = true; return nil },
		EscrowedVolumes: escrowFunc("vol-a"), // agent only escrowed vol-a, order names vol-a + vol-b
	}
	d := signedDirective(t, signer, baseOrder())

	res := we.PerformWipe(context.Background(), signer.PublicKeyBase64(), "HW-1", d)
	if res.Status != string(types.WipeCompleted) {
		t.Fatalf("expected COMPLETED, got %s (%s)", res.Status, res.Detail)
	}
	if res.ErasedSlots != 1 {
		t.Fatalf("expected 1 volume erased (only own-escrowed vol-a), got %d", res.ErasedSlots)
	}
	if !poweredOff {
		t.Fatalf("expected power-off after erase")
	}
	// Exactly one luksErase against vol-a's device path; never vol-b.
	var erasedPaths []string
	for _, c := range rr.calls {
		if len(c) >= 2 && c[1] == "luksErase" {
			erasedPaths = append(erasedPaths, c[len(c)-1])
		}
	}
	if len(erasedPaths) != 1 || erasedPaths[0] != "/dev/mapper/vol-a" {
		t.Fatalf("expected only /dev/mapper/vol-a erased, got %v", erasedPaths)
	}
}

func TestPerformWipe_InvalidSignature_Refused(t *testing.T) {
	signer := newTestSigner(t)
	d := signedDirective(t, signer, baseOrder())
	d.OrderSignature[0] ^= 0xFF // corrupt the signature

	we := &WipeEngine{Runner: (&recordingRunner{}).run, EscrowedVolumes: escrowFunc("vol-a")}
	res := we.PerformWipe(context.Background(), signer.PublicKeyBase64(), "HW-1", d)
	if res.Status != string(types.WipeFailed) {
		t.Fatalf("expected FAILED for bad signature, got %s", res.Status)
	}
	if res.ErasedSlots != 0 {
		t.Fatalf("no volume must be erased on bad signature")
	}
}

func TestPerformWipe_WrongKey_Refused(t *testing.T) {
	signer := newTestSigner(t)
	other := newTestSigner(t) // a different key than the one that signed
	d := signedDirective(t, signer, baseOrder())

	we := &WipeEngine{Runner: (&recordingRunner{}).run, EscrowedVolumes: escrowFunc("vol-a")}
	res := we.PerformWipe(context.Background(), other.PublicKeyBase64(), "HW-1", d)
	if res.Status != string(types.WipeFailed) {
		t.Fatalf("expected FAILED when verified against the wrong pinned key, got %s", res.Status)
	}
	if res.ErasedSlots != 0 {
		t.Fatalf("no volume must be erased when the key does not match")
	}
}

func TestPerformWipe_Expired_Refused(t *testing.T) {
	signer := newTestSigner(t)
	o := baseOrder()
	o.IssuedAt = time.Now().Add(-2 * time.Hour)
	o.ExpiresAt = time.Now().Add(-time.Hour) // already expired
	d := signedDirective(t, signer, o)

	we := &WipeEngine{Runner: (&recordingRunner{}).run, EscrowedVolumes: escrowFunc("vol-a")}
	res := we.PerformWipe(context.Background(), signer.PublicKeyBase64(), "HW-1", d)
	if res.Status != string(types.WipeFailed) {
		t.Fatalf("expected FAILED for expired order, got %s (%s)", res.Status, res.Detail)
	}
	if res.ErasedSlots != 0 {
		t.Fatalf("no volume must be erased for an expired order")
	}
}

func TestPerformWipe_HardwareUUIDMismatch_Refused(t *testing.T) {
	signer := newTestSigner(t)
	d := signedDirective(t, signer, baseOrder()) // order is for HW-1
	we := &WipeEngine{Runner: (&recordingRunner{}).run, EscrowedVolumes: escrowFunc("vol-a")}
	res := we.PerformWipe(context.Background(), signer.PublicKeyBase64(), "HW-OTHER", d)
	if res.Status != string(types.WipeFailed) || res.ErasedSlots != 0 {
		t.Fatalf("expected refusal on hardware UUID mismatch, got %s slots=%d", res.Status, res.ErasedSlots)
	}
}

func TestPerformWipe_DisableEnvGuard_Refused(t *testing.T) {
	t.Setenv(WipeDisableEnv, "1")
	signer := newTestSigner(t)
	d := signedDirective(t, signer, baseOrder())
	rr := &recordingRunner{}
	we := &WipeEngine{Runner: rr.run, EscrowedVolumes: escrowFunc("vol-a")}
	res := we.PerformWipe(context.Background(), signer.PublicKeyBase64(), "HW-1", d)
	if res.Status != string(types.WipeFailed) {
		t.Fatalf("expected FAILED when %s=1, got %s", WipeDisableEnv, res.Status)
	}
	if len(rr.calls) != 0 {
		t.Fatalf("no command may run when wipe is disabled, got %v", rr.calls)
	}
}

func TestPerformWipe_NoIntersection_NothingErased(t *testing.T) {
	signer := newTestSigner(t)
	d := signedDirective(t, signer, baseOrder()) // names vol-a, vol-b
	rr := &recordingRunner{}
	we := &WipeEngine{Runner: rr.run, EscrowedVolumes: escrowFunc("vol-zzz")} // agent escrowed none named
	res := we.PerformWipe(context.Background(), signer.PublicKeyBase64(), "HW-1", d)
	if res.Status != string(types.WipeFailed) || res.ErasedSlots != 0 || len(rr.calls) != 0 {
		t.Fatalf("expected nothing erased when no order volume is locally escrowed")
	}
}

func TestVerifyWipeOrder_Direct(t *testing.T) {
	signer := newTestSigner(t)
	order, _ := baseOrder().MarshalCanonical()
	sig := signer.Sign(order)
	if err := crypto.VerifyWipeOrder(signer.PublicKeyBase64(), order, sig); err != nil {
		t.Fatalf("valid signature should verify: %v", err)
	}
	if err := crypto.VerifyWipeOrder(signer.PublicKeyBase64(), append([]byte("x"), order...), sig); err == nil {
		t.Fatalf("tampered order must not verify")
	}
	if err := crypto.VerifyWipeOrder("not-base64!!", order, sig); err == nil {
		t.Fatalf("malformed key must error")
	}
}

// A validly signed order that omits its expiry or its device binding is refused: either
// omission would make the order replayable forever or on any device.
func TestPerformWipe_MissingExpiryOrDeviceBinding_Refused(t *testing.T) {
	signer := newTestSigner(t)
	cases := map[string]func(*types.WipeOrder){
		"no expiry":        func(o *types.WipeOrder) { o.ExpiresAt = time.Time{} },
		"no hardware uuid": func(o *types.WipeOrder) { o.HardwareUUID = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := baseOrder()
			mutate(&o)
			rr := &recordingRunner{}
			we := &WipeEngine{Runner: rr.run, EscrowedVolumes: escrowFunc("vol-a")}
			res := we.PerformWipe(context.Background(), signer.PublicKeyBase64(), "HW-1", signedDirective(t, signer, o))
			if res.Status != string(types.WipeFailed) || res.ErasedSlots != 0 || len(rr.calls) != 0 {
				t.Fatalf("expected refusal with no commands run, got %s slots=%d calls=%v (%s)", res.Status, res.ErasedSlots, rr.calls, res.Detail)
			}
		})
	}
}
