package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

func TestApplyAndRevertLost_InjectedRoot(t *testing.T) {
	root := t.TempDir()
	rr := &recordingRunner{}
	// Stub the active-session lookup so no real loginctl is consulted.
	orig := getActiveSessionDetails
	getActiveSessionDetails = func() (string, string, error) { return "alice", "1000", nil }
	defer func() { getActiveSessionDetails = orig }()

	e := &DeviceActionEngine{
		Root:     root,
		Runner:   rr.run,
		LookPath: func(string) (string, error) { return "/usr/bin/x", nil }, // pretend all tools exist
	}

	detail, err := e.ApplyLost(context.Background(), "Reported lost")
	if err != nil {
		t.Fatalf("ApplyLost error: %v (%s)", err, detail)
	}
	nologin := filepath.Join(root, "etc", "nologin")
	if b, rerr := os.ReadFile(nologin); rerr != nil {
		t.Fatalf("expected /etc/nologin written under root: %v", rerr)
	} else if string(b) == "" {
		t.Fatalf("/etc/nologin should carry the lock message")
	}
	if _, serr := os.Stat(filepath.Join(root, "etc", "spire", "lost-mode")); serr != nil {
		t.Fatalf("expected lost-mode marker written")
	}
	// loginctl lock-sessions and terminate-user must have been attempted.
	var sawLock, sawTerminate bool
	for _, c := range rr.calls {
		if len(c) >= 2 && c[0] == "loginctl" && c[1] == "lock-sessions" {
			sawLock = true
		}
		if len(c) >= 2 && c[0] == "loginctl" && c[1] == "terminate-user" {
			sawTerminate = true
		}
	}
	if !sawLock || !sawTerminate {
		t.Fatalf("expected loginctl lock-sessions + terminate-user, calls=%v", rr.calls)
	}

	// Revert removes the nologin file and marker.
	if _, err := e.RevertLost(context.Background()); err != nil {
		t.Fatalf("RevertLost error: %v", err)
	}
	if _, serr := os.Stat(nologin); !os.IsNotExist(serr) {
		t.Fatalf("expected /etc/nologin removed after revert")
	}
	if _, serr := os.Stat(filepath.Join(root, "etc", "spire", "lost-mode")); !os.IsNotExist(serr) {
		t.Fatalf("expected lost marker cleared after revert")
	}
}

func TestRevertLost_NoMarker_NoOp(t *testing.T) {
	root := t.TempDir()
	// Pre-create an /etc/nologin the agent did NOT write (no marker); revert must not remove it.
	_ = os.MkdirAll(filepath.Join(root, "etc"), 0755)
	foreign := filepath.Join(root, "etc", "nologin")
	if err := os.WriteFile(foreign, []byte("maintenance\n"), 0644); err != nil {
		t.Fatal(err)
	}
	e := &DeviceActionEngine{Root: root, Runner: (&recordingRunner{}).run, LookPath: func(string) (string, error) { return "", os.ErrNotExist }}
	if _, err := e.RevertLost(context.Background()); err != nil {
		t.Fatalf("RevertLost error: %v", err)
	}
	if _, serr := os.Stat(foreign); serr != nil {
		t.Fatalf("revert must NOT remove an /etc/nologin the agent did not create")
	}
}

func TestLockSessions_CallsLoginctl(t *testing.T) {
	rr := &recordingRunner{}
	e := &DeviceActionEngine{Root: t.TempDir(), Runner: rr.run, LookPath: func(n string) (string, error) {
		if n == "loginctl" {
			return "/usr/bin/loginctl", nil
		}
		return "", os.ErrNotExist // no notify-send
	}}
	if _, err := e.LockSessions(context.Background(), ""); err != nil {
		t.Fatalf("LockSessions error: %v", err)
	}
	if len(rr.calls) != 1 || rr.calls[0][0] != "loginctl" || rr.calls[0][1] != "lock-sessions" {
		t.Fatalf("expected a single loginctl lock-sessions call, got %v", rr.calls)
	}
}

// fakeCryptsetup records cryptsetup invocations and fails nothing, so the rotation sequence
// can be asserted without touching real disks.
type fakeCryptsetup struct{ order []string }

func (f *fakeCryptsetup) run(_ context.Context, name string, args ...string) (string, error) {
	if name == "cryptsetup" && len(args) > 0 {
		f.order = append(f.order, args[0])
	}
	return "", nil
}

func TestLUKSRotate_Sequence(t *testing.T) {
	master := filepath.Join(t.TempDir(), "luks-master.key")
	if err := os.WriteFile(master, []byte("master-key-bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	fc := &fakeCryptsetup{}
	rt := &LUKSRotator{
		Runner:        fc.run,
		MasterKeyPath: master,
		GenerateKey:   func() (string, error) { return "NEWRECOVERYKEY48CHARSOFSOMETHINGRANDOMENOUGHXX", nil },
		NewSlot:       2,
	}
	// Give it a real RSA KEK public key so the re-escrow step succeeds.
	priv, _, err := db.GenerateKEKKeyPair()
	if err != nil {
		t.Fatalf("gen kek: %v", err)
	}
	res := rt.Rotate(context.Background(), "/dev/sda3", "vol-a", 1, &priv.PublicKey)
	if res.Status != string(types.RotationDone) {
		t.Fatalf("expected DONE, got %s (%s)", res.Status, res.Detail)
	}
	// Order must be: luksAddKey (new slot) -> open (test-passphrase) -> luksKillSlot (old slot).
	want := []string{"luksAddKey", "open", "luksKillSlot"}
	if len(fc.order) != len(want) {
		t.Fatalf("expected sequence %v, got %v", want, fc.order)
	}
	for i := range want {
		if fc.order[i] != want[i] {
			t.Fatalf("step %d: expected %s, got %s (full %v)", i, want[i], fc.order[i], fc.order)
		}
	}
	if len(res.EncryptedRecoveryKey) == 0 || len(res.EncryptedDEK) == 0 || len(res.Nonce) == 0 {
		t.Fatalf("expected the new key to be re-escrowed (envelope populated)")
	}
	if res.NewKeySlot != 2 {
		t.Fatalf("expected new key slot 2, got %d", res.NewKeySlot)
	}
}

func TestLUKSRotate_MissingMasterKey_Fails(t *testing.T) {
	rt := &LUKSRotator{Runner: (&fakeCryptsetup{}).run, MasterKeyPath: "/nonexistent/key"}
	priv, _, _ := db.GenerateKEKKeyPair()
	res := rt.Rotate(context.Background(), "/dev/sda3", "vol-a", 1, &priv.PublicKey)
	if res.Status != string(types.RotationFailed) {
		t.Fatalf("expected FAILED without master keyfile, got %s", res.Status)
	}
}
