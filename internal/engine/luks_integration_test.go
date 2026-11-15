//go:build luksintegration

// Real-cryptsetup integration tests for LUKS key rotation and crypto-erase.
//
// These run ONLY against a throwaway loop device. Build and run as root on a lab machine:
//
//	scripts/luks_integration.sh   (creates the loop device, runs this test, cleans up)
//
// The test refuses to run unless SPIRE_LUKS_TEST_DEVICE is a /dev/loopN whose backing file
// lives under /tmp/spire-luks-test/. It never powers the machine off.
package engine

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

const luksTestDir = "/tmp/spire-luks-test/"

func luksTestDevice(t *testing.T) (dev, masterKey string) {
	t.Helper()
	dev = os.Getenv("SPIRE_LUKS_TEST_DEVICE")
	masterKey = os.Getenv("SPIRE_LUKS_TEST_MASTER_KEY")
	if !regexp.MustCompile(`^/dev/loop[0-9]+$`).MatchString(dev) {
		t.Fatalf("SPIRE_LUKS_TEST_DEVICE must be a /dev/loopN device, got %q", dev)
	}
	back, err := os.ReadFile("/sys/block/" + strings.TrimPrefix(dev, "/dev/") + "/loop/backing_file")
	if err != nil || !strings.HasPrefix(strings.TrimSpace(string(back)), luksTestDir) {
		t.Fatalf("%s is not backed by a file under %s (backing=%q err=%v); refusing", dev, luksTestDir, back, err)
	}
	if !strings.HasPrefix(masterKey, luksTestDir) {
		t.Fatalf("SPIRE_LUKS_TEST_MASTER_KEY must be under %s", luksTestDir)
	}
	return dev, masterKey
}

// opens reports whether key unlocks dev (optionally restricted to one slot).
func opens(t *testing.T, dev, key string, slot string) bool {
	t.Helper()
	args := []string{"open", "--test-passphrase", dev}
	if slot != "" {
		args = append(args, "--key-slot", slot)
	}
	cmd := exec.Command("cryptsetup", args...)
	cmd.Stdin = strings.NewReader(key)
	return cmd.Run() == nil
}

func luksUUID(t *testing.T, dev string) string {
	t.Helper()
	out, err := exec.Command("cryptsetup", "luksUUID", dev).Output()
	if err != nil {
		t.Fatalf("luksUUID: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// TestLUKSIntegration_RotateThenWipe runs in one test because the wipe destroys the volume
// the rotation needs. The setup script leaves the master key in slot 0 and the "revealed"
// recovery key (SPIRE_LUKS_TEST_OLD_KEY) in slot 1.
func TestLUKSIntegration_RotateThenWipe(t *testing.T) {
	dev, masterKey := luksTestDevice(t)
	oldKey := os.Getenv("SPIRE_LUKS_TEST_OLD_KEY")
	if !opens(t, dev, oldKey, "1") {
		t.Fatal("setup: old recovery key does not open slot 1")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	kek, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// --- Rotation -------------------------------------------------------------------------
	rt := &LUKSRotator{MasterKeyPath: masterKey}
	res := rt.Rotate(ctx, dev, luksUUID(t, dev), 1, &kek.PublicKey)
	t.Logf("rotate: status=%s slot=%d detail=%s", res.Status, res.NewKeySlot, res.Detail)
	if res.Status != string(types.RotationDone) {
		t.Fatalf("rotation failed: %s", res.Detail)
	}
	newKey, err := db.EnvelopeDecryptRecoveryKey(kek, res.EncryptedDEK, res.EncryptedRecoveryKey, res.Nonce)
	if err != nil {
		t.Fatalf("decrypt escrowed key: %v", err)
	}
	if !opens(t, dev, newKey, "") {
		t.Fatal("the escrowed new recovery key does not open the volume")
	}
	if opens(t, dev, oldKey, "") {
		t.Fatal("the revealed old recovery key still opens the volume")
	}
	if !opens(t, dev, mustRead(t, masterKey), "0") {
		t.Fatal("rotation broke the master key in slot 0")
	}

	// --- Crypto-erase -----------------------------------------------------------------------
	signer, err := crypto.NewWipeSigner(t.TempDir() + "/wipe.pem")
	if err != nil {
		t.Fatal(err)
	}
	uuid := luksUUID(t, dev)
	now := time.Now().UTC()
	order := types.WipeOrder{Version: 1, RequestID: "itest", DeviceID: "dev", HardwareUUID: "HW-ITEST",
		Hostname: "itest", VolumeUUIDs: []string{uuid}, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	b, err := order.MarshalCanonical()
	if err != nil {
		t.Fatal(err)
	}
	poweredOff := false
	we := &WipeEngine{
		PowerOff: func(context.Context) error { poweredOff = true; return nil }, // never real power-off
		EscrowedVolumes: func() map[string]DiscoveredLUKSVolume {
			return map[string]DiscoveredLUKSVolume{uuid: {Name: "itest", DevicePath: dev, VolumeUUID: uuid}}
		},
	}
	wres := we.PerformWipe(ctx, signer.PublicKeyBase64(), "HW-ITEST",
		types.ActionDirective{Kind: types.ActionWipe, SignedOrder: b, OrderSignature: signer.Sign(b)})
	t.Logf("wipe: status=%s detail=%s", wres.Status, wres.Detail)
	if wres.Status != string(types.WipeCompleted) || !poweredOff {
		t.Fatalf("wipe did not complete: %s", wres.Detail)
	}
	for name, key := range map[string]string{"master": mustRead(t, masterKey), "new recovery": newKey, "old recovery": oldKey} {
		if opens(t, dev, key, "") {
			t.Errorf("%s key still opens the volume after crypto-erase", name)
		}
	}
	dump, _ := exec.Command("cryptsetup", "luksDump", dev).CombinedOutput()
	if regexp.MustCompile(`(?m)^\s+[0-9]+: luks2`).Match(dump) {
		t.Errorf("keyslots remain after luksErase:\n%s", dump)
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
