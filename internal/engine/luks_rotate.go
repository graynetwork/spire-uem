package engine

import (
	"context"
	"crypto/rsa"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

// LUKSRotateResult reports the outcome of a recovery-key rotation.
type LUKSRotateResult struct {
	VolumeUUID string
	Status     string // DONE | FAILED
	Detail     string
	NewKeySlot int
	// Envelope of the NEW recovery key, to be escrowed with the server on success.
	EncryptedDEK         []byte
	EncryptedRecoveryKey []byte
	Nonce                []byte
}

// LUKSRotator rotates a LUKS2 recovery key after an admin revealed one. Runner, MasterKeyPath
// and GenerateKey are injected so tests never touch real cryptsetup or disks.
//
// The agent holds the provisioning master keyfile (default /etc/spire/luks-master.key), which
// it used to enroll the original recovery key. Rotation therefore does NOT need the revealed
// key: it adds a fresh random key to a free slot using the master keyfile, verifies it opens
// the volume, escrows it, then removes the previously-revealed key's slot.
type LUKSRotator struct {
	// Runner runs cryptsetup. stdin carries the new key for luksAddKey and the passphrase test;
	// it is "" for commands that read nothing.
	Runner        InputRunner
	MasterKeyPath string
	GenerateKey   func() (string, error)
	// NewSlot picks the free keyslot to add the new key into (default 2, since slot 1 holds
	// the current recovery key and slot 0 is typically the user passphrase).
	NewSlot int
}

// InputRunner runs a command with the given stdin and returns its combined output.
type InputRunner func(ctx context.Context, stdin, name string, args ...string) (string, error)

func execInputRunner(ctx context.Context, stdin, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (rt *LUKSRotator) runner() InputRunner {
	if rt.Runner != nil {
		return rt.Runner
	}
	return execInputRunner
}

func (rt *LUKSRotator) masterKeyPath() string {
	if strings.TrimSpace(rt.MasterKeyPath) != "" {
		return rt.MasterKeyPath
	}
	return luksMasterKeyPath
}

func (rt *LUKSRotator) generateKey() (string, error) {
	if rt.GenerateKey != nil {
		return rt.GenerateKey()
	}
	return GenerateLUKSRecoveryKey()
}

// Rotate performs the add-verify-escrow-remove sequence for one volume. oldSlot is the slot
// of the revealed key to remove once the new key is proven. kekPub re-encrypts the new key
// with the existing envelope scheme.
func (rt *LUKSRotator) Rotate(ctx context.Context, devicePath, volumeUUID string, oldSlot int, kekPub *rsa.PublicKey) LUKSRotateResult {
	res := LUKSRotateResult{VolumeUUID: volumeUUID, Status: string(types.RotationFailed)}

	newSlot := rt.NewSlot
	if newSlot <= 0 {
		newSlot = 2
	}
	if newSlot == oldSlot {
		newSlot = oldSlot + 1
	}
	res.NewKeySlot = newSlot

	if _, err := os.Stat(rt.masterKeyPath()); err != nil {
		res.Detail = fmt.Sprintf("master keyfile %s missing: %v", rt.masterKeyPath(), err)
		return res
	}
	if kekPub == nil {
		res.Detail = "server KEK public key unavailable; cannot escrow rotated key"
		return res
	}

	newKey, err := rt.generateKey()
	if err != nil {
		res.Detail = "generate new recovery key: " + err.Error()
		return res
	}

	// 1. Add the new key to a free slot using the master keyfile as the existing key.
	// cryptsetup reads the new passphrase from stdin up to the first newline, the same way
	// EnrollLUKSKeySlot1 enrolls the original recovery key.
	if out, err := rt.runner()(ctx, newKey+"\n", "cryptsetup", "luksAddKey",
		"--key-slot", strconv.Itoa(newSlot),
		"--key-file", rt.masterKeyPath(),
		devicePath,
	); err != nil {
		res.Detail = fmt.Sprintf("luksAddKey slot %d: %v (%s)", newSlot, err, strings.TrimSpace(out))
		return res
	}

	// 2. Verify the new key actually opens the volume before removing anything.
	if out, err := rt.runner()(ctx, newKey+"\n", "cryptsetup", "open", "--test-passphrase",
		"--key-slot", strconv.Itoa(newSlot), devicePath); err != nil {
		res.Detail = fmt.Sprintf("test-passphrase slot %d: %v (%s)", newSlot, err, strings.TrimSpace(out))
		return res
	}

	// 3. Escrow the new key with the same RSA-OAEP-4096 + AES-256-GCM envelope.
	encDEK, encKey, nonce, err := db.EnvelopeEncryptRecoveryKey(kekPub, newKey)
	if err != nil {
		res.Detail = "envelope-encrypt new recovery key: " + err.Error()
		return res
	}
	res.EncryptedDEK, res.EncryptedRecoveryKey, res.Nonce = encDEK, encKey, nonce

	// 4. Remove the revealed key's slot now that a verified replacement exists.
	if oldSlot >= 0 && oldSlot != newSlot {
		if out, err := rt.runner()(ctx, "", "cryptsetup", "luksKillSlot", "--batch-mode",
			"--key-file", rt.masterKeyPath(), devicePath, strconv.Itoa(oldSlot)); err != nil {
			// The new key is live and escrowed; failing to remove the old slot is a partial
			// success worth surfacing, not a reason to leave the volume without a known key.
			res.Status = string(types.RotationFailed)
			res.Detail = fmt.Sprintf("new key escrowed in slot %d but failed to remove old slot %d: %v (%s)",
				newSlot, oldSlot, err, strings.TrimSpace(out))
			return res
		}
	}

	res.Status = string(types.RotationDone)
	res.Detail = fmt.Sprintf("rotated recovery key: new slot %d, removed slot %d", newSlot, oldSlot)
	return res
}
