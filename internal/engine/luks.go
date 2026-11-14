package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
)

const (
	recoveryKeyAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	recoveryKeyLength   = 48
	luksMasterKeyPath   = "/etc/spire/luks-master.key"
	luksEscrowStatePath = "/etc/spire/luks-escrowed.json"
)

// DiscoveredLUKSVolume represents a LUKS2 volume detected via lsblk / cryptsetup.
type DiscoveredLUKSVolume struct {
	Name       string `json:"name"`
	DevicePath string `json:"device_path"`
	VolumeUUID string `json:"volume_uuid"`
	MountPoint string `json:"mount_point"`
}

type lsblkOutput struct {
	BlockDevices []lsblkDevice `json:"blockdevices"`
}

type lsblkDevice struct {
	Name       string        `json:"name"`
	Path       string        `json:"path"`
	UUID       string        `json:"uuid"`
	FSType     string        `json:"fstype"`
	MountPoint string        `json:"mountpoint"`
	Children   []lsblkDevice `json:"children"`
}

// DiscoverLUKSVolumes runs lsblk -J to discover crypto_LUKS partitions and their unlocked mountpoints.
func DiscoverLUKSVolumes(ctx context.Context) ([]DiscoveredLUKSVolume, error) {
	if _, err := exec.LookPath("lsblk"); err != nil {
		return nil, nil
	}

	cmd := exec.CommandContext(ctx, "lsblk", "-J", "-o", "NAME,PATH,UUID,FSTYPE,MOUNTPOINT")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("lsblk discovery failed: %w", err)
	}

	var parsed lsblkOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("parse lsblk JSON: %w", err)
	}

	var volumes []DiscoveredLUKSVolume
	var walk func(devs []lsblkDevice)
	walk = func(devs []lsblkDevice) {
		for _, d := range devs {
			if strings.EqualFold(strings.TrimSpace(d.FSType), "crypto_LUKS") && strings.TrimSpace(d.UUID) != "" {
				mountPoint := strings.TrimSpace(d.MountPoint)
				for _, ch := range d.Children {
					if strings.TrimSpace(ch.MountPoint) != "" {
						mountPoint = strings.TrimSpace(ch.MountPoint)
						break
					}
				}
				if mountPoint == "" {
					mountPoint = "/"
				}
				devPath := strings.TrimSpace(d.Path)
				if devPath == "" {
					devPath = "/dev/" + strings.TrimSpace(d.Name)
				}
				volumes = append(volumes, DiscoveredLUKSVolume{
					Name:       strings.TrimSpace(d.Name),
					DevicePath: devPath,
					VolumeUUID: strings.TrimSpace(d.UUID),
					MountPoint: mountPoint,
				})
			}
			if len(d.Children) > 0 {
				walk(d.Children)
			}
		}
	}
	walk(parsed.BlockDevices)
	return volumes, nil
}

// GenerateLUKSRecoveryKey generates a cryptographically random 48-character recovery key.
func GenerateLUKSRecoveryKey() (string, error) {
	var b strings.Builder
	b.Grow(recoveryKeyLength)
	maxIdx := big.NewInt(int64(len(recoveryKeyAlphabet)))
	for i := 0; i < recoveryKeyLength; i++ {
		n, err := rand.Int(rand.Reader, maxIdx)
		if err != nil {
			return "", fmt.Errorf("generate random recovery key char: %w", err)
		}
		b.WriteByte(recoveryKeyAlphabet[n.Int64()])
	}
	return b.String(), nil
}

// EnrollLUKSKeySlot1 adds the generated 48-char recovery key into LUKS2 slot 1 via cryptsetup
// using the provisioning keyfile (/etc/spire/luks-master.key) and cryptsetup binary.
// It verifies the new key opens the volume before reporting success.
func EnrollLUKSKeySlot1(ctx context.Context, devicePath, recoveryKey string) error {
	if _, err := os.Stat(luksMasterKeyPath); err != nil {
		return fmt.Errorf("LUKS provisioning keyfile %s missing: %w", luksMasterKeyPath, err)
	}
	if _, err := exec.LookPath("cryptsetup"); err != nil {
		return fmt.Errorf("cryptsetup executable not found in PATH: %w", err)
	}

	cmd := exec.CommandContext(ctx, "cryptsetup", "luksAddKey",
		"--key-slot", "1",
		"--key-file", luksMasterKeyPath,
		devicePath,
	)
	cmd.Stdin = strings.NewReader(recoveryKey + "\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cryptsetup luksAddKey %s slot 1: %w (%s)", devicePath, err, strings.TrimSpace(string(out)))
	}

	// Test passphrase verification on slot 1 to ensure key is valid and functional
	testCmd := exec.CommandContext(ctx, "cryptsetup", "open", "--test-passphrase", "--key-slot", "1", devicePath)
	testCmd.Stdin = strings.NewReader(recoveryKey + "\n")
	if testOut, testErr := testCmd.CombinedOutput(); testErr != nil {
		return fmt.Errorf("cryptsetup open --test-passphrase failed for %s slot 1: %w (%s)", devicePath, testErr, strings.TrimSpace(string(testOut)))
	}

	return nil
}

// EscrowDiscoveredLUKSVolumes discovers LUKS2 volumes, generates a 48-char recovery key,
// adds it to slot 1, envelope-encrypts it with the server's RSA-OAEP-4096 public KEK + AES-256-GCM,
// and posts the payload to POST /api/v1/desktop/escrow/luks.
func EscrowDiscoveredLUKSVolumes(ctx context.Context, client *http.Client, serverURL, token, hwUUID, serverKEKPEM string) error {
	volumes, err := DiscoverLUKSVolumes(ctx)
	if err != nil || len(volumes) == 0 {
		return err
	}

	if strings.TrimSpace(serverKEKPEM) == "" {
		return nil
	}
	kekPub, err := db.ParseRSAPublicKeyPEM(serverKEKPEM)
	if err != nil {
		return fmt.Errorf("parse server KEK public key: %w", err)
	}

	escrowedState := loadEscrowedVolumes()

	for _, vol := range volumes {
		if escrowedState[vol.VolumeUUID] {
			continue
		}

		recoveryKey, err := GenerateLUKSRecoveryKey()
		if err != nil {
			return err
		}

		if err := EnrollLUKSKeySlot1(ctx, vol.DevicePath, recoveryKey); err != nil {
			return err
		}

		encDEK, encRecoveryKey, nonce, err := db.EnvelopeEncryptRecoveryKey(kekPub, recoveryKey)
		if err != nil {
			return fmt.Errorf("envelope encrypt LUKS recovery key: %w", err)
		}

		payload := types.LUKSEscrowPayload{
			HardwareUUID:         hwUUID,
			VolumeUUID:           vol.VolumeUUID,
			DevicePath:           vol.DevicePath,
			MountPoint:           vol.MountPoint,
			KeySlot:              1,
			EncryptedDEK:         encDEK,
			EncryptedRecoveryKey: encRecoveryKey,
			Nonce:                nonce,
		}
		bodyBytes, _ := json.Marshal(payload)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/desktop/escrow/luks", bytes.NewReader(bodyBytes))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("post LUKS escrow for %s: %w", vol.VolumeUUID, err)
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("post LUKS escrow returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		}

		escrowedState[vol.VolumeUUID] = true
		saveEscrowedVolumes(escrowedState)
	}
	return nil
}

func loadEscrowedVolumes() map[string]bool {
	state := make(map[string]bool)
	data, err := os.ReadFile(luksEscrowStatePath)
	if err == nil {
		_ = json.Unmarshal(data, &state)
	}
	return state
}

// LoadEscrowedVolumeState returns the agent's local record of which LUKS volume UUIDs it has
// escrowed. The lost-device wipe engine intersects this with a signed order so it only ever
// targets volumes this agent itself reported.
func LoadEscrowedVolumeState() map[string]bool {
	return loadEscrowedVolumes()
}

func saveEscrowedVolumes(state map[string]bool) {
	data, err := json.MarshalIndent(state, "", "  ")
	if err == nil {
		_ = os.WriteFile(luksEscrowStatePath, append(data, '\n'), 0600)
	}
}
