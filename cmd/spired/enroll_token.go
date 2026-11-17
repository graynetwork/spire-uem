package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/spire-uem/spire-uem/internal/config"
	"github.com/spire-uem/spire-uem/internal/types"
)

// enrollmentTokenSource is where a resolved enrollment token came from, for logging and to
// decide whether the on-disk token file must be deleted after a successful registration.
type enrollmentTokenSource int

const (
	tokenSourceNone enrollmentTokenSource = iota
	tokenSourceFile
	tokenSourceEnv
	tokenSourceConfig
)

func (s enrollmentTokenSource) String() string {
	switch s {
	case tokenSourceFile:
		return "file"
	case tokenSourceEnv:
		return "env"
	case tokenSourceConfig:
		return "config"
	default:
		return "none"
	}
}

// resolveEnrollmentToken returns the enrollment token to use and where it came from, honouring
// the precedence: enrollment_token_file, then env SPIRE_ENROLLMENT_TOKEN, then the config
// value. The file is READ but NOT deleted here — deletion happens only after a successful
// registration, so a transient failure does not lose the token. A missing file is not an
// error (the agent falls through to env/config, then to manual enrollment).
func resolveEnrollmentToken(cfg config.AgentConfig) (token string, source enrollmentTokenSource) {
	if p := strings.TrimSpace(cfg.EnrollmentTokenFile); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			if t := strings.TrimSpace(string(b)); t != "" {
				return t, tokenSourceFile
			}
		} else if !os.IsNotExist(err) {
			log.Printf("[spired] warning: cannot read enrollment_token_file %s: %v", p, err)
		}
	}
	if t := strings.TrimSpace(os.Getenv("SPIRE_ENROLLMENT_TOKEN")); t != "" {
		return t, tokenSourceEnv
	}
	if t := strings.TrimSpace(cfg.EnrollmentToken); t != "" {
		return t, tokenSourceConfig
	}
	return "", tokenSourceNone
}

// registerWithToken performs one-request token-based registration. It binds the hardware
// UUID, the agent's enrollment key and a CSR for the device's local key, and returns the
// issued bearer token on auto-approval, or "" when the token requires admin approval (the
// agent then falls back to the normal polling loop). The device private key never leaves
// this host.
func registerWithToken(ctx context.Context, client *http.Client, serverURL, tokenPath, enrollToken, hwUUID, hostname, enrollKey string, deviceKey *ecdsa.PrivateKey, certPaths deviceCertPaths) (bearer string, pending bool, err error) {
	csrPEM, csrErr := buildDeviceCSR(deviceKey, hwUUID)
	if csrErr != nil {
		log.Printf("[spired] warning: could not build device CSR for token enroll (continuing without mTLS cert): %v", csrErr)
	}
	reqBody, _ := json.Marshal(types.EnrollmentRegisterRequest{
		Token:         enrollToken,
		HardwareUUID:  hwUUID,
		Hostname:      hostname,
		EnrollmentKey: enrollKey,
		CSRPEM:        csrPEM,
	})
	req, rerr := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/enrollment/register", bytes.NewReader(reqBody))
	if rerr != nil {
		return "", false, rerr
	}
	req.Header.Set("Content-Type", "application/json")

	resp, derr := client.Do(req)
	if derr != nil {
		return "", false, derr
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	// A 4xx is a decision by the server (bad/exhausted/mismatched token, key conflict); it is
	// NOT a transient network error, so it must not trigger network backoff. Surface it as a
	// non-nil result with pending=false and bearer="" so the caller stops the token path and
	// logs the refusal, falling back to manual enrollment.
	if resp.StatusCode == http.StatusTooManyRequests {
		return "", false, fmt.Errorf("server rate-limited enrollment (HTTP 429): %s", strings.TrimSpace(string(body)))
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("[spired] token registration refused (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
		return "", false, nil
	}

	var regResp types.EnrollmentRegisterResponse
	if uerr := json.Unmarshal(body, &regResp); uerr != nil {
		return "", false, fmt.Errorf("decode register response: %w", uerr)
	}

	if regResp.Status == types.StatusApproved && regResp.AuthToken != "" {
		// Pin the server's Ed25519 wipe-signing key next to the token (same as the manual flow).
		pinWipeKey(tokenPath, regResp.WipeSigningPublicKey)
		if strings.TrimSpace(regResp.DeviceCertificatePEM) != "" {
			if serr := storeDeviceCert(certPaths.certPath, regResp.DeviceCertificatePEM); serr != nil {
				log.Printf("[spired] warning: failed to persist device certificate from token enroll: %v", serr)
			} else {
				log.Printf("[spired] stored device client certificate from token enroll (not_after=%s)", regResp.DeviceCertNotAfter)
			}
		}
		return regResp.AuthToken, false, nil
	}

	// Token required approval: device is staged PENDING_APPROVAL. Fall back to polling.
	log.Printf("[spired] token registration staged device as %s; awaiting admin approval", regResp.Status)
	return "", true, nil
}

// resetDeviceIdentity securely removes every on-disk artefact that identifies this device:
// the bearer token, the enrollment key, the device key/cert, the pinned wipe-signing key, and
// any staged one-time enrollment-token file. It is used before sealing a golden image so a
// clone enrolls as a FRESH device instead of silently sharing this one's record. Missing
// files are not an error. It never contacts the server or touches the network.
func resetDeviceIdentity(tokenPath string) error {
	dir := filepath.Dir(tokenPath)
	certPaths := deviceCertFiles(tokenPath)
	targets := []string{
		tokenPath,
		enrollmentKeyPath(tokenPath),
		certPaths.keyPath,
		certPaths.certPath,
		certPaths.keyPath + ".new", // a staged renewal key, if any
		wipeKeyPath(tokenPath),
		filepath.Join(dir, "enrollment-token"), // one-time bootstrap token file
	}
	var firstErr error
	for _, p := range targets {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			log.Printf("[spired] reset-identity: could not remove %s: %v", p, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		log.Printf("[spired] reset-identity: removed %s", p)
	}
	return firstErr
}
