package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spire-uem/spire-uem/internal/config"
	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/inventory"
	"github.com/spire-uem/spire-uem/internal/ipc"
	"github.com/spire-uem/spire-uem/internal/release"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/version"
)

func main() {
	// Defensively cap NOFILE rlimit to prevent GLib/Flatpak child processes from looping up to 1B fds on fork
	var rLim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLim); err == nil && rLim.Cur > 65536 {
		rLim.Cur = 65536
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLim)
	}

	configPath := flag.String("config", "", "Path to YAML configuration file")
	once := flag.Bool("once", false, "Run a single check-in/enforcement cycle and exit")
	rollbackCheck := flag.Bool("rollback-check", false, "Run the independent agent-update rollback check and exit (invoked by the rollback timer; does not depend on a healthy new binary)")
	flag.Parse()

	cfg := config.Load(*configPath)

	// Rollback trigger entry point: reinstall the previous agent package if the just-installed
	// one never confirmed healthy. This runs off on-disk state only, so a crash-looping new
	// binary is still reverted. It is deliberately BEFORE enrollment/network setup.
	if *rollbackCheck {
		rb := engine.NewRollbacker(engine.DefaultRollbackDir, nil, nil)
		outcome := rb.CheckAndRollback(context.Background(), engine.DefaultUpdateStatePath)
		switch outcome.Action {
		case engine.RollbackActionRolledBack:
			if outcome.Err != nil {
				log.Printf("[spired] rollback-check: reinstall FAILED: %v", outcome.Err)
				os.Exit(1)
			}
			log.Printf("[spired] rollback-check: new agent did not confirm healthy; reinstalled previous package")
		case engine.RollbackActionConfirmed:
			log.Printf("[spired] rollback-check: update confirmed healthy; nothing to do")
		default:
			log.Printf("[spired] rollback-check: nothing to do (%s)", outcome.Action)
		}
		return
	}

	hwUUID, err := inventory.GetHardwareUUID()
	if err != nil {
		log.Fatalf("[spired] failed to determine hardware UUID: %v", err)
	}
	hostname := inventory.GetHostname()
	if err := config.CheckAgentServerURL(cfg.Agent.ServerURL, cfg.Agent.AllowInsecureHTTP); err != nil {
		log.Fatalf("[spired] refusing to start: %v", err)
	}
	log.Printf("[spired] starting daemon hardware_uuid=%s hostname=%s server=%s", hwUUID, hostname, cfg.Agent.ServerURL)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	certPaths := deviceCertFiles(cfg.Agent.TokenPath)
	deviceKey, err := loadOrCreateDeviceKey(certPaths.keyPath)
	if err != nil {
		log.Fatalf("[spired] failed to load or create device key: %v", err)
	}

	client, err := buildHTTPClient(4*time.Second, certPaths, cfg.Agent.ServerCAFile, cfg.Agent.ServerCASHA256)
	if err != nil {
		log.Fatalf("[spired] failed to build HTTP client: %v", err)
	}
	if strings.TrimSpace(cfg.Agent.ServerCAFile) != "" || strings.TrimSpace(cfg.Agent.ServerCASHA256) != "" {
		log.Printf("[spired] pinning control-plane TLS trust (server_ca_file=%q server_ca_sha256 set=%v); system roots are NOT used for the server connection", cfg.Agent.ServerCAFile, strings.TrimSpace(cfg.Agent.ServerCASHA256) != "")
	}
	backoffAttempt := 0
	triggerCheckinCh := make(chan struct{}, 1)
	var checkinMu sync.Mutex
	var ipcSrv *ipc.Server

	syncNow := func(syncCtx context.Context) error {
		checkinMu.Lock()
		defer checkinMu.Unlock()

		token := readToken(cfg.Agent.TokenPath)
		if token == "" {
			return fmt.Errorf("device is not yet enrolled/approved")
		}
		checkinResp, installedPkgs, statusCode, err := performCheckin(syncCtx, client, cfg.Agent.ServerURL, token, hwUUID, hostname)
		if err != nil {
			if ipcSrv != nil {
				ipcSrv.UpdateStatus(false, time.Time{}, nil)
			}
			return err
		}
		if statusCode == http.StatusForbidden {
			if ipcSrv != nil {
				ipcSrv.UpdateStatus(false, time.Time{}, nil)
			}
			return fmt.Errorf("server returned HTTP 403 Forbidden")
		}
		if checkinResp != nil {
			_ = engine.SavePolicyCache(engine.DefaultPolicyCachePath, checkinResp)
			pendingReports, _ := engine.LoadPendingReports(engine.DefaultPendingReportsPath)
			results := executePoliciesAndCleanup(syncCtx, checkinResp.Policies, checkinResp.RevokedPolicies, installedPkgs)
			allResults := engine.MergeReports(pendingReports, results)
			if len(allResults) > 0 {
				if repErr := reportPolicyResults(syncCtx, client, cfg.Agent.ServerURL, token, hwUUID, allResults); repErr != nil {
					_ = engine.QueuePendingReports(engine.DefaultPendingReportsPath, allResults)
				} else if len(pendingReports) > 0 {
					_ = engine.ClearPendingReports(engine.DefaultPendingReportsPath)
				}
			}
			if ipcSrv != nil {
				ipcSrv.UpdateDevicePolicies(checkinResp.DeviceID, checkinResp.Policies, allResults)
				ipcSrv.UpdateStatus(true, time.Now().UTC(), allResults)
			}
		}
		return nil
	}

	ipcSrv = ipc.NewServer(
		ipc.DefaultSocketPath,
		cfg.Agent.ServerURL,
		cfg.Agent.TokenPath,
		hwUUID,
		hostname,
		client,
		syncNow,
		triggerCheckinCh,
	)
	ipcSrv.SetEngineMutex(&checkinMu)

	if !*once {
		go runWebSocketStream(ctx, client, cfg.Agent.ServerURL, cfg.Agent.TokenPath, triggerCheckinCh, ipcSrv)
		go runCertRenewalLoop(ctx, client, cfg.Agent.ServerURL, cfg.Agent.TokenPath, hwUUID, deviceKey, certPaths)
		go func() {
			if err := ipcSrv.Run(ctx); err != nil {
				log.Printf("[spired] local IPC server stopped: %v", err)
			}
		}()
	}

	for {
		select {
		case <-ctx.Done():
			log.Printf("[spired] shutting down")
			return
		default:
		}

		token := readToken(cfg.Agent.TokenPath)
		if token == "" {
			enrollKey, keyErr := loadOrCreateEnrollmentKey(enrollmentKeyPath(cfg.Agent.TokenPath))
			if keyErr != nil {
				log.Printf("[spired] cannot load or create enrollment key: %v", keyErr)
				if *once || !sleepContext(ctx, cfg.Agent.PollInterval) {
					return
				}
				continue
			}
			enrolledToken, netErr := enrollAndPoll(ctx, client, cfg.Agent.ServerURL, cfg.Agent.TokenPath, hwUUID, hostname, enrollKey, deviceKey, certPaths)
			if netErr != nil {
				backoffAttempt++
				sleepDur := backoffWithJitter(backoffAttempt, cfg.Agent.PollInterval)
				log.Printf("[spired] network error during enrollment: %v (retrying in %s)", netErr, sleepDur)
				if *once {
					return
				}
				if !sleepContext(ctx, sleepDur) {
					return
				}
				continue
			}
			backoffAttempt = 0

			if enrolledToken == "" {
				if *once {
					return
				}
				if !sleepContext(ctx, cfg.Agent.PollInterval) {
					return
				}
				continue
			}

			if err := persistToken(cfg.Agent.TokenPath, enrolledToken); err != nil {
				log.Printf("[spired] failed to persist token to %s: %v", cfg.Agent.TokenPath, err)
				if *once {
					return
				}
				if !sleepContext(ctx, cfg.Agent.PollInterval) {
					return
				}
				continue
			}
			log.Printf("[spired] device approved! Token persisted to %s (mode 0600)", cfg.Agent.TokenPath)
			token = enrolledToken
		}

		statusCode, checkErr := func() (int, error) {
			checkinMu.Lock()
			defer checkinMu.Unlock()

			checkinResp, installedPkgs, code, err := performCheckin(ctx, client, cfg.Agent.ServerURL, token, hwUUID, hostname)
			if err != nil {
				log.Printf("[WARN] Server unreachable; falling back to local policy cache (%v)", err)
				cached, cacheErr := engine.LoadPolicyCache(engine.DefaultPolicyCachePath)
				if cacheErr != nil {
					log.Printf("[spired] unable to load local policy cache %s: %v", engine.DefaultPolicyCachePath, cacheErr)
					ipcSrv.UpdateStatus(false, time.Time{}, nil)
				} else {
					results := executePoliciesAndCleanup(ctx, cached.Policies, cached.RevokedPolicies, installedPkgs)
					ipcSrv.UpdateDevicePolicies(cached.DeviceID, cached.Policies, results)
					ipcSrv.UpdateStatus(false, time.Time{}, results)
					if qErr := engine.QueuePendingReports(engine.DefaultPendingReportsPath, results); qErr != nil {
						log.Printf("[spired] failed to buffer offline compliance reports: %v", qErr)
					} else {
						log.Printf("[spired] offline reconciliation complete: reconciled %d cached policies, buffered %d reports in %s",
							len(cached.Policies), len(results), engine.DefaultPendingReportsPath)
					}
				}
				return code, err
			}

			if code == http.StatusForbidden {
				log.Printf("[spired] server returned HTTP 403 Forbidden on check-in; clearing token and staging enrollment")
				_ = os.Remove(cfg.Agent.TokenPath)
				ipcSrv.UpdateStatus(false, time.Time{}, nil)
				return code, nil
			}

			if checkinResp != nil {
				if err := engine.SavePolicyCache(engine.DefaultPolicyCachePath, checkinResp); err != nil {
					log.Printf("[spired] warning: failed to update local policy cache %s: %v", engine.DefaultPolicyCachePath, err)
				}

				// Pin the server's Ed25519 wipe-signing key once (persisted next to the token).
				pinWipeKey(cfg.Agent.TokenPath, checkinResp.WipeSigningPublicKey)

				pendingReports, _ := engine.LoadPendingReports(engine.DefaultPendingReportsPath)
				results := executePoliciesAndCleanup(ctx, checkinResp.Policies, checkinResp.RevokedPolicies, installedPkgs)
				allResults := engine.MergeReports(pendingReports, results)
				ipcSrv.UpdateDevicePolicies(checkinResp.DeviceID, checkinResp.Policies, allResults)
				ipcSrv.UpdateStatus(true, time.Now().UTC(), allResults)

				if len(allResults) > 0 {
					if err := reportPolicyResults(ctx, client, cfg.Agent.ServerURL, token, hwUUID, allResults); err != nil {
						log.Printf("[spired] failed to report policy compliance (buffering locally): %v", err)
						_ = engine.QueuePendingReports(engine.DefaultPendingReportsPath, allResults)
					} else {
						if len(pendingReports) > 0 {
							_ = engine.ClearPendingReports(engine.DefaultPendingReportsPath)
							log.Printf("[spired] flushed %d buffered offline reports + current execution results (%d total)", len(pendingReports), len(allResults))
						} else {
							log.Printf("[spired] reported %d policy execution/cleanup results to server", len(allResults))
						}
					}
				} else {
					log.Printf("[spired] check-in complete (0 policy updates to report)")
				}

				if len(checkinResp.QueuedCommands) > 0 {
					log.Printf("[spired] received %d queued diagnostic commands", len(checkinResp.QueuedCommands))
					for _, cmdDTO := range checkinResp.QueuedCommands {
						if IsActionDirective(cmdDTO.Command) {
							d, perr := parseActionDirective(cmdDTO.Command)
							if perr != nil {
								log.Printf("[spired] invalid action directive id=%s: %v", cmdDTO.ID, perr)
								_ = reportCommandResult(ctx, client, cfg.Agent.ServerURL, token, types.CommandReportRequest{
									CommandID: cmdDTO.ID, Status: "FAILED", ExitCode: 1, Stderr: "invalid action directive",
								})
								continue
							}
							log.Printf("[spired] executing lost-device action id=%s kind=%s", cmdDTO.ID, d.Kind)
							dispatchActionDirective(ctx, client, cfg.Agent.ServerURL, token, cfg.Agent.TokenPath, hwUUID, checkinResp.ServerKEKPublicPEM, d)
							_ = reportCommandResult(ctx, client, cfg.Agent.ServerURL, token, types.CommandReportRequest{
								CommandID: cmdDTO.ID, Status: "COMPLETED", ExitCode: 0, Stdout: "action " + string(d.Kind) + " dispatched",
							})
							continue
						}
						log.Printf("[spired] executing diagnostic command id=%s cmd=%q", cmdDTO.ID, cmdDTO.Command)
						cmdReport := engine.ExecuteDiagnosticCommand(ctx, cmdDTO, 30*time.Second)
						if err := reportCommandResult(ctx, client, cfg.Agent.ServerURL, token, cmdReport); err != nil {
							log.Printf("[spired] failed to report command result id=%s: %v", cmdDTO.ID, err)
						} else {
							log.Printf("[spired] reported command id=%s status=%s exit=%d", cmdDTO.ID, cmdReport.Status, cmdReport.ExitCode)
						}
					}
				}

				if attResp, attErr := engine.PerformTPMAttestation(ctx, client, cfg.Agent.ServerURL, token, hwUUID); attErr != nil {
					log.Printf("[spired] warning: TPM 2.0 attestation failed: %v", attErr)
				} else if attResp != nil {
					ipcSrv.UpdateAttestation(string(attResp.Status), attResp.SecureBootEnabled)
					log.Printf("[spired] TPM 2.0 attestation completed status=%s secure_boot=%v", attResp.Status, attResp.SecureBootEnabled)
				}

				if luksErr := engine.EscrowDiscoveredLUKSVolumes(ctx, client, cfg.Agent.ServerURL, token, hwUUID, checkinResp.ServerKEKPublicPEM); luksErr != nil {
					log.Printf("[spired] warning: LUKS2 volume escrow failed: %v", luksErr)
				} else {
					ipcSrv.UpdateLUKSEscrow(true)
				}

				// Agent self-update: if the server dispatched a target version and the
				// maintenance window permits it, verify and install it. The install detaches
				// via systemd-run so spired does not kill itself mid-dpkg; the result is
				// persisted and reported on the NEXT check-in (it survives the restart).
				if checkinResp.AgentUpdate != nil && checkinResp.AgentUpdate.Action == types.UpdateActionUpdate {
					if !checkinResp.MaintenanceWindowActive {
						log.Printf("[spired] agent update to %s deferred: outside maintenance window", checkinResp.AgentUpdate.TargetVersion)
					} else {
						log.Printf("[spired] agent self-update directive: %s -> %s (%s)", version.Version, checkinResp.AgentUpdate.TargetVersion, checkinResp.AgentUpdate.Reason)
						updateClient := &http.Client{Timeout: 10 * time.Minute}
						updater := engine.NewSelfUpdater(updateClient, cfg.Agent.ServerURL, version.Version, nil)

						// Pin release trust anchors from the keys shipped INSIDE this package;
						// they are never fetched from the server. require_signed defaults true.
						trust, keyErrs := release.LoadTrustAnchors(cfg.Agent.ReleaseKeysDir)
						for _, e := range keyErrs {
							log.Printf("[spired] warning: release trust anchor load: %v", e)
						}
						engine.SetSignatureVerification(updater, trust, cfg.Agent.RequireSignedUpdates, cfg.Agent.ReleaseKeysDir)

						// Arm an independent rollback trigger around the install.
						engine.SetRollbacker(updater, engine.NewRollbacker(engine.DefaultRollbackDir, nil, nil))

						if res := updater.ApplyDirective(ctx, checkinResp.AgentUpdate, token); res != nil {
							log.Printf("[spired] agent self-update result target=%s status=%s msg=%s", res.TargetVersion, res.Status, res.Message)
						}
					}
				}

				// A completed check-in is the agent's "healthy" signal: if THIS process is the
				// newly-installed agent from a recent update, confirm it so the independent
				// rollback trigger stands down. Harmless on a normal (non-update) check-in.
				if err := engine.NewRollbacker(engine.DefaultRollbackDir, nil, nil).ConfirmHealthy(version.Version); err != nil {
					log.Printf("[spired] warning: could not write update health marker: %v", err)
				}
			}
			return code, nil
		}()

		if checkErr != nil {
			if *once {
				return
			}
			backoffAttempt++
			sleepDur := backoffWithJitter(backoffAttempt, cfg.Agent.PollInterval)
			if !sleepContext(ctx, sleepDur) {
				return
			}
			continue
		}
		backoffAttempt = 0

		if statusCode == http.StatusForbidden {
			if *once {
				return
			}
			if !sleepContext(ctx, cfg.Agent.PollInterval) {
				return
			}
			continue
		}

		if *once {
			return
		}

		if !sleepOrTrigger(ctx, cfg.Agent.CheckinInterval, triggerCheckinCh) {
			return
		}
	}
}

func enrollAndPoll(ctx context.Context, client *http.Client, serverURL, tokenPath, hwUUID, hostname, enrollKey string, deviceKey *ecdsa.PrivateKey, certPaths deviceCertPaths) (string, error) {
	// Include a CSR for the device's local key so the server can issue a client-auth leaf at
	// the moment the token is claimed. The private key never leaves this host.
	csrPEM, csrErr := buildDeviceCSR(deviceKey, hwUUID)
	if csrErr != nil {
		log.Printf("[spired] warning: could not build device CSR (continuing without mTLS cert): %v", csrErr)
	}
	reqBody, _ := json.Marshal(types.EnrollRequest{
		HardwareUUID:  hwUUID,
		Hostname:      hostname,
		EnrollmentKey: enrollKey,
		CSRPEM:        csrPEM,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/desktop/enroll", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var enrollResp types.EnrollResponse
	_ = json.Unmarshal(bodyBytes, &enrollResp)

	if resp.StatusCode == http.StatusOK && enrollResp.Status == types.StatusApproved && enrollResp.Token != "" {
		// Pin the server's Ed25519 wipe-signing key at enrollment (once, persisted).
		pinWipeKey(tokenPath, enrollResp.WipeSigningPublicKey)
		// Persist the issued client certificate, if the server returned one.
		if strings.TrimSpace(enrollResp.DeviceCertificatePEM) != "" {
			if err := storeDeviceCert(certPaths.certPath, enrollResp.DeviceCertificatePEM); err != nil {
				log.Printf("[spired] warning: failed to persist device certificate: %v", err)
			} else {
				log.Printf("[spired] stored device client certificate (not_after=%s)", enrollResp.DeviceCertNotAfter)
			}
		}
		return enrollResp.Token, nil
	}

	log.Printf("[spired] device staged as %s (HTTP %d); polling check-in while awaiting admin approval", enrollResp.Status, resp.StatusCode)
	_, _, code, _ := performCheckin(ctx, client, serverURL, "", hwUUID, hostname)
	log.Printf("[spired] polling check-in returned HTTP %d", code)
	return "", nil
}

func performCheckin(ctx context.Context, client *http.Client, serverURL, token, hwUUID, hostname string) (*types.CheckinResponse, map[string]bool, int, error) {
	pkgs, err := inventory.GetInstalledPackages()
	if err != nil {
		log.Printf("[spired] warning: package inventory collection failed: %v", err)
	}
	installedMap := engine.BuildInstalledPackageMap(pkgs)
	flatpaks, _ := engine.GetInstalledFlatpaks(ctx)
	activeSession, _ := inventory.GetActiveSession()
	rebootReq := engine.IsRebootRequired()
	patchStatus, err := engine.CollectPatchTelemetry()
	if err != nil {
		log.Printf("[spired] warning: patch telemetry collection failed: %v", err)
	}
	if patchStatus != nil {
		if rebootReq {
			patchStatus.RebootRequired = true
		} else if patchStatus.RebootRequired {
			rebootReq = true
		}
	}
	if rebootReq {
		_ = engine.NotifyDesktopRebootPending(ctx, "A system update applied by SpireUEM is awaiting a reboot.")
	}

	osInfo := inventory.GetOSInfo()
	srcPkgs, srcErr := inventory.GetSourcePackages()
	if srcErr != nil {
		log.Printf("[spired] warning: source package inventory collection failed: %v", srcErr)
	}
	releaseCodename := inventory.GetReleaseCodename()
	payload, _ := json.Marshal(types.CheckinRequest{
		HardwareUUID:    hwUUID,
		Hostname:        hostname,
		Packages:        pkgs,
		Flatpaks:        flatpaks,
		ActiveSession:   activeSession,
		RebootRequired:  rebootReq,
		PatchStatus:     patchStatus,
		OSName:          osInfo.Name,
		KernelVersion:   osInfo.Kernel,
		SourcePackages:  srcPkgs,
		ReleaseCodename: releaseCodename,
		AgentVersion:    version.Version,
		UpdateResult:    engine.ConsumePendingUpdateResult(engine.DefaultUpdateStatePath),
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/desktop/checkin", bytes.NewReader(payload))
	if err != nil {
		return nil, installedMap, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Advertise the agent version on every authenticated request so the server's
	// minimum-version gate can refuse an outdated agent on gated endpoints.
	req.Header.Set("X-Spire-Agent-Version", version.Version)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, installedMap, 0, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusForbidden {
		return nil, installedMap, http.StatusForbidden, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, installedMap, resp.StatusCode, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var checkinResp types.CheckinResponse
	if err := json.Unmarshal(bodyBytes, &checkinResp); err != nil {
		return nil, installedMap, resp.StatusCode, fmt.Errorf("decode checkin response: %w", err)
	}
	return &checkinResp, installedMap, http.StatusOK, nil
}

func executePoliciesAndCleanup(
	ctx context.Context,
	policies []types.AssignedPolicy,
	revokedPolicies []types.AssignedPolicy,
	installedPkgs map[string]bool,
) []types.PolicyExecutionItem {
	cleanupItems, cleanupDconfModified := engine.CleanupOrphanedPolicies(ctx, policies, revokedPolicies)
	results := make([]types.PolicyExecutionItem, 0, len(policies)+len(cleanupItems))
	results = append(results, cleanupItems...)

	_, installedFlatpaks := engine.GetInstalledFlatpaks(ctx)

	var dconfIndices []int
	dconfNeedsUpdate := cleanupDconfModified

	for _, pol := range policies {
		log.Printf("[spired] evaluating policy id=%s name=%q type=%s", pol.ID, pol.Name, pol.PolicyType)
		var item types.PolicyExecutionItem
		switch pol.PolicyType {
		case types.PolicyTypePackageAbsence:
			item = engine.ReconcilePackageAbsence(ctx, pol, installedPkgs)
		case types.PolicyTypePackagePresence:
			item = engine.ReconcilePackagePresence(ctx, pol, installedPkgs)
		case types.PolicyTypeDconfSetting:
			var drifted bool
			item, drifted = engine.ReconcileDconfSetting(ctx, pol)
			if drifted {
				dconfNeedsUpdate = true
			}
			dconfIndices = append(dconfIndices, len(results))
		case types.PolicyTypeSystemdService:
			item = engine.EnforceSystemdServicePolicy(ctx, pol)
		case types.PolicyTypeFlatpakApp:
			item = engine.ReconcileFlatpakApp(ctx, pol, installedFlatpaks)
		case types.PolicyTypeFlatpakBundle:
			item = engine.ReconcileFlatpakBundle(ctx, pol, installedFlatpaks, nil, "", "")
		case types.PolicyTypeSysctlSetting:
			item = engine.EnforceSysctlPolicy(ctx, pol)
		case types.PolicyTypeAptConfig:
			item = engine.ReconcileAptConfig(ctx, pol)
		case types.PolicyTypeFirewallRuleset:
			item = engine.EnforceFirewallRuleset(ctx, pol)
		case types.PolicyTypeLocalAccountPolicy:
			item = engine.EnforceLocalAccountPolicy(ctx, pol)
		case types.PolicyTypeTrustedCACerts:
			item = engine.EnforceTrustedCACertificates(ctx, pol)
		case types.PolicyTypeNetworkProfile:
			item = engine.EnforceNetworkProfilePolicy(ctx, pol)
		case types.PolicyTypeUSBDeviceControl:
			item = engine.ReconcileUSBDeviceControl(ctx, pol)
		case types.PolicyTypeAuditdRules:
			item = engine.EnforceAuditdRulesPolicy(ctx, pol)
		default:
			out, _ := json.Marshal(map[string]string{"note": "unsupported policy type"})
			item = types.PolicyExecutionItem{
				PolicyID:         pol.ID,
				ComplianceStatus: types.ComplianceFailed,
				ErrorMessage:     fmt.Sprintf("unsupported policy_type: %s", pol.PolicyType),
				ExecutionOutput:  out,
			}
		}
		if pol.RequiresReboot && item.ComplianceStatus == types.ComplianceCompliant {
			_ = engine.MarkRebootRequired(ctx, fmt.Sprintf("Policy %q requires system reboot", pol.Name))
		}
		log.Printf("[spired] policy id=%s result=%s err=%q", pol.ID, item.ComplianceStatus, item.ErrorMessage)
		results = append(results, item)
	}

	if dconfNeedsUpdate {
		outStr, err := engine.RunDconfUpdate(ctx)
		if err != nil {
			log.Printf("[spired] dconf update failed: %v", err)
			for _, idx := range dconfIndices {
				if results[idx].ComplianceStatus == types.ComplianceCompliant {
					results[idx].ComplianceStatus = types.ComplianceFailed
					results[idx].ErrorMessage = err.Error()
				}
			}
		} else {
			log.Printf("[spired] dconf update completed (%s)", outStr)
		}
	}

	return results
}

func reportPolicyResults(ctx context.Context, client *http.Client, serverURL, token, hwUUID string, results []types.PolicyExecutionItem) error {
	payload, _ := json.Marshal(types.PolicyReportRequest{
		HardwareUUID: hwUUID,
		Results:      results,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/desktop/report", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("report failed with HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}
	return nil
}

func reportCommandResult(ctx context.Context, client *http.Client, serverURL, token string, report types.CommandReportRequest) error {
	payload, _ := json.Marshal(report)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/desktop/commands/report", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("command report failed with HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}
	return nil
}

func reportBenchmarkStatus(ctx context.Context, client *http.Client, serverURL, token string, report types.BenchmarkResultPayload) error {
	payload, _ := json.Marshal(report)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/desktop/benchmarks/report", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("benchmark report failed with HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}
	return nil
}

func readToken(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	tok := strings.Clone(strings.TrimSpace(string(data)))
	clear(data)
	return tok
}

// enrollmentKeyPath is where the agent keeps its enrollment key: next to the token file.
func enrollmentKeyPath(tokenPath string) string {
	return filepath.Join(filepath.Dir(tokenPath), "enrollment.key")
}

// loadOrCreateEnrollmentKey returns the agent's enrollment key, generating and storing a
// new random one (mode 0600) on first use. The key survives token loss, so an agent that
// is told to re-enroll proves it is the same installation that first staged the device.
func loadOrCreateEnrollmentKey(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		if k := strings.TrimSpace(string(b)); len(k) >= 32 {
			return k, nil
		}
	} else if !os.IsNotExist(err) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := cryptorand.Read(raw); err != nil {
		return "", err
	}
	key := hex.EncodeToString(raw)
	if err := persistToken(path, key); err != nil {
		return "", err
	}
	return key, nil
}

func persistToken(path, token string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	buf := []byte(strings.TrimSpace(token) + "\n")
	defer clear(buf)
	return os.WriteFile(path, buf, 0600)
}

func backoffWithJitter(attempt int, base time.Duration) time.Duration {
	if base <= 0 {
		base = 5 * time.Second
	}
	if attempt > 6 {
		attempt = 6
	}
	mult := time.Duration(1 << (attempt - 1))
	maxWait := base * mult
	if maxWait > 2*time.Minute {
		maxWait = 2 * time.Minute
	}
	jitter := time.Duration(rand.Int63n(int64(base)))
	return maxWait + jitter
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func sleepOrTrigger(ctx context.Context, d time.Duration, trigger <-chan struct{}) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-trigger:
		return true
	case <-t.C:
		return true
	}
}
