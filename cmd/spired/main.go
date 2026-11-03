package main

import (
	"bytes"
	"context"
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
	"syscall"
	"time"

	"github.com/spire-uem/spire-uem/internal/config"
	"github.com/spire-uem/spire-uem/internal/engine"
	"github.com/spire-uem/spire-uem/internal/inventory"
	"github.com/spire-uem/spire-uem/internal/types"
)

func main() {
	configPath := flag.String("config", "", "Path to YAML configuration file")
	once := flag.Bool("once", false, "Run a single check-in/enforcement cycle and exit")
	flag.Parse()

	cfg := config.Load(*configPath)

	hwUUID, err := inventory.GetHardwareUUID()
	if err != nil {
		log.Fatalf("[spired] failed to determine hardware UUID: %v", err)
	}
	hostname := inventory.GetHostname()
	log.Printf("[spired] starting daemon hardware_uuid=%s hostname=%s server=%s", hwUUID, hostname, cfg.Agent.ServerURL)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client := &http.Client{Timeout: 4 * time.Second}
	backoffAttempt := 0

	for {
		select {
		case <-ctx.Done():
			log.Printf("[spired] shutting down")
			return
		default:
		}

		token := readToken(cfg.Agent.TokenPath)
		if token == "" {
			enrolledToken, netErr := enrollAndPoll(ctx, client, cfg.Agent.ServerURL, hwUUID, hostname)
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

		checkinResp, installedPkgs, statusCode, err := performCheckin(ctx, client, cfg.Agent.ServerURL, token, hwUUID, hostname)
		if err != nil {
			log.Printf("[WARN] Server unreachable; falling back to local policy cache (%v)", err)
			cached, cacheErr := engine.LoadPolicyCache(engine.DefaultPolicyCachePath)
			if cacheErr != nil {
				log.Printf("[spired] unable to load local policy cache %s: %v", engine.DefaultPolicyCachePath, cacheErr)
			} else {
				results := executePoliciesAndCleanup(ctx, cached.Policies, cached.RevokedPolicies, installedPkgs)
				if qErr := engine.QueuePendingReports(engine.DefaultPendingReportsPath, results); qErr != nil {
					log.Printf("[spired] failed to buffer offline compliance reports: %v", qErr)
				} else {
					log.Printf("[spired] offline reconciliation complete: reconciled %d cached policies, buffered %d reports in %s",
						len(cached.Policies), len(results), engine.DefaultPendingReportsPath)
				}
			}

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
			log.Printf("[spired] server returned HTTP 403 Forbidden on check-in; clearing token and staging enrollment")
			_ = os.Remove(cfg.Agent.TokenPath)
			if *once {
				return
			}
			if !sleepContext(ctx, cfg.Agent.PollInterval) {
				return
			}
			continue
		}

		if checkinResp != nil {
			if err := engine.SavePolicyCache(engine.DefaultPolicyCachePath, checkinResp); err != nil {
				log.Printf("[spired] warning: failed to update local policy cache %s: %v", engine.DefaultPolicyCachePath, err)
			}

			pendingReports, _ := engine.LoadPendingReports(engine.DefaultPendingReportsPath)
			results := executePoliciesAndCleanup(ctx, checkinResp.Policies, checkinResp.RevokedPolicies, installedPkgs)
			allResults := engine.MergeReports(pendingReports, results)

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
					log.Printf("[spired] executing diagnostic command id=%s cmd=%q", cmdDTO.ID, cmdDTO.Command)
					cmdReport := engine.ExecuteDiagnosticCommand(ctx, cmdDTO, 30*time.Second)
					if err := reportCommandResult(ctx, client, cfg.Agent.ServerURL, token, cmdReport); err != nil {
						log.Printf("[spired] failed to report command result id=%s: %v", cmdDTO.ID, err)
					} else {
						log.Printf("[spired] reported command id=%s status=%s exit=%d", cmdDTO.ID, cmdReport.Status, cmdReport.ExitCode)
					}
				}
			}
		}

		if *once {
			return
		}

		if !sleepContext(ctx, cfg.Agent.CheckinInterval) {
			return
		}
	}
}

func enrollAndPoll(ctx context.Context, client *http.Client, serverURL, hwUUID, hostname string) (string, error) {
	reqBody, _ := json.Marshal(types.EnrollRequest{
		HardwareUUID: hwUUID,
		Hostname:     hostname,
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
	activeSession, _ := inventory.GetActiveSession()

	payload, _ := json.Marshal(types.CheckinRequest{
		HardwareUUID:  hwUUID,
		Hostname:      hostname,
		Packages:      pkgs,
		ActiveSession: activeSession,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/api/v1/desktop/checkin", bytes.NewReader(payload))
	if err != nil {
		return nil, installedMap, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
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
		default:
			out, _ := json.Marshal(map[string]string{"note": "unsupported policy type"})
			item = types.PolicyExecutionItem{
				PolicyID:         pol.ID,
				ComplianceStatus: types.ComplianceFailed,
				ErrorMessage:     fmt.Sprintf("unsupported policy_type: %s", pol.PolicyType),
				ExecutionOutput:  out,
			}
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

func readToken(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func persistToken(path, token string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.TrimSpace(token)+"\n"), 0600)
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
