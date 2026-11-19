package posture

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/crypto"
	"github.com/spire-uem/spire-uem/internal/db"
	"github.com/spire-uem/spire-uem/internal/types"
	"github.com/spire-uem/spire-uem/internal/workflows"
)

// Config tunes the service.
type Config struct {
	// Interval between fleet sweeps (default 5 minutes).
	Interval time.Duration
	// Validity of a verdict (default 3x Interval, at least DefaultValidity).
	Validity time.Duration
	// Now is the clock (tests).
	Now func() time.Time
}

// Service evaluates devices and writes device_posture. It is the only writer.
type Service struct {
	repo  *db.Repository
	cfg   Config
	owner string
}

// New builds a Service with defaults applied.
func New(repo *db.Repository, cfg Config) *Service {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	if cfg.Validity <= 0 {
		cfg.Validity = 3 * cfg.Interval
		if cfg.Validity < DefaultValidity {
			cfg.Validity = DefaultValidity
		}
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	host, _ := os.Hostname()
	return &Service{repo: repo, cfg: cfg, owner: fmt.Sprintf("%s/%d", host, os.Getpid())}
}

// Hook returns the callback to install with repo.SetPostureHook.
func (s *Service) Hook() db.PostureHook {
	return func(ctx context.Context, deviceID string) {
		if err := s.EvaluateDevice(ctx, deviceID); err != nil {
			log.Printf("[posture] immediate evaluation of %s failed: %v", deviceID, err)
		}
	}
}

// loadFacts gathers only the facts the enabled checks need. Any error is returned so the
// caller can fail closed.
func (s *Service) loadFacts(ctx context.Context, id string, rs types.AccessRuleSet, now time.Time) (Facts, error) {
	var f Facts
	dev, err := s.repo.GetDeviceByID(ctx, id)
	if err != nil {
		return f, fmt.Errorf("device: %w", err)
	}
	if dev == nil {
		return f, errDeviceGone
	}
	f.DeviceID = dev.ID
	f.Approved = dev.Status == types.StatusApproved
	f.LastCheckinAt = dev.LastCheckinAt
	if f.Lost, err = s.repo.DeviceIsLost(ctx, id); err != nil {
		return f, err
	}
	if f.Quarantine, err = s.repo.GetActiveQuarantine(ctx, id); err != nil {
		return f, err
	}

	if rs.AttestationTrusted.Enabled {
		maxAge, err := s.repo.AttestationMaxAge(ctx)
		if err != nil {
			return f, fmt.Errorf("attestation max age: %w", err)
		}
		latest, err := s.repo.GetLatestAttestationResult(ctx, id)
		if err != nil {
			return f, fmt.Errorf("attestation result: %w", err)
		}
		exc, err := s.repo.GetActiveBaselineException(ctx, id)
		if err != nil {
			return f, fmt.Errorf("attestation exception: %w", err)
		}
		f.Trust = crypto.EvaluateTrust(latest, exc, maxAge, now)
	}
	if rs.DiskEncrypted.Enabled {
		attrs, err := s.repo.GetDeviceAttributes(ctx, id)
		if err != nil {
			return f, fmt.Errorf("attributes: %w", err)
		}
		for _, a := range attrs {
			if a.Key == db.KeyHWDiskEncrypted {
				v := strings.TrimSpace(string(a.Value)) == "true"
				f.DiskEncrypted = &v
			}
		}
	}
	if rs.PoliciesCompliant.Enabled {
		details, err := s.repo.GetDevicePolicyDetails(ctx, id)
		if err != nil {
			return f, fmt.Errorf("policies: %w", err)
		}
		for _, d := range details {
			f.Policies = append(f.Policies, PolicyFact{Name: d.PolicyName, Status: d.ComplianceStatus})
		}
	}
	if rs.PatchesCurrent.Enabled {
		if f.Patch, err = s.repo.GetDevicePatchStatus(ctx, id); err != nil {
			return f, fmt.Errorf("patch status: %w", err)
		}
	}
	if rs.NoCriticalCVEs.Enabled {
		matches, err := s.repo.ListDeviceCVEMatches(ctx, id)
		if err != nil {
			return f, fmt.Errorf("cve matches: %w", err)
		}
		acc, err := s.repo.ListActiveRiskAcceptances(ctx, now)
		if err != nil {
			return f, fmt.Errorf("risk acceptances: %w", err)
		}
		groups, err := s.repo.DeviceGroupIDs(ctx, id)
		if err != nil {
			return f, err
		}
		cf := campaign.DeviceFacts{DeviceID: id, Tags: dev.Tags, GroupIDs: groups}
		for _, m := range matches {
			ra := campaign.MatchingRiskAcceptance(acc, now, cf, m.CVEID, m.SourcePackage)
			f.CVEs = append(f.CVEs, CVEFact{ID: m.CVEID, Package: m.SourcePackage, Urgency: m.Urgency, Accepted: ra != nil})
		}
	}
	if rs.GroupRule.Enabled {
		if f.GroupRuleMatch, err = s.repo.DeviceMatchesRule(ctx, rs.GroupRule.Rule, id); err != nil {
			return f, fmt.Errorf("group rule: %w", err)
		}
	}
	return f, nil
}

var errDeviceGone = errors.New("device not found")

// EvaluateDevice computes and stores one device's verdict and emits posture_changed on a
// real transition. On any error it stores an UNKNOWN verdict (never COMPLIANT) and returns
// the error.
func (s *Service) EvaluateDevice(ctx context.Context, id string) error {
	now := s.cfg.Now()
	rs, err := s.repo.GetAccessRuleSet(ctx)
	if err != nil {
		s.storeUnknown(ctx, id, 0, "rule_set", now)
		return err
	}
	f, err := s.loadFacts(ctx, id, rs, now)
	if err != nil {
		if errors.Is(err, errDeviceGone) {
			return nil
		}
		s.storeUnknown(ctx, id, rs.Version, "load_facts", now)
		return err
	}
	return s.store(ctx, Evaluate(f, rs, now, s.cfg.Validity))
}

func (s *Service) storeUnknown(ctx context.Context, id string, version int, class string, now time.Time) {
	if err := s.store(ctx, UnknownOnError(id, version, class, now, s.cfg.Validity)); err != nil {
		log.Printf("[posture] could not store UNKNOWN verdict for %s: %v", id, err)
	}
}

func (s *Service) store(ctx context.Context, p types.DevicePosture) error {
	prior, err := s.repo.GetDevicePosture(ctx, p.DeviceID)
	if err != nil {
		return err
	}
	prev, err := s.repo.UpsertDevicePosture(ctx, &p)
	if err != nil {
		return err
	}
	// The first verdict a device ever gets is not a transition. Afterwards the event fires
	// only when the stored state changes; UpsertDevicePosture locks the row, so of two
	// concurrent evaluators only the one that actually changes the state sees prev != new.
	if prior != nil && prev != p.State {
		s.repo.EmitEvent(ctx, workflows.EventPostureChanged, p.DeviceID, map[string]any{
			"from": string(prev), "to": string(p.State), "reasons": p.Reasons,
		}, false)
	}
	return nil
}

// EvaluateAll evaluates every device. Per-device errors are logged and do not stop the sweep.
func (s *Service) EvaluateAll(ctx context.Context) (n int, failed int) {
	ids, err := s.repo.ListAllDeviceIDs(ctx)
	if err != nil {
		log.Printf("[posture] sweep: list devices: %v", err)
		return 0, 0
	}
	for _, id := range ids {
		if ctx.Err() != nil {
			return n, failed
		}
		n++
		if err := s.EvaluateDevice(ctx, id); err != nil {
			failed++
			log.Printf("[posture] evaluate %s: %v", id, err)
		}
	}
	return n, failed
}

// Sweep runs one fleet sweep if this instance wins the DB claim.
func (s *Service) Sweep(ctx context.Context) bool {
	hold := s.cfg.Interval - 5*time.Second
	if hold < 10*time.Second {
		hold = 10 * time.Second
	}
	ok, err := s.repo.ClaimPostureSweep(ctx, s.owner, hold)
	if err != nil {
		log.Printf("[posture] sweep claim: %v", err)
		return false
	}
	if !ok {
		return false
	}
	n, failed := s.EvaluateAll(ctx)
	if failed > 0 {
		log.Printf("[posture] sweep: %d devices, %d failed", n, failed)
	}
	return true
}

// Run sweeps every Interval until ctx ends. Safe on every server instance.
func (s *Service) Run(ctx context.Context) {
	select {
	case <-ctx.Done():
		return
	case <-time.After(15 * time.Second):
	}
	s.Sweep(ctx)
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Sweep(ctx)
		}
	}
}

// EvaluateFleetAsync re-evaluates every device in the background (after a rule-set edit).
// It bypasses the sweep claim: per-device writes are idempotent and event emission is
// transition-only, so concurrent runs cannot duplicate events.
func (s *Service) EvaluateFleetAsync() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		s.EvaluateAll(ctx)
	}()
}

// EvaluateDeviceAsync is the check-in entry point: it must never fail or slow a check-in.
func (s *Service) EvaluateDeviceAsync(id string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := s.EvaluateDevice(ctx, id); err != nil {
			log.Printf("[posture] check-in evaluation of %s failed: %v", id, err)
		}
	}()
}
