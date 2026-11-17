package db

import (
	"context"
	"fmt"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/types"
)

// ListActiveCampaigns returns every campaign in the RUNNING state. The periodic evaluation
// loop and the check-in dispatch path both read this. A DRAFT/PAUSED/HALTED/terminal
// campaign dispatches nothing, so it is intentionally excluded here rather than filtered
// again by every caller.
func (r *Repository) ListActiveCampaigns(ctx context.Context) ([]campaign.Campaign, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+campaignColumns+` FROM patch_campaigns WHERE state='RUNNING' ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("list active campaigns: %w", err)
	}
	defer rows.Close()
	out := make([]campaign.Campaign, 0)
	for rows.Next() {
		c, err := scanCampaign(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// DeviceMaintenanceWindowActive reports whether the device currently has ANY active patch
// maintenance window. A campaign with RespectMaintenanceWindow set dispatches only while
// this is true. A device with no patch window attached to any assigned policy is treated as
// "always in window" (there is no window to wait for), matching how the per-policy dispatch
// treats an empty cron. Fail-closed on a query error: the caller holds work until the next
// check-in rather than dispatching outside a window it could not read.
func (r *Repository) DeviceMaintenanceWindowActive(ctx context.Context, deviceID string, now time.Time) (bool, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT COALESCE(pw.cron_expression,''), COALESCE(pw.duration_minutes,120)
		FROM policies p
		JOIN devices d ON d.id = $1
		JOIN patch_windows pw ON pw.id = p.patch_window_id
		WHERE p.is_active = true
		  AND (p.target_tags = '{}' OR p.target_tags && d.tags)
		  AND (p.target_ring IS NULL OR p.target_ring = d.patch_ring)`, deviceID)
	if err != nil {
		return false, fmt.Errorf("device maintenance windows: %w", err)
	}
	defer rows.Close()
	any := false
	for rows.Next() {
		var cron string
		var dur int
		if err := rows.Scan(&cron, &dur); err != nil {
			return false, err
		}
		if cron == "" {
			continue
		}
		any = true
		if IsMaintenanceWindowActive(cron, dur, now) {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	// No window configured anywhere => nothing to wait for.
	return !any, nil
}

// DispatchCampaignDirectivesForDevice is the check-in hook: for every RUNNING campaign, it
// refreshes this device's work, applies the campaign-level and device-level gates, then
// atomically claims any dispatchable work and returns it as directives the agent executes.
//
// Gates applied, in order (any failing gate yields no directive for that campaign):
//   - campaign is RUNNING and not in a blackout window (campaign.EvaluateDispatchGate);
//   - the campaign's active stage includes the device's ring (campaign.StageIncludesRing) —
//     a PRODUCTION device gets nothing while a campaign is still in its CANARY stage;
//   - if the campaign respects maintenance windows, the device is currently in one;
//   - the device's work row is PENDING for the active stage with a non-empty work list; the
//     claim (ClaimCampaignDispatch) flips exactly one of two racing instances to DISPATCHED.
//
// Deferral/deadline are resolved per campaign so the agent is told whether the user may
// still defer (the server owns that decision). The work is materialised first, so a device
// that left the target is marked REMOVED and gets nothing. Best-effort per campaign: a
// per-campaign failure skips that campaign and continues, never failing the check-in.
func (r *Repository) DispatchCampaignDirectivesForDevice(ctx context.Context, dev *types.Device, now time.Time) ([]types.CampaignDirective, error) {
	if dev == nil || dev.Status != types.StatusApproved {
		return nil, nil
	}
	campaigns, err := r.ListActiveCampaigns(ctx)
	if err != nil {
		return nil, err
	}
	var directives []types.CampaignDirective
	for i := range campaigns {
		c := &campaigns[i]

		// Campaign-level gate: running + not in blackout.
		if g := campaign.EvaluateDispatchGate(c, now, IsMaintenanceWindowActive); !g.Allowed {
			continue
		}
		// Ring gate: the active stage must include this device's ring.
		if !c.StageIncludesRing(string(dev.PatchRing)) {
			continue
		}
		// Refresh this device's work for the campaign (REMOVED if it left the target, work
		// recomputed from current CVE matches / packages, risk acceptances applied).
		if err := r.MaterializeCampaignWorkForDevice(ctx, c, dev.ID, now); err != nil {
			// Skip this campaign; a single device/campaign failure must not fail the check-in.
			continue
		}
		// Maintenance-window gate (device level), only when the campaign opts in.
		if c.RespectMaintenanceWindow {
			inWindow, werr := r.DeviceMaintenanceWindowActive(ctx, dev.ID, now)
			if werr != nil || !inWindow {
				continue
			}
		}
		// Atomically claim PENDING work for the active stage. Returns false when there is
		// nothing to dispatch (wrong state/stage, empty work, or another instance won).
		work, claimed, cerr := r.ClaimCampaignDispatch(ctx, c.ID, dev.ID, c.CurrentStage)
		if cerr != nil || !claimed {
			continue
		}
		// Resolve the deferral/deadline state the agent is told about (server owns it).
		deferralsUsed := r.deferralsUsed(ctx, c.ID, dev.ID)
		mayDefer := c.MayDeferAt(deferralsUsed, now)
		left := c.MaxDeferrals - deferralsUsed
		if left < 0 {
			left = 0
		}
		directives = append(directives, types.CampaignDirective{
			CampaignID:     c.ID,
			Name:           c.Name,
			Packages:       toDirectivePackages(work),
			RebootPolicy:   string(c.RebootPolicy),
			MayDefer:       mayDefer,
			DeferralsLeft:  left,
			DeadlinePassed: c.DeadlinePassed(now),
		})
	}
	return directives, nil
}

// deferralsUsed reads a device's current deferral count for a campaign (0 if no row).
func (r *Repository) deferralsUsed(ctx context.Context, campaignID, deviceID string) int {
	var n int
	_ = r.pool.QueryRow(ctx, `SELECT deferrals_used FROM campaign_device_work WHERE campaign_id=$1 AND device_id=$2`, campaignID, deviceID).Scan(&n)
	return n
}

// toDirectivePackages converts the server-side work list to the wire form the agent reads.
func toDirectivePackages(work []campaign.PackageWork) []types.CampaignPackageWork {
	out := make([]types.CampaignPackageWork, 0, len(work))
	for _, w := range work {
		out = append(out, types.CampaignPackageWork{Package: w.Package, Target: w.Target, FromCVE: w.FromCVE})
	}
	return out
}

// MaterializeCampaignWork refreshes the work rows for EVERY device the campaign targets whose
// ring is included in the active stage, so the evaluation loop sees the whole stage and not
// just devices that happened to check in. Without it a freshly promoted stage would look empty
// (and be declared complete) before its devices had checked in.
//
// It also retires rows that no longer apply: a device that left the target (group change, tag
// change, revoked) has its non-terminal row marked REMOVED, and so does a targeted device
// whose ring is not in the active stage but which holds a non-terminal row for it. Terminal
// results are kept for reporting. Returns the number of devices materialized.
func (r *Repository) MaterializeCampaignWork(ctx context.Context, c *campaign.Campaign, now time.Time) (int, error) {
	targets, err := r.ResolveCampaignTargetDeviceIDs(ctx, c)
	if err != nil {
		return 0, err
	}
	acceptances, err := r.ListActiveRiskAcceptances(ctx, now)
	if err != nil {
		return 0, err
	}
	eligible := make([]string, 0, len(targets))
	n := 0
	for _, id := range targets {
		dev, derr := r.GetDeviceByID(ctx, id)
		if derr != nil || dev == nil {
			continue
		}
		if !c.StageIncludesRing(string(dev.PatchRing)) {
			continue
		}
		eligible = append(eligible, id)
		facts, ferr := r.deviceFactsFor(ctx, id)
		if ferr != nil {
			return n, ferr
		}
		work := campaign.ComputeWork(c, facts, acceptances, now)
		if uerr := r.UpsertCampaignWork(ctx, c.ID, id, c.CurrentStage, work); uerr != nil {
			return n, uerr
		}
		n++
	}
	if targets == nil {
		targets = []string{}
	}
	// Left the target entirely: retire any non-terminal row.
	if _, err := r.pool.Exec(ctx, `
		UPDATE campaign_device_work SET state='REMOVED', updated_at=NOW()
		WHERE campaign_id=$1 AND state IN ('PENDING','DISPATCHED','EXCLUDED')
		  AND NOT (device_id = ANY($2::uuid[]))`, c.ID, targets); err != nil {
		return n, fmt.Errorf("retire removed devices: %w", err)
	}
	// Targeted but outside the active stage's ring: retire unstarted rows for this stage.
	if _, err := r.pool.Exec(ctx, `
		UPDATE campaign_device_work SET state='REMOVED', updated_at=NOW()
		WHERE campaign_id=$1 AND stage=$3 AND state IN ('PENDING','EXCLUDED')
		  AND device_id = ANY($2::uuid[]) AND NOT (device_id = ANY($4::uuid[]))`,
		c.ID, targets, c.CurrentStage, nonNil(eligible)); err != nil {
		return n, fmt.Errorf("retire out-of-ring devices: %w", err)
	}
	return n, nil
}
