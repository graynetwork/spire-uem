package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/types"
)

// ResolveCampaignTargetDeviceIDs returns the device ids a campaign currently targets, before
// per-device work is computed. Targeting is the kind selection (group / cve / packages)
// intersected with the optional tag and ring limits. For a tag-scoped CREATOR, the target is
// additionally intersected with the creator's scope so a scoped admin can never target
// devices outside their tags.
func (r *Repository) ResolveCampaignTargetDeviceIDs(ctx context.Context, c *campaign.Campaign) ([]string, error) {
	var (
		clauses []string
		args    []any
	)
	add := func(cl string, a ...any) {
		clauses = append(clauses, cl)
		args = append(args, a...)
	}

	switch c.TargetKind {
	case campaign.TargetGroup:
		if strings.TrimSpace(c.GroupID) == "" {
			return nil, nil
		}
		args = append(args, c.GroupID)
		clauses = append(clauses, fmt.Sprintf("EXISTS (SELECT 1 FROM group_memberships gm WHERE gm.device_id = d.id AND gm.group_id = $%d::uuid)", len(args)))
	case campaign.TargetCVE:
		if len(c.CVEIDs) == 0 {
			return nil, nil
		}
		args = append(args, c.CVEIDs)
		clauses = append(clauses, fmt.Sprintf("EXISTS (SELECT 1 FROM device_cve_matches m WHERE m.device_id = d.id AND m.cve_id = ANY($%d::text[]) AND m.no_fix_available = false AND m.fixed_version <> '')", len(args)))
	case campaign.TargetPackages:
		// Devices that currently report any of the named source packages installed. Matched
		// against reported_state JSON source_packages; keep it simple and robust.
		if len(c.Packages) == 0 {
			return nil, nil
		}
		args = append(args, c.Packages)
		clauses = append(clauses, fmt.Sprintf(`EXISTS (
			SELECT 1 FROM jsonb_array_elements(COALESCE(d.reported_state->'source_packages','[]'::jsonb)) sp
			WHERE sp->>'s' = ANY($%d::text[]) OR sp->>'n' = ANY($%d::text[]))`, len(args), len(args)))
	default:
		return nil, fmt.Errorf("unknown target kind %q", c.TargetKind)
	}

	if len(c.TargetTags) > 0 {
		args = append(args, c.TargetTags)
		add(fmt.Sprintf("d.tags && $%d::text[]", len(args)))
	}
	if strings.TrimSpace(c.TargetRing) != "" {
		args = append(args, c.TargetRing)
		add(fmt.Sprintf("d.patch_ring = $%d::deployment_ring", len(args)))
	}
	// A tag-scoped creator's target is intersected with their scope.
	if len(c.CreatorScopedTags) > 0 {
		args = append(args, c.CreatorScopedTags)
		add(fmt.Sprintf("d.tags && $%d::text[]", len(args)))
	}
	// Only approved devices are targeted.
	clauses = append(clauses, "d.status = 'APPROVED'")

	q := `SELECT d.id FROM devices d WHERE ` + strings.Join(clauses, " AND ")
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("resolve campaign targets: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// deviceFactsFor loads the DeviceFacts a campaign work computation needs for one device.
func (r *Repository) deviceFactsFor(ctx context.Context, deviceID string) (campaign.DeviceFacts, error) {
	facts := campaign.DeviceFacts{DeviceID: deviceID, InstalledSource: map[string]string{}}
	dev, err := r.GetDeviceByID(ctx, deviceID)
	if err != nil || dev == nil {
		return facts, err
	}
	facts.Tags = dev.Tags
	if gids, err := r.GroupIDsForDevice(ctx, deviceID); err == nil {
		facts.GroupIDs = gids
	}
	if matches, err := r.ListDeviceCVEMatches(ctx, deviceID); err == nil {
		facts.CVEMatches = matches
	}
	// Installed source packages from reported_state.
	if len(dev.ReportedState) > 0 {
		var rep types.ReportedState
		if err := json.Unmarshal(dev.ReportedState, &rep); err == nil {
			for _, p := range rep.SourcePackages {
				src := strings.TrimSpace(p.Source)
				if src == "" {
					src = strings.TrimSpace(p.Name)
				}
				if src != "" {
					facts.InstalledSource[src] = p.SourceVersion
				}
			}
		}
	}
	return facts, nil
}

// MaterializeCampaignWorkForDevice recomputes and upserts one device's work for a campaign,
// applying active risk acceptances and exclusions. If the device is no longer in the target,
// its work is marked REMOVED (it stops being dispatched to). Called on the device's check-in
// and by the periodic campaign loop. Returns the device's work state after the update.
func (r *Repository) MaterializeCampaignWorkForDevice(ctx context.Context, c *campaign.Campaign, deviceID string, now time.Time) error {
	// Is the device still targeted?
	targets, err := r.ResolveCampaignTargetDeviceIDs(ctx, c)
	if err != nil {
		return err
	}
	inTarget := false
	for _, id := range targets {
		if id == deviceID {
			inTarget = true
			break
		}
	}
	if !inTarget {
		return r.MarkWorkRemoved(ctx, c.ID, deviceID)
	}
	facts, err := r.deviceFactsFor(ctx, deviceID)
	if err != nil {
		return err
	}
	acceptances, err := r.ListActiveRiskAcceptances(ctx, now)
	if err != nil {
		return err
	}
	work := campaign.ComputeWork(c, facts, acceptances, now)
	return r.UpsertCampaignWork(ctx, c.ID, deviceID, c.CurrentStage, work)
}
