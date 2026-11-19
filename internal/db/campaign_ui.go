package db

import (
	"context"
	"fmt"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
)

// CampaignProgress is the per-campaign device tally shown on the campaign list. Counts only
// include devices inside the caller's scope, so a tag-scoped admin never learns how many
// out-of-scope devices a campaign has.
type CampaignProgress struct {
	CampaignID string
	Pending    int // PENDING and not currently deferred
	Deferred   int // PENDING with deferred_until in the future
	Dispatched int
	Succeeded  int
	Failed     int // FAILED, INTERRUPTED, UNSUPPORTED
	Other      int // REMOVED, EXCLUDED
	Total      int
	StartedAt  *time.Time // time of the first "start" event, nil until started
}

// CampaignProgressFor returns progress tallies for the given campaigns, scoped to the admin's
// tags. A campaign with no visible work rows still gets an entry (all zeros).
func (r *Repository) CampaignProgressFor(ctx context.Context, ids []string, scope DeviceScope) (map[string]CampaignProgress, error) {
	out := make(map[string]CampaignProgress, len(ids))
	for _, id := range ids {
		out[id] = CampaignProgress{CampaignID: id}
	}
	if len(ids) == 0 {
		return out, nil
	}
	scoped, tags := scope.sqlArgs()
	rows, err := r.pool.Query(ctx, `
		SELECT w.campaign_id::text,
		  COUNT(*) FILTER (WHERE w.state='PENDING' AND (w.deferred_until IS NULL OR w.deferred_until <= NOW())),
		  COUNT(*) FILTER (WHERE w.state='PENDING' AND w.deferred_until > NOW()),
		  COUNT(*) FILTER (WHERE w.state='DISPATCHED'),
		  COUNT(*) FILTER (WHERE w.state='SUCCEEDED'),
		  COUNT(*) FILTER (WHERE w.state IN ('FAILED','INTERRUPTED','UNSUPPORTED')),
		  COUNT(*) FILTER (WHERE w.state IN ('REMOVED','EXCLUDED')),
		  COUNT(*)
		FROM campaign_device_work w
		JOIN devices d ON d.id = w.device_id
		WHERE w.campaign_id::text = ANY($1::text[]) AND (NOT $2::bool OR d.tags && $3::text[])
		GROUP BY w.campaign_id`, ids, scoped, tags)
	if err != nil {
		return nil, fmt.Errorf("campaign progress: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p CampaignProgress
		if err := rows.Scan(&p.CampaignID, &p.Pending, &p.Deferred, &p.Dispatched, &p.Succeeded, &p.Failed, &p.Other, &p.Total); err != nil {
			return nil, err
		}
		out[p.CampaignID] = p
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()

	srows, err := r.pool.Query(ctx, `
		SELECT campaign_id::text, MIN(created_at) FROM campaign_events
		WHERE kind='start' AND campaign_id::text = ANY($1::text[]) GROUP BY campaign_id`, ids)
	if err != nil {
		return nil, fmt.Errorf("campaign started-at: %w", err)
	}
	defer srows.Close()
	for srows.Next() {
		var id string
		var t time.Time
		if err := srows.Scan(&id, &t); err != nil {
			return nil, err
		}
		p := out[id]
		p.StartedAt = &t
		out[id] = p
	}
	return out, srows.Err()
}

// CampaignPackageResultRow is one package outcome a device reported for a campaign. The
// Output field is untrusted device-supplied text.
type CampaignPackageResultRow struct {
	DeviceID    string
	Package     string
	State       campaign.PackageResultState
	FromVersion string
	ToVersion   string
	Output      string
}

// ListCampaignPackageResults returns the reported per-package results for a campaign, limited
// to devices inside the caller's scope (the same join ListCampaignWork uses).
func (r *Repository) ListCampaignPackageResults(ctx context.Context, campaignID string, scope DeviceScope) ([]CampaignPackageResultRow, error) {
	scoped, tags := scope.sqlArgs()
	rows, err := r.pool.Query(ctx, `
		SELECT p.device_id::text, p.package, p.state, p.from_version, p.to_version, p.output
		FROM campaign_package_results p
		JOIN devices d ON d.id = p.device_id
		WHERE p.campaign_id = $1 AND (NOT $2::bool OR d.tags && $3::text[])
		ORDER BY p.device_id, p.package`, campaignID, scoped, tags)
	if err != nil {
		return nil, fmt.Errorf("list campaign package results: %w", err)
	}
	defer rows.Close()
	out := make([]CampaignPackageResultRow, 0)
	for rows.Next() {
		var row CampaignPackageResultRow
		if err := rows.Scan(&row.DeviceID, &row.Package, &row.State, &row.FromVersion, &row.ToVersion, &row.Output); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// GetRiskAcceptanceScoped loads one risk acceptance if it is visible to the scope (same
// predicate as ListAllRiskAcceptances). It returns nil, nil when it does not exist or is out
// of scope, so callers cannot distinguish the two.
func (r *Repository) GetRiskAcceptanceScoped(ctx context.Context, id string, scope DeviceScope) (*campaign.RiskAcceptance, error) {
	tags := scope.Tags
	if tags == nil {
		tags = []string{}
	}
	rows, err := r.pool.Query(ctx, `SELECT `+riskColumns+` FROM risk_acceptances
		WHERE id::text = $1 AND (NOT $2::bool OR creator_scoped_tags && $3::text[]
		      OR (scope_kind='tags' AND tags && $3::text[]))`, id, scope.Scoped, tags)
	if err != nil {
		return nil, fmt.Errorf("get risk acceptance: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	return scanRisk(rows)
}
