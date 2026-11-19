package db

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spire-uem/spire-uem/internal/campaign"
)

// ListCampaignWork returns the per-device work rows for a campaign, scoped to the admin's
// tags, joined with hostname/tags for the UI and CSV/JSON export.
func (r *Repository) ListCampaignWork(ctx context.Context, campaignID string, scope DeviceScope) ([]campaign.DeviceWorkRow, error) {
	scoped, tags := scope.sqlArgs()
	rows, err := r.pool.Query(ctx, `
		SELECT w.device_id, d.hostname, d.tags, w.stage, w.state, w.failure_class, w.work,
		       w.deferrals_used, w.reboot_required, w.updated_at
		FROM campaign_device_work w
		JOIN devices d ON d.id = w.device_id
		WHERE w.campaign_id = $1 AND (NOT $2::bool OR d.tags && $3::text[])
		ORDER BY w.stage ASC, d.hostname ASC`, campaignID, scoped, tags)
	if err != nil {
		return nil, fmt.Errorf("list campaign work: %w", err)
	}
	defer rows.Close()
	out := make([]campaign.DeviceWorkRow, 0)
	for rows.Next() {
		var row campaign.DeviceWorkRow
		var workRaw []byte
		if err := rows.Scan(&row.DeviceID, &row.Hostname, &row.Tags, &row.Stage, &row.State,
			&row.FailureClass, &workRaw, &row.DeferralsUsed, &row.RebootRequired, &row.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(workRaw, &row.Work)
		if row.Tags == nil {
			row.Tags = []string{}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// CampaignReport builds the per-campaign report: device counts by (stage,state), failure
// classes, and completion timing.
//
// The counts are limited to devices inside scope, so a tag-scoped admin never sees how many
// devices outside their tags a campaign touched.
func (r *Repository) CampaignReport(ctx context.Context, campaignID string, scope DeviceScope) (*campaign.CampaignReport, error) {
	rep := &campaign.CampaignReport{CampaignID: campaignID}
	scoped, tags := scope.sqlArgs()

	rows, err := r.pool.Query(ctx, `
		SELECT w.stage, w.state, COUNT(*) FROM campaign_device_work w
		JOIN devices d ON d.id = w.device_id
		WHERE w.campaign_id=$1 AND (NOT $2::bool OR d.tags && $3::text[])
		GROUP BY w.stage, w.state ORDER BY w.stage, w.state`, campaignID, scoped, tags)
	if err != nil {
		return nil, fmt.Errorf("campaign report stage states: %w", err)
	}
	for rows.Next() {
		var s campaign.StageStateCount
		if err := rows.Scan(&s.Stage, &s.State, &s.Count); err != nil {
			rows.Close()
			return nil, err
		}
		rep.StageStates = append(rep.StageStates, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	frows, err := r.pool.Query(ctx, `
		SELECT w.failure_class, COUNT(*) FROM campaign_device_work w
		JOIN devices d ON d.id = w.device_id
		WHERE w.campaign_id=$1 AND w.failure_class <> '' AND (NOT $2::bool OR d.tags && $3::text[])
		GROUP BY w.failure_class ORDER BY COUNT(*) DESC`, campaignID, scoped, tags)
	if err != nil {
		return nil, fmt.Errorf("campaign report failure classes: %w", err)
	}
	for frows.Next() {
		var f campaign.FailureClassCount
		if err := frows.Scan(&f.Class, &f.Count); err != nil {
			frows.Close()
			return nil, err
		}
		rep.FailureClasses = append(rep.FailureClasses, f)
	}
	frows.Close()
	if err := frows.Err(); err != nil {
		return nil, err
	}
	return rep, nil
}

// CVEMeanTimeToRemediate returns, for a completed campaign, the mean hours between a device
// first matching a CVE and no longer matching it (work succeeded), per CVE. It reads the
// from_cve in each device's work and the resolved_at of successful work rows.
func (r *Repository) CVEMeanTimeToRemediate(ctx context.Context, campaignID string) ([]campaign.CVERemediation, error) {
	// Expand each successful work row's work[] into (cve, hours-to-resolve) and average.
	rows, err := r.pool.Query(ctx, `
		SELECT elem->>'from_cve' AS cve,
		       EXTRACT(EPOCH FROM (w.resolved_at - w.first_matched_at)) / 3600.0 AS hours
		FROM campaign_device_work w,
		     LATERAL jsonb_array_elements(w.work) AS elem
		WHERE w.campaign_id=$1 AND w.state='SUCCEEDED' AND w.resolved_at IS NOT NULL
		  AND COALESCE(elem->>'from_cve','') <> ''`, campaignID)
	if err != nil {
		return nil, fmt.Errorf("cve mttr: %w", err)
	}
	defer rows.Close()
	type agg struct {
		n   int
		sum float64
	}
	byCVE := map[string]*agg{}
	for rows.Next() {
		var cve string
		var hours float64
		if err := rows.Scan(&cve, &hours); err != nil {
			return nil, err
		}
		a := byCVE[cve]
		if a == nil {
			a = &agg{}
			byCVE[cve] = a
		}
		a.n++
		a.sum += hours
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]campaign.CVERemediation, 0, len(byCVE))
	for cve, a := range byCVE {
		mean := 0.0
		if a.n > 0 {
			mean = a.sum / float64(a.n)
		}
		out = append(out, campaign.CVERemediation{CVEID: cve, DevicesFixed: a.n, MeanHoursToFix: mean})
	}
	return out, nil
}
