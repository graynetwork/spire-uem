package db

import (
	"context"
	"fmt"
	"time"

	"github.com/spire-uem/spire-uem/internal/campaign"
	"github.com/spire-uem/spire-uem/internal/types"
)

// AnnotateFleetCVEsWithAcceptance marks fleet CVE rows covered by an ACTIVE risk acceptance.
// Findings are never removed: an accepted finding stays in the list with its reason and
// expiry. Only devices inside the caller's tag scope are considered, so a scoped admin's
// "accepted" counts reflect their own devices. An expired acceptance no longer matches, so
// the finding reverts to open automatically. The matching rule is campaign
// .MatchingRiskAcceptance, the same one that excludes work from campaigns.
//
// Fail-open for DISPLAY only: on an error the rows are returned unannotated (shown as open),
// which can only over-report risk, never hide a finding.
func (r *Repository) AnnotateFleetCVEsWithAcceptance(ctx context.Context, scope DeviceScope, cves []types.FleetCVE, now time.Time) error {
	if len(cves) == 0 {
		return nil
	}
	acc, err := r.ListActiveRiskAcceptances(ctx, now)
	if err != nil {
		return fmt.Errorf("annotate cves: %w", err)
	}
	if len(acc) == 0 {
		return nil
	}
	cveIDs := make([]string, 0, len(acc))
	pkgs := make([]string, 0, len(acc))
	for _, a := range acc {
		if a.CVEID != "" {
			cveIDs = append(cveIDs, a.CVEID)
		}
		if a.Package != "" {
			pkgs = append(pkgs, a.Package)
		}
	}
	scoped, tags := scope.sqlArgs()
	rows, err := r.pool.Query(ctx, `
		SELECT m.cve_id, m.device_id::text, COALESCE(m.source_package,''), d.tags,
		       COALESCE((SELECT array_agg(gm.group_id::text) FROM group_memberships gm WHERE gm.device_id = d.id), '{}')
		FROM device_cve_matches m
		JOIN devices d ON d.id = m.device_id
		WHERE (NOT $1::bool OR d.tags && $2::text[])
		  AND (UPPER(m.cve_id) = ANY(SELECT UPPER(x) FROM unnest($3::text[]) x) OR m.source_package = ANY($4::text[]))`,
		scoped, tags, cveIDs, pkgs)
	if err != nil {
		return fmt.Errorf("annotate cves: %w", err)
	}
	defer rows.Close()

	type agg struct {
		devices map[string]struct{}
		best    *campaign.RiskAcceptance
	}
	byCVE := map[string]*agg{}
	for rows.Next() {
		var cve, dev, src string
		var devTags, groups []string
		if err := rows.Scan(&cve, &dev, &src, &devTags, &groups); err != nil {
			return err
		}
		facts := campaign.DeviceFacts{DeviceID: dev, Tags: devTags, GroupIDs: groups}
		ra := campaign.MatchingRiskAcceptance(acc, now, facts, cve, src)
		if ra == nil {
			continue
		}
		a := byCVE[cve]
		if a == nil {
			a = &agg{devices: map[string]struct{}{}}
			byCVE[cve] = a
		}
		a.devices[dev] = struct{}{}
		if a.best == nil || ra.ExpiresAt.After(a.best.ExpiresAt) {
			a.best = ra
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range cves {
		a := byCVE[cves[i].CVEID]
		if a == nil {
			continue
		}
		cves[i].AcceptedHosts = len(a.devices)
		cves[i].Accepted = len(a.devices) >= cves[i].AffectedHosts
		cves[i].AcceptedReason = a.best.Reason
		exp := a.best.ExpiresAt
		cves[i].AcceptedUntil = &exp
		cves[i].AcceptedBy = a.best.CreatedBy
	}
	return nil
}
