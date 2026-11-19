package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/campaign"
)

// campaignColumns is the fixed column list for patch_campaigns.
const campaignColumns = `id, name, description, state, target_kind,
	COALESCE(group_id::text,''), COALESCE(cve_ids,'{}'), COALESCE(packages,'{}'),
	COALESCE(target_tags,'{}'), COALESCE(target_ring,''), stages, current_stage,
	reboot_policy, max_deferrals, deadline_at, blackout_cron, blackout_duration_minutes,
	respect_maintenance_window, COALESCE(package_exclusions,'{}'),
	COALESCE(creator_scoped_tags,'{}'), created_by, stage_entered_at, soak_started_at,
	halted_reason, created_at, updated_at`

func scanCampaign(row pgx.Row) (*campaign.Campaign, error) {
	var c campaign.Campaign
	var groupID, targetRing string
	var stagesRaw []byte
	if err := row.Scan(
		&c.ID, &c.Name, &c.Description, &c.State, &c.TargetKind,
		&groupID, &c.CVEIDs, &c.Packages,
		&c.TargetTags, &targetRing, &stagesRaw, &c.CurrentStage,
		&c.RebootPolicy, &c.MaxDeferrals, &c.DeadlineAt, &c.BlackoutCron, &c.BlackoutDurationMinutes,
		&c.RespectMaintenanceWindow, &c.PackageExclusions,
		&c.CreatorScopedTags, &c.CreatedBy, &c.StageEnteredAt, &c.SoakStartedAt,
		&c.HaltedReason, &c.CreatedAt, &c.UpdatedAt,
	); err != nil {
		return nil, err
	}
	c.GroupID = groupID
	c.TargetRing = targetRing
	stages, err := campaign.UnmarshalStages(stagesRaw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal stages: %w", err)
	}
	c.Stages = stages
	return &c, nil
}

// CreateCampaign inserts a new campaign in DRAFT. The caller has validated stages, packages
// and target. creatorScopedTags carries the creating admin's scope (nil for unscoped).
func (r *Repository) CreateCampaign(ctx context.Context, c *campaign.Campaign) (*campaign.Campaign, error) {
	stagesJSON, err := campaign.MarshalStages(c.Stages)
	if err != nil {
		return nil, fmt.Errorf("marshal stages: %w", err)
	}
	var groupID any
	if strings.TrimSpace(c.GroupID) != "" {
		groupID = c.GroupID
	}
	var ring any
	if strings.TrimSpace(c.TargetRing) != "" {
		ring = c.TargetRing
	}
	const q = `
		INSERT INTO patch_campaigns
			(name, description, state, target_kind, group_id, cve_ids, packages, target_tags,
			 target_ring, stages, current_stage, reboot_policy, max_deferrals, deadline_at,
			 blackout_cron, blackout_duration_minutes, respect_maintenance_window,
			 package_exclusions, creator_scoped_tags, created_by)
		VALUES ($1,$2,'DRAFT',$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		RETURNING ` + campaignColumns
	return scanCampaign(r.pool.QueryRow(ctx, q,
		strings.TrimSpace(c.Name), strings.TrimSpace(c.Description), string(c.TargetKind), groupID,
		nonNil(c.CVEIDs), nonNil(c.Packages), nonNil(c.TargetTags), ring, string(stagesJSON),
		c.CurrentStage, string(c.RebootPolicy), c.MaxDeferrals, c.DeadlineAt, c.BlackoutCron,
		c.BlackoutDurationMinutes, c.RespectMaintenanceWindow, nonNil(c.PackageExclusions),
		nonNil(c.CreatorScopedTags), c.CreatedBy,
	))
}

// GetCampaign returns one campaign, or nil if not found.
func (r *Repository) GetCampaign(ctx context.Context, id string) (*campaign.Campaign, error) {
	c, err := scanCampaign(r.pool.QueryRow(ctx, `SELECT `+campaignColumns+` FROM patch_campaigns WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get campaign: %w", err)
	}
	return c, nil
}

// ListCampaigns returns campaigns visible to the given scope. An unscoped scope sees all.
// A tag-scoped admin sees only campaigns they created within their scope (creator_scoped_tags
// overlaps their tags) OR campaigns whose target_tags overlap their scope — never an unscoped
// admin's fleet-wide campaign they cannot act on.
func (r *Repository) ListCampaigns(ctx context.Context, scope DeviceScope) ([]campaign.Campaign, error) {
	var (
		q    = `SELECT ` + campaignColumns + ` FROM patch_campaigns`
		args []any
	)
	if scope.Scoped {
		tags := scope.Tags
		if tags == nil {
			tags = []string{}
		}
		args = append(args, tags)
		q += ` WHERE (creator_scoped_tags && $1::text[] OR target_tags && $1::text[])`
	}
	q += ` ORDER BY created_at DESC`
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list campaigns: %w", err)
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

// CampaignVisibleToScope reports whether a scoped admin may see/act on a campaign.
func CampaignVisibleToScope(c *campaign.Campaign, scope DeviceScope) bool {
	if !scope.Scoped {
		return true
	}
	set := make(map[string]struct{}, len(scope.Tags))
	for _, t := range scope.Tags {
		set[t] = struct{}{}
	}
	for _, t := range c.CreatorScopedTags {
		if _, ok := set[t]; ok {
			return true
		}
	}
	for _, t := range c.TargetTags {
		if _, ok := set[t]; ok {
			return true
		}
	}
	return false
}

// UpdateCampaignLifecycle persists the mutable lifecycle fields (state, stage pointers, soak
// timing, halted reason). Definition fields are not changed here.
func (r *Repository) UpdateCampaignLifecycle(ctx context.Context, c *campaign.Campaign) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE patch_campaigns
		SET state=$2, current_stage=$3, stage_entered_at=$4, soak_started_at=$5,
		    halted_reason=$6, updated_at=NOW()
		WHERE id=$1`,
		c.ID, string(c.State), c.CurrentStage, c.StageEnteredAt, c.SoakStartedAt, c.HaltedReason)
	if err != nil {
		return fmt.Errorf("update campaign lifecycle: %w", err)
	}
	return nil
}

// SetCampaignState sets only the campaign state (pause/resume/cancel), clearing halted_reason
// when leaving HALTED.
func (r *Repository) SetCampaignState(ctx context.Context, id string, state campaign.CampaignState) error {
	clearHalt := ""
	if state != campaign.StateHalted {
		clearHalt = ", halted_reason=''"
	}
	_, err := r.pool.Exec(ctx, `UPDATE patch_campaigns SET state=$2`+clearHalt+`, updated_at=NOW() WHERE id=$1`, id, string(state))
	if err != nil {
		return fmt.Errorf("set campaign state: %w", err)
	}
	return nil
}

// RecordCampaignEvent appends a lifecycle event.
func (r *Repository) RecordCampaignEvent(ctx context.Context, campaignID, kind, actor, detail string, stage int) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO campaign_events (campaign_id, kind, actor, detail, stage)
		VALUES ($1,$2,$3,$4,$5)`,
		campaignID, kind, strings.TrimSpace(actor), detail, stage)
	return err
}

// ListCampaignEvents returns a campaign's lifecycle events, newest first.
func (r *Repository) ListCampaignEvents(ctx context.Context, campaignID string, limit int) ([]campaign.CampaignEventRow, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, kind, actor, detail, stage, created_at
		FROM campaign_events WHERE campaign_id=$1 ORDER BY id DESC LIMIT $2`, campaignID, limit)
	if err != nil {
		return nil, fmt.Errorf("list campaign events: %w", err)
	}
	defer rows.Close()
	out := make([]campaign.CampaignEventRow, 0)
	for rows.Next() {
		var e campaign.CampaignEventRow
		if err := rows.Scan(&e.ID, &e.Kind, &e.Actor, &e.Detail, &e.Stage, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- Risk acceptances ---

const riskColumns = `id, cve_id, package, scope_kind, COALESCE(group_id::text,''),
	COALESCE(tags,'{}'), reason, created_by, COALESCE(creator_scoped_tags,'{}'),
	created_at, expires_at`

func scanRisk(row pgx.Row) (*campaign.RiskAcceptance, error) {
	var ra campaign.RiskAcceptance
	var groupID string
	var creatorScoped []string
	if err := row.Scan(&ra.ID, &ra.CVEID, &ra.Package, &ra.ScopeKind, &groupID,
		&ra.Tags, &ra.Reason, &ra.CreatedBy, &creatorScoped, &ra.CreatedAt, &ra.ExpiresAt); err != nil {
		return nil, err
	}
	ra.GroupID = groupID
	return &ra, nil
}

// CreateRiskAcceptance inserts a risk acceptance. The service validates the 180-day cap and
// that at least one of CVE/package is set before calling.
func (r *Repository) CreateRiskAcceptance(ctx context.Context, ra *campaign.RiskAcceptance, creatorScopedTags []string) (*campaign.RiskAcceptance, error) {
	var groupID any
	if strings.TrimSpace(ra.GroupID) != "" {
		groupID = ra.GroupID
	}
	const q = `
		INSERT INTO risk_acceptances
			(cve_id, package, scope_kind, group_id, tags, reason, created_by, creator_scoped_tags, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING ` + riskColumns
	return scanRisk(r.pool.QueryRow(ctx, q,
		strings.TrimSpace(ra.CVEID), strings.TrimSpace(ra.Package), string(ra.ScopeKind), groupID,
		nonNil(ra.Tags), ra.Reason, ra.CreatedBy, nonNil(creatorScopedTags), ra.ExpiresAt))
}

// ListActiveRiskAcceptances returns all risk acceptances that have not expired at now.
func (r *Repository) ListActiveRiskAcceptances(ctx context.Context, now time.Time) ([]campaign.RiskAcceptance, error) {
	rows, err := r.pool.Query(ctx, `SELECT `+riskColumns+` FROM risk_acceptances WHERE expires_at > $1 ORDER BY created_at DESC`, now)
	if err != nil {
		return nil, fmt.Errorf("list active risk acceptances: %w", err)
	}
	defer rows.Close()
	out := make([]campaign.RiskAcceptance, 0)
	for rows.Next() {
		ra, err := scanRisk(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ra)
	}
	return out, rows.Err()
}

// ListAllRiskAcceptances returns every risk acceptance (including expired, shown struck out),
// scoped: an unscoped admin sees all; a scoped admin sees entries whose creator scope or tag
// scope overlaps theirs.
func (r *Repository) ListAllRiskAcceptances(ctx context.Context, scope DeviceScope) ([]campaign.RiskAcceptance, error) {
	var (
		q    = `SELECT ` + riskColumns + ` FROM risk_acceptances`
		args []any
	)
	if scope.Scoped {
		tags := scope.Tags
		if tags == nil {
			tags = []string{}
		}
		args = append(args, tags)
		q += ` WHERE (creator_scoped_tags && $1::text[] OR (scope_kind='tags' AND tags && $1::text[]))`
	}
	q += ` ORDER BY created_at DESC`
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list risk acceptances: %w", err)
	}
	defer rows.Close()
	out := make([]campaign.RiskAcceptance, 0)
	for rows.Next() {
		ra, err := scanRisk(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ra)
	}
	return out, rows.Err()
}

// DeleteRiskAcceptance removes a risk acceptance by id.
func (r *Repository) DeleteRiskAcceptance(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM risk_acceptances WHERE id=$1`, id)
	return err
}
