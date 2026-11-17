package db

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/campaign"
)

// campaignPromotionLockBase is the advisory-lock keyspace base for per-campaign promotion so
// two server instances never promote/halt the same campaign at once, while different
// campaigns proceed in parallel. Distinct from the group recompute band.
const campaignPromotionLockBase = int64(0x636d_7000) // "cmp\0"

func hashCampaignID(id string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return h.Sum32() & 0x00FF_FFFF
}

// UpsertCampaignWork inserts or updates one device's computed work for a campaign. It sets
// the work list and stage, and for a brand-new row records first_matched_at. It never
// downgrades a terminal state back to PENDING on recompute: a device that already SUCCEEDED
// keeps that result unless the work materially changes. An empty work list marks the device
// EXCLUDED (nothing to do), unless it already has a terminal result.
func (r *Repository) UpsertCampaignWork(ctx context.Context, campaignID, deviceID string, stage int, work []campaign.PackageWork) error {
	workJSON, err := json.Marshal(nonNilWork(work))
	if err != nil {
		return fmt.Errorf("marshal work: %w", err)
	}
	state := campaign.WorkPending
	if len(work) == 0 {
		state = campaign.WorkExcluded
	}
	// Insert new, or refresh work for a non-terminal row. A terminal row is left alone.
	_, err = r.pool.Exec(ctx, `
		INSERT INTO campaign_device_work (campaign_id, device_id, stage, state, work)
		VALUES ($1,$2,$3,$4,$5::jsonb)
		ON CONFLICT (campaign_id, device_id) DO UPDATE SET
			work = EXCLUDED.work,
			stage = EXCLUDED.stage,
			state = CASE
				WHEN campaign_device_work.state IN ('SUCCEEDED','FAILED','INTERRUPTED','UNSUPPORTED') THEN campaign_device_work.state
				WHEN EXCLUDED.state = 'EXCLUDED' THEN 'EXCLUDED'
				WHEN campaign_device_work.state IN ('EXCLUDED','REMOVED') AND EXCLUDED.state = 'PENDING' THEN 'PENDING'
				ELSE campaign_device_work.state END,
			updated_at = NOW()`,
		campaignID, deviceID, stage, string(state), string(workJSON))
	if err != nil {
		return fmt.Errorf("upsert campaign work: %w", err)
	}
	return nil
}

// MarkWorkRemoved sets a device's work state to REMOVED (it left the target), so it is no
// longer dispatched to and drops out of stage math. Only non-terminal rows are changed, so a
// device that already completed keeps its result for reporting.
func (r *Repository) MarkWorkRemoved(ctx context.Context, campaignID, deviceID string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE campaign_device_work SET state='REMOVED', updated_at=NOW()
		WHERE campaign_id=$1 AND device_id=$2 AND state IN ('PENDING','DISPATCHED','EXCLUDED')`,
		campaignID, deviceID)
	return err
}

// ClaimCampaignDispatch atomically claims a device's PENDING work for the active stage,
// moving it to DISPATCHED and stamping dispatched_at, returning the work list to send. It
// returns (nil,false,nil) when there is nothing to dispatch (not pending, wrong stage, or no
// work). The conditional UPDATE ... RETURNING makes two server instances racing to dispatch
// the same device resolve to exactly one claim.
func (r *Repository) ClaimCampaignDispatch(ctx context.Context, campaignID, deviceID string, activeStage int) ([]campaign.PackageWork, bool, error) {
	var raw []byte
	err := r.pool.QueryRow(ctx, `
		UPDATE campaign_device_work
		SET state='DISPATCHED', dispatched_at=NOW(), updated_at=NOW()
		WHERE campaign_id=$1 AND device_id=$2 AND stage=$3 AND state='PENDING'
		  AND work <> '[]'::jsonb
		  AND (deferred_until IS NULL OR deferred_until <= NOW())
		RETURNING work`, campaignID, deviceID, activeStage).Scan(&raw)
	if err == pgx.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("claim campaign dispatch: %w", err)
	}
	var work []campaign.PackageWork
	_ = json.Unmarshal(raw, &work)
	return work, true, nil
}

// RecordCampaignResult records a device's reported result: it replaces the package result
// rows, captures previous versions for rollback, sets the work state and failure class, and
// stamps resolved_at on success. prevVersions maps package -> version before upgrade.
func (r *Repository) RecordCampaignResult(ctx context.Context, campaignID, deviceID string, res campaign.DeviceRunResult, state campaign.DeviceWorkState, class campaign.FailureClass) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin record result: %w", err)
	}
	defer tx.Rollback(ctx)

	prev := map[string]string{}
	for _, p := range res.Packages {
		if p.FromVersion != "" {
			prev[p.Package] = p.FromVersion
		}
	}
	prevJSON, _ := json.Marshal(prev)

	resolvedClause := ""
	if state == campaign.WorkSucceeded {
		resolvedClause = ", resolved_at = NOW()"
	}
	if _, err := tx.Exec(ctx, `
		UPDATE campaign_device_work
		SET state=$3, failure_class=$4, reboot_required=$5,
		    previous_versions = previous_versions || $6::jsonb,
		    updated_at=NOW()`+resolvedClause+`
		WHERE campaign_id=$1 AND device_id=$2`,
		campaignID, deviceID, string(state), string(class), res.RebootRequired, string(prevJSON)); err != nil {
		return fmt.Errorf("update work result: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM campaign_package_results WHERE campaign_id=$1 AND device_id=$2`, campaignID, deviceID); err != nil {
		return fmt.Errorf("clear package results: %w", err)
	}
	for _, p := range res.Packages {
		if _, err := tx.Exec(ctx, `
			INSERT INTO campaign_package_results (campaign_id, device_id, package, state, from_version, to_version, output)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			campaignID, deviceID, p.Package, string(p.State), p.FromVersion, p.ToVersion, capOutputDB(p.Output)); err != nil {
			return fmt.Errorf("insert package result: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// MarkUnsupportedTimedOut flips DISPATCHED devices that have not reported within the timeout
// to UNSUPPORTED (an old agent that ignored the campaign directive). It never touches a
// device that reported (any terminal state). Returns the number marked.
func (r *Repository) MarkUnsupportedTimedOut(ctx context.Context, campaignID string, timeout time.Duration) (int, error) {
	cutoff := time.Now().UTC().Add(-timeout)
	tag, err := r.pool.Exec(ctx, `
		UPDATE campaign_device_work
		SET state='UNSUPPORTED', failure_class='other', updated_at=NOW()
		WHERE campaign_id=$1 AND state='DISPATCHED' AND dispatched_at IS NOT NULL AND dispatched_at < $2`,
		campaignID, cutoff)
	if err != nil {
		return 0, fmt.Errorf("mark unsupported: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// RecordDeferral increments a device's deferral count and appends a deferral history row,
// returning the new count. It refuses (returns the current count and false) once the campaign
// max is reached or the deadline has passed.
func (r *Repository) RecordDeferral(ctx context.Context, campaignID, deviceID string, maxDeferrals int, deadline *time.Time, now time.Time) (int, bool, error) {
	if deadline != nil && !now.Before(*deadline) {
		var cur int
		_ = r.pool.QueryRow(ctx, `SELECT deferrals_used FROM campaign_device_work WHERE campaign_id=$1 AND device_id=$2`, campaignID, deviceID).Scan(&cur)
		return cur, false, nil
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback(ctx)
	var used int
	err = tx.QueryRow(ctx, `SELECT deferrals_used FROM campaign_device_work WHERE campaign_id=$1 AND device_id=$2 FOR UPDATE`, campaignID, deviceID).Scan(&used)
	if err == pgx.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if used >= maxDeferrals {
		return used, false, tx.Commit(ctx)
	}
	used++
	// A granted deferral holds the install back: DISPATCHED work returns to PENDING and the
	// claim ignores it until deferred_until (now + DeferralDelay, never past the deadline).
	until := now.Add(campaign.DeferralDelay)
	if deadline != nil && until.After(*deadline) {
		until = *deadline
	}
	if _, err := tx.Exec(ctx, `UPDATE campaign_device_work
		SET deferrals_used=$3, deferred_until=$4,
		    state = CASE WHEN state='DISPATCHED' THEN 'PENDING' ELSE state END,
		    updated_at=NOW()
		WHERE campaign_id=$1 AND device_id=$2`, campaignID, deviceID, used, until); err != nil {
		return 0, false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO campaign_deferrals (campaign_id, device_id) VALUES ($1,$2)`, campaignID, deviceID); err != nil {
		return 0, false, err
	}
	return used, true, tx.Commit(ctx)
}

// StageTally computes the active-stage tally for a campaign (counts by terminal outcome,
// excluding REMOVED/EXCLUDED devices).
func (r *Repository) StageTally(ctx context.Context, campaignID string, stage int) (campaign.StageTally, error) {
	var t campaign.StageTally
	rows, err := r.pool.Query(ctx, `
		SELECT state, COUNT(*) FROM campaign_device_work
		WHERE campaign_id=$1 AND stage=$2 AND state <> 'REMOVED' AND state <> 'EXCLUDED'
		GROUP BY state`, campaignID, stage)
	if err != nil {
		return t, fmt.Errorf("stage tally: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		var n int
		if err := rows.Scan(&s, &n); err != nil {
			return t, err
		}
		st := campaign.DeviceWorkState(s)
		t.InStage += n
		if st.IsTerminalResult() {
			t.Terminal += n
			if st.IsSuccess() {
				t.Succeeded += n
			} else if st.IsFailure() {
				t.Failed += n
			}
		}
	}
	return t, rows.Err()
}

// WithCampaignPromotionLock runs fn while holding this campaign's advisory lock in a
// transaction, so exactly one server instance evaluates promotion/halt at a time. Different
// campaigns proceed in parallel. fn receives the tx-bound executor via the repository (it
// uses the pool for reads, which is fine — the lock only serialises the decision+write).
func (r *Repository) WithCampaignPromotionLock(ctx context.Context, campaignID string, fn func(ctx context.Context) error) error {
	lockKey := campaignPromotionLockBase + int64(hashCampaignID(campaignID))
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin promotion lock: %w", err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey); err != nil {
		return fmt.Errorf("acquire promotion lock: %w", err)
	}
	if err := fn(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// TryCampaignPromotionLock attempts a non-blocking advisory lock for a campaign's promotion.
// It returns (acquired, unlock, err). When acquired is true the caller MUST call unlock when
// done. When false another instance holds it and the caller should skip this cycle. Used by
// tests to prove mutual exclusion deterministically.
func (r *Repository) TryCampaignPromotionLock(ctx context.Context, campaignID string) (bool, func(), error) {
	lockKey := campaignPromotionLockBase + int64(hashCampaignID(campaignID))
	conn, err := r.pool.Acquire(ctx)
	if err != nil {
		return false, func() {}, err
	}
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&got); err != nil {
		conn.Release()
		return false, func() {}, err
	}
	if !got {
		conn.Release()
		return false, func() {}, nil
	}
	unlock := func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, lockKey)
		conn.Release()
	}
	return true, unlock, nil
}

func nonNilWork(w []campaign.PackageWork) []campaign.PackageWork {
	if w == nil {
		return []campaign.PackageWork{}
	}
	return w
}

func capOutputDB(s string) string {
	const cap = 4096
	if len(s) <= cap {
		return s
	}
	return s[:cap] + "\n...[truncated]"
}
