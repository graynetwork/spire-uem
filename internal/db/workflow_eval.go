package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/grouprule"
)

// EvalConditionForDevice compiles a group-rule condition and reports whether ONE device
// matches it RIGHT NOW. A nil/empty condition is treated as "always true". The compiled
// predicate runs against the same `devices d LEFT JOIN device_patch_status ps` scaffold the
// group membership query uses, so a workflow condition sees exactly the fields a group rule
// does. Every value is a bound parameter — no input is ever concatenated into SQL.
//
// A rule that fails to parse/compile is returned as an error so the engine records the run as
// FAILED (fail-closed: a broken condition never silently counts as "matched" and fires
// actions).
func (r *Repository) EvalConditionForDevice(ctx context.Context, deviceID string, condition []byte) (bool, error) {
	if len(condition) == 0 {
		return true, nil
	}
	rule, err := grouprule.Parse(condition, nil)
	if err != nil {
		return false, fmt.Errorf("parse condition: %w", err)
	}
	if rule == nil {
		return true, nil
	}
	// The device id is bound as $1; the compiled predicate's placeholders start at $2.
	pred, args, cerr := rule.Compile(2)
	if cerr != nil {
		return false, fmt.Errorf("compile condition: %w", cerr)
	}
	query := `SELECT EXISTS (
		SELECT 1 FROM devices d
		LEFT JOIN device_patch_status ps ON ps.device_id = d.id
		WHERE d.id = $1 AND (` + pred + `)
	)`
	callArgs := make([]any, 0, len(args)+1)
	callArgs = append(callArgs, deviceID)
	callArgs = append(callArgs, args...)

	var match bool
	if err := r.pool.QueryRow(ctx, query, callArgs...).Scan(&match); err != nil {
		if err == pgx.ErrNoRows {
			return false, nil
		}
		return false, fmt.Errorf("evaluate condition: %w", err)
	}
	return match, nil
}
