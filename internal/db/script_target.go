package db

import (
	"context"
	"fmt"

	"github.com/spire-uem/spire-uem/internal/types"
)

// ScriptTarget selects devices for a script run. Exactly one of DeviceIDs, Tags or Ring is the
// primary selector; a tag-scoped admin's ScopeTags, when non-nil, is intersected with the
// result so a scoped admin can never target a device outside their scope. A group target can
// be added later behind this same resolver without changing callers.
type ScriptTarget struct {
	DeviceIDs []string
	Tags      []string
	Ring      *types.DeploymentRing
	// ScopeTags limits the resolved set to devices carrying at least one of these tags. Nil
	// means unscoped (the admin is not tag-limited).
	ScopeTags []string
}

// ResolveScriptTargetDevices returns the approved device ids a target selects, intersected
// with the admin's tag scope. Only APPROVED devices are returned (a script never runs on a
// pending or revoked device).
func (r *Repository) ResolveScriptTargetDevices(ctx context.Context, t ScriptTarget) ([]string, error) {
	scoped := t.ScopeTags != nil
	scopeTags := t.ScopeTags
	if scopeTags == nil {
		scopeTags = []string{}
	}

	var query string
	var args []any
	switch {
	case len(t.DeviceIDs) > 0:
		query = `SELECT id FROM devices WHERE id = ANY($1) AND status = 'APPROVED' AND (NOT $2::bool OR tags && $3::text[])`
		args = []any{t.DeviceIDs, scoped, scopeTags}
	case t.Ring != nil:
		query = `SELECT id FROM devices WHERE status = 'APPROVED' AND patch_ring = $1 AND (NOT $2::bool OR tags && $3::text[])`
		args = []any{string(*t.Ring), scoped, scopeTags}
	case len(t.Tags) > 0:
		query = `SELECT id FROM devices WHERE status = 'APPROVED' AND tags && $1::text[] AND (NOT $2::bool OR tags && $3::text[])`
		args = []any{t.Tags, scoped, scopeTags}
	default:
		return nil, fmt.Errorf("script target selects no devices (give device ids, tags, or a ring)")
	}

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("resolve script target: %w", err)
	}
	defer rows.Close()
	out := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan target device: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
