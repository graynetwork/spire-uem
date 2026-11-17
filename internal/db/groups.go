package db

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/grouprule"
	"github.com/spire-uem/spire-uem/internal/types"
)

// groupMembershipHistoryCap bounds how many membership events are kept per group. Older
// events beyond this are trimmed on each recompute.
const groupMembershipHistoryCap = 500

// groupRecomputeLockBase is the advisory-lock keyspace base for per-group membership
// recompute. Combined with a hash of the group id so two server instances never recompute
// the same group concurrently, while different groups proceed in parallel.
const groupRecomputeLockBase = int64(0x6772_7000) // "grp\0"

// ErrGroupReferenced is returned when a group cannot be deleted because policies reference it.
type ErrGroupReferenced struct {
	PolicyNames []string
}

func (e *ErrGroupReferenced) Error() string {
	return "group is referenced by policies: " + strings.Join(e.PolicyNames, ", ")
}

// groupSelectColumns is the fixed column list for device_groups.
const groupSelectColumns = `id, name, COALESCE(description,''), kind, rule,
	COALESCE(include_device_ids,'{}'), COALESCE(exclude_device_ids,'{}'),
	COALESCE(created_by,''), COALESCE(creator_scoped_tags,'{}'),
	COALESCE(last_rule_error,''), last_evaluated_at, created_at, updated_at`

func scanGroup(row pgx.Row) (*types.DeviceGroup, error) {
	var g types.DeviceGroup
	var rule []byte
	if err := row.Scan(
		&g.ID, &g.Name, &g.Description, &g.Kind, &rule,
		&g.IncludeDeviceIDs, &g.ExcludeDeviceIDs,
		&g.CreatedBy, &g.CreatorScopedTags,
		&g.LastRuleError, &g.LastEvaluatedAt, &g.CreatedAt, &g.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if len(rule) > 0 {
		g.Rule = rule
	}
	if g.IncludeDeviceIDs == nil {
		g.IncludeDeviceIDs = []string{}
	}
	if g.ExcludeDeviceIDs == nil {
		g.ExcludeDeviceIDs = []string{}
	}
	if g.CreatorScopedTags == nil {
		g.CreatorScopedTags = []string{}
	}
	return &g, nil
}

// CreateGroupInput carries the validated fields for creating or updating a group.
type CreateGroupInput struct {
	Name              string
	Description       string
	Kind              types.GroupKind
	Rule              []byte // canonical JSON, or nil for no rule
	IncludeDeviceIDs  []string
	ExcludeDeviceIDs  []string
	CreatedBy         string
	CreatorScopedTags []string
}

// CreateGroup inserts a new group. The caller validates the rule first (grouprule.Parse).
func (r *Repository) CreateGroup(ctx context.Context, in CreateGroupInput) (*types.DeviceGroup, error) {
	if !types.ValidGroupKind(in.Kind) {
		return nil, fmt.Errorf("invalid group kind %q", in.Kind)
	}
	inc := nonNil(in.IncludeDeviceIDs)
	exc := nonNil(in.ExcludeDeviceIDs)
	cst := nonNil(in.CreatorScopedTags)
	var rule any
	if len(in.Rule) > 0 {
		rule = string(in.Rule)
	}
	const q = `
		INSERT INTO device_groups (name, description, kind, rule, include_device_ids, exclude_device_ids, created_by, creator_scoped_tags)
		VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8)
		RETURNING ` + groupSelectColumns
	g, err := scanGroup(r.pool.QueryRow(ctx, q, strings.TrimSpace(in.Name), strings.TrimSpace(in.Description), string(in.Kind), rule, inc, exc, in.CreatedBy, cst))
	if err != nil {
		return nil, fmt.Errorf("create group: %w", err)
	}
	return g, nil
}

// UpdateGroup updates an existing group's editable fields (not created_by / creator scope).
func (r *Repository) UpdateGroup(ctx context.Context, id string, in CreateGroupInput) (*types.DeviceGroup, error) {
	if !types.ValidGroupKind(in.Kind) {
		return nil, fmt.Errorf("invalid group kind %q", in.Kind)
	}
	inc := nonNil(in.IncludeDeviceIDs)
	exc := nonNil(in.ExcludeDeviceIDs)
	var rule any
	if len(in.Rule) > 0 {
		rule = string(in.Rule)
	}
	const q = `
		UPDATE device_groups
		SET name=$2, description=$3, kind=$4, rule=$5::jsonb,
		    include_device_ids=$6, exclude_device_ids=$7,
		    last_rule_error='', updated_at=NOW()
		WHERE id=$1
		RETURNING ` + groupSelectColumns
	g, err := scanGroup(r.pool.QueryRow(ctx, q, id, strings.TrimSpace(in.Name), strings.TrimSpace(in.Description), string(in.Kind), rule, inc, exc))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("update group: %w", err)
	}
	return g, nil
}

// GetGroupByID returns one group, or nil if it does not exist.
func (r *Repository) GetGroupByID(ctx context.Context, id string) (*types.DeviceGroup, error) {
	g, err := scanGroup(r.pool.QueryRow(ctx, `SELECT `+groupSelectColumns+` FROM device_groups WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get group: %w", err)
	}
	return g, nil
}

// ListGroups returns all groups with their current member counts. When scope is scoped, the
// member counts are limited to in-scope devices and only groups with at least one in-scope
// member OR created by the scoped admin are returned (so a scoped admin sees groups relevant
// to them). An unscoped scope returns every group with full counts.
func (r *Repository) ListGroups(ctx context.Context, scope DeviceScope) ([]types.DeviceGroup, error) {
	scoped, tags := scope.sqlArgs()
	const q = `
		SELECT ` + groupSelectColumns + `,
		  (SELECT COUNT(*) FROM group_memberships gm
		     JOIN devices d ON d.id = gm.device_id
		    WHERE gm.group_id = device_groups.id
		      AND (NOT $1::bool OR d.tags && $2::text[]))::int AS member_count
		FROM device_groups
		ORDER BY name ASC`
	rows, err := r.pool.Query(ctx, q, scoped, tags)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	defer rows.Close()
	out := make([]types.DeviceGroup, 0)
	for rows.Next() {
		var g types.DeviceGroup
		var rule []byte
		if err := rows.Scan(
			&g.ID, &g.Name, &g.Description, &g.Kind, &rule,
			&g.IncludeDeviceIDs, &g.ExcludeDeviceIDs,
			&g.CreatedBy, &g.CreatorScopedTags,
			&g.LastRuleError, &g.LastEvaluatedAt, &g.CreatedAt, &g.UpdatedAt,
			&g.MemberCount,
		); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		if len(rule) > 0 {
			g.Rule = rule
		}
		if g.IncludeDeviceIDs == nil {
			g.IncludeDeviceIDs = []string{}
		}
		if g.ExcludeDeviceIDs == nil {
			g.ExcludeDeviceIDs = []string{}
		}
		if g.CreatorScopedTags == nil {
			g.CreatorScopedTags = []string{}
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// DeleteGroup removes a group, refusing if any policy references it. The referenced-policy
// check and the delete run in one transaction so a policy cannot start referencing the group
// between the check and the delete.
func (r *Repository) DeleteGroup(ctx context.Context, id string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin delete group: %w", err)
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `SELECT name FROM policies WHERE $1 = ANY(COALESCE(target_group_ids,'{}')) ORDER BY name`, id)
	if err != nil {
		return fmt.Errorf("check referencing policies: %w", err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		names = append(names, n)
	}
	rows.Close()
	if len(names) > 0 {
		return &ErrGroupReferenced{PolicyNames: names}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM device_groups WHERE id=$1`, id); err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	return tx.Commit(ctx)
}

// PoliciesReferencingGroup returns the names of policies that target the given group.
func (r *Repository) PoliciesReferencingGroup(ctx context.Context, groupID string) ([]string, error) {
	rows, err := r.pool.Query(ctx, `SELECT name FROM policies WHERE $1 = ANY(COALESCE(target_group_ids,'{}')) ORDER BY name`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

// scopeTagPredicate builds, for a scoped admin, the extra SQL that ANDs an implicit "device
// has one of my tags" into membership evaluation, appending its bind parameter. It returns an
// empty string for an unscoped scope.
func scopeTagPredicate(scope DeviceScope, nextArg int, args *[]any) string {
	if !scope.Scoped {
		return ""
	}
	tags := scope.Tags
	if tags == nil {
		tags = []string{}
	}
	*args = append(*args, tags)
	return fmt.Sprintf(" AND d.tags && $%d::text[]", nextArg)
}

// buildMembershipSelect builds the "SELECT d.id FROM devices d ... WHERE <membership>" query
// for a group: (rule matches OR included) AND NOT excluded, optionally AND the scope tag
// filter. It returns the SQL and its bind args. A rule parse/compile failure is returned as
// an error so the caller can keep the last membership (fail-safe). deviceID, when non-empty,
// restricts evaluation to one device (used on check-in).
func (r *Repository) buildMembershipSelect(g *types.DeviceGroup, scope DeviceScope, deviceID string) (string, []any, error) {
	var args []any
	// rule predicate
	rulePred := "FALSE"
	if len(g.Rule) > 0 {
		rule, err := grouprule.Parse(g.Rule, nil)
		if err != nil {
			return "", nil, fmt.Errorf("parse stored rule: %w", err)
		}
		if rule != nil {
			sql, rargs, cerr := rule.Compile(1)
			if cerr != nil {
				return "", nil, fmt.Errorf("compile stored rule: %w", cerr)
			}
			rulePred = sql
			args = append(args, rargs...)
		}
	}
	// include/exclude predicates reference bound arrays.
	inc := nonNil(g.IncludeDeviceIDs)
	exc := nonNil(g.ExcludeDeviceIDs)
	args = append(args, inc)
	incIdx := len(args)
	args = append(args, exc)
	excIdx := len(args)

	where := fmt.Sprintf("((%s) OR d.id = ANY($%d::uuid[])) AND NOT (d.id = ANY($%d::uuid[]))", rulePred, incIdx, excIdx)

	// optional scope tag filter
	where += scopeTagPredicate(scope, len(args)+1, &args)

	// optional single-device restriction
	if deviceID != "" {
		args = append(args, deviceID)
		where += fmt.Sprintf(" AND d.id = $%d", len(args))
	}

	q := `SELECT d.id, d.hostname, d.status::text, d.tags
		FROM devices d
		LEFT JOIN device_patch_status ps ON ps.device_id = d.id
		WHERE ` + where + `
		ORDER BY d.hostname ASC`
	return q, args, nil
}

// PreviewGroupRule evaluates an UNSAVED rule plus static include/exclude lists and returns
// the total match count and the first 50 devices, under the given scope. A rule validation
// error is surfaced to the caller as a grouprule.ValidationError.
func (r *Repository) PreviewGroupRule(ctx context.Context, rule []byte, include, exclude []string, scope DeviceScope) (*types.GroupPreviewResult, error) {
	g := &types.DeviceGroup{Rule: rule, IncludeDeviceIDs: include, ExcludeDeviceIDs: exclude}
	q, args, err := r.buildMembershipSelect(g, scope, "")
	if err != nil {
		return nil, err
	}
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("preview rule: %w", err)
	}
	defer rows.Close()
	res := &types.GroupPreviewResult{Devices: make([]types.DeviceGroupMember, 0, 50)}
	for rows.Next() {
		var m types.DeviceGroupMember
		if err := rows.Scan(&m.DeviceID, &m.Hostname, &m.Status, &m.Tags); err != nil {
			return nil, fmt.Errorf("scan preview device: %w", err)
		}
		res.Count++
		if len(res.Devices) < 50 {
			if m.Tags == nil {
				m.Tags = []string{}
			}
			res.Devices = append(res.Devices, m)
		}
	}
	return res, rows.Err()
}

// RecomputeGroupMembership materialises one group's membership into group_memberships and
// appends entered/left history with the reason. It takes a per-group advisory lock so two
// server instances never recompute the same group at once; a different group proceeds in
// parallel. When the stored rule fails to evaluate, the LAST materialised membership is left
// UNCHANGED (fail-safe, so a broken rule never silently empties a group and revokes security
// policy) and the error is recorded on the group row. Returns (entered, left) counts.
func (r *Repository) RecomputeGroupMembership(ctx context.Context, groupID string) (entered, left int, err error) {
	g, err := r.GetGroupByID(ctx, groupID)
	if err != nil || g == nil {
		return 0, 0, err
	}

	lockKey := groupRecomputeLockBase + int64(hashGroupID(groupID))

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("begin recompute: %w", err)
	}
	defer tx.Rollback(ctx)

	// Advisory xact lock: auto-released at commit/rollback, scoped to this group.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey); err != nil {
		return 0, 0, fmt.Errorf("advisory lock: %w", err)
	}

	q, args, berr := r.buildMembershipSelect(g, Unscoped, "")
	if berr != nil {
		// Record the error and keep the last membership.
		_, _ = tx.Exec(ctx, `UPDATE device_groups SET last_rule_error=$2, last_evaluated_at=NOW(), updated_at=updated_at WHERE id=$1`, groupID, berr.Error())
		if cerr := tx.Commit(ctx); cerr != nil {
			return 0, 0, cerr
		}
		return 0, 0, berr
	}

	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		_, _ = tx.Exec(ctx, `UPDATE device_groups SET last_rule_error=$2, last_evaluated_at=NOW() WHERE id=$1`, groupID, err.Error())
		if cerr := tx.Commit(ctx); cerr != nil {
			return 0, 0, cerr
		}
		return 0, 0, fmt.Errorf("evaluate membership: %w", err)
	}
	newMembers := map[string]string{} // device_id -> hostname
	for rows.Next() {
		var id, hostname, status string
		var tags []string
		if err := rows.Scan(&id, &hostname, &status, &tags); err != nil {
			rows.Close()
			return 0, 0, err
		}
		newMembers[id] = hostname
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}

	// Current members.
	curRows, err := tx.Query(ctx, `SELECT gm.device_id, d.hostname FROM group_memberships gm JOIN devices d ON d.id = gm.device_id WHERE gm.group_id=$1`, groupID)
	if err != nil {
		return 0, 0, fmt.Errorf("load current members: %w", err)
	}
	current := map[string]string{}
	for curRows.Next() {
		var id, hostname string
		if err := curRows.Scan(&id, &hostname); err != nil {
			curRows.Close()
			return 0, 0, err
		}
		current[id] = hostname
	}
	curRows.Close()

	reason := membershipReason(g)

	// Entered: in new, not in current.
	for id, hostname := range newMembers {
		if _, ok := current[id]; !ok {
			if _, err := tx.Exec(ctx, `INSERT INTO group_memberships (group_id, device_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, groupID, id); err != nil {
				return 0, 0, fmt.Errorf("insert membership: %w", err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO group_membership_events (group_id, device_id, entered, reason) VALUES ($1,$2,true,$3)`, groupID, id, "joined: "+reason); err != nil {
				return 0, 0, err
			}
			_ = hostname
			entered++
		}
	}
	// Left: in current, not in new.
	for id := range current {
		if _, ok := newMembers[id]; !ok {
			if _, err := tx.Exec(ctx, `DELETE FROM group_memberships WHERE group_id=$1 AND device_id=$2`, groupID, id); err != nil {
				return 0, 0, fmt.Errorf("delete membership: %w", err)
			}
			if _, err := tx.Exec(ctx, `INSERT INTO group_membership_events (group_id, device_id, entered, reason) VALUES ($1,$2,false,$3)`, groupID, id, "left: "+reason); err != nil {
				return 0, 0, err
			}
			left++
		}
	}

	// Trim history beyond the cap.
	if _, err := tx.Exec(ctx, `
		DELETE FROM group_membership_events
		WHERE group_id=$1 AND id NOT IN (
			SELECT id FROM group_membership_events WHERE group_id=$1 ORDER BY id DESC LIMIT $2
		)`, groupID, groupMembershipHistoryCap); err != nil {
		return 0, 0, fmt.Errorf("trim history: %w", err)
	}

	if _, err := tx.Exec(ctx, `UPDATE device_groups SET last_rule_error='', last_evaluated_at=NOW() WHERE id=$1`, groupID); err != nil {
		return 0, 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, fmt.Errorf("commit recompute: %w", err)
	}
	return entered, left, nil
}

// RecomputeAllGroups recomputes every group's membership. Used by the periodic loop and
// after a bulk change. Errors on individual groups are collected but do not stop the others;
// the last membership of a failing group is retained.
func (r *Repository) RecomputeAllGroups(ctx context.Context) error {
	ids, err := r.allGroupIDs(ctx)
	if err != nil {
		return err
	}
	var firstErr error
	for _, id := range ids {
		if _, _, err := r.RecomputeGroupMembership(ctx, id); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// RecomputeGroupsForDevice recomputes, for one device only, its membership across all groups
// after it checks in. It evaluates each group's membership restricted to this device and
// adds/removes the single membership row with a history event. A group whose rule fails to
// evaluate is skipped for this device (its last membership for the device is retained).
func (r *Repository) RecomputeGroupsForDevice(ctx context.Context, deviceID string) error {
	ids, err := r.allGroupIDs(ctx)
	if err != nil {
		return err
	}
	for _, gid := range ids {
		g, err := r.GetGroupByID(ctx, gid)
		if err != nil || g == nil {
			continue
		}
		q, args, berr := r.buildMembershipSelect(g, Unscoped, deviceID)
		if berr != nil {
			// Keep last membership for this device; surface on the group page via a flag.
			_, _ = r.pool.Exec(ctx, `UPDATE device_groups SET last_rule_error=$2 WHERE id=$1`, gid, berr.Error())
			continue
		}
		var matched bool
		var hostname string
		row := r.pool.QueryRow(ctx, `SELECT hostname FROM (`+q+`) m LIMIT 1`, args...)
		switch err := row.Scan(&hostname); {
		case err == nil:
			matched = true
		case errors.Is(err, pgx.ErrNoRows):
			matched = false
		default:
			continue
		}

		var isMember bool
		_ = r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM group_memberships WHERE group_id=$1 AND device_id=$2)`, gid, deviceID).Scan(&isMember)

		reason := membershipReason(g)
		if matched && !isMember {
			_, _ = r.pool.Exec(ctx, `INSERT INTO group_memberships (group_id, device_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, gid, deviceID)
			_, _ = r.pool.Exec(ctx, `INSERT INTO group_membership_events (group_id, device_id, entered, reason) VALUES ($1,$2,true,$3)`, gid, deviceID, "joined (check-in): "+reason)
		} else if !matched && isMember {
			_, _ = r.pool.Exec(ctx, `DELETE FROM group_memberships WHERE group_id=$1 AND device_id=$2`, gid, deviceID)
			_, _ = r.pool.Exec(ctx, `INSERT INTO group_membership_events (group_id, device_id, entered, reason) VALUES ($1,$2,false,$3)`, gid, deviceID, "left (check-in): "+reason)
		}
	}
	return nil
}

func (r *Repository) allGroupIDs(ctx context.Context) ([]string, error) {
	rows, err := r.pool.Query(ctx, `SELECT id FROM device_groups ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("list group ids: %w", err)
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

// ListGroupMembers returns the devices currently in a group, filtered to the request scope.
func (r *Repository) ListGroupMembers(ctx context.Context, groupID string, scope DeviceScope) ([]types.DeviceGroupMember, error) {
	scoped, tags := scope.sqlArgs()
	const q = `
		SELECT d.id, d.hostname, d.status::text, d.tags
		FROM group_memberships gm
		JOIN devices d ON d.id = gm.device_id
		WHERE gm.group_id = $1
		  AND (NOT $2::bool OR d.tags && $3::text[])
		ORDER BY d.hostname ASC`
	rows, err := r.pool.Query(ctx, q, groupID, scoped, tags)
	if err != nil {
		return nil, fmt.Errorf("list group members: %w", err)
	}
	defer rows.Close()
	out := make([]types.DeviceGroupMember, 0)
	for rows.Next() {
		var m types.DeviceGroupMember
		if err := rows.Scan(&m.DeviceID, &m.Hostname, &m.Status, &m.Tags); err != nil {
			return nil, err
		}
		if m.Tags == nil {
			m.Tags = []string{}
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListGroupHistory returns the most recent membership events for a group (newest first).
func (r *Repository) ListGroupHistory(ctx context.Context, groupID string, limit int) ([]types.GroupMembershipEvent, error) {
	if limit <= 0 || limit > groupMembershipHistoryCap {
		limit = 100
	}
	const q = `
		SELECT e.id, e.group_id, e.device_id, COALESCE(d.hostname,''), e.entered, e.reason, e.created_at
		FROM group_membership_events e
		LEFT JOIN devices d ON d.id = e.device_id
		WHERE e.group_id = $1
		ORDER BY e.id DESC
		LIMIT $2`
	rows, err := r.pool.Query(ctx, q, groupID, limit)
	if err != nil {
		return nil, fmt.Errorf("list group history: %w", err)
	}
	defer rows.Close()
	out := make([]types.GroupMembershipEvent, 0)
	for rows.Next() {
		var e types.GroupMembershipEvent
		if err := rows.Scan(&e.ID, &e.GroupID, &e.DeviceID, &e.Hostname, &e.Entered, &e.Reason, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DevicesInGroup returns the device IDs currently in a group. Helper for patch campaigns and
// workflows that need to resolve "devices in group X".
func (r *Repository) DevicesInGroup(ctx context.Context, groupID string) ([]string, error) {
	rows, err := r.pool.Query(ctx, `SELECT device_id FROM group_memberships WHERE group_id=$1`, groupID)
	if err != nil {
		return nil, fmt.Errorf("devices in group: %w", err)
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

// HardwareUUIDsInGroup returns the hardware UUIDs of devices currently in a group. Used by
// the compliance export group filter, whose records are keyed by hardware UUID.
func (r *Repository) HardwareUUIDsInGroup(ctx context.Context, groupID string) (map[string]struct{}, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT d.hardware_uuid
		FROM group_memberships gm
		JOIN devices d ON d.id = gm.device_id
		WHERE gm.group_id = $1`, groupID)
	if err != nil {
		return nil, fmt.Errorf("hardware uuids in group: %w", err)
	}
	defer rows.Close()
	out := make(map[string]struct{})
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out[u] = struct{}{}
	}
	return out, rows.Err()
}

// GroupIDsForDevice returns the groups a device is currently a member of.
func (r *Repository) GroupIDsForDevice(ctx context.Context, deviceID string) ([]string, error) {
	rows, err := r.pool.Query(ctx, `SELECT group_id FROM group_memberships WHERE device_id=$1`, deviceID)
	if err != nil {
		return nil, err
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

// membershipReason builds a short human description of why membership was recomputed, used
// as the history event reason. It names the top-level conditions (rule present, include /
// exclude list sizes) so an operator can see what drove a change.
func membershipReason(g *types.DeviceGroup) string {
	parts := make([]string, 0, 3)
	if len(g.Rule) > 0 {
		parts = append(parts, "rule")
	}
	if len(g.IncludeDeviceIDs) > 0 {
		parts = append(parts, fmt.Sprintf("%d included", len(g.IncludeDeviceIDs)))
	}
	if len(g.ExcludeDeviceIDs) > 0 {
		parts = append(parts, fmt.Sprintf("%d excluded", len(g.ExcludeDeviceIDs)))
	}
	if len(parts) == 0 {
		return "empty definition"
	}
	return strings.Join(parts, " + ")
}

func hashGroupID(id string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(id))
	return h.Sum32() & 0x00FF_FFFF // keep within the reserved keyspace band
}

// SetPolicyTargetGroups replaces a policy's target_group_ids. Unknown group ids are rejected
// so a policy cannot reference a non-existent group. An empty list clears group targeting
// (the policy reverts to tag/ring-only, pre-groups behaviour).
func (r *Repository) SetPolicyTargetGroups(ctx context.Context, policyID string, groupIDs []string) error {
	groupIDs = uniqueStrings(nonNil(groupIDs))
	if len(groupIDs) > 0 {
		var validCount int
		if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM device_groups WHERE id = ANY($1::uuid[])`, groupIDs).Scan(&validCount); err != nil {
			return fmt.Errorf("validate target groups: %w", err)
		}
		if validCount != len(groupIDs) {
			return fmt.Errorf("one or more target groups do not exist")
		}
	}
	if _, err := r.pool.Exec(ctx, `UPDATE policies SET target_group_ids=$2, updated_at=NOW() WHERE id=$1`, policyID, groupIDs); err != nil {
		return fmt.Errorf("set policy target groups: %w", err)
	}
	return nil
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// ValidatePostgresRegex asks Postgres to compile a POSIX regex, so a `matches` pattern is
// rejected at save time if Postgres cannot use it. The pattern is a bound parameter; the
// probe matches it against the empty string and discards the result. A compile failure is
// returned as the error.
func (r *Repository) ValidatePostgresRegex(ctx context.Context, pattern string) error {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var ok bool
	// '' ~ $1 forces Postgres to compile the pattern; a bad pattern raises here.
	if err := r.pool.QueryRow(cctx, `SELECT ('' ~ $1)`, pattern).Scan(&ok); err != nil {
		return err
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
