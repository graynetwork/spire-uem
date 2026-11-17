package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/spire-uem/spire-uem/internal/types"
)

// ReplaceDeviceAttributes makes attrs the complete set of attributes that source owns on
// a device: keys in attrs are inserted or updated, and keys source previously wrote that are
// absent from attrs are deleted. Keys owned by a different source are never modified; they
// are returned in skipped. The whole change is one transaction.
func (r *Repository) ReplaceDeviceAttributes(ctx context.Context, deviceID, source string, attrs []types.DeviceAttribute) (skipped []string, err error) {
	if !types.ValidAttributeSource(source) {
		return nil, fmt.Errorf("invalid attribute source %q", source)
	}
	if len(attrs) > types.MaxAttributesPerSet {
		return nil, fmt.Errorf("%d attributes exceeds the limit of %d per source", len(attrs), types.MaxAttributesPerSet)
	}
	seen := make(map[string]bool, len(attrs))
	keys := make([]string, 0, len(attrs))
	for _, a := range attrs {
		if err := a.Validate(); err != nil {
			return nil, err
		}
		if seen[a.Key] {
			return nil, fmt.Errorf("duplicate attribute key %q", a.Key)
		}
		seen[a.Key] = true
		keys = append(keys, a.Key)
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin replace attributes: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		DELETE FROM device_attributes
		WHERE device_id = $1 AND source = $2 AND NOT (key = ANY($3))`, deviceID, source, keys); err != nil {
		return nil, fmt.Errorf("delete stale attributes: %w", err)
	}

	for _, a := range attrs {
		// The WHERE clause on the conflict branch keeps another source's key untouched.
		tag, err := tx.Exec(ctx, `
			INSERT INTO device_attributes (device_id, key, value_type, value, source, updated_at)
			VALUES ($1, $2, $3, $4::jsonb, $5, NOW())
			ON CONFLICT (device_id, key) DO UPDATE
			SET value_type = EXCLUDED.value_type, value = EXCLUDED.value, updated_at = NOW()
			WHERE device_attributes.source = EXCLUDED.source`,
			deviceID, a.Key, string(a.Type), string(a.Value), source)
		if err != nil {
			return nil, fmt.Errorf("upsert attribute %s: %w", a.Key, err)
		}
		if tag.RowsAffected() == 0 {
			skipped = append(skipped, a.Key)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit replace attributes: %w", err)
	}
	return skipped, nil
}

// GetDeviceAttributes returns every attribute of a device, ordered by key.
func (r *Repository) GetDeviceAttributes(ctx context.Context, deviceID string) ([]types.DeviceAttribute, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT device_id, key, value_type, value, source, updated_at
		FROM device_attributes WHERE device_id = $1 ORDER BY key`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("get device attributes: %w", err)
	}
	defer rows.Close()
	out := make([]types.DeviceAttribute, 0)
	for rows.Next() {
		var a types.DeviceAttribute
		var t string
		var v []byte
		if err := rows.Scan(&a.DeviceID, &a.Key, &t, &v, &a.Source, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan device attribute: %w", err)
		}
		a.Type = types.AttributeType(t)
		a.Value = v
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListAttributeKeys summarises every attribute key in use, optionally filtered by a key
// prefix, with how many devices carry it. If one key has been written with more than one
// type or source, one row is returned per combination.
func (r *Repository) ListAttributeKeys(ctx context.Context, prefix string) ([]types.AttributeKeyInfo, error) {
	prefix = strings.TrimSpace(prefix)
	rows, err := r.pool.Query(ctx, `
		SELECT key, value_type, source, COUNT(*)::int
		FROM device_attributes
		WHERE $1 = '' OR starts_with(key, $1)
		GROUP BY key, value_type, source
		ORDER BY key, value_type, source`, prefix)
	if err != nil {
		return nil, fmt.Errorf("list attribute keys: %w", err)
	}
	defer rows.Close()
	out := make([]types.AttributeKeyInfo, 0)
	for rows.Next() {
		var k types.AttributeKeyInfo
		var t string
		if err := rows.Scan(&k.Key, &t, &k.Source, &k.DeviceCount); err != nil {
			return nil, fmt.Errorf("scan attribute key: %w", err)
		}
		k.Type = types.AttributeType(t)
		out = append(out, k)
	}
	return out, rows.Err()
}
