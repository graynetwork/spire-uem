package db

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/spire-uem/spire-uem/internal/types"
)

// ErrScriptVersionNotFound is returned when a referenced script version id does not exist
// (e.g. a SCRIPT_POLICY or sensor pins a version that was since deleted with its script).
var ErrScriptVersionNotFound = errors.New("script version not found")

// CreateScript inserts a script with its first immutable version. The whole thing is one
// transaction: a script always has at least one version, and current_version_id points at it.
func (r *Repository) CreateScript(ctx context.Context, s *types.Script, content string, params []types.ScriptParam, createdBy string) (*types.Script, error) {
	s.NormalizeLimits()
	if err := s.ValidateMeta(); err != nil {
		return nil, err
	}
	if len(params) > types.MaxScriptParameters {
		return nil, fmt.Errorf("%d parameters exceeds the limit of %d", len(params), types.MaxScriptParameters)
	}
	if len(content) > types.MaxScriptContentBytes {
		return nil, fmt.Errorf("script content is %d bytes, limit %d", len(content), types.MaxScriptContentBytes)
	}
	if err := validateParams(params); err != nil {
		return nil, err
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal params: %w", err)
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin create script: %w", err)
	}
	defer tx.Rollback(ctx)

	var scriptID string
	err = tx.QueryRow(ctx, `
		INSERT INTO scripts (name, description, interpreter, run_as, timeout_seconds, max_output_bytes, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id`,
		s.Name, s.Description, string(s.Interpreter), string(s.RunAs), s.TimeoutSeconds, s.MaxOutputBytes, createdBy,
	).Scan(&scriptID)
	if err != nil {
		return nil, fmt.Errorf("insert script: %w", err)
	}

	sha := types.ComputeScriptSHA256(content)
	var versionID string
	err = tx.QueryRow(ctx, `
		INSERT INTO script_versions (script_id, version, content, sha256, params, created_by)
		VALUES ($1, 1, $2, $3, $4::jsonb, $5)
		RETURNING id`,
		scriptID, content, sha, string(paramsJSON), createdBy,
	).Scan(&versionID)
	if err != nil {
		return nil, fmt.Errorf("insert script version: %w", err)
	}

	if _, err := tx.Exec(ctx, `UPDATE scripts SET current_version_id = $2, updated_at = NOW() WHERE id = $1`, scriptID, versionID); err != nil {
		return nil, fmt.Errorf("set current version: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit create script: %w", err)
	}

	s.ID = scriptID
	s.CurrentVersionID = &versionID
	s.CreatedBy = createdBy
	return s, nil
}

// UpdateScriptMeta changes a script's mutable metadata (name, description, interpreter,
// run_as, limits). Content is NOT changed here — that is AddScriptVersion.
func (r *Repository) UpdateScriptMeta(ctx context.Context, s *types.Script) error {
	s.NormalizeLimits()
	if err := s.ValidateMeta(); err != nil {
		return err
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE scripts
		SET name=$2, description=$3, interpreter=$4, run_as=$5, timeout_seconds=$6, max_output_bytes=$7, updated_at=NOW()
		WHERE id=$1`,
		s.ID, s.Name, s.Description, string(s.Interpreter), string(s.RunAs), s.TimeoutSeconds, s.MaxOutputBytes)
	if err != nil {
		return fmt.Errorf("update script meta: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("script %s not found", s.ID)
	}
	return nil
}

// AddScriptVersion appends a new immutable version with its own sha256 and makes it current.
// Editing content/params is always a new version — prior versions are never mutated.
func (r *Repository) AddScriptVersion(ctx context.Context, scriptID, content string, params []types.ScriptParam, createdBy string) (*types.ScriptVersion, error) {
	if len(content) > types.MaxScriptContentBytes {
		return nil, fmt.Errorf("script content is %d bytes, limit %d", len(content), types.MaxScriptContentBytes)
	}
	if len(params) > types.MaxScriptParameters {
		return nil, fmt.Errorf("%d parameters exceeds the limit of %d", len(params), types.MaxScriptParameters)
	}
	if err := validateParams(params); err != nil {
		return nil, err
	}
	paramsJSON, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal params: %w", err)
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin add version: %w", err)
	}
	defer tx.Rollback(ctx)

	var next int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version),0)+1 FROM script_versions WHERE script_id=$1`, scriptID).Scan(&next); err != nil {
		return nil, fmt.Errorf("compute next version: %w", err)
	}
	sha := types.ComputeScriptSHA256(content)
	v := &types.ScriptVersion{ScriptID: scriptID, Version: next, Content: content, SHA256: sha, Params: params, CreatedBy: createdBy}
	err = tx.QueryRow(ctx, `
		INSERT INTO script_versions (script_id, version, content, sha256, params, created_by)
		VALUES ($1,$2,$3,$4,$5::jsonb,$6)
		RETURNING id, created_at`,
		scriptID, next, content, sha, string(paramsJSON), createdBy,
	).Scan(&v.ID, &v.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("insert script version: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE scripts SET current_version_id=$2, updated_at=NOW() WHERE id=$1`, scriptID, v.ID); err != nil {
		return nil, fmt.Errorf("mark version current: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit add version: %w", err)
	}
	return v, nil
}

// SetCurrentScriptVersion marks an existing version of a script current.
func (r *Repository) SetCurrentScriptVersion(ctx context.Context, scriptID, versionID string) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE scripts SET current_version_id=$2, updated_at=NOW()
		WHERE id=$1 AND EXISTS (SELECT 1 FROM script_versions WHERE id=$2 AND script_id=$1)`,
		scriptID, versionID)
	if err != nil {
		return fmt.Errorf("set current version: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("version %s does not belong to script %s", versionID, scriptID)
	}
	return nil
}

// DeleteScript removes a script and (via cascade) its versions, runs and secrets. Sensors and
// SCRIPT_POLICY references cascade too; the agent-side handling treats a missing version safely.
func (r *Repository) DeleteScript(ctx context.Context, scriptID string) error {
	// Break the self-reference so the version rows can cascade-delete cleanly.
	if _, err := r.pool.Exec(ctx, `UPDATE scripts SET current_version_id=NULL WHERE id=$1`, scriptID); err != nil {
		return fmt.Errorf("clear current version: %w", err)
	}
	tag, err := r.pool.Exec(ctx, `DELETE FROM scripts WHERE id=$1`, scriptID)
	if err != nil {
		return fmt.Errorf("delete script: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("script %s not found", scriptID)
	}
	return nil
}

// GetScript returns a script with its current version populated.
func (r *Repository) GetScript(ctx context.Context, scriptID string) (*types.Script, error) {
	s, err := r.scanScript(ctx, `WHERE s.id=$1`, scriptID)
	if err != nil {
		return nil, err
	}
	if len(s) == 0 {
		return nil, nil
	}
	return s[0], nil
}

// ListScripts returns all scripts with current versions, ordered by name.
func (r *Repository) ListScripts(ctx context.Context) ([]*types.Script, error) {
	return r.scanScript(ctx, `ORDER BY s.name`)
}

func (r *Repository) scanScript(ctx context.Context, where string, args ...any) ([]*types.Script, error) {
	q := `
		SELECT s.id, s.name, s.description, s.interpreter, s.run_as, s.timeout_seconds, s.max_output_bytes,
		       s.current_version_id, s.created_by, s.created_at, s.updated_at,
		       v.id, v.version, v.content, v.sha256, v.params, v.created_by, v.created_at
		FROM scripts s
		LEFT JOIN script_versions v ON v.id = s.current_version_id ` + where
	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query scripts: %w", err)
	}
	defer rows.Close()
	out := make([]*types.Script, 0)
	for rows.Next() {
		var s types.Script
		var interp, runAs string
		var vID, vContent, vSHA, vCreatedBy *string
		var vVersion *int
		var vParams []byte
		var vCreatedAt *any
		if err := rows.Scan(
			&s.ID, &s.Name, &s.Description, &interp, &runAs, &s.TimeoutSeconds, &s.MaxOutputBytes,
			&s.CurrentVersionID, &s.CreatedBy, &s.CreatedAt, &s.UpdatedAt,
			&vID, &vVersion, &vContent, &vSHA, &vParams, &vCreatedBy, &vCreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan script: %w", err)
		}
		s.Interpreter = types.ScriptInterpreter(interp)
		s.RunAs = types.ScriptRunAs(runAs)
		if vID != nil {
			cv := &types.ScriptVersion{ID: *vID, ScriptID: s.ID}
			if vVersion != nil {
				cv.Version = *vVersion
			}
			if vContent != nil {
				cv.Content = *vContent
			}
			if vSHA != nil {
				cv.SHA256 = *vSHA
			}
			if vCreatedBy != nil {
				cv.CreatedBy = *vCreatedBy
			}
			_ = json.Unmarshal(vParams, &cv.Params)
			s.CurrentVersion = cv
		}
		out = append(out, &s)
	}
	return out, rows.Err()
}

// GetScriptVersion loads one immutable version (content + params) by id.
func (r *Repository) GetScriptVersion(ctx context.Context, versionID string) (*types.ScriptVersion, error) {
	var v types.ScriptVersion
	var params []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id, script_id, version, content, sha256, params, created_by, created_at
		FROM script_versions WHERE id=$1`, versionID).
		Scan(&v.ID, &v.ScriptID, &v.Version, &v.Content, &v.SHA256, &params, &v.CreatedBy, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrScriptVersionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get script version: %w", err)
	}
	_ = json.Unmarshal(params, &v.Params)
	return &v, nil
}

// GetScriptVersionWithScript loads a version together with its parent script's execution
// settings (interpreter, run_as, limits), which the directive builder needs.
func (r *Repository) GetScriptVersionWithScript(ctx context.Context, versionID string) (*types.ScriptVersion, *types.Script, error) {
	v, err := r.GetScriptVersion(ctx, versionID)
	if err != nil {
		return nil, nil, err
	}
	s, err := r.GetScript(ctx, v.ScriptID)
	if err != nil {
		return nil, nil, err
	}
	if s == nil {
		return nil, nil, ErrScriptVersionNotFound
	}
	return v, s, nil
}

// ListScriptVersions returns a script's version history, newest first.
func (r *Repository) ListScriptVersions(ctx context.Context, scriptID string) ([]types.ScriptVersion, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, script_id, version, content, sha256, params, created_by, created_at
		FROM script_versions WHERE script_id=$1 ORDER BY version DESC`, scriptID)
	if err != nil {
		return nil, fmt.Errorf("list script versions: %w", err)
	}
	defer rows.Close()
	out := make([]types.ScriptVersion, 0)
	for rows.Next() {
		var v types.ScriptVersion
		var params []byte
		if err := rows.Scan(&v.ID, &v.ScriptID, &v.Version, &v.Content, &v.SHA256, &params, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan version: %w", err)
		}
		_ = json.Unmarshal(params, &v.Params)
		out = append(out, v)
	}
	return out, rows.Err()
}

// validateParams checks each declared parameter and rejects duplicate names.
func validateParams(params []types.ScriptParam) error {
	seen := map[string]bool{}
	for _, p := range params {
		if err := p.Validate(); err != nil {
			return err
		}
		if seen[p.Name] {
			return fmt.Errorf("duplicate parameter name %q", p.Name)
		}
		seen[p.Name] = true
	}
	return nil
}

// GetScriptVersionByNumber returns a script's version by its integer version number, or nil
// (ErrScriptVersionNotFound) if the script or that version no longer exists. Used by the
// run_script workflow action to pin a specific version.
func (r *Repository) GetScriptVersionByNumber(ctx context.Context, scriptID string, version int) (*types.ScriptVersion, error) {
	var v types.ScriptVersion
	var params []byte
	err := r.pool.QueryRow(ctx, `
		SELECT id, script_id, version, content, sha256, params, created_by, created_at
		FROM script_versions WHERE script_id=$1 AND version=$2`, scriptID, version).
		Scan(&v.ID, &v.ScriptID, &v.Version, &v.Content, &v.SHA256, &params, &v.CreatedBy, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrScriptVersionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get script version by number: %w", err)
	}
	_ = json.Unmarshal(params, &v.Params)
	return &v, nil
}

// GetCurrentScriptVersion returns the script's current (published) version — the one
// SetCurrentScriptVersion marked — or nil (ErrScriptVersionNotFound) if the script has no
// current version or was deleted. Used by the run_script workflow action when no explicit
// version is given.
func (r *Repository) GetCurrentScriptVersion(ctx context.Context, scriptID string) (*types.ScriptVersion, error) {
	s, err := r.GetScript(ctx, scriptID)
	if err != nil {
		return nil, err
	}
	if s == nil || s.CurrentVersionID == nil || *s.CurrentVersionID == "" {
		return nil, ErrScriptVersionNotFound
	}
	return r.GetScriptVersion(ctx, *s.CurrentVersionID)
}
