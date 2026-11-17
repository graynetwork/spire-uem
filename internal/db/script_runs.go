package db

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spire-uem/spire-uem/internal/types"
)

// maxStoredRunOutput caps stdout/stderr stored per run (defence in depth; the agent also caps).
const maxStoredRunOutput = types.ScriptMaxOutputBytesCeiling

// ResolveScriptParams validates supplied values against a version's parameter schema and
// splits them into non-secret (plain) and secret values. Missing required parameters are an
// error; a declared parameter with a default supplies it; an unknown supplied name is an
// error so a typo cannot silently drop a value. Values are kept as literal strings — they are
// NEVER interpreted, so an injection attempt in a value stays a literal env-var value.
func ResolveScriptParams(v *types.ScriptVersion, supplied map[string]string) (plain map[string]string, secret map[string]string, err error) {
	plain = map[string]string{}
	secret = map[string]string{}
	declared := map[string]bool{}
	for _, p := range v.Params {
		declared[p.Name] = true
		val, ok := supplied[p.Name]
		if !ok || strings.TrimSpace(val) == "" {
			if p.Required && p.Default == "" {
				return nil, nil, fmt.Errorf("missing required parameter %q", p.Name)
			}
			if p.Default == "" {
				continue // optional, unset: not passed at all
			}
			val = p.Default
		}
		if verr := types.ValidateScriptParamValue(p.Type, val); verr != nil {
			return nil, nil, fmt.Errorf("parameter %s: %w", p.Name, verr)
		}
		if p.Type == types.ScriptParamBoolean {
			val = types.NormalizeBool(val)
		}
		if p.Secret {
			secret[p.Name] = val
		} else {
			plain[p.Name] = val
		}
	}
	for name := range supplied {
		if !declared[name] {
			return nil, nil, fmt.Errorf("unknown parameter %q", name)
		}
	}
	return plain, secret, nil
}

// QueueScriptRun creates a QUEUED run for one device, storing non-secret params in the clear
// and sealing secret params with the server KEK. Returns the run id. Targeting/scoping is the
// caller's responsibility (the web layer intersects with the admin's tag scope first).
func (r *Repository) QueueScriptRun(ctx context.Context, deviceID string, v *types.ScriptVersion, trigger types.ScriptRunTrigger, plain, secret map[string]string, requestedBy string) (string, error) {
	plainJSON, err := json.Marshal(plain)
	if err != nil {
		return "", fmt.Errorf("marshal run params: %w", err)
	}

	var sealed []types.SecretEnvelope
	var sealedNames []string
	if len(secret) > 0 {
		pub := r.KEKPrivateKey()
		if pub == nil {
			return "", fmt.Errorf("server KEK unavailable: cannot seal secret parameters")
		}
		for name, val := range secret {
			env, serr := SealSecret(&pub.PublicKey, val)
			if serr != nil {
				return "", fmt.Errorf("seal secret param %s: %w", name, serr)
			}
			sealed = append(sealed, env)
			sealedNames = append(sealedNames, name)
		}
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin queue run: %w", err)
	}
	defer tx.Rollback(ctx)

	var runID string
	err = tx.QueryRow(ctx, `
		INSERT INTO script_runs (device_id, script_id, script_version_id, version, trigger, status, params, requested_by)
		VALUES ($1,$2,$3,$4,$5,'QUEUED',$6::jsonb,$7)
		RETURNING id`,
		deviceID, v.ScriptID, v.ID, v.Version, string(trigger), string(plainJSON), requestedBy,
	).Scan(&runID)
	if err != nil {
		return "", fmt.Errorf("insert script run: %w", err)
	}
	for i, env := range sealed {
		if _, err := tx.Exec(ctx, `
			INSERT INTO script_run_secrets (run_id, param_name, ciphertext, encrypted_dek, nonce)
			VALUES ($1,$2,$3,$4,$5)`,
			runID, sealedNames[i], env.Ciphertext, env.EncryptedDEK, env.Nonce); err != nil {
			return "", fmt.Errorf("store sealed param %s: %w", sealedNames[i], err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("commit queue run: %w", err)
	}
	return runID, nil
}

// ClaimScriptDirectivesForDevice returns the QUEUED runs for a device as fully-resolved
// directives (content, sha256, opened secret params) and marks them RUNNING in the same
// transaction so a run is dispatched exactly once even across two server instances. Secret
// values are opened here and placed only in the returned directive, never persisted in plain.
func (r *Repository) ClaimScriptDirectivesForDevice(ctx context.Context, deviceID string) ([]types.ScriptDirective, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin claim script runs: %w", err)
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `
		UPDATE script_runs
		SET status='RUNNING'
		WHERE id IN (
			SELECT id FROM script_runs
			WHERE device_id=$1 AND status='QUEUED'
			ORDER BY created_at ASC
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, script_id, script_version_id, version, params`, deviceID)
	if err != nil {
		return nil, fmt.Errorf("claim script runs: %w", err)
	}

	type claimed struct {
		runID, scriptID, versionID string
		version                    int
		plain                      map[string]string
	}
	var claims []claimed
	for rows.Next() {
		var c claimed
		var plainJSON []byte
		if err := rows.Scan(&c.runID, &c.scriptID, &c.versionID, &c.version, &plainJSON); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan claimed run: %w", err)
		}
		c.plain = map[string]string{}
		_ = json.Unmarshal(plainJSON, &c.plain)
		claims = append(claims, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	priv := r.KEKPrivateKey()
	out := make([]types.ScriptDirective, 0, len(claims))
	for _, c := range claims {
		v, err := r.GetScriptVersion(ctx, c.versionID)
		if err != nil {
			// Version deleted since queueing: mark the run FAILED and skip it.
			_, _ = tx.Exec(ctx, `UPDATE script_runs SET status='FAILED', stderr=$2, reported_at=NOW() WHERE id=$1`,
				c.runID, "script version no longer exists")
			continue
		}
		s, err := r.GetScript(ctx, v.ScriptID)
		if err != nil || s == nil {
			_, _ = tx.Exec(ctx, `UPDATE script_runs SET status='FAILED', stderr=$2, reported_at=NOW() WHERE id=$1`,
				c.runID, "script no longer exists")
			continue
		}

		params := map[string]string{}
		for k, val := range c.plain {
			params[k] = val
		}
		// Open sealed secrets for this run.
		srows, serr := tx.Query(ctx, `SELECT param_name, ciphertext, encrypted_dek, nonce FROM script_run_secrets WHERE run_id=$1`, c.runID)
		if serr == nil {
			for srows.Next() {
				var name string
				var env types.SecretEnvelope
				if err := srows.Scan(&name, &env.Ciphertext, &env.EncryptedDEK, &env.Nonce); err != nil {
					continue
				}
				pt, oerr := OpenSecret(priv, env)
				if oerr == nil {
					params[name] = pt
				}
			}
			srows.Close()
		}

		out = append(out, types.ScriptDirective{
			RunID:       c.runID,
			ScriptID:    v.ScriptID,
			VersionID:   v.ID,
			Version:     v.Version,
			Interpreter: s.Interpreter,
			RunAs:       s.RunAs,
			Content:     v.Content,
			SHA256:      v.SHA256,
			TimeoutSecs: s.TimeoutSeconds,
			MaxOutput:   s.MaxOutputBytes,
			Params:      params,
		})
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit claim script runs: %w", err)
	}
	return out, nil
}

// RecordScriptRunResult stores a reported run outcome. Only a run currently in a non-terminal
// state is updated, so a duplicate report cannot overwrite a finished run.
func (r *Repository) RecordScriptRunResult(ctx context.Context, deviceID string, res types.ScriptRunResult) error {
	stdout := capString(res.Stdout, maxStoredRunOutput)
	stderr := capString(res.Stderr, maxStoredRunOutput)
	status := string(res.Status)
	switch types.ScriptRunStatus(status) {
	case types.ScriptRunCompleted, types.ScriptRunFailed, types.ScriptRunTimedOut, types.ScriptRunInterrupted:
	default:
		return fmt.Errorf("invalid script run status %q", status)
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE script_runs
		SET status=$3, exit_code=$4, stdout=$5, stderr=$6, duration_ms=$7, reported_at=NOW()
		WHERE id=$1 AND device_id=$2 AND status IN ('QUEUED','RUNNING')`,
		res.RunID, deviceID, status, res.ExitCode, stdout, stderr, res.DurationMS)
	if err != nil {
		return fmt.Errorf("record script run result: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("run %s not found or already finalized for device", res.RunID)
	}
	return nil
}

// RequeueStaleRunningScriptRuns marks runs left RUNNING past a cutoff as INTERRUPTED, so a run
// cut off by an agent restart is reported as interrupted, not lost. Returns the count affected.
func (r *Repository) RequeueStaleRunningScriptRuns(ctx context.Context, deviceID string, olderThan time.Duration) (int, error) {
	cutoff := time.Now().UTC().Add(-olderThan)
	tag, err := r.pool.Exec(ctx, `
		UPDATE script_runs SET status='INTERRUPTED', reported_at=NOW()
		WHERE device_id=$1 AND status='RUNNING' AND created_at < $2`, deviceID, cutoff)
	if err != nil {
		return 0, fmt.Errorf("requeue stale runs: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// ListScriptRunsForDevice returns recent runs for a device, newest first.
func (r *Repository) ListScriptRunsForDevice(ctx context.Context, deviceID string, limit int) ([]types.ScriptRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := r.pool.Query(ctx, `
		SELECT id, device_id, script_id, script_version_id, version, trigger, status,
		       exit_code, stdout, stderr, duration_ms, params, requested_by, created_at, reported_at
		FROM script_runs WHERE device_id=$1 ORDER BY created_at DESC LIMIT $2`, deviceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list script runs: %w", err)
	}
	defer rows.Close()
	out := make([]types.ScriptRun, 0)
	for rows.Next() {
		var run types.ScriptRun
		var trigger, status string
		if err := rows.Scan(&run.ID, &run.DeviceID, &run.ScriptID, &run.ScriptVersionID, &run.Version,
			&trigger, &status, &run.ExitCode, &run.Stdout, &run.Stderr, &run.DurationMS,
			&run.ParamsJSON, &run.RequestedBy, &run.CreatedAt, &run.ReportedAt); err != nil {
			return nil, fmt.Errorf("scan script run: %w", err)
		}
		run.Trigger = types.ScriptRunTrigger(trigger)
		run.Status = types.ScriptRunStatus(status)
		out = append(out, run)
	}
	return out, rows.Err()
}

// capString truncates s to at most n bytes, respecting UTF-8 boundaries loosely (byte cap is
// sufficient here: the content is bounded program output, not an identifier).
func capString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
