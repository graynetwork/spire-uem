-- Per-device script runs, their sealed secret parameters, custom sensors, sensor readings,
-- and per-device sensor scheduling state.

-- One execution of a script version on one device. The non-secret parameter values bound for
-- the run are kept in `params` for audit; secret values live only in script_run_secrets,
-- sealed. stdout/stderr are capped before storage by the server.
CREATE TABLE IF NOT EXISTS script_runs (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id         UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    script_id         UUID        NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
    script_version_id UUID        NOT NULL REFERENCES script_versions(id) ON DELETE CASCADE,
    version           INTEGER     NOT NULL DEFAULT 0,
    trigger           TEXT        NOT NULL DEFAULT 'on_demand' CHECK (trigger IN ('on_demand', 'scheduled', 'agent_start')),
    status            TEXT        NOT NULL DEFAULT 'QUEUED' CHECK (status IN ('QUEUED','RUNNING','COMPLETED','FAILED','TIMED_OUT','INTERRUPTED')),
    exit_code         INTEGER     NULL,
    stdout            TEXT        NOT NULL DEFAULT '',
    stderr            TEXT        NOT NULL DEFAULT '',
    duration_ms       BIGINT      NOT NULL DEFAULT 0,
    params            JSONB       NOT NULL DEFAULT '{}'::jsonb,
    requested_by      TEXT        NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reported_at       TIMESTAMPTZ NULL
);
CREATE INDEX IF NOT EXISTS idx_script_runs_device ON script_runs (device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_script_runs_claim ON script_runs (device_id, status) WHERE status = 'QUEUED';

-- Sealed secret parameter values for a run. Stored with the server's RSA-OAEP + AES-GCM
-- envelope (SealSecret); opened only when the directive for the target device is built, and
-- never rendered or logged. Deleted with the run (cascade).
CREATE TABLE IF NOT EXISTS script_run_secrets (
    run_id        UUID NOT NULL REFERENCES script_runs(id) ON DELETE CASCADE,
    param_name    TEXT NOT NULL,
    ciphertext    TEXT NOT NULL,
    encrypted_dek TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    PRIMARY KEY (run_id, param_name)
);

-- A custom sensor: a script version run on a schedule whose typed result is stored as the
-- device attribute sensor.<name>.
CREATE TABLE IF NOT EXISTS sensors (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name              TEXT        NOT NULL UNIQUE,
    description       TEXT        NOT NULL DEFAULT '',
    script_id         UUID        NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
    script_version_id UUID        NOT NULL REFERENCES script_versions(id) ON DELETE CASCADE,
    return_type       TEXT        NOT NULL CHECK (return_type IN ('string','integer','boolean','datetime','json')),
    interval_seconds  INTEGER     NOT NULL CHECK (interval_seconds >= 900),
    target_tags       TEXT[]      NOT NULL DEFAULT '{}',
    target_ring       TEXT        NULL,
    enabled           BOOLEAN     NOT NULL DEFAULT TRUE,
    created_by        TEXT        NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT sensors_name_format CHECK (name ~ '^[a-z][a-z0-9_]{0,47}$')
);

-- Bounded per device+sensor reading history. ok=false rows record a parse/exec error; the
-- device attribute keeps its last good value in that case.
CREATE TABLE IF NOT EXISTS sensor_results (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id   UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    sensor_name TEXT        NOT NULL,
    ok          BOOLEAN     NOT NULL,
    value       JSONB       NULL,
    error_msg   TEXT        NOT NULL DEFAULT '',
    exit_code   INTEGER     NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sensor_results_device_sensor ON sensor_results (device_id, sensor_name, created_at DESC);

-- Per device+sensor scheduling state: when the sensor was last dispatched to a device, so the
-- server dispatches it again only once its interval has elapsed. A server restart or a second
-- server instance reads the same row, so a sensor is not re-dispatched on every check-in.
CREATE TABLE IF NOT EXISTS sensor_device_state (
    device_id      UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    sensor_id      UUID        NOT NULL REFERENCES sensors(id) ON DELETE CASCADE,
    last_dispatched_at TIMESTAMPTZ NULL,
    PRIMARY KEY (device_id, sensor_id)
);
