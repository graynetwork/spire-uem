-- Reusable scripts and their immutable versions.
--
-- A script is a named program with a fixed interpreter, run-as identity and resource caps.
-- Editing the content or parameter schema creates a NEW row in script_versions; existing
-- versions are never mutated, so a sensor or policy that pins a version id keeps running the
-- exact bytes it was created with. current_version_id points at the version dispatched for
-- an on-demand run.
CREATE TABLE IF NOT EXISTS scripts (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name               TEXT        NOT NULL,
    description        TEXT        NOT NULL DEFAULT '',
    interpreter        TEXT        NOT NULL CHECK (interpreter IN ('bash', 'python3')),
    run_as             TEXT        NOT NULL CHECK (run_as IN ('root', 'active_user')),
    timeout_seconds    INTEGER     NOT NULL DEFAULT 300 CHECK (timeout_seconds > 0 AND timeout_seconds <= 3600),
    max_output_bytes   INTEGER     NOT NULL DEFAULT 65536 CHECK (max_output_bytes > 0 AND max_output_bytes <= 1048576),
    current_version_id UUID        NULL,
    created_by         TEXT        NOT NULL DEFAULT '',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS script_versions (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    script_id  UUID        NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
    version    INTEGER     NOT NULL,
    content    TEXT        NOT NULL,
    sha256     TEXT        NOT NULL,
    params     JSONB       NOT NULL DEFAULT '[]'::jsonb,
    created_by TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (script_id, version)
);

-- current_version_id references a row in script_versions once the first version exists.
ALTER TABLE scripts
    ADD CONSTRAINT scripts_current_version_fk
    FOREIGN KEY (current_version_id) REFERENCES script_versions(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_script_versions_script ON script_versions (script_id, version DESC);
