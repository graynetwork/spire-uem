-- Typed per-device attributes: the shared data model that inventory collection and
-- custom sensors write to, and that dynamic groups query.
--
-- Each attribute is owned by exactly one source. A writer can only replace or remove keys
-- it owns, so a sensor cannot overwrite an inventory field and vice versa.
CREATE TABLE IF NOT EXISTS device_attributes (
    device_id   UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key         TEXT        NOT NULL,
    value_type  TEXT        NOT NULL CHECK (value_type IN ('string', 'integer', 'boolean', 'datetime', 'json')),
    value       JSONB       NOT NULL,
    source      TEXT        NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (device_id, key),
    CONSTRAINT device_attributes_key_format CHECK (key ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$' AND length(key) <= 128),
    CONSTRAINT device_attributes_source_format CHECK (source ~ '^[a-z][a-z0-9_]*(:[a-z0-9_.-]+)?$' AND length(source) <= 128)
);

-- Group rules filter by key across the fleet.
CREATE INDEX IF NOT EXISTS idx_device_attributes_key ON device_attributes (key);
CREATE INDEX IF NOT EXISTS idx_device_attributes_source ON device_attributes (source);
