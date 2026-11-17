-- =====================================================================
-- SpireUEM — Migration 000048: dynamic device groups and saved fleet queries
-- =====================================================================
-- A device group is a dynamic set defined by an optional JSON rule plus static include /
-- exclude device lists. Membership = (rule matches OR included) AND NOT excluded, and is
-- materialised into group_memberships, recomputed after a device checks in, periodically,
-- and whenever a group is saved. group_membership_events records a bounded entered/left
-- history with the reason. Idempotent.

CREATE TABLE IF NOT EXISTS device_groups (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(128) NOT NULL UNIQUE,
    description         TEXT         NOT NULL DEFAULT '',
    kind                VARCHAR(16)  NOT NULL DEFAULT 'target'
                                     CHECK (kind IN ('target', 'query')),
    -- rule is the JSON rule tree (null when the group is a pure static list).
    rule                JSONB,
    include_device_ids  UUID[]       NOT NULL DEFAULT '{}',
    exclude_device_ids  UUID[]       NOT NULL DEFAULT '{}',
    created_by          VARCHAR(255) NOT NULL DEFAULT '',
    -- creator_scoped_tags records the allowed_tags of the creating admin: non-empty means a
    -- tag-scoped admin created it, so another scoped admin's edits are allowed only on their
    -- own groups. Empty means an unscoped admin created it (uneditable by a scoped admin).
    creator_scoped_tags TEXT[]       NOT NULL DEFAULT '{}',
    -- last_rule_error surfaces the most recent evaluation failure on the group page; when
    -- set, the last successfully materialised membership is retained (fail-safe).
    last_rule_error     TEXT         NOT NULL DEFAULT '',
    last_evaluated_at   TIMESTAMPTZ,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Materialised membership. One row per (group, device) currently in the group.
CREATE TABLE IF NOT EXISTS group_memberships (
    group_id   UUID        NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    device_id  UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    entered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_group_memberships_device ON group_memberships (device_id);
CREATE INDEX IF NOT EXISTS idx_group_memberships_group ON group_memberships (group_id);

-- Bounded entered/left history with the reason (which top-level conditions changed, plus the
-- evaluated values). Trimmed per group by the recompute path.
CREATE TABLE IF NOT EXISTS group_membership_events (
    id         BIGSERIAL   PRIMARY KEY,
    group_id   UUID        NOT NULL REFERENCES device_groups(id) ON DELETE CASCADE,
    device_id  UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    entered    BOOLEAN     NOT NULL,
    reason     TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_group_membership_events_group
    ON group_membership_events (group_id, created_at DESC);
