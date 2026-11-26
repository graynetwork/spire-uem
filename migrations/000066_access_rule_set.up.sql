-- =====================================================================
-- SpireUEM — Migration 000066: access rule set (conditional access)
-- =====================================================================
-- One fleet-wide, versioned rule set that the posture evaluator applies to every device to
-- produce device_posture (migration 000065). access_rule_set holds the CURRENT rules (a
-- single row); access_rule_set_history keeps every version so an edit is auditable and a
-- verdict's rule_set_version can be traced to the exact rules that produced it.
--
-- Fresh install default: only the check-in freshness check is enabled, so switching on a
-- connector does not lock every device out before an administrator configures checks.
-- Idempotent.

CREATE TABLE IF NOT EXISTS access_rule_set (
    id          SMALLINT    PRIMARY KEY CHECK (id = 1),
    version     INT         NOT NULL CHECK (version >= 1),
    rules       JSONB       NOT NULL,
    updated_by  TEXT        NOT NULL DEFAULT 'system',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS access_rule_set_history (
    version     INT         PRIMARY KEY,
    rules       JSONB       NOT NULL,
    changed_by  TEXT        NOT NULL,
    changed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO access_rule_set (id, version, rules, updated_by)
VALUES (1, 1, '{"checkin_fresh":{"enabled":true,"max_age_hours":24}}'::jsonb, 'system')
ON CONFLICT (id) DO NOTHING;

INSERT INTO access_rule_set_history (version, rules, changed_by)
VALUES (1, '{"checkin_fresh":{"enabled":true,"max_age_hours":24}}'::jsonb, 'system')
ON CONFLICT (version) DO NOTHING;
