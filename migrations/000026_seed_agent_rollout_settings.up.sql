-- =====================================================================
-- SpireUEM — Migration 000026: Agent self-update rollout control settings
-- =====================================================================
-- Seeds the system_settings rows that drive server-side rollout control for
-- agent self-update. SUPER_ADMIN edits these in Settings → Agent Rollout.
--   rollout.target_version.<RING> : target agent version for that patch ring,
--                                   or "none" to disable auto-update for the ring.
--   rollout.minimum_version       : agents below this are refused on check-in
--                                   (HTTP 426), except self-update endpoints.
-- Empty string / "none" / "dev" are all treated as "no constraint" by the
-- rollout engine. Idempotent: ON CONFLICT DO NOTHING preserves operator edits.

INSERT INTO system_settings (key, category, value, description, is_secret, updated_by)
VALUES
    ('rollout.minimum_version', 'rollout', '""'::jsonb,
     'Minimum supported agent version; agents below this are refused on check-in with HTTP 426 (except self-update endpoints). Empty disables the floor.', FALSE, 'system'),
    ('rollout.target_version.CANARY', 'rollout', '"none"'::jsonb,
     'Target agent version for the CANARY patch ring, or "none" to disable auto-update for this ring.', FALSE, 'system'),
    ('rollout.target_version.BETA', 'rollout', '"none"'::jsonb,
     'Target agent version for the BETA patch ring, or "none" to disable auto-update for this ring.', FALSE, 'system'),
    ('rollout.target_version.PILOT', 'rollout', '"none"'::jsonb,
     'Target agent version for the PILOT patch ring, or "none" to disable auto-update for this ring.', FALSE, 'system'),
    ('rollout.target_version.PRODUCTION', 'rollout', '"none"'::jsonb,
     'Target agent version for the PRODUCTION patch ring, or "none" to disable auto-update for this ring.', FALSE, 'system')
ON CONFLICT (key) DO NOTHING;
