-- =====================================================================
-- SpireUEM — Migration 000049: group-based policy/application targeting
-- =====================================================================
-- Policies (which also back applications) gain target_group_ids. A policy with no groups
-- behaves exactly as before (upgrade safety); a policy WITH groups targets a device only
-- when the existing tag/ring rules match AND the device is a member of at least one listed
-- group. Referenced-group protection is enforced in the repository (a group referenced by a
-- policy cannot be deleted). Idempotent.

ALTER TABLE policies
    ADD COLUMN IF NOT EXISTS target_group_ids UUID[] NOT NULL DEFAULT '{}';

-- GIN index so "policies referencing group X" and "devices targeted via a group" stay cheap.
CREATE INDEX IF NOT EXISTS idx_policies_target_group_ids
    ON policies USING GIN (target_group_ids);
