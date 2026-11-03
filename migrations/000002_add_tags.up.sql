-- SpireUEM Phase 4: Fleet Grouping & Tag-Based Policy Targeting

ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}';

ALTER TABLE policies
    ADD COLUMN IF NOT EXISTS target_tags TEXT[] NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_devices_tags ON devices USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_policies_target_tags ON policies USING GIN (target_tags);
