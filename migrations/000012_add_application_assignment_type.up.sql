-- =====================================================================
-- SpireUEM — Migration 000012: Application Assignment Type (REQUIRED vs AVAILABLE)
-- =====================================================================

DO $$ BEGIN
    CREATE TYPE application_assignment_type AS ENUM (
        'REQUIRED',
        'AVAILABLE'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE policies
    ADD COLUMN IF NOT EXISTS assignment_type TEXT NOT NULL DEFAULT 'REQUIRED'
    CHECK (assignment_type IN ('REQUIRED', 'AVAILABLE'));

-- Synchronize existing self-service policies to AVAILABLE assignment_type
UPDATE policies
SET assignment_type = 'AVAILABLE'
WHERE is_self_service = true AND assignment_type = 'REQUIRED';

-- Ensure existing non-self-service FLATPAK_APP and PACKAGE_PRESENCE policies default to REQUIRED
UPDATE policies
SET assignment_type = 'REQUIRED'
WHERE is_self_service = false
  AND policy_type IN ('FLATPAK_APP', 'PACKAGE_PRESENCE')
  AND (assignment_type IS NULL OR assignment_type = '');

CREATE INDEX IF NOT EXISTS idx_policies_assignment_type
    ON policies (assignment_type);
