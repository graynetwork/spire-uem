ALTER TABLE enrollment_tokens
    DROP COLUMN IF EXISTS require_approval,
    DROP COLUMN IF EXISTS hostname_pattern,
    DROP COLUMN IF EXISTS created_by,
    DROP COLUMN IF EXISTS rotated_at;
