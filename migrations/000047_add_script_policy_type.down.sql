-- PostgreSQL cannot remove a value from an enum type without rebuilding it, which would
-- require rewriting every table that uses policy_type. Leaving SCRIPT_POLICY in the enum is
-- harmless when the feature is rolled back: no policy rows reference it. Intentional no-op,
-- matching the down migrations of the earlier ADD VALUE policy-type migrations.
SELECT 1;
