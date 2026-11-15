-- Rollback for Migration 000027: scoped personal access tokens.
DROP TABLE IF EXISTS personal_access_tokens;
