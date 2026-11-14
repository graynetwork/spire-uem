-- 000031_add_network_usb_policy_types.down.sql
-- Postgres cannot remove a value from an enum type without recreating it. Enum additions
-- are forward-only and harmless if unused, so this down migration is intentionally a no-op.
SELECT 1;
