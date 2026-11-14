-- Migration 000026 down: remove agent rollout control settings.
DELETE FROM system_settings WHERE category = 'rollout';
