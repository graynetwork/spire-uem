-- Reverse of 000034_add_wipe_and_luks_rotation.up.sql
DROP TABLE IF EXISTS luks_rotation_state;
DROP TABLE IF EXISTS device_wipe_requests;
DROP TYPE IF EXISTS luks_rotation_status;
DROP TYPE IF EXISTS wipe_request_status;
