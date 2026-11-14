-- 000031_add_network_usb_policy_types.up.sql
-- Add NETWORK_PROFILE (NetworkManager) and USB_DEVICE_CONTROL (usbguard) to policy_type enum.
-- Re-applied on every server start, so each ADD VALUE is guarded with IF NOT EXISTS.

ALTER TYPE policy_type ADD VALUE IF NOT EXISTS 'NETWORK_PROFILE';
ALTER TYPE policy_type ADD VALUE IF NOT EXISTS 'USB_DEVICE_CONTROL';
