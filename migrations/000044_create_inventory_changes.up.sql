-- Field-level inventory change history. One row per observed change to a device's inventory:
-- a scalar attribute changing value, or a list entry being added or removed (a new listening
-- port, a new local admin, a package install/removal...). Bounded per device (the writer
-- trims to the most recent N rows) so it never grows without limit.

CREATE TABLE IF NOT EXISTS device_inventory_changes (
    id         BIGSERIAL   PRIMARY KEY,
    device_id  UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    -- category groups the change: 'attr', 'package', 'listening', 'account', 'module',
    -- 'cacert', 'usb'. change_key identifies the specific field/entry within that category.
    category   TEXT        NOT NULL,
    change_key TEXT        NOT NULL,
    -- change_type is 'added', 'removed' or 'modified'.
    change_type TEXT       NOT NULL CHECK (change_type IN ('added', 'removed', 'modified')),
    old_value  TEXT        NOT NULL DEFAULT '',
    new_value  TEXT        NOT NULL DEFAULT '',
    changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_inv_changes_device_time
    ON device_inventory_changes (device_id, changed_at DESC, id DESC);
