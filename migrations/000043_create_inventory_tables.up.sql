-- Rich inventory list tables. Scalar inventory facts live in device_attributes (source
-- 'inventory'); the large per-device lists live here and are replaced wholesale on each
-- report. Every row cascades on device delete.

CREATE TABLE IF NOT EXISTS device_inventory_packages (
    device_id    UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name         TEXT        NOT NULL,
    version      TEXT        NOT NULL DEFAULT '',
    architecture TEXT        NOT NULL DEFAULT '',
    origin       TEXT        NOT NULL DEFAULT '',
    install_time TIMESTAMPTZ,
    PRIMARY KEY (device_id, name)
);
CREATE INDEX IF NOT EXISTS idx_inv_packages_name ON device_inventory_packages (name);
CREATE INDEX IF NOT EXISTS idx_inv_packages_name_version ON device_inventory_packages (name, version);

CREATE TABLE IF NOT EXISTS device_inventory_modules (
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name      TEXT NOT NULL,
    PRIMARY KEY (device_id, name)
);

CREATE TABLE IF NOT EXISTS device_inventory_listening (
    device_id    UUID    NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    protocol     TEXT    NOT NULL,
    port         INTEGER NOT NULL,
    address      TEXT    NOT NULL DEFAULT '',
    process_name TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (device_id, protocol, port, address)
);
CREATE INDEX IF NOT EXISTS idx_inv_listening_port ON device_inventory_listening (port);

CREATE TABLE IF NOT EXISTS device_inventory_accounts (
    device_id UUID    NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    username  TEXT    NOT NULL,
    uid       INTEGER NOT NULL,
    is_sudo   BOOLEAN NOT NULL DEFAULT FALSE,
    shell     TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (device_id, username)
);
CREATE INDEX IF NOT EXISTS idx_inv_accounts_username ON device_inventory_accounts (username);
CREATE INDEX IF NOT EXISTS idx_inv_accounts_sudo ON device_inventory_accounts (is_sudo) WHERE is_sudo;

CREATE TABLE IF NOT EXISTS device_inventory_cacerts (
    device_id UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    sha256    TEXT        NOT NULL,
    subject   TEXT        NOT NULL DEFAULT '',
    expiry    TIMESTAMPTZ,
    PRIMARY KEY (device_id, sha256)
);

CREATE TABLE IF NOT EXISTS device_inventory_usb (
    device_id  UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    vendor_id  TEXT NOT NULL,
    product_id TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (device_id, vendor_id, product_id, name)
);
