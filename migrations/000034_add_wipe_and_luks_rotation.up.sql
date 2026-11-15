-- =====================================================================
-- SpireUEM — Lost-Device Actions (part 2): crypto-erase wipe & LUKS rotation
-- =====================================================================
-- device_wipe_requests implements a two-person rule irreversible crypto-erase:
--   1. a SUPER_ADMIN REQUESTS a wipe (typed hostname confirmation),
--   2. a DIFFERENT SUPER_ADMIN APPROVES it within 24h,
--   3. the server signs a wipe order (Ed25519) the agent fetches on check-in,
--   4. a cancellation window remains until the agent picks the order up.
-- The static break-glass account counts as one person.

DO $$ BEGIN
    CREATE TYPE wipe_request_status AS ENUM (
        'PENDING_APPROVAL',  -- requested, awaiting a second super-admin
        'APPROVED',          -- approved, signed order available for the agent
        'DELIVERED',         -- agent fetched the signed order (cancellation window closed)
        'COMPLETED',         -- agent reported the crypto-erase done
        'CANCELLED',         -- cancelled before delivery
        'EXPIRED',           -- approval window elapsed without a second approver
        'FAILED'             -- agent reported failure
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS device_wipe_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    status          wipe_request_status NOT NULL DEFAULT 'PENDING_APPROVAL',
    -- hostname the requester typed to confirm (must match the device at request time).
    confirm_hostname TEXT NOT NULL,
    reason          TEXT NOT NULL DEFAULT '',
    requested_by    TEXT NOT NULL,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- approval must happen within this deadline (request + 24h).
    approval_deadline TIMESTAMPTZ NOT NULL,
    approved_by     TEXT NULL,
    approved_at     TIMESTAMPTZ NULL,
    cancelled_by    TEXT NULL,
    cancelled_at    TIMESTAMPTZ NULL,
    -- the signed order payload (canonical JSON) and its Ed25519 signature, filled at approval.
    signed_order    BYTEA NULL,
    order_signature BYTEA NULL,
    delivered_at    TIMESTAMPTZ NULL,
    completed_at    TIMESTAMPTZ NULL,
    result_detail   TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_device_wipe_requests_device
    ON device_wipe_requests (device_id, created_at DESC);
-- At most one open (not terminal) wipe request per device.
CREATE UNIQUE INDEX IF NOT EXISTS uq_device_wipe_requests_open
    ON device_wipe_requests (device_id)
    WHERE status IN ('PENDING_APPROVAL', 'APPROVED', 'DELIVERED');

-- luks_rotation_state tracks the auto-queued recovery-key rotation after a reveal.
DO $$ BEGIN
    CREATE TYPE luks_rotation_status AS ENUM (
        'PENDING',   -- queued, awaiting agent
        'DONE',      -- agent rotated and re-escrowed
        'FAILED'     -- agent could not rotate
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS luks_rotation_state (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id     UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    volume_uuid   TEXT NOT NULL,
    status        luks_rotation_status NOT NULL DEFAULT 'PENDING',
    reason        TEXT NOT NULL DEFAULT '',
    requested_by  TEXT NOT NULL DEFAULT '',
    detail        TEXT NOT NULL DEFAULT '',
    requested_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at  TIMESTAMPTZ NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_luks_rotation_state_device
    ON luks_rotation_state (device_id, requested_at DESC);
-- At most one PENDING rotation per (device, volume).
CREATE UNIQUE INDEX IF NOT EXISTS uq_luks_rotation_state_pending
    ON luks_rotation_state (device_id, volume_uuid)
    WHERE status = 'PENDING';
