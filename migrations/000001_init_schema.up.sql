-- SpireUEM Initial Database Schema

DO $$ BEGIN
    CREATE TYPE device_status AS ENUM (
        'PENDING_APPROVAL',
        'APPROVED',
        'REJECTED',
        'REVOKED'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE policy_type AS ENUM (
        'PACKAGE_ABSENCE',
        'PACKAGE_PRESENCE',
        'DCONF_SETTING',
        'SYSTEMD_SERVICE'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE compliance_status AS ENUM (
        'PENDING',
        'COMPLIANT',
        'NON_COMPLIANT',
        'FAILED'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hardware_uuid TEXT NOT NULL UNIQUE,
    hostname TEXT NOT NULL,
    status device_status NOT NULL DEFAULT 'PENDING_APPROVAL',
    auth_token_hash TEXT NULL,
    reported_state JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_checkin_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_devices_hardware_uuid ON devices (hardware_uuid);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices (status);
CREATE INDEX IF NOT EXISTS idx_devices_reported_state ON devices USING GIN (reported_state);

CREATE TABLE IF NOT EXISTS policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    policy_type policy_type NOT NULL,
    payload JSONB NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS device_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    compliance_status compliance_status NOT NULL DEFAULT 'PENDING',
    last_enforced_at TIMESTAMPTZ NULL,
    error_message TEXT NULL,
    execution_output JSONB NULL,
    CONSTRAINT uq_device_policy UNIQUE (device_id, policy_id)
);
