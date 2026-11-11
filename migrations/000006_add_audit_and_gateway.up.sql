-- =====================================================================
-- SpireUEM — Phase 9 Migration: Real-Time WebSocket Gateway & SIEM Audit
-- =====================================================================

-- 1. Extend devices with real-time WebSocket presence tracking
ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS ws_connected BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS last_ws_seen_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS idx_devices_ws_connected ON devices (ws_connected);

-- 2. Create system_audit_events table for enterprise audit & SIEM forwarding
CREATE TABLE IF NOT EXISTS system_audit_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    target_id   TEXT NULL,
    details     JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_system_audit_events_action_created
    ON system_audit_events (action, created_at DESC);
