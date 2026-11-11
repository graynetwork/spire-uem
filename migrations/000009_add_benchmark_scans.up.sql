-- 000009_add_benchmark_scans.up.sql
-- Native OpenSCAP & CIS Benchmark Scans

CREATE TABLE IF NOT EXISTS benchmark_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    benchmark_type VARCHAR(64) NOT NULL DEFAULT 'CIS_DEBIAN_12',
    profile VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    score NUMERIC(5,2) DEFAULT 0.00,
    rules_passed INT NOT NULL DEFAULT 0,
    rules_failed INT NOT NULL DEFAULT 0,
    rules_other INT NOT NULL DEFAULT 0,
    failed_rules JSONB DEFAULT '[]'::jsonb,
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_benchmark_scans_device_id ON benchmark_scans(device_id);
CREATE INDEX IF NOT EXISTS idx_benchmark_scans_status ON benchmark_scans(status);
CREATE INDEX IF NOT EXISTS idx_benchmark_scans_created_at ON benchmark_scans(created_at DESC);
