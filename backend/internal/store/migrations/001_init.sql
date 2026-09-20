CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY,
    scan_mode TEXT NOT NULL CHECK (scan_mode IN ('passive', 'active', 'combined')),
    target TEXT NOT NULL,
    findings JSONB NOT NULL,
    summary JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS scans_expires_at_idx ON scans (expires_at);
