PRAGMA foreign_keys = ON;

CREATE TABLE workspaces (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);

CREATE TABLE targets (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  hostname TEXT NOT NULL,
  verification_token TEXT NOT NULL,
  verified_at TEXT,
  verification_method TEXT,
  created_at TEXT NOT NULL,
  last_scan_at TEXT,
  last_discovery_at TEXT,
  UNIQUE(workspace_id, hostname)
);

CREATE TABLE scans (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed')),
  mode TEXT NOT NULL DEFAULT 'passive',
  started_at TEXT NOT NULL,
  finished_at TEXT,
  summary_json TEXT,
  error_code TEXT
);

CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  check_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','info')),
  confidence TEXT NOT NULL CHECK(confidence IN ('confirmed','high','medium','low')),
  status TEXT NOT NULL DEFAULT 'open',
  description TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  remediation TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(scan_id, check_id)
);

CREATE TABLE scan_events (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE source_artifacts (
  id TEXT PRIMARY KEY,
  worker_name TEXT NOT NULL,
  deployment_version TEXT NOT NULL,
  filename TEXT NOT NULL,
  source_text TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE INDEX idx_targets_workspace_created ON targets(workspace_id, created_at DESC);
CREATE INDEX idx_scans_workspace_started ON scans(workspace_id, started_at DESC);
CREATE INDEX idx_findings_workspace_status ON findings(workspace_id, status);
CREATE INDEX idx_findings_target_created ON findings(target_id, created_at DESC);
CREATE INDEX idx_scan_events_scan_created ON scan_events(scan_id, created_at);


CREATE TABLE discovered_assets (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  hostname TEXT NOT NULL,
  source TEXT NOT NULL CHECK(source IN ('certificate-transparency')),
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  certificate_not_before TEXT,
  certificate_not_after TEXT,
  issuer_name TEXT,
  UNIQUE(target_id, hostname)
);

CREATE INDEX idx_discovered_assets_workspace_last_seen
  ON discovered_assets(workspace_id, last_seen_at DESC);
CREATE INDEX idx_discovered_assets_target_hostname
  ON discovered_assets(target_id, hostname);
