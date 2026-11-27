CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  received_at TEXT NOT NULL,
  event_type TEXT NOT NULL,
  install_id TEXT NOT NULL,
  app_version TEXT NOT NULL,
  os_version TEXT NOT NULL,
  items_scanned INTEGER NOT NULL DEFAULT 0,
  action_needed INTEGER NOT NULL DEFAULT 0,
  detections INTEGER NOT NULL DEFAULT 0,
  unknown_count INTEGER NOT NULL DEFAULT 0,
  errors INTEGER NOT NULL DEFAULT 0,
  high_risk INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_received_at ON events(received_at);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_install_id ON events(install_id);
CREATE INDEX IF NOT EXISTS idx_events_app_version ON events(app_version);

-- Composite indexes for dashboard presence / launch queries.
CREATE INDEX IF NOT EXISTS idx_events_type_received ON events(event_type, received_at);
CREATE INDEX IF NOT EXISTS idx_events_install_type_received ON events(install_id, event_type, received_at);
CREATE INDEX IF NOT EXISTS idx_events_type_install_received ON events(event_type, install_id, received_at);

-- Rollup tables (2026-09): ingest upserts these instead of appending a row per
-- heartbeat, so dashboard summaries read O(#installs + #days) instead of the
-- full heartbeat log. The old `events` table is kept as the historical source
-- for backfill (see migration-rollup.sql); nothing new writes to it.
CREATE TABLE IF NOT EXISTS installs (
  install_id TEXT PRIMARY KEY,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  last_start TEXT,
  app_version TEXT NOT NULL,
  os_version TEXT NOT NULL,
  starts INTEGER NOT NULL DEFAULT 0,
  pings INTEGER NOT NULL DEFAULT 0,
  last_ping TEXT,
  -- Latest firewall snapshot from app_ping (1.1.8+; NULL for older versions).
  fw_monitoring INTEGER,
  fw_online INTEGER,
  fw_blocked INTEGER
);
CREATE INDEX IF NOT EXISTS idx_installs_last_seen ON installs(last_seen);
CREATE INDEX IF NOT EXISTS idx_installs_last_start ON installs(last_start);

CREATE TABLE IF NOT EXISTS presence_days (
  install_id TEXT NOT NULL,
  day TEXT NOT NULL,
  PRIMARY KEY (install_id, day)
);
CREATE INDEX IF NOT EXISTS idx_presence_days_day ON presence_days(day);

CREATE TABLE IF NOT EXISTS scan_days (
  install_id TEXT NOT NULL,
  day TEXT NOT NULL,
  scans INTEGER NOT NULL DEFAULT 0,
  items_scanned INTEGER NOT NULL DEFAULT 0,
  action_needed INTEGER NOT NULL DEFAULT 0,
  detections INTEGER NOT NULL DEFAULT 0,
  unknown_count INTEGER NOT NULL DEFAULT 0,
  errors INTEGER NOT NULL DEFAULT 0,
  high_risk INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (install_id, day)
);
CREATE INDEX IF NOT EXISTS idx_scan_days_day ON scan_days(day);

-- Firewall actions per install per day (1.1.8+). Counts only.
CREATE TABLE IF NOT EXISTS firewall_days (
  install_id TEXT NOT NULL,
  day TEXT NOT NULL,
  user_blocks INTEGER NOT NULL DEFAULT 0,
  auto_blocks INTEGER NOT NULL DEFAULT 0,
  unblocks INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (install_id, day)
);
CREATE INDEX IF NOT EXISTS idx_firewall_days_day ON firewall_days(day);
