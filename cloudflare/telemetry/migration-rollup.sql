-- One-time backfill (2026-09): populate the rollup tables from the legacy
-- `events` heartbeat log so historical dashboards stay identical after the
-- Phase 2 worker ships. Run AFTER schema.sql has created the new tables:
--   wrangler d1 execute hashguard_telemetry --remote --file=schema.sql
--   wrangler d1 execute hashguard_telemetry --remote --file=migration-rollup.sql
-- Safe to re-run (INSERT OR IGNORE / additive upserts).
--
-- If the rollup schema was deployed before this migration shipped, the
-- `installs` table may already exist without the `last_ping` column. Add it
-- first (the ALTER is idempotent — re-running it just errors harmlessly):
--   wrangler d1 execute hashguard_telemetry --remote --command "ALTER TABLE installs ADD COLUMN last_ping TEXT"

-- Per-install state + lifetime counters (backfilled; new writes come from ingest).
INSERT OR IGNORE INTO installs (install_id, first_seen, last_seen, last_start, app_version, os_version, starts, pings, last_ping)
SELECT
  e.install_id,
  MIN(e.received_at),
  MAX(e.received_at),
  MAX(CASE WHEN e.event_type = 'app_start' THEN e.received_at END),
  (SELECT e2.app_version FROM events e2 WHERE e2.install_id = e.install_id ORDER BY e2.received_at DESC LIMIT 1),
  (SELECT e2.os_version  FROM events e2 WHERE e2.install_id = e.install_id ORDER BY e2.received_at DESC LIMIT 1),
  SUM(CASE WHEN e.event_type = 'app_start' THEN 1 ELSE 0 END),
  SUM(CASE WHEN e.event_type = 'app_ping'  THEN 1 ELSE 0 END),
  MAX(CASE WHEN e.event_type = 'app_ping' THEN e.received_at END)
FROM events e
WHERE e.install_id != 'probe' AND length(e.install_id) >= 8
GROUP BY e.install_id;

-- Daily presence (one row per install per UTC day it was seen).
INSERT OR IGNORE INTO presence_days (install_id, day)
SELECT DISTINCT install_id, substr(received_at, 1, 10)
FROM events
WHERE event_type IN ('app_install', 'app_start', 'app_ping', 'scan_complete')
  AND install_id != 'probe' AND length(install_id) >= 8;

-- Per-day scan totals (scans = number of scan events that day).
INSERT OR IGNORE INTO scan_days (install_id, day, scans, items_scanned, action_needed, detections, unknown_count, errors, high_risk)
SELECT
  install_id,
  substr(received_at, 1, 10),
  COUNT(*),
  COALESCE(SUM(items_scanned), 0),
  COALESCE(SUM(action_needed), 0),
  COALESCE(SUM(detections), 0),
  COALESCE(SUM(unknown_count), 0),
  COALESCE(SUM(errors), 0),
  COALESCE(SUM(high_risk), 0)
FROM events
WHERE event_type = 'scan_complete'
  AND install_id != 'probe' AND length(install_id) >= 8
GROUP BY install_id, substr(received_at, 1, 10);