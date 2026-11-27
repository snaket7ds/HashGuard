-- 2026-11-27 (HashGuard 1.1.8): firewall counts. Run once on an existing database:
--   wrangler d1 execute hashguard_telemetry --remote --file=./migration-firewall.sql
-- Counts only; no app names, paths, hashes or addresses are ever stored.
ALTER TABLE installs ADD COLUMN fw_monitoring INTEGER;
ALTER TABLE installs ADD COLUMN fw_online INTEGER;
ALTER TABLE installs ADD COLUMN fw_blocked INTEGER;

CREATE TABLE IF NOT EXISTS firewall_days (
  install_id TEXT NOT NULL,
  day TEXT NOT NULL,
  user_blocks INTEGER NOT NULL DEFAULT 0,
  auto_blocks INTEGER NOT NULL DEFAULT 0,
  unblocks INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (install_id, day)
);
CREATE INDEX IF NOT EXISTS idx_firewall_days_day ON firewall_days(day);
