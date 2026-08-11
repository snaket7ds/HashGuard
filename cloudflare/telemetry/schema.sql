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
