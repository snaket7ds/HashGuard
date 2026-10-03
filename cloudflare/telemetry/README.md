# HashGuard Anonymous Telemetry

This Cloudflare Worker receives opt-in HashGuard usage events and stores them in D1.

The app should only send anonymous, aggregate-safe data:

- random install ID
- app version
- OS version
- event type

It must not send file paths, hashes, process names, usernames, machine names, API keys, or provider report links.

The dashboard uses these events:

- `app_install`: sent once per anonymous install ID; counted toward total installs.
- `app_start`: sent when the app launches; counts as presence **and** as a launch.
- `app_ping`: heartbeat every five minutes while the app is open; counts as presence for Online Now / Active 24h / 7d / 30d / daily charts.
- `scan_complete`: optional scan totals (items, action needed, detections, high risk).

Presence metrics count install IDs with activity in the window (so tray apps that stay open still show as active). Launch metrics count only `app_start`. Duplicate `app_ping` events within ~4 minutes from the same install are acknowledged (`{ ok: true, deduped: true }`) but not stored; the last accepted heartbeat time is tracked in `installs.last_ping`, so dedupe no longer reads the event log.

Installs with **no activity for more than 7 days** are hidden from the dashboard (total installs, roster, versions, and OS tables). Their rollup rows remain in D1 but are not shown.

## Storage model

Ingest is **rollup-on-write**: no per-heartbeat event rows are stored. Each accepted request upserts:

- `installs` — one row per install ID with lifetime counters (`starts`, `pings`) and a latest-status snapshot (`app_version`, `os_version`, `first_seen`, `last_seen`, `last_start`, `last_ping`).
- `presence_days` — one row per install per UTC day, which drives the daily chart.
- `scan_days` — per-install, per-day scan totals summed from `scan_complete` payloads.

This keeps `/api/summary` reads at O(#installs + #days) instead of scanning the full heartbeat history, which is what pushed the database past the D1 free-tier read limits in 2026-09. The legacy append-only `events` table is no longer written to and has been dropped; `migration-rollup.sql` is the one-time backfill that copied its history into the rollup tables.

## Deploy

1. Install Wrangler and authenticate with a scoped API token (`CLOUDFLARE_API_TOKEN`) that has Workers Scripts Write plus D1 Read/Write. Avoid the legacy Global API Key.

```bash
npm install -g wrangler
```

2. Create the D1 database.

```bash
wrangler d1 create hashguard_telemetry
```

3. Copy `wrangler.toml.example` to `wrangler.toml` and set the D1 `database_id`.

4. Create the schema and backfill the rollups.

```bash
wrangler d1 execute hashguard_telemetry --remote --file=./schema.sql
# One-time backfill of the rollup tables from the legacy events log.
wrangler d1 execute hashguard_telemetry --remote --file=./migration-rollup.sql
```

If `installs` already exists from an earlier rollup deploy, it may be missing the dedupe column. Add it before deploying the worker:

```bash
wrangler d1 execute hashguard_telemetry --remote --command "ALTER TABLE installs ADD COLUMN last_ping TEXT"
```

5. Set a dashboard token.

```bash
wrangler secret put DASHBOARD_TOKEN
```

6. Deploy.

```bash
wrangler deploy
```

7. Set `TelemetryEndpointUrl` in `MainForm.cs` to the deployed `/events` URL, then ship the next HashGuard release.

## Dashboard

Open:

```text
https://your-worker.workers.dev/dashboard?token=YOUR_DASHBOARD_TOKEN
```

The dashboard reads only aggregate counts from `/api/summary`.
