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

Presence metrics count unique install IDs that sent `app_start`, `app_ping`, or `scan_complete` in the window (so tray apps that stay open still show as active). Launch metrics count only `app_start`. Duplicate `app_ping` events within ~4 minutes from the same install are accepted but not stored, to keep D1 write volume low.

Installs with **no activity for more than 7 days** are hidden from the dashboard (total installs, roster, versions, and OS tables). Their historical events remain in D1 but are not shown.

## Deploy

1. Install Wrangler.

```bash
npm install -g wrangler
```

2. Create the D1 database.

```bash
wrangler d1 create hashguard_telemetry
```

3. Copy `wrangler.toml.example` to `wrangler.toml` and set the D1 `database_id`.

4. Create the schema.

```bash
wrangler d1 execute hashguard_telemetry --file=./schema.sql
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
