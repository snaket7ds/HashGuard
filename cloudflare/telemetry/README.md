# HashGuard Anonymous Telemetry

This Cloudflare Worker receives opt-in HashGuard usage events and stores them in D1.

The app should only send anonymous, aggregate-safe data:

- random install ID
- app version
- OS version
- event type

It must not send file paths, hashes, process names, usernames, machine names, API keys, or provider report links.

The dashboard uses these events:

- `app_install`: sent once per anonymous install ID; used for total installs.
- `app_start`: sent when the app starts; used for running apps in 24h, 7d, and 30d windows.
- `app_ping`: sent every five minutes while the app is open; used for the live running count.

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
