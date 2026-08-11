const ALLOWED_EVENTS = new Set(["app_install", "app_start", "app_ping", "scan_complete"]);
// Presence = any proof the app was running (launch, heartbeat, or completed scan).
const PRESENCE_EVENTS = "('app_start', 'app_ping', 'scan_complete')";
// Heartbeats are every 5 minutes; ignore duplicate pings inside this window to cut D1 write volume.
const PING_MIN_INTERVAL_MS = 4 * 60 * 1000;
const VALID_INSTALL = `install_id != 'probe' AND length(install_id) >= 8`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders() });
    }

    if (request.method === "POST" && url.pathname === "/events") {
      return withCors(await recordEvent(request, env));
    }

    if (request.method === "GET" && url.pathname === "/api/summary") {
      if (!isAuthorized(request, env, url)) {
        return withCors(json({ error: "unauthorized" }, 401));
      }

      return withCors(json(await buildSummary(env)), {
        "cache-control": "private, max-age=30",
      });
    }

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/dashboard")) {
      if (!isAuthorized(request, env, url)) {
        return new Response("Unauthorized", { status: 401 });
      }

      return new Response(renderDashboard(), {
        headers: {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "private, max-age=60",
        },
      });
    }

    return new Response("Not found", { status: 404 });
  },
};

async function recordEvent(request, env) {
  let payload;
  try {
    payload = await request.json();
  } catch {
    return json({ error: "invalid_json" }, 400);
  }

  const eventType = stringValue(payload.eventType, 64);
  const installId = stringValue(payload.installId, 80);
  const appVersion = stringValue(payload.appVersion, 32);
  const osVersion = stringValue(payload.osVersion, 160);
  const data = payload.data && typeof payload.data === "object" ? payload.data : {};

  if (!ALLOWED_EVENTS.has(eventType) || !installId || !appVersion) {
    return json({ error: "invalid_event" }, 400);
  }

  // Drop obvious probe / invalid IDs so dashboard counts stay clean.
  if (installId === "probe" || installId.length < 8) {
    return json({ error: "invalid_event" }, 400);
  }

  if (eventType === "app_ping") {
    const recent = await first(
      env,
      `SELECT received_at AS value
       FROM events
       WHERE install_id = ? AND event_type = 'app_ping'
       ORDER BY received_at DESC
       LIMIT 1`,
      installId
    );
    if (recent?.value) {
      const ageMs = Date.now() - Date.parse(recent.value);
      if (Number.isFinite(ageMs) && ageMs >= 0 && ageMs < PING_MIN_INTERVAL_MS) {
        return json({ ok: true, deduped: true });
      }
    }
  }

  await env.DB.prepare(
    `INSERT INTO events (
      received_at,
      event_type,
      install_id,
      app_version,
      os_version,
      items_scanned,
      action_needed,
      detections,
      unknown_count,
      errors,
      high_risk
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      new Date().toISOString(),
      eventType,
      installId,
      appVersion,
      osVersion,
      numberValue(data.items_scanned),
      numberValue(data.action_needed),
      numberValue(data.detections),
      numberValue(data.unknown),
      numberValue(data.errors),
      numberValue(data.high_risk)
    )
    .run();

  return json({ ok: true });
}

async function buildSummary(env) {
  const sinceLive = isoMinutesAgo(10);
  const since1Day = isoHoursAgo(24);
  const since7Days = isoHoursAgo(24 * 7);
  const since30Days = isoHoursAgo(24 * 30);

  // Presence = any start or heartbeat. Launches = app_start only (session starts).
  const [
    totalInstalls,
    liveRunning,
    active1,
    active7,
    active30,
    launches1,
    launches7,
    launches30,
    versions,
    osVersions,
    scanStats,
    scanStats30,
    daily,
    eventVolume,
    installRoster,
  ] = await Promise.all([
    scalar(
      env,
      `SELECT COUNT(*) AS value FROM (
         SELECT install_id FROM events
         WHERE event_type = 'app_install' AND ${VALID_INSTALL}
         UNION
         SELECT install_id FROM events
         WHERE event_type IN ${PRESENCE_EVENTS} AND ${VALID_INSTALL}
       )`
    ),
    distinctPresence(env, sinceLive),
    distinctPresence(env, since1Day),
    distinctPresence(env, since7Days),
    distinctPresence(env, since30Days),
    distinctLaunches(env, since1Day),
    distinctLaunches(env, since7Days),
    distinctLaunches(env, since30Days),
    all(
      env,
      `SELECT app_version, COUNT(*) AS installs
       FROM (
         SELECT install_id, app_version,
                ROW_NUMBER() OVER (PARTITION BY install_id ORDER BY received_at DESC) AS rn
         FROM events
         WHERE event_type IN ('app_install', 'app_start', 'app_ping', 'scan_complete')
           AND received_at >= ?
           AND ${VALID_INSTALL}
       )
       WHERE rn = 1
       GROUP BY app_version
       ORDER BY installs DESC, app_version DESC`,
      since30Days
    ),
    all(
      env,
      `SELECT os_version, COUNT(*) AS installs
       FROM (
         SELECT install_id, os_version,
                ROW_NUMBER() OVER (PARTITION BY install_id ORDER BY received_at DESC) AS rn
         FROM events
         WHERE event_type IN ('app_install', 'app_start', 'app_ping', 'scan_complete')
           AND received_at >= ?
           AND ${VALID_INSTALL}
           AND os_version != ''
       )
       WHERE rn = 1
       GROUP BY os_version
       ORDER BY installs DESC, os_version ASC`,
      since30Days
    ),
    all(
      env,
      `SELECT
         COALESCE(SUM(CASE WHEN event_type = 'scan_complete' THEN items_scanned ELSE 0 END), 0) AS total_scanned,
         COALESCE(SUM(CASE WHEN event_type = 'scan_complete' THEN action_needed ELSE 0 END), 0) AS total_action_needed,
         COALESCE(SUM(CASE WHEN event_type = 'scan_complete' THEN detections ELSE 0 END), 0) AS total_detections,
         COALESCE(SUM(CASE WHEN event_type = 'scan_complete' THEN high_risk ELSE 0 END), 0) AS total_high_risk,
         COALESCE(SUM(CASE WHEN event_type = 'scan_complete' THEN 1 ELSE 0 END), 0) AS total_scans
       FROM events`
    ),
    all(
      env,
      `SELECT
         COALESCE(SUM(CASE WHEN event_type = 'scan_complete' THEN items_scanned ELSE 0 END), 0) AS total_scanned,
         COALESCE(SUM(CASE WHEN event_type = 'scan_complete' THEN action_needed ELSE 0 END), 0) AS total_action_needed,
         COALESCE(SUM(CASE WHEN event_type = 'scan_complete' THEN detections ELSE 0 END), 0) AS total_detections,
         COALESCE(SUM(CASE WHEN event_type = 'scan_complete' THEN high_risk ELSE 0 END), 0) AS total_high_risk,
         COALESCE(SUM(CASE WHEN event_type = 'scan_complete' THEN 1 ELSE 0 END), 0) AS total_scans
       FROM events
       WHERE received_at >= ?`,
      since30Days
    ),
    all(
      env,
      `SELECT substr(received_at, 1, 10) AS day, COUNT(DISTINCT install_id) AS running_apps
       FROM events
       WHERE event_type IN ${PRESENCE_EVENTS}
         AND received_at >= ?
         AND ${VALID_INSTALL}
       GROUP BY day
       ORDER BY day ASC`,
      since30Days
    ),
    all(
      env,
      `SELECT event_type, COUNT(*) AS count
       FROM events
       WHERE received_at >= ?
       GROUP BY event_type
       ORDER BY count DESC`,
      since30Days
    ),
    all(
      env,
      `SELECT
         substr(install_id, 1, 8) AS install_short,
         MAX(app_version) AS app_version,
         MAX(os_version) AS os_version,
         MIN(received_at) AS first_seen,
         MAX(received_at) AS last_seen,
         SUM(CASE WHEN event_type = 'app_start' THEN 1 ELSE 0 END) AS starts,
         SUM(CASE WHEN event_type = 'app_ping' THEN 1 ELSE 0 END) AS pings,
         SUM(CASE WHEN event_type = 'scan_complete' THEN 1 ELSE 0 END) AS scans
       FROM events
       WHERE ${VALID_INSTALL}
       GROUP BY install_id
       ORDER BY last_seen DESC
       LIMIT 50`
    ),
  ]);

  const filledDaily = fillDailySeries(daily, 30);
  const now = Date.now();
  const installs = installRoster.map((row) => {
    const lastMs = Date.parse(row.last_seen);
    const ageMin = Number.isFinite(lastMs) ? Math.max(0, (now - lastMs) / 60000) : null;
    let status = "offline";
    if (ageMin != null && ageMin <= 10) status = "online";
    else if (ageMin != null && ageMin <= 60 * 24) status = "recent";
    else if (ageMin != null && ageMin <= 60 * 24 * 30) status = "idle";
    return { ...row, status, age_minutes: ageMin == null ? null : Math.round(ageMin) };
  });

  return {
    generatedAt: new Date().toISOString(),
    totalInstalls,
    runningApps: {
      live: liveRunning,
      oneDay: active1,
      sevenDays: active7,
      thirtyDays: active30,
    },
    launches: {
      oneDay: launches1,
      sevenDays: launches7,
      thirtyDays: launches30,
    },
    versions,
    osVersions,
    scanStats: normalizeScanStats(scanStats[0]),
    scanStats30d: normalizeScanStats(scanStats30[0]),
    daily: filledDaily,
    eventVolume30d: eventVolume,
    installs,
  };
}

function normalizeScanStats(row) {
  return {
    total_scanned: row?.total_scanned ?? 0,
    total_action_needed: row?.total_action_needed ?? 0,
    total_detections: row?.total_detections ?? 0,
    total_high_risk: row?.total_high_risk ?? 0,
    total_scans: row?.total_scans ?? 0,
  };
}

function distinctPresence(env, since) {
  return scalar(
    env,
    `SELECT COUNT(DISTINCT install_id) AS value
     FROM events
     WHERE event_type IN ${PRESENCE_EVENTS}
       AND received_at >= ?
       AND ${VALID_INSTALL}`,
    since
  );
}

function distinctLaunches(env, since) {
  return scalar(
    env,
    `SELECT COUNT(DISTINCT install_id) AS value
     FROM events
     WHERE event_type = 'app_start'
       AND received_at >= ?
       AND ${VALID_INSTALL}`,
    since
  );
}

/** Ensure every calendar day in the window appears (0 if silent). */
function fillDailySeries(rows, days) {
  const byDay = new Map(rows.map((r) => [r.day, r.running_apps]));
  const result = [];
  const now = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - i));
    const key = d.toISOString().slice(0, 10);
    result.push({ day: key, running_apps: byDay.get(key) ?? 0 });
  }
  return result;
}

function renderDashboard() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>HashGuard \u2014 Telemetry Dashboard</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    :root {
      --bg: #f4f6f5;
      --surface: #ffffff;
      --surface-raised: #eef1ef;
      --border: #d9e0dc;
      --text: #15201a;
      --text-secondary: #5c6b63;
      --accent: #0f9f4f;
      --accent-muted: #8fd4ab;
      --accent-soft: #e6f7ed;
      --success: #0f9f4f;
      --warning: #d97706;
      --danger: #dc2626;
      --info: #2563eb;
      --radius: 12px;
      --shadow: 0 1px 2px rgba(21, 32, 26, 0.04), 0 8px 24px rgba(21, 32, 26, 0.04);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0f1411;
        --surface: #171d19;
        --surface-raised: #1f2722;
        --border: #2a342e;
        --text: #e8eee9;
        --text-secondary: #93a399;
        --accent: #34d399;
        --accent-muted: #065f46;
        --accent-soft: #0f2a1c;
        --success: #34d399;
        --warning: #fbbf24;
        --danger: #f87171;
        --info: #60a5fa;
        --shadow: 0 1px 2px rgba(0,0,0,0.25), 0 8px 24px rgba(0,0,0,0.2);
      }
    }
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      -webkit-font-smoothing: antialiased;
    }
    header {
      background: linear-gradient(160deg, #0f1a14 0%, #152820 55%, #0f9f4f22 100%);
      border-bottom: 1px solid var(--border);
      padding: 28px 28px 24px;
    }
    header .container { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; gap: 16px; align-items: flex-end; flex-wrap: wrap; }
    header h1 { margin: 0; font-size: 26px; font-weight: 700; letter-spacing: -0.3px; color: #ffffff; }
    header h1 .accent { color: #6ee7a8; }
    header .tagline { color: #a7b8ad; margin-top: 6px; font-size: 14px; }
    header .meta { color: #a7b8ad; font-size: 12px; text-align: right; }
    header .meta strong { color: #e8eee9; font-weight: 600; }
    main { padding: 28px; max-width: 1200px; margin: 0 auto; }

    .metrics {
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 14px;
      margin-bottom: 20px;
    }
    .metrics-secondary {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 14px;
      margin-bottom: 28px;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 18px 18px 16px;
      box-shadow: var(--shadow);
      transition: border-color 0.15s ease;
    }
    .card:hover { border-color: var(--accent-muted); }
    .card .label {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.55px;
      color: var(--text-secondary);
      margin-bottom: 8px;
    }
    .card .value { font-size: 34px; font-weight: 750; letter-spacing: -0.5px; color: var(--text); font-variant-numeric: tabular-nums; }
    .card .hint { font-size: 11px; color: var(--text-secondary); margin-top: 6px; }
    .card.live { border-color: color-mix(in srgb, var(--success) 35%, var(--border)); }
    .card.live .value { color: var(--success); }
    .card.live .label::before {
      content: '';
      display: inline-block;
      width: 7px; height: 7px;
      border-radius: 50%;
      background: var(--success);
      margin-right: 6px;
      box-shadow: 0 0 0 0 color-mix(in srgb, var(--success) 50%, transparent);
      animation: pulse 2s infinite;
      vertical-align: 1px;
    }
    @keyframes pulse {
      0% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--success) 45%, transparent); }
      70% { box-shadow: 0 0 0 8px transparent; }
      100% { box-shadow: 0 0 0 0 transparent; }
    }

    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 28px; }
    .stat-grid {
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 14px;
    }
    .stat-grid .card .value { font-size: 26px; }

    .section { margin-bottom: 28px; }
    .section-head {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
      margin: 0 0 12px;
    }
    .section h2 {
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      color: var(--text-secondary);
      margin: 0;
    }
    .section .sub { font-size: 12px; color: var(--text-secondary); }

    .panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow: hidden;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }
    th {
      text-align: left;
      padding: 12px 16px;
      background: var(--surface-raised);
      color: var(--text-secondary);
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border-bottom: 1px solid var(--border);
    }
    td {
      padding: 11px 16px;
      border-bottom: 1px solid var(--border);
      color: var(--text);
      font-variant-numeric: tabular-nums;
    }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: color-mix(in srgb, var(--accent) 5%, transparent); }
    .empty-row td { color: var(--text-secondary); font-style: italic; text-align: center; padding: 28px 16px; }

    .version-latest { font-weight: 650; }
    .version-latest::after {
      content: 'latest';
      font-size: 10px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.4px;
      color: var(--accent);
      background: var(--accent-soft);
      padding: 2px 7px;
      border-radius: 999px;
      margin-left: 8px;
      vertical-align: 1px;
    }
    .status-pill {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.3px;
    }
    .status-online { background: var(--accent-soft); color: var(--success); }
    .status-recent { background: color-mix(in srgb, var(--info) 15%, transparent); color: var(--info); }
    .status-idle { background: color-mix(in srgb, var(--warning) 18%, transparent); color: var(--warning); }
    .status-offline { background: var(--surface-raised); color: var(--text-secondary); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }

    .chart-wrap { padding: 16px 16px 8px; }
    .chart {
      display: grid;
      grid-template-columns: repeat(30, minmax(0, 1fr));
      gap: 3px;
      align-items: end;
      height: 120px;
    }
    .chart .bar {
      background: linear-gradient(180deg, var(--accent) 0%, color-mix(in srgb, var(--accent) 55%, #0b5c2e) 100%);
      border-radius: 3px 3px 1px 1px;
      min-height: 2px;
      position: relative;
      opacity: 0.92;
    }
    .chart .bar.zero { background: var(--surface-raised); opacity: 1; height: 2px !important; }
    .chart .bar:hover { opacity: 1; outline: 2px solid var(--accent-muted); outline-offset: 1px; }
    .chart-legend {
      display: flex;
      justify-content: space-between;
      color: var(--text-secondary);
      font-size: 11px;
      padding: 8px 2px 4px;
    }
    .chart-peak {
      font-size: 12px;
      color: var(--text-secondary);
      padding: 0 16px 14px;
    }
    .chart-peak strong { color: var(--text); }

    .error-banner {
      display: none;
      background: color-mix(in srgb, var(--danger) 12%, var(--surface));
      border: 1px solid color-mix(in srgb, var(--danger) 35%, var(--border));
      color: var(--danger);
      border-radius: var(--radius);
      padding: 12px 16px;
      margin-bottom: 18px;
      font-size: 14px;
    }
    .error-banner.show { display: block; }

    footer {
      text-align: center;
      padding: 24px;
      color: var(--text-secondary);
      font-size: 12px;
      border-top: 1px solid var(--border);
      margin-top: 12px;
    }

    @media (max-width: 980px) {
      .metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .stat-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    }
    @media (max-width: 720px) {
      .metrics, .metrics-secondary, .two-col, .stat-grid { grid-template-columns: 1fr 1fr; }
    }
    @media (max-width: 520px) {
      .metrics, .metrics-secondary, .two-col, .stat-grid { grid-template-columns: 1fr; }
      header { padding: 20px 16px; }
      main { padding: 16px; }
      header .meta { text-align: left; }
    }
  </style>
</head>
<body>
  <header>
    <div class="container">
      <div>
        <h1><span class="accent">HashGuard</span> Telemetry</h1>
        <div class="tagline">Anonymous adoption, presence, and scan analytics</div>
      </div>
      <div class="meta">
        <div id="generated">loading&hellip;</div>
        <div style="margin-top:4px">auto-refresh <strong>60s</strong></div>
      </div>
    </div>
  </header>
  <main>
    <div id="error" class="error-banner"></div>

    <div class="metrics">
      <div class="card">
        <div class="label">Total Installs</div>
        <div class="value" id="totalInstalls">-</div>
        <div class="hint">Unique install IDs ever seen</div>
      </div>
      <div class="card live">
        <div class="label">Online Now</div>
        <div class="value" id="runningLive">-</div>
        <div class="hint">Start or ping in last 10 min</div>
      </div>
      <div class="card">
        <div class="label">Active 24 h</div>
        <div class="value" id="running1">-</div>
        <div class="hint">Seen via start or heartbeat</div>
      </div>
      <div class="card">
        <div class="label">Active 7 d</div>
        <div class="value" id="running7">-</div>
        <div class="hint">Seen via start or heartbeat</div>
      </div>
      <div class="card">
        <div class="label">Active 30 d</div>
        <div class="value" id="running30">-</div>
        <div class="hint">Seen via start or heartbeat</div>
      </div>
    </div>

    <div class="metrics-secondary">
      <div class="card">
        <div class="label">Launches 24 h</div>
        <div class="value" id="launches1">-</div>
        <div class="hint">Distinct installs that opened the app</div>
      </div>
      <div class="card">
        <div class="label">Launches 7 d</div>
        <div class="value" id="launches7">-</div>
        <div class="hint">app_start only</div>
      </div>
      <div class="card">
        <div class="label">Launches 30 d</div>
        <div class="value" id="launches30">-</div>
        <div class="hint">app_start only</div>
      </div>
    </div>

    <div class="section">
      <div class="section-head">
        <h2>Daily Active Installs</h2>
        <div class="sub">Last 30 days &middot; start or heartbeat</div>
      </div>
      <div class="panel">
        <div class="chart-wrap">
          <div class="chart" id="dailyChart" title="Daily active installs"></div>
          <div class="chart-legend">
            <span id="chartStart">-</span>
            <span id="chartEnd">-</span>
          </div>
        </div>
        <div class="chart-peak" id="chartPeak">Peak: -</div>
      </div>
    </div>

    <div class="two-col">
      <div class="section" style="margin-bottom:0">
        <div class="section-head"><h2>Active Versions</h2><div class="sub">Last 30 days</div></div>
        <div class="panel">
          <table>
            <thead><tr><th>Version</th><th style="width:88px">Installs</th><th style="width:180px">Share</th></tr></thead>
            <tbody id="versions"></tbody>
          </table>
        </div>
      </div>
      <div class="section" style="margin-bottom:0">
        <div class="section-head"><h2>Operating Systems</h2><div class="sub">Latest OS per install, 30 d</div></div>
        <div class="panel">
          <table>
            <thead><tr><th>OS Version</th><th style="width:88px">Installs</th><th style="width:180px">Share</th></tr></thead>
            <tbody id="osVersions"></tbody>
          </table>
        </div>
      </div>
    </div>

    <div class="section" style="margin-top:28px">
      <div class="section-head"><h2>Scan Statistics</h2><div class="sub">All time / last 30 days</div></div>
      <div class="stat-grid" id="scanStats"></div>
    </div>

    <div class="section">
      <div class="section-head">
        <h2>Install Roster</h2>
        <div class="sub">Each unique install ID &middot; why Online may be less than Total</div>
      </div>
      <div class="panel">
        <table>
          <thead>
            <tr>
              <th>Install</th>
              <th>Status</th>
              <th>Version</th>
              <th>OS</th>
              <th>Last seen</th>
              <th style="width:70px">Starts</th>
              <th style="width:70px">Pings</th>
              <th style="width:70px">Scans</th>
            </tr>
          </thead>
          <tbody id="installs"></tbody>
        </table>
      </div>
    </div>

    <div class="section">
      <div class="section-head"><h2>Event Volume</h2><div class="sub">Last 30 days</div></div>
      <div class="panel">
        <table>
          <thead><tr><th>Event</th><th style="width:120px">Count</th><th style="width:200px">Share</th></tr></thead>
          <tbody id="eventVolume"></tbody>
        </table>
      </div>
    </div>

    <div class="section">
      <div class="section-head"><h2>Daily Detail</h2><div class="sub">Newest first</div></div>
      <div class="panel">
        <table>
          <thead><tr><th>Date</th><th style="width:100px">Active</th><th style="width:220px">Level</th></tr></thead>
          <tbody id="daily"></tbody>
        </table>
      </div>
    </div>
  </main>
  <footer>Anonymous aggregate telemetry &mdash; no paths, hashes, process names, or machine identifiers are stored in this view.</footer>
  <script>
    const token = new URLSearchParams(location.search).get("token") || "";
    const errorEl = document.getElementById("error");
    let refreshTimer = null;

    function load() {
      fetch("/api/summary?token=" + encodeURIComponent(token), { cache: "no-store" })
        .then(async r => {
          const data = await r.json();
          if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
          return data;
        })
        .then(render)
        .catch(err => {
          errorEl.textContent = "Failed to load summary: " + err.message;
          errorEl.classList.add("show");
        });
    }

    function render(data) {
      errorEl.classList.remove("show");
      document.getElementById("generated").textContent = "updated " + formatTime(data.generatedAt);
      document.getElementById("totalInstalls").textContent = formatNumber(data.totalInstalls);
      document.getElementById("runningLive").textContent = formatNumber(data.runningApps.live);
      document.getElementById("running1").textContent = formatNumber(data.runningApps.oneDay);
      document.getElementById("running7").textContent = formatNumber(data.runningApps.sevenDays);
      document.getElementById("running30").textContent = formatNumber(data.runningApps.thirtyDays);

      const launches = data.launches || {};
      document.getElementById("launches1").textContent = formatNumber(launches.oneDay || 0);
      document.getElementById("launches7").textContent = formatNumber(launches.sevenDays || 0);
      document.getElementById("launches30").textContent = formatNumber(launches.thirtyDays || 0);

      const versions = (data.versions || []).filter(v => isRealVersion(v.app_version));
      const latestVersion = versions.length ? versions.map(v => v.app_version).sort(semverCompare).pop() : null;
      renderRows("versions", versions, row => {
        const label = row.app_version === latestVersion
          ? '<span class="version-latest">' + escapeHtml(row.app_version) + '</span>'
          : escapeHtml(row.app_version);
        return [label, formatNumber(row.installs), shareBar(versions, row.installs)];
      }, "No active installs in the last 30 days");

      renderRows("osVersions", data.osVersions || [], row => [
        escapeHtml(shortOs(row.os_version)),
        formatNumber(row.installs),
        shareBar(data.osVersions || [], row.installs)
      ], "No OS data yet");

      const allTime = data.scanStats || {};
      const last30 = data.scanStats30d || {};
      document.getElementById("scanStats").innerHTML =
        statCard("Items Scanned", allTime.total_scanned, last30.total_scanned) +
        statCard("Scans Completed", allTime.total_scans, last30.total_scans) +
        statCard("Action Needed", allTime.total_action_needed, last30.total_action_needed) +
        statCard("Detections", allTime.total_detections, last30.total_detections) +
        statCard("High Risk", allTime.total_high_risk, last30.total_high_risk);

      const installs = data.installs || [];
      renderRows("installs", installs, row => [
        '<span class="mono">' + escapeHtml(row.install_short) + '&hellip;</span>',
        statusPill(row.status),
        escapeHtml(row.app_version || "-"),
        escapeHtml(shortOs(row.os_version || "-")),
        formatTime(row.last_seen) + (row.age_minutes != null ? ' <span style="color:var(--text-secondary);font-size:11px">(' + formatAge(row.age_minutes) + ')</span>' : ''),
        formatNumber(row.starts || 0),
        formatNumber(row.pings || 0),
        formatNumber(row.scans || 0)
      ], "No installs recorded yet");

      const volume = data.eventVolume30d || [];
      renderRows("eventVolume", volume, row => [
        escapeHtml(prettyEvent(row.event_type)),
        formatNumber(row.count),
        shareBar(volume.map(v => ({ installs: v.count })), row.count)
      ], "No events in the last 30 days");

      const daily = data.daily || [];
      renderDailyChart(daily);
      const dailyDesc = daily.slice().reverse();
      const maxDaily = Math.max(0, ...daily.map(d => d.running_apps || 0));
      renderRows("daily", dailyDesc, row => [
        formatDate(row.day),
        formatNumber(row.running_apps),
        levelBar(row.running_apps, maxDaily)
      ], "No daily activity yet");
    }

    function statCard(label, allTime, last30) {
      return '<div class="card"><div class="label">' + escapeHtml(label) + '</div>' +
        '<div class="value">' + formatNumber(allTime || 0) + '</div>' +
        '<div class="hint">30d: ' + formatNumber(last30 || 0) + '</div></div>';
    }

    function renderDailyChart(daily) {
      const max = Math.max(1, ...daily.map(d => d.running_apps || 0));
      const chart = document.getElementById("dailyChart");
      chart.innerHTML = daily.map(d => {
        const v = d.running_apps || 0;
        const h = Math.max(2, Math.round((v / max) * 100));
        const cls = v === 0 ? "bar zero" : "bar";
        return '<div class="' + cls + '" style="height:' + h + '%" title="' +
          escapeHtml(formatDate(d.day) + ': ' + v + ' active') + '"></div>';
      }).join("");
      document.getElementById("chartStart").textContent = daily.length ? formatDate(daily[0].day) : "-";
      document.getElementById("chartEnd").textContent = daily.length ? formatDate(daily[daily.length - 1].day) : "-";
      const peak = daily.reduce((best, d) => (d.running_apps > (best.running_apps || 0) ? d : best), { running_apps: 0 });
      document.getElementById("chartPeak").innerHTML = peak.running_apps
        ? 'Peak: <strong>' + formatNumber(peak.running_apps) + '</strong> on ' + formatDate(peak.day)
        : 'Peak: none yet';
    }

    function shareBar(dataset, value) {
      const total = dataset.reduce((s, r) => s + (r.installs || r.reports || r.count || 0), 0);
      const pct = total > 0 ? (value / total * 100) : 0;
      return '<div style="display:flex;align-items:center;gap:8px"><span style="font-size:12px;color:var(--text-secondary);min-width:42px;text-align:right">' +
        pct.toFixed(1) + '%</span><div style="display:flex;height:6px;border-radius:3px;overflow:hidden;background:var(--surface-raised);flex:1"><div style="width:' +
        pct + '%;background:var(--accent)"></div></div></div>';
    }

    function levelBar(value, max) {
      const pct = max > 0 ? (value / max * 100) : 0;
      return '<div style="display:flex;height:8px;border-radius:4px;overflow:hidden;background:var(--surface-raised)"><div style="width:' +
        pct + '%;background:var(--accent)"></div></div>';
    }

    function isRealVersion(v) {
      return typeof v === "string" && /^\\d+\\.\\d+/.test(v);
    }

    function prettyEvent(type) {
      return ({
        app_install: "Install",
        app_start: "App start",
        app_ping: "Heartbeat",
        scan_complete: "Scan complete"
      })[type] || type;
    }

    function statusPill(status) {
      const label = ({ online: "Online", recent: "24h", idle: "30d", offline: "Stale" })[status] || status;
      const cls = ({ online: "status-online", recent: "status-recent", idle: "status-idle", offline: "status-offline" })[status] || "status-offline";
      return '<span class="status-pill ' + cls + '">' + escapeHtml(label) + '</span>';
    }

    function formatAge(minutes) {
      if (minutes < 60) return minutes + "m ago";
      if (minutes < 60 * 24) return Math.round(minutes / 60) + "h ago";
      return Math.round(minutes / (60 * 24)) + "d ago";
    }

    function shortOs(os) {
      return String(os || "")
        .replace(/^Microsoft Windows NT\\s+/i, "Windows ")
        .replace(/\\.0$/, "");
    }

    function semverCompare(a, b) {
      const pa = String(a).split(".").map(n => parseInt(n, 10) || 0);
      const pb = String(b).split(".").map(n => parseInt(n, 10) || 0);
      for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
        if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
      }
      return 0;
    }

    function formatDate(dateStr) {
      const d = new Date(dateStr + 'T00:00:00Z');
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' });
    }

    function formatTime(iso) {
      const d = new Date(iso);
      return d.toLocaleString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZoneName: 'short' });
    }

    function formatNumber(n) {
      return Number(n || 0).toLocaleString('en-US');
    }

    function renderRows(id, rows, values, emptyMessage) {
      const el = document.getElementById(id);
      if (!rows || !rows.length) {
        const cols = el.closest('table')?.querySelectorAll('thead th')?.length || 1;
        el.innerHTML = '<tr class="empty-row"><td colspan="' + cols + '">' + escapeHtml(emptyMessage || "No data") + '</td></tr>';
        return;
      }
      el.innerHTML = rows.map(row => "<tr>" + values(row).map(value => "<td>" + value + "</td>").join("") + "</tr>").join("");
    }

    function escapeHtml(value) {
      return String(value ?? "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
    }

    load();
    refreshTimer = setInterval(load, 60000);
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible") load();
    });
  </script>
</body>
</html>`;
}

function isAuthorized(request, env, url) {
  const token = env.DASHBOARD_TOKEN || "";
  if (!token) {
    return false;
  }

  const auth = request.headers.get("authorization") || "";
  return auth === `Bearer ${token}` || url.searchParams.get("token") === token;
}

function corsHeaders() {
  return {
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-allow-headers": "content-type, authorization",
  };
}

function withCors(response, extraHeaders = {}) {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries({ ...corsHeaders(), ...extraHeaders })) {
    headers.set(key, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function json(value, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

async function scalar(env, sql, ...params) {
  const row = await first(env, sql, ...params);
  return row?.value ?? 0;
}

async function first(env, sql, ...params) {
  return await env.DB.prepare(sql).bind(...params).first();
}

async function all(env, sql, ...params) {
  const result = await env.DB.prepare(sql).bind(...params).all();
  return result.results || [];
}

function stringValue(value, maxLength) {
  return typeof value === "string" ? value.slice(0, maxLength) : "";
}

function numberValue(value) {
  return Number.isSafeInteger(value) && value >= 0 ? value : 0;
}

function isoHoursAgo(hours) {
  return new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();
}

function isoMinutesAgo(minutes) {
  return new Date(Date.now() - minutes * 60 * 1000).toISOString();
}
