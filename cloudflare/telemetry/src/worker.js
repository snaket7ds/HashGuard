const ALLOWED_EVENTS = new Set(["app_install", "app_start", "app_ping", "scan_complete"]);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/events") {
      return recordEvent(request, env);
    }

    if (request.method === "GET" && url.pathname === "/api/summary") {
      if (!isAuthorized(request, env, url)) {
        return json({ error: "unauthorized" }, 401);
      }

      return json(await buildSummary(env));
    }

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/dashboard")) {
      if (!isAuthorized(request, env, url)) {
        return new Response("Unauthorized", { status: 401 });
      }

      return new Response(renderDashboard(), {
        headers: { "content-type": "text/html; charset=utf-8" },
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

  const [totalInstalls, liveRunning, running1, running7, running30, versions, osVersions, scanStats, daily] = await Promise.all([
    scalar(env, "SELECT COUNT(DISTINCT install_id) AS value FROM events WHERE event_type = 'app_install'"),
    scalar(env, "SELECT COUNT(DISTINCT install_id) AS value FROM events WHERE event_type IN ('app_start', 'app_ping') AND received_at >= ?", sinceLive),
    scalar(env, "SELECT COUNT(DISTINCT install_id) AS value FROM events WHERE event_type = 'app_start' AND received_at >= ?", since1Day),
    scalar(env, "SELECT COUNT(DISTINCT install_id) AS value FROM events WHERE event_type = 'app_start' AND received_at >= ?", since7Days),
    scalar(env, "SELECT COUNT(DISTINCT install_id) AS value FROM events WHERE event_type = 'app_start' AND received_at >= ?", since30Days),
    all(
      env,
      `SELECT app_version, COUNT(*) AS installs
       FROM (
         SELECT install_id, app_version,
                ROW_NUMBER() OVER (PARTITION BY install_id ORDER BY received_at DESC) AS rn
         FROM events
         WHERE event_type IN ('app_install', 'app_start', 'app_ping')
       )
       WHERE rn = 1
       GROUP BY app_version
       ORDER BY installs DESC, app_version DESC`
    ),
    all(
      env,
      `SELECT os_version, COUNT(DISTINCT install_id) AS installs
       FROM events
       WHERE event_type = 'app_start'
       GROUP BY os_version
       ORDER BY installs DESC, os_version ASC`
    ),
    all(
      env,
      `SELECT
         COALESCE(SUM(CASE WHEN event_type = 'scan_complete' THEN items_scanned ELSE 0 END), 0) AS total_scanned,
         COALESCE(SUM(CASE WHEN event_type = 'scan_complete' THEN action_needed ELSE 0 END), 0) AS total_action_needed,
         COALESCE(SUM(CASE WHEN event_type = 'scan_complete' THEN detections ELSE 0 END), 0) AS total_detections,
         COALESCE(SUM(CASE WHEN event_type = 'scan_complete' THEN high_risk ELSE 0 END), 0) AS total_high_risk
       FROM events`
    ),
    all(
      env,
      `SELECT substr(received_at, 1, 10) AS day, COUNT(DISTINCT install_id) AS running_apps
       FROM events
       WHERE event_type = 'app_start' AND received_at >= ?
       GROUP BY day
       ORDER BY day DESC`,
      since30Days
    ),
  ]);

  return {
    generatedAt: new Date().toISOString(),
    totalInstalls,
    runningApps: {
      live: liveRunning,
      oneDay: running1,
      sevenDays: running7,
      thirtyDays: running30,
    },
    versions,
    osVersions,
    scanStats: scanStats[0] || { total_scanned: 0, total_action_needed: 0, total_detections: 0, total_high_risk: 0 },
    daily,
  };
}

function renderDashboard() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HashGuard \u2014 Telemetry Dashboard</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    :root {
      --bg: #f5f5f7;
      --surface: #ffffff;
      --surface-raised: #f0f0f3;
      --border: #e0e0e5;
      --text: #1d1d1f;
      --text-secondary: #6e6e73;
      --accent: #2563eb;
      --accent-muted: #93b4f8;
      --success: #16a34a;
      --warning: #d97706;
      --danger: #dc2626;
      --radius: 10px;
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
      background: #1d1d1f;
      border-bottom: 1px solid var(--border);
      padding: 32px 28px 28px;
    }
    header .container { max-width: 1200px; margin: 0 auto; }
    header h1 { margin: 0; font-size: 26px; font-weight: 700; letter-spacing: -0.3px; color: #ffffff; }
    header h1 .accent { color: var(--accent); }
    header .tagline { color: #a1a1a6; margin-top: 6px; font-size: 14px; }
    main { padding: 28px; max-width: 1200px; margin: 0 auto; }

    .metrics {
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 14px;
      margin-bottom: 28px;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 20px;
      transition: border-color 0.2s;
    }
    .card:hover { border-color: var(--accent-muted); }
    .card .label {
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-secondary);
      margin-bottom: 8px;
    }
    .card .value { font-size: 36px; font-weight: 700; color: var(--text); }
    .card .hint { font-size: 11px; color: var(--text-secondary); margin-top: 4px; }
    .card.live .value { color: var(--success); }

    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 28px; }
    .stat-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 14px;
    }
    .stat-grid .card .value { font-size: 28px; }

    .section { margin-bottom: 28px; }
    .section h2 {
      font-size: 15px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      color: var(--text-secondary);
      margin: 0 0 12px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
      font-size: 14px;
    }
    th {
      text-align: left;
      padding: 12px 16px;
      background: var(--surface-raised);
      color: var(--text-secondary);
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      border-bottom: 1px solid var(--border);
    }
    td {
      padding: 11px 16px;
      border-bottom: 1px solid var(--border);
      color: var(--text);
    }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #f5f5f7; }

    .badge {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 600;
    }
    .badge-green { background: #dcfce7; color: var(--success); }
    .badge-yellow { background: #fef3c7; color: var(--warning); }
    .badge-red { background: #fee2e2; color: var(--danger); }
    .badge-blue { background: #dbeafe; color: var(--accent); }
    .badge-gray { background: #f4f4f5; color: var(--text-secondary); }

    .version-latest { font-weight: 600; }
    .version-latest::after {
      content: '\\00a0latest';
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.4px;
      color: var(--accent);
      background: #dbeafe;
      padding: 1px 6px;
      border-radius: 8px;
      margin-left: 6px;
    }

    footer {
      text-align: center;
      padding: 24px;
      color: var(--text-secondary);
      font-size: 12px;
      border-top: 1px solid var(--border);
      margin-top: 12px;
    }

    @media (max-width: 900px) {
      .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .two-col { grid-template-columns: 1fr; }
    }
    @media (max-width: 560px) {
      .metrics { grid-template-columns: 1fr; }
      header { padding: 20px 16px; }
      main { padding: 16px; }
    }
  </style>
</head>
<body>
  <header>
    <div class="container">
      <h1><span class="accent">HashGuard</span> Telemetry</h1>
      <div class="tagline">Adoption and scan analytics for HashGuard \u2014 <span id="generated">loading&hellip;</span></div>
    </div>
  </header>
  <main>
    <div class="metrics">
      <div class="card">
        <div class="label">Total Installs</div>
        <div class="value" id="totalInstalls">-</div>
        <div class="hint">Unique installations since launch</div>
      </div>
      <div class="card live">
        <div class="label">Online Now</div>
        <div class="value" id="runningLive">-</div>
        <div class="hint">Active in the last 10 minutes</div>
      </div>
      <div class="card">
        <div class="label">Active 24 h</div>
        <div class="value" id="running1">-</div>
        <div class="hint">Unique installs seen today</div>
      </div>
      <div class="card">
        <div class="label">Active 7 d</div>
        <div class="value" id="running7">-</div>
        <div class="hint">Unique installs this week</div>
      </div>
      <div class="card">
        <div class="label">Active 30 d</div>
        <div class="value" id="running30">-</div>
        <div class="hint">Unique installs this month</div>
      </div>
    </div>

    <div class="two-col">
      <div class="section">
        <h2>Active Versions</h2>
        <table>
          <thead><tr><th>Version</th><th style="width:100px">Installs</th><th style="width:200px">Share</th></tr></thead>
          <tbody id="versions"></tbody>
        </table>
      </div>
      <div class="section">
        <h2>Operating Systems</h2>
        <table>
          <thead><tr><th>OS Version</th><th style="width:100px">Installs</th><th style="width:200px">Share</th></tr></thead>
          <tbody id="osVersions"></tbody>
        </table>
      </div>
    </div>

    <div class="section">
      <h2>Scan Statistics</h2>
      <div class="stat-grid" id="scanStats"></div>
    </div>

    <div class="section">
      <h2>Daily Active Installs &mdash; Last 30 Days</h2>
      <table>
        <thead><tr><th>Date</th><th style="width:100px">Active</th></tr></thead>
        <tbody id="daily"></tbody>
      </table>
    </div>
  </main>
  <footer>Anonymous aggregate telemetry \u2014 no personal data is collected or displayed.</footer>
  <script>
    const token = new URLSearchParams(location.search).get("token") || "";
    fetch("/api/summary?token=" + encodeURIComponent(token))
      .then(r => r.json())
      .then(data => {
        document.getElementById("generated").textContent = "updated " + formatTime(data.generatedAt);
        document.getElementById("totalInstalls").textContent = data.totalInstalls;
        document.getElementById("runningLive").textContent = data.runningApps.live;
        document.getElementById("running1").textContent = data.runningApps.oneDay;
        document.getElementById("running7").textContent = data.runningApps.sevenDays;
        document.getElementById("running30").textContent = data.runningApps.thirtyDays;

        const latestVersion = data.versions.length ? data.versions.map(v => v.app_version).sort(semverCompare).pop() : null;
        renderRows("versions", data.versions, row => {
          const label = row.app_version === latestVersion
            ? '<span class="version-latest">' + escapeHtml(row.app_version) + '</span>'
            : escapeHtml(row.app_version);
          return [label, row.installs, shareBar(data.versions, row.installs)];
        });

        renderRows("osVersions", data.osVersions, row => [escapeHtml(row.os_version), row.installs, shareBar(data.osVersions, row.installs)]);

        const stats = data.scanStats;
        document.getElementById("scanStats").innerHTML =
          '<div class="card"><div class="label">Items Scanned</div><div class="value">' + (stats.total_scanned || 0) + '</div></div>' +
          '<div class="card"><div class="label">Action Needed</div><div class="value">' + (stats.total_action_needed || 0) + '</div></div>' +
          '<div class="card"><div class="label">Detections</div><div class="value">' + (stats.total_detections || 0) + '</div></div>' +
          '<div class="card"><div class="label">High Risk</div><div class="value">' + (stats.total_high_risk || 0) + '</div></div>';

        renderRows("daily", data.daily, row => [formatDate(row.day), row.running_apps]);
      });

    function shareBar(dataset, value) {
      const total = dataset.reduce((s, r) => s + (r.installs || r.reports || 0), 0);
      const pct = total > 0 ? (value / total * 100) : 0;
      return '<div style="display:flex;align-items:center;gap:8px"><span style="font-size:13px;color:var(--text-secondary);min-width:40px;text-align:right">' +
        pct.toFixed(1) + '%</span><div style="display:flex;height:6px;border-radius:3px;overflow:hidden;background:var(--surface-raised);flex:1"><div style="width:' +
        pct + '%;background:var(--accent)"></div></div></div>';
    }

    function semverCompare(a, b) {
      const pa = a.split(".").map(Number);
      const pb = b.split(".").map(Number);
      for (let i = 0; i < 3; i++) {
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
      return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit', timeZoneName: 'short' });
    }

    function renderRows(id, rows, values) {
      document.getElementById(id).innerHTML = rows.map(row => "<tr>" + values(row).map(value => "<td>" + value + "</td>").join("") + "</tr>").join("");
    }

    function escapeHtml(value) {
      return value.replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
    }
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
