const ALLOWED_EVENTS = new Set(["app_start", "scan_complete"]);

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

    if (request.method === "GET" && url.pathname === "/dashboard") {
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
  const since1Day = isoHoursAgo(24);
  const since7Days = isoHoursAgo(24 * 7);
  const since30Days = isoHoursAgo(24 * 30);

  const [active1, active7, active30, eventCounts, versions, scanTotals, daily] = await Promise.all([
    scalar(env, "SELECT COUNT(DISTINCT install_id) AS value FROM events WHERE received_at >= ?", since1Day),
    scalar(env, "SELECT COUNT(DISTINCT install_id) AS value FROM events WHERE received_at >= ?", since7Days),
    scalar(env, "SELECT COUNT(DISTINCT install_id) AS value FROM events WHERE received_at >= ?", since30Days),
    all(env, "SELECT event_type, COUNT(*) AS count FROM events WHERE received_at >= ? GROUP BY event_type ORDER BY count DESC", since30Days),
    all(env, "SELECT app_version, COUNT(DISTINCT install_id) AS installs FROM events WHERE received_at >= ? GROUP BY app_version ORDER BY installs DESC", since30Days),
    first(
      env,
      `SELECT
        COALESCE(SUM(items_scanned), 0) AS items_scanned,
        COALESCE(SUM(action_needed), 0) AS action_needed,
        COALESCE(SUM(detections), 0) AS detections,
        COALESCE(SUM(unknown_count), 0) AS unknown,
        COALESCE(SUM(errors), 0) AS errors,
        COALESCE(SUM(high_risk), 0) AS high_risk
      FROM events
      WHERE event_type = 'scan_complete' AND received_at >= ?`,
      since30Days
    ),
    all(
      env,
      `SELECT
        substr(received_at, 1, 10) AS day,
        COUNT(DISTINCT install_id) AS active_installs,
        COUNT(*) AS events
      FROM events
      WHERE received_at >= ?
      GROUP BY day
      ORDER BY day DESC`,
      since30Days
    ),
  ]);

  return {
    generatedAt: new Date().toISOString(),
    activeInstalls: {
      oneDay: active1,
      sevenDays: active7,
      thirtyDays: active30,
    },
    eventCounts,
    versions,
    scanTotals,
    daily,
  };
}

function renderDashboard() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>HashGuard Usage</title>
  <style>
    body { margin: 0; font-family: Segoe UI, Arial, sans-serif; background: #f4f6f8; color: #1f2933; }
    header { background: #171717; color: white; padding: 22px 28px; }
    main { padding: 24px; max-width: 1180px; margin: 0 auto; }
    h1 { margin: 0; font-size: 28px; }
    h2 { font-size: 16px; margin: 0 0 12px; }
    .subtle { color: #c8ced6; margin-top: 4px; }
    .grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 14px; margin-bottom: 16px; }
    .card { background: white; border: 1px solid #d4dae1; border-radius: 6px; padding: 16px; }
    .metric { font-size: 32px; font-weight: 700; }
    table { width: 100%; border-collapse: collapse; background: white; border: 1px solid #d4dae1; }
    th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid #e5e9ee; font-size: 14px; }
    th { background: #eef2f5; }
    section { margin-bottom: 18px; }
    @media (max-width: 760px) { .grid { grid-template-columns: 1fr; } main { padding: 14px; } }
  </style>
</head>
<body>
  <header>
    <h1>HashGuard Usage</h1>
    <div class="subtle" id="generated">Loading...</div>
  </header>
  <main>
    <div class="grid">
      <div class="card"><h2>Active Installs 24h</h2><div class="metric" id="active1">-</div></div>
      <div class="card"><h2>Active Installs 7d</h2><div class="metric" id="active7">-</div></div>
      <div class="card"><h2>Active Installs 30d</h2><div class="metric" id="active30">-</div></div>
    </div>
    <div class="grid">
      <div class="card"><h2>Items Scanned 30d</h2><div class="metric" id="items">-</div></div>
      <div class="card"><h2>Needs Review 30d</h2><div class="metric" id="actions">-</div></div>
      <div class="card"><h2>Errors 30d</h2><div class="metric" id="errors">-</div></div>
    </div>
    <section><h2>Versions</h2><table><thead><tr><th>Version</th><th>Active Installs</th></tr></thead><tbody id="versions"></tbody></table></section>
    <section><h2>Events</h2><table><thead><tr><th>Event</th><th>Count</th></tr></thead><tbody id="events"></tbody></table></section>
    <section><h2>Daily</h2><table><thead><tr><th>Day</th><th>Active Installs</th><th>Events</th></tr></thead><tbody id="daily"></tbody></table></section>
  </main>
  <script>
    const token = new URLSearchParams(location.search).get("token") || "";
    fetch("/api/summary?token=" + encodeURIComponent(token))
      .then(r => r.json())
      .then(data => {
        document.getElementById("generated").textContent = "Generated " + data.generatedAt;
        document.getElementById("active1").textContent = data.activeInstalls.oneDay;
        document.getElementById("active7").textContent = data.activeInstalls.sevenDays;
        document.getElementById("active30").textContent = data.activeInstalls.thirtyDays;
        document.getElementById("items").textContent = data.scanTotals.items_scanned;
        document.getElementById("actions").textContent = data.scanTotals.action_needed;
        document.getElementById("errors").textContent = data.scanTotals.errors;
        renderRows("versions", data.versions, row => [row.app_version, row.installs]);
        renderRows("events", data.eventCounts, row => [row.event_type, row.count]);
        renderRows("daily", data.daily, row => [row.day, row.active_installs, row.events]);
      });
    function renderRows(id, rows, values) {
      document.getElementById(id).innerHTML = rows.map(row => "<tr>" + values(row).map(value => "<td>" + escapeHtml(String(value)) + "</td>").join("") + "</tr>").join("");
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
