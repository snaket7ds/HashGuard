// Redesigned telemetry dashboard (Apple-style). Served at /dashboard.
// The previous design is still served at /dashboard-classic (renderDashboard in worker.js).
// Element IDs and the data logic match the classic page; only the presentation changed.

export function renderAppleDashboard() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>HashGuard — Telemetry Dashboard</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    :root {
      --bg: #f5f5f7;
      --surface: #ffffff;
      --fill: rgba(118, 118, 128, 0.10);
      --fill-strong: rgba(118, 118, 128, 0.18);
      --separator: rgba(60, 60, 67, 0.12);
      --label: #1d1d1f;
      --label-2: #6e6e73;
      --accent: #0f9f4f;
      --accent-soft: rgba(15, 159, 79, 0.12);
      --success: #0f9f4f;
      --warning: #b45309;
      --danger: #d70015;
      --info: #0a6cff;
      --radius-card: 18px;
      --radius-inset: 12px;
      --ease-spring: cubic-bezier(0.2, 0.8, 0.2, 1);
      --shadow: 0 1px 2px rgba(0, 0, 0, 0.04), 0 4px 16px rgba(0, 0, 0, 0.04);
      --toolbar: rgba(245, 245, 247, 0.72);
    }
    @media (prefers-color-scheme: dark) {
      :root:not([data-theme="light"]) {
        --bg: #000000;
        --surface: #1c1c1e;
        --fill: rgba(120, 120, 128, 0.24);
        --fill-strong: rgba(120, 120, 128, 0.36);
        --separator: rgba(84, 84, 88, 0.55);
        --label: #f5f5f7;
        --label-2: #98989d;
        --accent: #34d399;
        --accent-soft: rgba(52, 211, 153, 0.14);
        --success: #34d399;
        --warning: #fbbf24;
        --danger: #ff6961;
        --info: #64a8ff;
        --shadow: none;
        --toolbar: rgba(0, 0, 0, 0.72);
      }
    }
    :root[data-theme="dark"] {
      --bg: #000000;
      --surface: #1c1c1e;
      --fill: rgba(120, 120, 128, 0.24);
      --fill-strong: rgba(120, 120, 128, 0.36);
      --separator: rgba(84, 84, 88, 0.55);
      --label: #f5f5f7;
      --label-2: #98989d;
      --accent: #34d399;
      --accent-soft: rgba(52, 211, 153, 0.14);
      --success: #34d399;
      --warning: #fbbf24;
      --danger: #ff6961;
      --info: #64a8ff;
      --shadow: none;
      --toolbar: rgba(0, 0, 0, 0.72);
    }

    html { -webkit-text-size-adjust: 100%; }
    body {
      margin: 0;
      font: 15px/1.45 -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", system-ui, sans-serif;
      background: var(--bg);
      color: var(--label);
      -webkit-font-smoothing: antialiased;
    }

    /* Translucent toolbar: content scrolls underneath it */
    .toolbar {
      position: sticky; top: 0; z-index: 10;
      background: var(--toolbar);
      -webkit-backdrop-filter: blur(20px) saturate(180%);
      backdrop-filter: blur(20px) saturate(180%);
      border-bottom: 0.5px solid var(--separator);
    }
    .toolbar-inner {
      max-width: 1120px; margin: 0 auto; padding: 12px 24px;
      display: flex; align-items: center; justify-content: space-between; gap: 16px;
    }
    .toolbar-title { font-size: 15px; font-weight: 600; letter-spacing: -0.01em; }
    .toolbar-meta { font-size: 13px; color: var(--label-2); font-variant-numeric: tabular-nums; }

    main { max-width: 1120px; margin: 0 auto; padding: 28px 24px 8px; }

    .hero { margin: 4px 0 28px; }
    .hero .eyebrow { font-size: 13px; font-weight: 600; color: var(--label-2); margin: 0 0 4px; }
    .hero h1 {
      margin: 0; font-size: 40px; font-weight: 700; line-height: 1.08; letter-spacing: -0.03em;
    }
    .hero h1 .accent { color: var(--accent); }
    .hero .tagline { margin: 8px 0 0; font-size: 17px; color: var(--label-2); letter-spacing: -0.01em; }

    .grid { display: grid; gap: 14px; margin-bottom: 14px; }
    .cols-5 { grid-template-columns: repeat(5, minmax(0, 1fr)); }
    .cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }

    .card {
      background: var(--surface);
      border-radius: var(--radius-card);
      padding: 18px 18px 16px;
      box-shadow: var(--shadow);
      transition: transform 0.35s var(--ease-spring);
      animation: rise 0.5s var(--ease-spring) both;
    }
    .grid > .card:nth-child(2) { animation-delay: 0.03s; }
    .grid > .card:nth-child(3) { animation-delay: 0.06s; }
    .grid > .card:nth-child(4) { animation-delay: 0.09s; }
    .grid > .card:nth-child(5) { animation-delay: 0.12s; }
    .card .label {
      font-size: 13px; font-weight: 500; color: var(--label-2); margin-bottom: 6px;
    }
    .card .value {
      font-size: 34px; font-weight: 700; line-height: 1.1; letter-spacing: -0.02em;
      color: var(--label); font-variant-numeric: tabular-nums;
    }
    .card .hint { font-size: 12px; color: var(--label-2); margin-top: 6px; }
    .card.live .value { color: var(--success); }
    .card.live .label { display: flex; align-items: center; gap: 6px; }
    .card.live .label::before {
      content: ""; width: 8px; height: 8px; border-radius: 50%;
      background: var(--success); animation: pulse 2.4s ease-out infinite;
    }

    @keyframes rise {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: none; }
    }
    @keyframes pulse {
      0% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--success) 50%, transparent); }
      70% { box-shadow: 0 0 0 7px transparent; }
      100% { box-shadow: 0 0 0 0 transparent; }
    }

    .section { margin-top: 32px; }
    .section-head {
      display: flex; align-items: baseline; justify-content: space-between; gap: 12px;
      margin: 0 4px 10px;
    }
    .section h2 { font-size: 20px; font-weight: 700; letter-spacing: -0.02em; margin: 0; }
    .section .sub { font-size: 13px; color: var(--label-2); }
    .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }

    .panel {
      background: var(--surface); border-radius: var(--radius-card);
      box-shadow: var(--shadow); overflow: hidden;
    }
    table { width: 100%; border-collapse: collapse; font-size: 15px; }
    th {
      text-align: left; padding: 10px 16px; font-size: 12px; font-weight: 500;
      color: var(--label-2); background: var(--fill); border-bottom: 0.5px solid var(--separator);
    }
    td {
      padding: 11px 16px; border-bottom: 0.5px solid var(--separator);
      font-variant-numeric: tabular-nums; vertical-align: middle;
    }
    tr:last-child td { border-bottom: none; }
    tbody tr { transition: background-color 0.2s ease; }
    tbody tr:hover td { background: var(--fill); }
    .empty-row td { color: var(--label-2); text-align: center; padding: 28px 16px; }
    .version-latest { font-weight: 600; }
    .version-latest::after {
      content: "latest"; font-size: 11px; font-weight: 600; color: var(--accent);
      background: var(--accent-soft); padding: 2px 8px; border-radius: 999px; margin-left: 8px;
      vertical-align: 1px;
    }

    .status-pill {
      display: inline-block; padding: 2px 9px; border-radius: 999px;
      font-size: 12px; font-weight: 600; white-space: nowrap;
    }
    .status-online { background: var(--accent-soft); color: var(--success); }
    .status-recent { background: color-mix(in srgb, var(--info) 14%, transparent); color: var(--info); }
    .status-idle { background: var(--fill-strong); color: var(--label-2); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }

    .chart-wrap { padding: 20px 20px 10px; }
    .chart {
      display: grid; grid-template-columns: repeat(30, minmax(0, 1fr));
      gap: 4px; align-items: end; height: 132px;
    }
    .chart .bar {
      background: linear-gradient(180deg, var(--accent) 0%, color-mix(in srgb, var(--accent) 60%, transparent) 100%);
      border-radius: 4px 4px 2px 2px; min-height: 2px;
      transition: opacity 0.2s ease;
    }
    .chart .bar:hover { opacity: 0.7; }
    .chart .bar.zero { background: var(--fill-strong); height: 2px !important; }
    .chart-legend {
      display: flex; justify-content: space-between; font-size: 12px; color: var(--label-2);
      padding: 10px 2px 2px;
    }
    .chart-peak { font-size: 13px; color: var(--label-2); padding: 4px 20px 18px; }
    .chart-peak strong { color: var(--label); font-weight: 600; }

    .stat-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 14px; }
    .stat-grid .card .value { font-size: 26px; }

    .error-banner {
      display: none; background: color-mix(in srgb, var(--danger) 12%, var(--surface));
      color: var(--danger); border-radius: var(--radius-inset); padding: 12px 16px;
      margin: 0 0 18px; font-size: 14px;
    }
    .error-banner.show { display: block; }
    footer {
      text-align: center; padding: 28px 24px 36px; color: var(--label-2); font-size: 12px;
    }

    .share-cell { display: flex; align-items: center; gap: 10px; }
    .share-cell .pct { font-size: 12px; color: var(--label-2); min-width: 44px; text-align: right; }
    .share-cell .track { flex: 1; height: 6px; border-radius: 3px; background: var(--fill-strong); overflow: hidden; }
    .share-cell .fill { height: 100%; background: var(--accent); border-radius: 3px; }

    @media (max-width: 1000px) {
      .cols-5, .stat-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    }
    @media (max-width: 680px) {
      main { padding: 20px 16px 8px; }
      .toolbar-inner { padding: 10px 16px; }
      .hero h1 { font-size: 32px; }
      .cols-5, .cols-3, .stat-grid, .two-col { grid-template-columns: 1fr 1fr; }
      .panel td, .panel th { padding-left: 12px; padding-right: 12px; }
    }
    @media (max-width: 420px) {
      .cols-5, .cols-3, .stat-grid, .two-col { grid-template-columns: 1fr; }
    }

    /* Reduced motion: no springs, no pulse; content simply appears */
    @media (prefers-reduced-motion: reduce) {
      .card, .card.live .label::before { animation: none; }
      .card { transition: none; }
      tbody tr, .chart .bar { transition: none; }
    }
    /* Reduced transparency: solid toolbar */
    @media (prefers-reduced-transparency: reduce) {
      .toolbar { -webkit-backdrop-filter: none; backdrop-filter: none; background: var(--surface); }
    }
    @supports not ((backdrop-filter: blur(1px)) or (-webkit-backdrop-filter: blur(1px))) {
      .toolbar { background: var(--surface); }
    }
  </style>
</head>
<body>
  <div class="toolbar">
    <div class="toolbar-inner">
      <div class="toolbar-title">HashGuard Telemetry</div>
      <div class="toolbar-meta" id="generated">loading&hellip;</div>
    </div>
  </div>

  <main>
    <header class="hero">
      <p class="eyebrow">Telemetry</p>
      <h1><span class="accent">HashGuard</span> Telemetry</h1>
      <p class="tagline">Anonymous adoption, presence, and scan analytics &middot; auto-refresh every 5 min</p>
    </header>

    <div id="error" class="error-banner"></div>

    <div class="grid cols-5">
      <div class="card">
        <div class="label">Total Installs</div>
        <div class="value" id="totalInstalls">-</div>
        <div class="hint">Seen in the last 7 days</div>
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

    <div class="grid cols-3">
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

    <section class="section">
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
    </section>

    <section class="section two-col">
      <div>
        <div class="section-head"><h2>Active Versions</h2><div class="sub">Last 7 days</div></div>
        <div class="panel">
          <table>
            <thead><tr><th>Version</th><th style="width:88px">Installs</th><th style="width:180px">Share</th></tr></thead>
            <tbody id="versions"></tbody>
          </table>
        </div>
      </div>
      <div>
        <div class="section-head"><h2>Operating Systems</h2><div class="sub">Latest OS per install, 7 d</div></div>
        <div class="panel">
          <table>
            <thead><tr><th>OS Version</th><th style="width:88px">Installs</th><th style="width:180px">Share</th></tr></thead>
            <tbody id="osVersions"></tbody>
          </table>
        </div>
      </div>
    </section>

    <section class="section">
      <div class="section-head"><h2>Scan Statistics</h2><div class="sub">All time / last 30 days</div></div>
      <div class="stat-grid" id="scanStats"></div>
    </section>

    <section class="section">
      <div class="section-head">
        <h2>Install Roster</h2>
        <div class="sub">Unique install IDs &middot; offline &gt; 7 days are hidden</div>
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
    </section>
  </main>

  <footer>Anonymous aggregate telemetry &mdash; no paths, hashes, process names, or machine identifiers are stored in this view.</footer>

  <script>
    const token = new URLSearchParams(location.search).get("token") || "";
    const errorEl = document.getElementById("error");

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
      document.getElementById("generated").textContent = "Updated " + formatTime(data.generatedAt);
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
        formatTime(row.last_seen) + (row.age_minutes != null ? ' <span style="color:var(--label-2);font-size:12px">(' + formatAge(row.age_minutes) + ')</span>' : ''),
        formatNumber(row.starts || 0),
        formatNumber(row.pings || 0),
        formatNumber(row.scans || 0)
      ], "No installs recorded yet");

      renderDailyChart(data.daily || []);
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
      return '<div class="share-cell"><span class="pct">' + pct.toFixed(1) + '%</span>' +
        '<div class="track"><div class="fill" style="width:' + pct + '%"></div></div></div>';
    }

    function isRealVersion(v) {
      return typeof v === "string" && /^\\d+\\.\\d+/.test(v);
    }

    function statusPill(status) {
      const label = ({ online: "Online", recent: "24h", idle: "7d" })[status] || status;
      const cls = ({ online: "status-online", recent: "status-recent", idle: "status-idle" })[status] || "status-idle";
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
    setInterval(load, 300000);
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible") load();
    });
  </script>
</body>
</html>`;
}
