import { renderAppleDashboard } from "./dashboard-apple.js";
const ALLOWED_EVENTS = new Set(["app_install", "app_start", "app_ping", "scan_complete"]);
// Serve cached /api/summary responses so dashboard auto-refresh / tab-focus
// reloads don't rescan D1 on every request. 120s keeps "Online Now" fresh
// (heartbeats arrive every 5 min anyway).
const SUMMARY_CACHE_TTL_SECONDS = 120;
// Heartbeats are every 5 minutes; ignore duplicate pings inside this window to cut
// D1 write volume. The install row tracks the last accepted heartbeat so the dedupe
// survives the rollup-on-write path (it no longer reads the `events` log).
const PING_MIN_INTERVAL_MS = 4 * 60 * 1000;

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

      // Serve summary from the edge cache when possible so the dashboard's
      // auto-refresh and tab-focus reloads don't re-scan D1 every time.
      const cached = await readCachedSummary(request);
      if (cached) {
        return cached;
      }

      const response = withCors(json(await buildSummary(env)), {
        "cache-control": `private, max-age=${SUMMARY_CACHE_TTL_SECONDS}`,
      });
      await writeCachedSummary(request, response);
      return response;
    }

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/dashboard")) {
      if (!isAuthorized(request, env, url)) {
        return new Response("Unauthorized", { status: 401 });
      }

      return new Response(renderAppleDashboard(), {
        headers: {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store, no-cache, must-revalidate",
          "pragma": "no-cache",
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

  // Rollup-on-write (2026-09): heartbeats no longer append rows to `events`.
  // Each event upserts one row in `installs` (per install) and one tiny row in
  // `presence_days` (per install per UTC day), so dashboard summaries read a
  // few hundred rows instead of the whole heartbeat log. `scan_complete` also
  // rolls totals into `scan_days`. This keeps D1 free-tier read/write usage
  // flat regardless of how many 5-minute heartbeats arrive.
  const nowIso = new Date().toISOString();
  const day = nowIso.slice(0, 10);
  const stmts = [];

  // Drop duplicate heartbeats inside PING_MIN_INTERVAL_MS. The last accepted
  // ping time lives on the installs row, so this is a single indexed read and
  // never touches the legacy events log.
  if (eventType === "app_ping") {
    const recent = await first(
      env,
      `SELECT last_ping AS value FROM installs WHERE install_id = ?`,
      installId
    );
    if (recent?.value) {
      const ageMs = Date.now() - Date.parse(recent.value);
      if (Number.isFinite(ageMs) && ageMs >= 0 && ageMs < PING_MIN_INTERVAL_MS) {
        return json({ ok: true, deduped: true });
      }
    }
  }

  if (eventType === "app_install") {
    stmts.push(
      env.DB.prepare(
        `INSERT INTO installs (install_id, first_seen, last_seen, last_start, app_version, os_version, starts, pings)
         VALUES (?, ?, ?, NULL, ?, ?, 0, 0)
         ON CONFLICT(install_id) DO UPDATE SET
           last_seen = excluded.last_seen,
           app_version = excluded.app_version,
           os_version = excluded.os_version`
      ).bind(installId, nowIso, nowIso, appVersion, osVersion)
    );
  } else if (eventType === "app_start") {
    stmts.push(
      env.DB.prepare(
        `INSERT INTO installs (install_id, first_seen, last_seen, last_start, app_version, os_version, starts, pings)
         VALUES (?, ?, ?, ?, ?, ?, 1, 0)
         ON CONFLICT(install_id) DO UPDATE SET
           last_seen = excluded.last_seen,
           last_start = excluded.last_start,
           app_version = excluded.app_version,
           os_version = excluded.os_version,
           starts = starts + 1`
      ).bind(installId, nowIso, nowIso, nowIso, appVersion, osVersion)
    );
  } else if (eventType === "app_ping") {
    stmts.push(
      env.DB.prepare(
        `INSERT INTO installs (install_id, first_seen, last_seen, last_start, app_version, os_version, starts, pings, last_ping)
         VALUES (?, ?, ?, NULL, ?, ?, 0, 1, ?)
         ON CONFLICT(install_id) DO UPDATE SET
           last_seen = excluded.last_seen,
           app_version = excluded.app_version,
           os_version = excluded.os_version,
           last_ping = excluded.last_ping,
           pings = pings + 1`
      ).bind(installId, nowIso, nowIso, appVersion, osVersion, nowIso)
    );
  } else if (eventType === "scan_complete") {
    stmts.push(
      env.DB.prepare(
        `INSERT INTO installs (install_id, first_seen, last_seen, last_start, app_version, os_version, starts, pings)
         VALUES (?, ?, ?, NULL, ?, ?, 0, 0)
         ON CONFLICT(install_id) DO UPDATE SET
           last_seen = excluded.last_seen,
           app_version = excluded.app_version,
           os_version = excluded.os_version`
      ).bind(installId, nowIso, nowIso, appVersion, osVersion),
      env.DB.prepare(
        `INSERT INTO scan_days (install_id, day, scans, items_scanned, action_needed, detections, unknown_count, errors, high_risk)
         VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(install_id, day) DO UPDATE SET
           scans = scans + 1,
           items_scanned = items_scanned + excluded.items_scanned,
           action_needed = action_needed + excluded.action_needed,
           detections = detections + excluded.detections,
           unknown_count = unknown_count + excluded.unknown_count,
           errors = errors + excluded.errors,
           high_risk = high_risk + excluded.high_risk`
      ).bind(
        installId,
        day,
        numberValue(data.items_scanned),
        numberValue(data.action_needed),
        numberValue(data.detections),
        numberValue(data.unknown),
        numberValue(data.errors),
        numberValue(data.high_risk)
      )
    );
  }

  // One tiny row per install per UTC day proves it ran that day (daily chart).
  stmts.push(
    env.DB.prepare(
      `INSERT OR IGNORE INTO presence_days (install_id, day) VALUES (?, ?)`
    ).bind(installId, day)
  );

  await env.DB.batch(stmts);
  return json({ ok: true });
}

async function buildSummary(env) {
  const sinceLive = isoMinutesAgo(10);
  const since1Day = isoHoursAgo(24);
  const since7Days = isoHoursAgo(24 * 7);
  const since30Days = isoHoursAgo(24 * 30);
  // Installs offline longer than this are omitted from the dashboard entirely.
  const rosterRetentionDays = 7;
  const sinceRoster = isoHoursAgo(24 * rosterRetentionDays);

  // Presence = any start, heartbeat, or scan. Launches = app_start only.
  // Installs with no activity in the last 7 days are hidden from the dashboard.
  const since30DaysDay = since30Days.slice(0, 10); // date-only compare for day columns

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
    installRoster,
  ] = await Promise.all([
    // "Total installs" = unique IDs seen in the last 7 days (not lifetime stale).
    countInstallsSeen(env, sinceRoster),
    countInstallsSeen(env, sinceLive),
    countInstallsSeen(env, since1Day),
    countInstallsSeen(env, since7Days),
    countInstallsSeen(env, since30Days),
    countLaunches(env, since1Day),
    countLaunches(env, since7Days),
    countLaunches(env, since30Days),
    all(
      env,
      `SELECT app_version, COUNT(*) AS installs
       FROM installs
       WHERE last_seen >= ? AND app_version != ''
       GROUP BY app_version
       ORDER BY installs DESC, app_version DESC`,
      sinceRoster
    ),
    all(
      env,
      `SELECT os_version, COUNT(*) AS installs
       FROM installs
       WHERE last_seen >= ? AND os_version != ''
       GROUP BY os_version
       ORDER BY installs DESC, os_version ASC`,
      sinceRoster
    ),
    first(
      env,
      `SELECT
         COALESCE(SUM(items_scanned), 0) AS total_scanned,
         COALESCE(SUM(action_needed), 0) AS total_action_needed,
         COALESCE(SUM(detections), 0) AS total_detections,
         COALESCE(SUM(high_risk), 0) AS total_high_risk,
         COALESCE(SUM(scans), 0) AS total_scans
       FROM scan_days`
    ),
    first(
      env,
      `SELECT
         COALESCE(SUM(items_scanned), 0) AS total_scanned,
         COALESCE(SUM(action_needed), 0) AS total_action_needed,
         COALESCE(SUM(detections), 0) AS total_detections,
         COALESCE(SUM(high_risk), 0) AS total_high_risk,
         COALESCE(SUM(scans), 0) AS total_scans
       FROM scan_days
       WHERE day >= ?`,
      since30DaysDay
    ),
    all(
      env,
      `SELECT day, COUNT(*) AS running_apps
       FROM presence_days
       WHERE day >= ?
       GROUP BY day
       ORDER BY day ASC`,
      since30DaysDay
    ),
    all(
      env,
      `SELECT
         substr(install_id, 1, 8) AS install_short,
         app_version,
         os_version,
         first_seen,
         last_seen,
         starts,
         pings,
         COALESCE((SELECT SUM(scans) FROM scan_days s WHERE s.install_id = installs.install_id), 0) AS scans
       FROM installs
       WHERE last_seen >= ?
       ORDER BY last_seen DESC
       LIMIT 50`,
      sinceRoster
    ),
  ]);

  const filledDaily = fillDailySeries(daily, 30);
  const now = Date.now();
  const maxRosterAgeMin = rosterRetentionDays * 24 * 60;
  const installs = installRoster
    .map((row) => {
      const lastMs = Date.parse(row.last_seen);
      const ageMin = Number.isFinite(lastMs) ? Math.max(0, (now - lastMs) / 60000) : null;
      let status = "idle";
      if (ageMin != null && ageMin <= 10) status = "online";
      else if (ageMin != null && ageMin <= 60 * 24) status = "recent";
      return { ...row, status, age_minutes: ageMin == null ? null : Math.round(ageMin) };
    })
    // Defense in depth: drop anything older than 7 days even if SQL timezone quirks.
    .filter((row) => row.age_minutes == null || row.age_minutes <= maxRosterAgeMin);

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
    scanStats: normalizeScanStats(scanStats),
    scanStats30d: normalizeScanStats(scanStats30),
    daily: filledDaily,
    installs,
    retentionDays: rosterRetentionDays,
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

function countInstallsSeen(env, since) {
  return scalar(
    env,
    `SELECT COUNT(*) AS value FROM installs WHERE last_seen >= ?`,
    since
  );
}

function countLaunches(env, since) {
  return scalar(
    env,
    `SELECT COUNT(*) AS value FROM installs WHERE last_start IS NOT NULL AND last_start >= ?`,
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

// Cache API helpers for /api/summary. The dashboard polls every few minutes and
// reloads on tab focus, so serving a cached JSON blob keeps those refreshes off D1.
// The cache key includes the ?token= URL, so only the authorized dashboard hits it.
async function readCachedSummary(request) {
  try {
    const cache = caches.default;
    const key = new Request(request.url, { method: "GET" });
    const hit = await cache.match(key);
    if (hit) {
      const headers = new Headers(hit.headers);
      headers.set("cache-control", "no-store"); // never let browsers cache the token URL
      return withCors(new Response(hit.body, { status: hit.status, statusText: hit.statusText, headers }));
    }
  } catch {
    // Cache unavailable — fall through and compute fresh.
  }
  return null;
}

async function writeCachedSummary(request, response) {
  try {
    const cache = caches.default;
    const key = new Request(request.url, { method: "GET" });
    const copy = response.clone();
    const headers = new Headers(copy.headers);
    // Cloudflare's cache won't store `private` responses. The dashboard fetches
    // with cache: "no-store" (and the URL carries the token), so making the edge
    // copy public is safe — only someone with the token URL can request it.
    headers.set("cache-control", `public, max-age=${SUMMARY_CACHE_TTL_SECONDS}`);
    await cache.put(key, new Response(copy.body, { status: copy.status, statusText: copy.statusText, headers }));
  } catch {
    // Best-effort caching only; a failed put just means the next call recomputes.
  }
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
