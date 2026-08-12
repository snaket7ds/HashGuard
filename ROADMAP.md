# HashGuard future roadmap

Living list of improvement ideas that are **not** scheduled for immediate work.
Last updated: 2026-08-12 (post v1.0.57).

When picking work up again, prefer the **Next up** section unless product priorities change.

---

## Explicitly deferred

| Idea | Notes |
|------|--------|
| **YARA** | Pattern/signature engine for unknown/repacked malware. Optional extra signal only (not a replacement for hash reputation). Leave alone for now — false positives, rule maintenance, engine dependency, and scan cost. Revisit if users need offline / novel-sample detection. |

---

## Next up (best remaining ROI)

1. **True delta scan** — Skip re-query for unchanged known-clean paths (size/mtime + cache). Builds on “new since last scan” highlighting; biggest remaining full-scan time and API-quota win.
2. **Batch UI updates during full scan** — Debounce ListView/summary refreshes (e.g. every N files or ~100–200 ms) so progress stays smooth on large process sets.
3. **Bounded provider concurrency** — Small parallel pool for MetaDefender/Cymru (and VT when quota allows) across different files, still respecting free-tier delays.

---

## Product / UX

| Idea | Notes |
|------|--------|
| Clearer update flow | Progress: downloading → verifying SHA-256 → publisher check → restarting. Reduce “did it hang?” moments. |
| Review Queue “diff mode” | Optional default/filter: only *new since last scan* and/or *action needed*. |
| One-click “copy diagnostics” | Version, elevated?, providers on/off, last errors, install path — support without screenshots. |
| Quarantine / ignore audit trail | Local-only short history of ignored/quarantined items. |
| Scheduled scan tray summary | Notify only when something changed vs last run. |
| Portable vs installed first-run | Further simplify the two-mode path (already improved in 1.0.5x). |

---

## Architecture / maintainability

| Idea | Notes |
|------|--------|
| Continue peeling `MainForm` | Still ~6.8k lines. Next extract: provider call sites, scan orchestration, quarantine UI. |
| `MainForm.*.cs` partials by area | Scanning / Settings / ActivityLog / Updates without a full rewrite. |
| Stronger unit coverage | Cache warm paths, delta-scan rules, pipe path security edge cases. |

---

## Security / distribution

| Idea | Notes |
|------|--------|
| Authenticode-sign GitHub release builds | SmartScreen; meaningful publisher checks (CI builds are often unsigned today). |
| Settings write fallback | If Program Files config is read-only, write under user profile and surface that clearly. |
| Rate-limit Explorer named-pipe | Guard against burst `--scan-file` requests. |
| Document unsigned vs signed release policy | So users know what Update verifier will accept. |

---

## Larger features (later)

| Idea | Notes |
|------|--------|
| Optional extra reputation providers | e.g. MalwareBazaar / Hybrid Analysis — opt-in, same privacy model. |
| YARA (see deferred) | High-risk paths or Review Queue only if revisited. |
| SmartScreen / WDAC / AppLocker signals | Read-only where possible. |
| Memory-only / pathless process UX | Already partly “limited access”; surface more clearly. |

---

## Explicitly not pursuing (for now)

- More scanning-badge animation experiments  
- Telemetry dashboard chrome unless install base grows  
- Drive-wide recursive file watchers (removed intentionally in 1.0.28)  
- Full app rewrite  

---

## Already shipped (context — do not re-open without reason)

Through **v1.0.57** roughly includes:

- Modular layout (Storage / Providers / Scanning / Telemetry / Updates / Models)  
- ScanGate concurrency; app-local `config\` path + 1.0.51 LocalAppData cleanup  
- Activity Log async load + caps/cache  
- Settings layout (no header strip, scrollable tabs)  
- Warm hash cache + quota; async process collection  
- Scheduled daily scan option, export, ignore publisher, tray alert dedupe  

See `CHANGELOG.md` for the full history.

---

## How to use this file

- Add new ideas under the right section with a one-line “why.”  
- When shipping an item, move a one-liner into `CHANGELOG.md` and strike or remove it here.  
- Prefer small versioned releases over large multi-theme drops.
