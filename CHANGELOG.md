# Changelog

## v1.0.72 - 2026-10-12

- **Faster scans.** HashGuard now looks up 3 files at a time instead of one. Results still appear in the same order. While the free VirusTotal limit or a "VirusTotal delay per request" is set, VirusTotal requests still go out one at a time with that delay between them. MetaDefender and Team Cymru lookups for other files run in the meantime.
- **Right-click scans of many files.** Selecting several files in Explorer and choosing Scan now scans them together in one batch. Previously each file started its own scan, and every file after the first showed an "A scan is already running" message. Requests that arrive during another scan wait for it to finish. Repeat requests for the same file within 5 seconds are ignored, and the queue holds at most 50 files.
- **Settings when the app folder is read-only.** If HashGuard cannot write next to `HashGuard.exe` (for example under Program Files without elevation), settings, caches and logs are saved in `%LocalAppData%\HashGuardUserData\` instead of failing to save. Existing settings, ignore lists and caches are copied over the first time. The status bar says so at startup, and Settings → Behavior → Version and Updates shows the folder in use.

## v1.0.71 - 2026-10-11

- **Refreshed main window.** Same layout and the same buttons in the same order, with a calmer, cleaner look:
  - Neutral gray background with rounded white cards and soft shadows instead of boxed borders. Brand green stays for the badge, the app mark and Scan Now; green text is darker so it is easier to read.
  - Simpler header: the green strip and the tagline are gone, Settings is a gear icon, and the update button reads "Check for Updates".
  - The status badge is a solid circle inside a soft halo of the same color. It is still static, with no animation.
  - Tiles have icons. Only the tiles you can click (Quarantine, Activity Log) show a chevron and highlight on hover and press.
  - Review Queue has a count badge next to its title, which turns red when items need a decision. Its buttons are grouped (open, ignore, act) with Quarantine in red; Export and Activity Log sit on the right.
  - Stop Scan is a plain outline button instead of red, because stopping a scan is not destructive.
  - The status bar is slimmer, with a thin progress line along its top edge.
- Dark mode uses the same layout with matching colors.

## v1.0.70 - 2026-10-11

- **Clearer results.** Error rows are neutral gray instead of red, so a file that could not be read no longer looks like a detection. Column headers now read "Malicious" and "Suspicious".
- **Clearer summary.** The scan summary reads "Done: 3 items need action · 1 detection · ..." with correct plurals, and shows the cache size with separators.
- **Activity Log tile** now says "View history" instead of "Open".
- **Cleanup.** Removed the unused Hash Cache tile code, the UI mockup screenshots, and the stale `RECOMMENDATIONS.md` and `GITHUB_RELEASES.md` notes.
- **Version 1.0.68 was removed.** It was published without a signature and cannot update in-app. Install v1.0.70 instead.

## v1.0.69 - 2026-10-11

- **Release signing key embedded.** Updates now install only when `HashGuard.exe.sig` verifies against the release public key. This is the first build that can install signed updates. v1.0.68 shipped with an empty key and cannot update in-app; install v1.0.69 by hand.

## v1.0.68 - 2026-10-11

- **Signed updates.** An update installs only when the release includes `HashGuard.exe.sig` and it verifies against the release public key (ECDSA P-256). The SHA-256 check alone cannot catch a tampered release, because its expected hash comes from the same GitHub release. `scripts/sign-release.sh` makes the signature.
- **Fail closed until the key is set.** The release public key (`ReleasePublicKeyBase64`) is empty in this build, so no update installs until it is generated and added.
- **Maintenance.** `MainForm.cs` is split into 18 feature partials (layout, theme, settings, scanning, providers, results, quarantine, ignore, reports, and others). The methods were moved without changes.

## v1.0.67 - 2026-10-04

- **Clarify the delta-scan option.** The v1.0.66 setting was labelled "skip unchanged clean files", but the unchanged-skip has been on since v1.0.57; the option actually controls whether an unchanged file whose clean result has *aged out* reuses its cached hash instead of being re-read. Renamed to "reuse cached hash for unchanged files" and the helper now encodes that exact rule (and is wired into the scan path instead of only tests).
- **Report provider failures honestly.** When no reputation provider returns a clean or detected verdict, a provider error now makes the file status `error` (counted in the scan summary) rather than falling through to `clean`/`unknown`.
- **Validate API keys once per scan.** A missing MetaDefender key no longer pops a modal Settings dialog from inside the per-file scan loop; it is checked once before the scan starts, and the provider is disabled if still unconfigured.
- **Faster scans.** Signature/authenticode checks now use offline revocation, are memoised by path+size+last-write time, and run off the UI thread; the fixed inter-file delay now only applies when a VirusTotal request was actually issued (cache hits no longer sleep).
- **More robust storage.** Hash and file-state caches are written atomically (temp file + replace) and file-state rows for deleted files are pruned on load; the cache loader only reads files HashGuard writes instead of every `*.json` in the config folder.
- **Safer updates.** The ~160 MB update asset streams straight to disk instead of buffering in a `MemoryStream`, and the install script restores the previous executable if the swap fails instead of deleting its backup unconditionally.
- **Hardening.** Trusting the self-signed certificate is now off by default (no prompt on every launch), plaintext API-key fields are `[JsonIgnore]` (legacy files are still migrated on load), and the telemetry payload safety check is enforced at send time.
- **Maintenance.** `MainForm.cs` split: the update/download/install path moved to `MainForm.Updates.cs`.

## v1.0.66 - 2026-10-03

- Add a **delta scan** option (Settings → Behavior → Scanning → "Skip unchanged clean files"). When enabled, files already cached clean and unchanged on disk (size + last-write time) skip re-hashing and provider lookups, cutting full-scan time and API-quota use. A file whose clean cache entry has aged out still reuses its cached hash instead of being re-read, then re-checks providers. Detections, unknown files, and changed files are always re-checked.

## v1.0.65 - 2026-10-03

- Telemetry backend hardening (server-side; no app behavior change in this build). The D1 rollup-on-write ingest and edge-cached summary are live on the shared worker, so existing installs already benefit without updating. This release republishes the current build at the new version.
- Fix: telemetry backend exceeded D1 free-tier read limits (enforced since 2026-09-01). Server-side only — no client change. `/api/summary` responses are now cached at the edge, dashboard queries no longer scan the full event history (bounded to recent 7–30 day windows), and the dashboard auto-refreshes every 5 minutes instead of 60 seconds.
- Fix: heartbeats are now aggregated on write (per-install row + per-day rows) instead of storing a row per 5-minute ping, so D1 read/write usage stays flat as history grows. Duplicate heartbeats inside the 4-minute window are still dropped, now tracked via a `last_ping` column on the per-install row instead of reading the event log. Lifetime scan totals and roster counters are preserved via backfill (`migration-rollup.sql`); the old `events` table is no longer written to.

## v1.0.64 - 2026-08-15

- Remove the Review Queue **View Quarantine** button so the action bar matches the previous layout. Open view/restore from the Quarantine tile.

## v1.0.63 - 2026-08-15

- Quarantine Manager is on the home screen: Quarantine tile (View / Restore), Review Queue **View Quarantine**, and a tray menu item.
- Manager lists quarantined files by name, supports search, restore to the original path or Desktop, permanent delete, copy hash, and repair of missing files.

## v1.0.62 - 2026-08-13

- Fix Approve Upload crashing with "Value of '-1' is not valid for 'index'" when the Review Queue clears the selected row after a successful submit.

## v1.0.61 - 2026-08-13

- Files whose hash is not in VirusTotal now appear in the Review Queue with "Approve VirusTotal upload".
- New Review Queue button **Approve Upload** sends only the selected file(s) after you confirm. Scans no longer auto-upload.

## v1.0.60 - 2026-08-13

- Fix the VirusTotal upload checkbox: accepting the warning now leaves the option enabled. Uploads are no longer turned off because "Scan files I open or select" is also on (that mode still never uploads files). The confirmation is remembered so Save does not re-prompt and clear the box.

## v1.0.59 - 2026-08-13

- Fix VirusTotal upload when a hash is not found and "Upload files missing from VirusTotal" is enabled: do not skip those files from a cached unknown result, keep the setting on when saving Settings, read the checkbox before background awaits, treat VT NotFoundError bodies as not-found, and surface upload/quota failures instead of failing silently.

## v1.0.58 - 2026-08-12

- Keep the hash cache dirty in memory during a scan and flush it every 25 mutations or 5 seconds, plus once when the scan ends — no more rewriting both JSON cache files after every file.
- Batch Review Queue / summary refreshes during full and monitoring scans (every 12 files or ~150 ms). Column autosize and empty-state work wait until the batch ends so large process sets stay smooth.

## v1.0.57 - 2026-08-12

- Keep hash cache and free-API quota warm in memory across scans; re-import scan logs only when files change.
- Skip re-hashing HashGuard.exe every scan when it is already known clean.
- Collect running processes (and persistence targets on full scan) off the UI thread so the window stays responsive while preparing a scan.

## v1.0.56 - 2026-08-12

- Settings: removed the large header strip (subtitle/white chrome) to free vertical space.
- Settings Behavior tab: enable scrolling and remeasure section heights so Version and Updates is no longer clipped.
- Settings dialog default height increased slightly; version shown in the window title.

## v1.0.55 - 2026-08-12

- Activity Log opens immediately and loads rows in the background (no multi-second UI freeze).
- Activity Log loads only recent log files / latest rows, tail-reads large CSVs, caches between opens, and debounces search filtering.

## v1.0.54 - 2026-08-12

- Review Queue action buttons are bottom-aligned in the footer strip (no longer floating mid-card when only one row is needed).

## v1.0.53 - 2026-08-12

- Review Queue action bar: wrap buttons onto a second row so Export and Activity Log are no longer clipped.
- On startup, merge any leftover v1.0.51 `%LocalAppData%\HashGuard` data into the app folder, then delete that LocalAppData tree.

## v1.0.52 - 2026-08-12

- Fixed settings/cache/log path regression from v1.0.51: store data next to `HashGuard.exe` again (`config\`, `logs\`), matching v1.0.50 and earlier.
- Auto-migrate any settings written under `%LocalAppData%\HashGuard\config` in v1.0.51 back next to the app when the app-local config is empty.
- Fixed in-app updates: do not block a SHA-256-verified update solely because the GitHub build is unsigned (publisher check only fails when both EXEs are signed and publishers differ).

## v1.0.51 - 2026-08-11

- Extracted modules: `Models/`, `Storage/` (HashCache, QuotaTracker, scan snapshot), `Providers/` (JSON helpers, VT/MetaDefender/Cymru stats, Cymru client), `Scanning/` (path security, file hash, report export, scheduled scan), `Telemetry/`, `Updates/`, `Ui/ThemePalette`, plus `AppPaths` and `AppConstants`.
- Unified scan concurrency on `ScanGate` (removed parallel busy flags for monitor/idle scans).
- Hardened Explorer named-pipe scan requests with path normalization and rejection of device/oversized/directory paths.
- Added daily scheduled full-scan option (Task Scheduler), CSV/HTML scan report export, and new-since-last-scan highlighting.
- Review Queue: Ignore Publisher bulk action; optional suppress-repeat tray alerts for the same detection set.
- Update installer verifies Authenticode publisher matches the current signed build (after SHA-256 check).
- First-run copy clarifies local-only vs cloud reputation modes; telemetry defaults remain off for new installs.
- Expanded unit tests from 13 to 27 (provider mapping, cache age, telemetry payload safety, path security, exports, snapshots).
- Telemetry worker/dashboard: installs offline >7 days hidden from roster; dashboard cache headers tightened (uncommitted worker polish included).

## v1.0.50 - 2026-08-11

- Telemetry starts immediately when enabled in Settings (no app restart required); disabling stops the heartbeat timer.
- Telemetry dashboard: Active 24h/7d/30d and daily charts count heartbeats (`app_ping`) and scans as presence, not only launches.
- Telemetry dashboard: separate launch counters, per-install last-seen table, 30-day scan stats, event volume, sparkline, auto-refresh, dark mode.
- Telemetry ingest: dedupe rapid `app_ping` writes; reject short/probe install IDs; composite D1 indexes for presence queries.

## v1.0.49 - 2026-08-09

- Scanning badge is static again (solid yellow with activity bars); no pulse or heartbeat animation.

## v1.0.48 - 2026-08-09

- Scanning badge uses an ECG-style heartbeat line that sweeps left↔right over faint file rows (main window); tray stays solid yellow.

## v1.0.47 - 2026-08-09

- Scanning badge uses a horizontal "searching files" scan line over faint file rows (main window); tray stays solid yellow.

## v1.0.46 - 2026-08-09

- Pulsing yellow main status badge while scanning (scale + soft halo); tray stays solid yellow.

## v1.0.45 - 2026-08-09

- Visual refresh inspired by Webroot SecureAnywhere: brand green primary CTA, soft light chrome, green status strip.
- Status language: "Your device is secure" / "Attention needed" / neutral "Not scanned yet" (no red alarm before first scan).
- Soft card borders; light header instead of solid black admin bar; "Scan Now" primary button.
- Traffic-light status badges (green / yellow / red / gray idle).
- Shared HTTP connection pool (`AppHttp`) so scans reuse sockets instead of creating a new pool each time.
- `ScanGate` prevents overlapping full scans, process monitoring, idle file scans, and right-click scans.
- Expanded `HashGuardLogic` helpers and unit tests for ignore/quarantine/action-needed rules.
- New installs default anonymous telemetry off (existing settings keep their saved value).
- Added `RECOMMENDATIONS.md` and UI mockup screenshots under `screenshots/`.

## v1.0.43 - 2026-06-06

- Added an anonymous `app_ping` heartbeat so the Cloudflare dashboard can show App Running Live from unique install IDs seen in the last 10 minutes.

## v1.0.42 - 2026-06-06

- Fixed Ignore so selected Review Queue rows without SHA-256 hashes, such as scan-error rows, can be ignored by file path instead of showing "No file selected."

## v1.0.41 - 2026-06-06

- Added a one-time anonymous `app_install` telemetry event per install ID so install counts are based on unique installed app IDs.
- Changed the Cloudflare usage dashboard to focus on app installs, installed versions, and apps running by unique install ID; scan totals are no longer shown.

## v1.0.40 - 2026-06-06

- Wired anonymous usage reporting to the Cloudflare Worker endpoint so updated clients can report active app usage when reporting is enabled.

## v1.0.39 - 2026-06-06

- Fixed ignored file hashes being re-added to the Review Queue when scan results were reused from the local provider cache.

## v1.0.38 - 2026-06-06

- Added opt-in anonymous usage reporting settings and Cloudflare Worker/D1 dashboard scaffolding.
- Added low-volume anonymous `app_start` and `scan_complete` event hooks with no file paths, hashes, process names, usernames, machine names, API keys, or report links.

## v1.0.37 - 2026-06-06

- Fixed ignored file hashes so high-risk unknown items stay out of the Review Queue on future scans.
- Kept ignored status out of the scan cache so clearing an ignore flag restores the original scan status.

## v1.0.36 - 2026-06-06

- Fixed scans failing at startup when local free API quota state was stale or malformed.

## v1.0.35 - 2026-06-06

- Changed first-run setup so Desktop shortcut creation is unchecked by default.
- Updated GitHub release automation to publish only updater assets and avoid re-adding installer files to updater releases.

## v1.0.34 - 2026-06-06

- Fixed Review Queue ignore actions so any selected file row with a SHA-256 hash can be ignored and removed from needs-review immediately.

## v1.0.33 - 2026-06-06

- Consolidated first-run setup into one options dialog for certificate trust, Program Files install, Desktop shortcut creation, and original-file cleanup.
- Clarified that leaving Program Files install unchecked runs HashGuard as a portable app.
- Updated user-facing scan timestamps to use the computer's local AM/PM time without a fixed timezone label.
- Improved Review Queue cleanup so ignored or quarantined detections are removed from needs-review status.
- Kept ignored and quarantined detections counted as handled activity instead of action-needed items.

## v1.0.32 - 2026-06-05

- Replaced the tray artwork with large status-only icons for clean, scanning, and action-needed states.
- Added explicit color modes in Settings: Use Windows setting, Light, and Dark.
- Applied app theming to Settings, Activity Log, and Quarantine dialogs.
- Renamed the tray icon factory to match the status-icon implementation.

## v1.0.31 - 2026-06-05

- Added a first-run setup prompt explaining local-only protection, cloud API keys, and optional uploads.
- Added quarantine restore-to-Desktop and stale-manifest repair controls.
- Added local release packaging with EXE/checksum, release notes, and a Windows QA checklist.
- Added Activity Log filters, selected-row explanations, copyable summaries, and improved remediation confirmations.
- Improved Settings layout with one large white tab surface, compact spacing, and no required scrolling on the Reputation tab at the default size.
- Improved the scan progress footer so the count is compact and right-aligned.
- Refactored Settings and quarantine UI helpers to reduce duplicated layout/state code.
- Fixed quarantine restore so verification does not lock up the UI and skipped/failed entries remain visible.
- Redesigned Settings into Reputation, Behavior, and Trust tabs with wider sectioned controls.
- Redesigned the main window layout with a compact overview, visible scan results table, and dedicated scan-status footer.
- Improved scan-status layout so long file paths do not cut off live scan text.
- Added structured per-provider reputation state tracking.
- Improved no-API local scanning so VirusTotal can be skipped without aborting scans.
- Hardened quarantine restore with hash verification, protected-path confirmation, and alternate restore paths.
- Improved scheduled task persistence scanning with XML task parsing.
- Added release workflow installer upload and logic tests for parsing/cache helpers.

## v1.0.30 - 2026-06-04

- Added scheduled task persistence scanning.
- Added smarter short-lived cache reuse for unknown, error, and quota-deferred provider results.
- Added trusted publisher allowlist support in Settings.
- Added quarantine manifest tracking with restore/delete actions.
- Updated the release workflow to publish only the matching changelog section.
- Added an Inno Setup installer scaffold.

## v1.0.29 - 2026-06-04

- Added local risk scoring and trust summaries for scanned files.
- Added Authenticode signer/publisher inspection and risky-path/recent-file triage notes.
- Added startup persistence scanning for Run keys, Startup folders, and Windows services.
- Added review actions for copying hashes, killing selected processes, and quarantining selected files.

## v1.0.28 - 2026-06-03

- Added "Scan files I open or select" background scanning for files touched through File Explorer or Windows Recent files.
- Removed drive-wide risky-file discovery and recursive drive watchers from background file scanning.
- Skipped common sensitive media types, including pictures, videos, audio files, and camera/raw files.
- Disabled automatic full-file VirusTotal uploads for background open/selected file scanning.
- Changed VirusTotal free API limit behavior so exhausted free quotas defer lookups instead of blocking scans.
- Added limited-access reporting for running processes Windows blocks from inspection.
- Increased the single-instance scan request pipe timeout from 700 ms to 2500 ms.

## v1.0.27 - 2026-06-02

- Renamed the app to HashGuard.
