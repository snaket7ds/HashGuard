# HashGuard v2 (in progress)

A fresh WinUI 3 front end with an engine library that has no UI code. v1 (WinForms) stays in the repo root until v2 replaces it.

```
v2/
  src/HashGuard.Core   engine, no UI types (net10.0)
  src/HashGuard.App    WinUI 3 app: pages + view models (Windows App SDK 2.7, unpackaged, self-contained)
```

## Build and run

```powershell
dotnet build v2/src/HashGuard.App/HashGuard.App.csproj
dotnet publish v2/src/HashGuard.App/HashGuard.App.csproj -c Release -o v2/out
```

Release publish produces one `HashGuard.exe`, like v1.

Spike-only switches: `HASHGUARD_THEME=Dark|Light` forces a theme; `HASHGUARD_MEASURE_FILE=<path>` writes the ms from process start to first frame, then exits.

## Phase 0 spike results (2026-11-27, this PC, 3440×1440)

| | v1.1.8 (WinForms) | v2 spike (WinUI 3) |
|---|---|---|
| Single exe | yes, 72 MB | yes, 112 MB (93 MB without ReadyToRun) |
| Start to first frame, repeat launches | not measured | ~465 ms (~535 ms without ReadyToRun) |
| First launch after install | +0.3 s for decompression | ~2.3 s (single-file unpacks its native libraries once) |

Verified on screen: Home in light and dark mode, all hero states (protected, scanning, decision, threat, not scanned), sidebar navigation with pages kept between visits, close-to-tray.
Not yet verified: clicking the tray icon/menu, running elevated, 125–150% display scaling.

## Phases

0. Spike: shell, Home, tray, single-file publish. **Done.**
1. Core: move the engine into `HashGuard.Core` with tests. **In progress.**
   - Done: v1's 24 UI-free engine files and their 80 tests; `IReputationProvider` (VirusTotal, MetaDefender, Team Cymru) with one `VirusTotalPacer`; `FileAnalyzer` (per-file pipeline), `RiskScorer`, `SignatureReader`; `SettingsStore` + `Dpapi` (v1's settings.json and encrypted keys), `IgnoreList`, `ProcessCollector`, `ScanLog`, `ScanService` (full, monitoring and chosen-file scans); `QuarantineStore` (v1's manifest and folder), `ActivityLogReader` + `ActivityFeed` (the Activity timeline), stopping a running file before quarantine..
   - Left in v1's `MainForm`: updates, network monitoring service, open/selected-file watching, and first-run setup (install, shortcuts, the Explorer menu registration). Single-instance start-up and the right-click/daily-scan hand-over are done (`SingleInstance`, `LaunchRequest`). 129 tests.
2. Pages: Scan, Quarantine, Activity and Settings (sources, keys, scanning, trusted publishers, ignored list, theme) done; left: Firewall, system-integration settings (with the upgrade), tray alerts.
3. Upgrade path: read v1's config, hash cache, quarantine manifest and the "HashGuard" firewall rule group; same release signing key and `HashGuard.exe` asset name so v1's updater can install v2.
4. Beta, then 2.0.
