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
1. Core: the engine in `HashGuard.Core` with tests. **Done** (152 tests).
   - Scanning: `IReputationProvider` (VirusTotal, MetaDefender, Team Cymru) with one `VirusTotalPacer`, `FileAnalyzer`, `RiskScorer`, `SignatureReader` (WinVerifyTrust, including Windows catalogs), `ScanService`, `BackgroundScanner` (start-up scan, new programs, real-time scan of files you open: `FileActivityWatcher`).
   - Storage: `SettingsStore` + `Dpapi`, `IgnoreList`, `HashCache`, `ScanLog`, `QuarantineStore`, `ActivityLogReader` + `ActivityFeed`.
   - Network: `NetworkMonitor` (connections, alerts, block/unblock, auto-block).
   - Windows: `SingleInstance` + `LaunchRequest`, `WindowsIntegration` (start at sign-in, elevated task, daily scan, Explorer menu), `Installer`, `UpdateService`, `LegacyHashGuard`.
2. Pages: Home, Scan, Quarantine, Firewall, Activity, Settings; tray notices. **Done.**
3. Upgrade path. **Built, not yet exercised** (see below).
4. Beta, then 2.0.

## Upgrade from v1

v1's updater installs v2 like any v1 release: it downloads `HashGuard.exe` from the newest full GitHub release, checks its SHA-256 and `HashGuard.exe.sig` (the release key), and swaps it in place. v2 then starts from the same folder and finds everything where v1 left it, in the same formats: `config\settings.json` (encrypted keys), ignore lists, hash cache, quarantine folder and manifest, `logs\`, `network-apps.json`, and the "HashGuard" firewall rule group. Its Windows registrations (Run key or elevated sign-in task, daily scan task, Explorer menu) already point at that exe, with arguments v2 understands (`--minimized`, `--scheduled-scan`, `--scan-file`).

Releasing:

- `scripts\package-release.ps1 -ReleaseKey <release-private-key.pem>` builds `release\` with `HashGuard.exe` (Authenticode-signed with v1's local certificate if present), `.sha256` and `.sig`. It uploads nothing.
- Beta: publish as a GitHub **pre-release** with a tag like `v2.0.0-beta.1`. v1 users don't get it: v1 asks for the latest full release only, and can't parse preview tags. v2 previews do get newer previews.
- 2.0: publish as a full release with a plain tag (`v2.0.0`), which v1 can parse and offers to everyone.

Copies that aren't installed (portable, test) never change Windows registrations by themselves, and never take one over from another copy that still exists.
