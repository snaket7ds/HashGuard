# HashGuard architecture notes

Status as of **v1.0.51**.

## Implemented modular layout

| Module | Path | Responsibility |
|--------|------|----------------|
| Paths / constants | `AppPaths.cs`, `AppConstants.cs` | Config locations, provider URLs, cache ages |
| HTTP | `AppHttp.cs` | Shared `SocketsHttpHandler` |
| Concurrency | `ScanGate.cs` | Single non-reentrant scan gate |
| Models | `Models/ScanModels.cs` | ScanResult, settings, GitHub assets, cache entries |
| Storage | `Storage/` | HashCache, QuotaTracker, scan snapshot |
| Providers | `Providers/` | VT/MetaDefender/Cymru JSON mapping + Cymru client |
| Scanning | `Scanning/` | Path security, SHA-256, report export, scheduled task |
| Telemetry | `Telemetry/TelemetryClient.cs` | Anonymous event POST |
| Updates | `Updates/UpdateVerifier.cs` | SHA-256 + publisher checks |
| UI theme | `Ui/ThemePalette.cs` | Light/dark palettes |
| Logic helpers | `HashGuardLogic.cs` | Pure filters, ignore notes, tray signatures |
| Shell UI | `MainForm.cs` (partial), `Program.cs` | WinForms orchestration |

`MainForm` remains the UI orchestrator (still large) but no longer owns cache/provider/model types or pure JSON parsers.

## Product features landed in 1.0.51

- Daily scheduled scan (Settings → Behavior)
- Export CSV/HTML scan report (Review Queue → Export)
- New-since-last-scan highlighting (snapshot + Prefer delta option)
- Ignore Publisher on Review Queue
- Suppress repeat tray alerts for the same action-needed set
- Pipe path validation for Explorer right-click scans
- Update Authenticode publisher match when current EXE is signed

## Still optional later

- Further peel WinForms scan/UI methods into `MainForm.*.cs` partials by feature area
- YARA / SmartScreen optional signals
- Graphite-style CI publish from Linux (WindowsForms still targets `win-x64`)

## How to test

```bash
export PATH="$HOME/.dotnet:$PATH"
dotnet run --project tests/HashGuardScanner.Tests/HashGuardScanner.Tests.csproj -c Release
dotnet build HashGuardScanner.csproj -c Release -r win-x64
```

On Windows:

```powershell
dotnet publish HashGuardScanner.csproj -c Release -r win-x64 --self-contained true -o dist
```

## Repo hygiene

- Keep `release/*.exe` and `cloudflare/telemetry/node_modules` out of git (gitignored).
- Prefer GitHub Releases for binaries (`HashGuard.exe` + `.sha256`).
