# HashGuard code recommendations

Refactor notes for `HashGuard_source`. These recommendations were implemented
in a **local-only** branch of the tree for testing before any GitHub push.

**Build label:** `1.0.45` (see `HashGuardScanner.csproj`).

---

## Goals of this local build

| Area | Change |
|------|--------|
| HTTP | Shared `SocketsHttpHandler` via `AppHttp.Create` (no new connection pool per scan) |
| Concurrency | `ScanGate` so full / monitor / idle / single-file scans do not overlap |
| Logic | Extra pure helpers in `HashGuardLogic` for status/quarantine/ignore rules |
| Tests | Expanded unit tests for those helpers |
| Privacy | New installs default **telemetry off** (`TelemetryEnabled = false`) |
| Docs | This file |

---

## Architecture (still recommended next)

`MainForm.cs` remains large (~7k lines). Longer-term peel into:

| Module | Responsibility |
|--------|----------------|
| `Scanning/` | process collection, monitor, single-file |
| `Providers/` | VirusTotal, MetaDefender, Cymru |
| `Storage/` | settings, cache, ignore, quarantine |
| `Updates/` | GitHub releases |
| `Telemetry/` | worker events |
| `Ui/` | form + dialogs only |

This local build takes the **high-ROI stabilizers** first without a full rewrite.

---

## What already was solid

- DPAPI for API keys
- Named-pipe ACL for Explorer `--scan-file`
- Hash cache, quota tracker, quarantine with hash verify
- Small pure helpers + tests (`HashGuardLogic`)
- Cancellation on full scans

---

## How to test

### Prebuilt (from this machine)

Self-contained Windows EXE (local QA only, **not** pushed to GitHub):

- `/home/administrator/hashguard-build-local/dist/HashGuard.exe`
- symlink: `~/HashGuard-dist-local/HashGuard.exe`
- also under source: `dist-local/HashGuard.exe` (if NAS copy succeeded)

Copy `HashGuard.exe` to a Windows PC and run it. Version shows as **1.0.44-local**.

### Rebuild on Windows

```powershell
cd path\to\HashGuard_source
dotnet run --project tests\HashGuardScanner.Tests\HashGuardScanner.Tests.csproj -c Release
dotnet publish HashGuardScanner.csproj -c Release -r win-x64 --self-contained true -o dist-local
```

Unit tests: **13 passed** on the AI box (logic + `ScanGate`; no WinForms required).

Manual checks:

1. Run Scan while process monitor is active — monitor should skip, not double-scan.
2. Right-click scan during a full scan — should report busy / skip cleanly.
3. Settings still save/load encrypted VT + MetaDefender keys.
4. Telemetry checkbox defaults off on a **fresh** settings file.
5. Activity filters still treat `ignored` as handled, not action-needed.

---

## Repo hygiene (not forced in this change)

- Keep `release/*.exe` out of git (already gitignored).
- Do not commit `cloudflare/telemetry/node_modules`.
- Prefer GitHub Releases for binaries.

---

## Decision cheat sheet

| Goal | Prefer |
|------|--------|
| Stability under monitor + full scan | This local build (`ScanGate` + `AppHttp`) |
| Faster future features | Continue extracting providers from `MainForm` |
| Publish publicly | Revisit telemetry default, pipe ACL, privacy copy |

When satisfied, commit and push from the Windows or AI box intentionally — this work was left **unpushed** for local QA.
