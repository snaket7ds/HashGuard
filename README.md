# HashGuard

HashGuard is a Windows desktop tool for checking the reputation of running process files and selected files from Explorer. It calculates file hashes, checks them against configured reputation services, caches clean results locally, and highlights files that need review.

## What It Does

- Scans running process executable files.
- Adds an optional Windows Explorer right-click action for scanning selected files.
- Can hash-scan files you open or select in File Explorer, while skipping common picture, video, audio, and camera/raw media files.
- Checks file reputation using VirusTotal, MetaDefender Cloud, and Team Cymru Malware Hash Registry when enabled.
- Caches clean hashes locally to reduce repeat lookups.
- Logs scan results for later review.
- Can monitor newly seen process files after an initial scan.
- Adds local triage context such as signer/publisher status, risky paths, startup persistence, and risk scoring.
- Can review selected results by opening reports, copying hashes, killing selected processes, and quarantining selected files.
- Tracks per-provider reputation state, supports local triage without API keys, and can restore/delete quarantined files from a manifest.
- Opens Quarantine Manager from the home-screen Quarantine tile, Activity Log, or the tray menu to search, restore, or permanently delete held files.
- Provides Activity Log filters, selected-row reason summaries, and quarantine repair/restore-to-Desktop recovery controls.
- Supports startup scanning, tray minimization, Windows startup registration, and update checks from GitHub Releases.
- Can schedule a daily full scan, export CSV/HTML reports, highlight files new since the last scan, and bulk-ignore a publisher from the Review Queue.
- Delta scan option: skip re-hashing and provider lookups for files already cached clean and unchanged on disk (size + last-write time).
- Verifies update downloads with SHA-256 and, when the current build is signed, matching Authenticode publisher.
- Network Monitor: shows which apps connect where, with each app's HashGuard verdict and signer, and blocks or unblocks an app in Windows Firewall with one click.

## How Scanning Works

HashGuard groups running processes by executable path, computes each file's SHA-256 hash, and checks enabled reputation providers. Results are shown with process names, PIDs, hash, path, provider status, detection counts, and notes.

When "Scan files I open or select" is enabled, HashGuard watches Windows Recent files and polls open File Explorer windows for selected or focused files. It skips common personal media types such as pictures, videos, audio, and camera/raw files, and it never uploads full files from this background mode.

Files are marked for action when a provider reports malicious or suspicious detections, or when a scan error needs review. Clean and recently cached hashes are skipped when the hash cache is enabled.

HashGuard also adds local trust and triage context. It checks whether scanned files are signed, whether they live in risky user-writable paths, whether they were recently modified, and whether they are referenced by common persistence locations such as Run keys, Startup folders, scheduled tasks, and Windows services.

## Network Monitor

Open it with the globe button in the header or **Network Monitor** in the tray menu. It lists every program with an open TCP connection to another machine (loopback is hidden), with its HashGuard verdict from the hash cache, its signer, the host it talks to (reverse DNS, falling back to the IP address), how many connections it has open now and this session, and whether HashGuard has blocked it. **Scan app** runs a normal HashGuard scan of the program; **Connections…** lists every host and port it reached this session.

**Block** adds a Windows Firewall rule that blocks the program's outgoing connections, optionally incoming too. **Unblock** removes it. Every rule HashGuard creates is in the Windows Firewall group **HashGuard** and named `HashGuard block: <file> (<id>)`; HashGuard lists, changes and removes only rules in that group, never your other rules. **Remove all HashGuard rules** undoes every block at once. Blocking needs HashGuard to run elevated (Settings → Behavior → Run elevated). Blocking parts of Windows (for example `svchost.exe`) or HashGuard itself shows an extra warning, because it can break Windows Update, DNS or sign-in.

Settings → Network:

- **Watch network connections in the background** (off by default). Without it, HashGuard only watches while the Network Monitor window is open, and sends no alerts.
- **Alerts:** when an untrusted app connects for the first time (default), when any app connects for the first time, or never. "Untrusted" means flagged by a provider, or not from a trusted publisher and either unsigned or not known clean. The first time background monitoring runs, apps that are already online are recorded without alerts. At most one alert is shown every 10 seconds; several new apps are combined into one.
- **Automatically block apps HashGuard flags as malicious** (off by default, needs Run elevated).

Limitations: this is a monitor, not a prompt-first firewall. Windows only lets a signed kernel driver hold a connection while asking the user, so traffic is allowed until you block an app, and connections an app already has open may continue until it reconnects. HashGuard reads the TCP table about once a second while the window is open (every 5 seconds in the background), so very short connections can be missed, and UDP traffic is not shown. All Windows services that share `svchost.exe` appear as one app. Seen apps are remembered in `network-apps.json` in the config folder; firewall actions are logged to `logs/network-actions.log`.

## Privacy Notes

Hash lookups send file hashes to the enabled reputation services. VirusTotal upload support is optional and disabled unless you enable it. When enabled, unknown files may be uploaded to VirusTotal for analysis, which can share the full file with VirusTotal. Do not enable uploads for private, proprietary, personal, or sensitive files unless you are comfortable sharing them.

## Configuration

Open settings inside the app to configure:

- VirusTotal API key
- MetaDefender Cloud API key
- Reputation providers
- Free API rate limiting
- Unknown-file uploads
- Hash cache
- Explorer right-click scan
- Startup behavior
- Automatic update checks
- Request delay and timeout values

Settings are stored in the local `config` folder. Scan logs are stored in `logs`. If the app folder is read-only (for example under Program Files without running elevated), both move to `%LocalAppData%\HashGuardUserData\`; Settings → Behavior → Version and Updates shows which folder is in use.

## Anonymous Usage Reporting

HashGuard can send optional anonymous usage events when enabled in Settings. The payload is limited to a random install ID, app version, OS version, event type, and scan summary counts. It does not include file paths, file hashes, process names, usernames, machine names, API keys, or provider report links.

The Cloudflare Worker and D1 dashboard live in `cloudflare/telemetry`. The worker rolls events up on write (one per-install row plus per-day rows) instead of storing a row per heartbeat, so dashboard reads stay inside D1 free-tier limits. Deploy it first, then set `TelemetryEndpointUrl` in `MainForm.cs` to the deployed `/events` URL before publishing a release. See [cloudflare/telemetry/README.md](cloudflare/telemetry/README.md) for the schema and deploy steps.

## Project Layout

Core logic is split under `Models/`, `Storage/`, `Providers/`, `Scanning/`, `Telemetry/`, `Updates/`, and `Ui/`. WinForms orchestration lives in `MainForm.cs` and `Program.cs`. Pure helpers and unit tests are in `HashGuardLogic.cs` and `tests/`.

Future ideas (YARA, true delta scan, more MainForm peels, etc.) are tracked in [ROADMAP.md](ROADMAP.md) — not committed work unless picked up intentionally.

## Build

HashGuard targets Windows and uses .NET 8 Windows Forms.

```bash
dotnet build HashGuardScanner.csproj -r win-x64
```

To publish a self-contained Windows build:

```bash
dotnet publish HashGuardScanner.csproj -c Release -r win-x64 --self-contained true
```

The published executable is named `HashGuard.exe`.

An Inno Setup installer scaffold is available at `installer/HashGuard.iss`. Build the release executable first, then compile the installer script on Windows with Inno Setup.

To create a local release package with checksums, release notes, and a Windows QA checklist:

```bash
scripts/package-release.sh
```

The generated files are written to `release/`. If Inno Setup's `iscc` compiler is not available, the package includes `INSTALLER_NOT_BUILT.txt` with the Windows installer command to run.

## Releases And Updates

The built-in updater reads GitHub Releases from `snaket7ds/HashGuard`. Release tags should match the app version, such as `v1.0.33`.

Attach both files to each release:

```text
HashGuard.exe
HashGuard.exe.sha256
```


## License

HashGuard is released under the license in [LICENSE](LICENSE).
