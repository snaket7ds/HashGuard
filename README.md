# HashGuard

HashGuard is a Windows desktop tool for checking the reputation of running process files and selected files from Explorer. It calculates file hashes, checks them against configured reputation services, caches clean results locally, and highlights files that need review.

## What It Does

- Scans running process executable files.
- Adds an optional Windows Explorer right-click action for scanning a single file.
- Checks file reputation using VirusTotal, MetaDefender Cloud, and Team Cymru Malware Hash Registry when enabled.
- Caches clean hashes locally to reduce repeat lookups.
- Logs scan results for later review.
- Can monitor newly seen process files after an initial scan.
- Supports startup scanning, tray minimization, Windows startup registration, and update checks from GitHub Releases.

## How Scanning Works

HashGuard groups running processes by executable path, computes each file's SHA-256 hash, and checks enabled reputation providers. Results are shown with process names, PIDs, hash, path, provider status, detection counts, and notes.

Files are marked for action when a provider reports malicious or suspicious detections, or when a scan error needs review. Clean and recently cached hashes are skipped when the hash cache is enabled.

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

Settings are stored in the local `config` folder. Scan logs are stored in `logs`.

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

## Releases And Updates

The built-in updater reads GitHub Releases from `snaket7ds/HashGuard`. Release tags should match the app version, such as `v1.0.27`.

Attach both files to each release:

```text
HashGuard.exe
HashGuard.exe.sha256
```

See [GITHUB_RELEASES.md](GITHUB_RELEASES.md) for release asset details.

## License

HashGuard is released under the license in [LICENSE](LICENSE).
