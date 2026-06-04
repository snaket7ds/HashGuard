# Changelog

## Unreleased

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
