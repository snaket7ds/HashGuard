# Changelog

## Unreleased

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
