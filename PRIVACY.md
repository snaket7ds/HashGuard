# Privacy Policy

HashGuard is a local Windows desktop tool for checking the reputation of running process files and selected files. HashGuard does not operate a HashGuard-owned cloud service.

## Local Data

HashGuard stores settings, ignored hashes, hash cache entries, and scan logs locally in the application's `config` and `logs` folders.

Settings may include encrypted API keys for reputation providers. Encryption uses Windows user or machine facilities available to the running application.

## Network Requests

HashGuard sends file hashes to reputation services only when those providers are enabled in settings.

Supported providers are:

- VirusTotal
- MetaDefender Cloud
- Team Cymru Malware Hash Registry
- GitHub Releases, for update checks

Hash lookups can reveal that a user has a file with a specific hash. Users should review each enabled provider's privacy terms before enabling that provider.

## File Uploads

VirusTotal full-file upload support is optional and disabled by default.

If enabled, HashGuard may upload files missing from VirusTotal for analysis during explicit process or single-file scans. Uploaded files are shared with VirusTotal and may be further shared according to VirusTotal's policies.

HashGuard never performs automatic full-file uploads from the background "Scan files I open or select" feature. That feature performs hash lookups only and skips common pictures, videos, audio files, and camera/raw files.

## System Changes

HashGuard may make system configuration changes only after user action or setup confirmation, including:

- installing to `C:\Program Files\HashGuard`
- creating Desktop or Start Menu shortcuts
- adding an Explorer right-click scan action
- registering HashGuard to start with Windows

These options can be declined or disabled in settings.

## Uninstalling

To uninstall HashGuard, disable "Start with Windows" and "Add Explorer right-click scan" in settings, exit the application from the tray menu, then remove the installed HashGuard folder and shortcuts.
