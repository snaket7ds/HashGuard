# HashGuard GitHub Releases

HashGuard updates are read from GitHub Releases only. The app expects the repository setting in this format:

```text
owner/repo
```

Each release tag should match the app version, for example:

```text
v1.0.33
```

Attach both files to the release:

```text
HashGuard.exe
HashGuard.exe.sha256
```

Generate a complete local release package after publishing:

```bash
scripts/package-release.sh
```

The package is written to `release/` and includes `HashGuard.exe`, `HashGuard.exe.sha256`, `RELEASE_NOTES.md`, and `WINDOWS_QA_CHECKLIST.md`. If Inno Setup is available, it also includes the setup executable and checksum.

The updater downloads `HashGuard.exe`, verifies it against `HashGuard.exe.sha256`, then replaces the local executable.
