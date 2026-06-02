# HashGuard GitHub Releases

HashGuard updates are read from GitHub Releases only. The app expects the repository setting in this format:

```text
owner/repo
```

Each release tag should match the app version, for example:

```text
v1.0.2
```

Attach both files to the release:

```text
HashGuard.exe
HashGuard.exe.sha256
```

Generate the checksum file after publishing:

```bash
sha256sum bin/Release/net8.0-windows/win-x64/publish/HashGuard.exe > HashGuard.exe.sha256
```

The updater downloads `HashGuard.exe`, verifies it against `HashGuard.exe.sha256`, then replaces the local executable.
