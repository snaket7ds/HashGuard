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

If the release executable is signed, generate the checksum file after signing:

```bash
sha256sum bin/Release/net8.0-windows/win-x64/publish/HashGuard.exe > HashGuard.exe.sha256
```

The updater downloads `HashGuard.exe`, verifies it against `HashGuard.exe.sha256`, then replaces the local executable.

## Code Signing

The project Code signing policy is documented in [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md).

When SignPath Foundation signing is available, the release order is:

```text
1. Build HashGuard.exe from the tagged source.
2. Submit HashGuard.exe for signing.
3. Verify the signed executable.
4. Generate HashGuard.exe.sha256 from the signed executable.
5. Attach both files to the GitHub Release.
```
