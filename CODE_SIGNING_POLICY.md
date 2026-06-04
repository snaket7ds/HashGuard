# Code Signing Policy

HashGuard intends to use free code signing provided by [SignPath.io](https://about.signpath.io/), certificate by [SignPath Foundation](https://signpath.org/), for public Windows release binaries when the project is accepted by SignPath Foundation.

## Signed Artifacts

Public releases are distributed from GitHub Releases for `snaket7ds/HashGuard`.

The expected signed artifact is:

```text
HashGuard.exe
```

The checksum file is generated after signing:

```text
HashGuard.exe.sha256
```

HashGuard's built-in updater verifies the downloaded executable against the published SHA-256 checksum before replacement.

## Build Origin

Signed release artifacts must be built from the public HashGuard source repository:

```text
https://github.com/snaket7ds/HashGuard
```

Release tags should match the application version, for example:

```text
v1.0.28
```

## Project Roles

Committers and reviewers: [snaket7ds](https://github.com/snaket7ds) and maintainers with write or admin access to `snaket7ds/HashGuard`.

Approvers: [snaket7ds](https://github.com/snaket7ds) and maintainers with admin access to `snaket7ds/HashGuard`.

All maintainers participating in release approval must use multi-factor authentication for GitHub and SignPath access.

## Privacy Policy

HashGuard's privacy policy is documented in [PRIVACY.md](PRIVACY.md).

HashGuard performs reputation checks by sending file hashes to user-enabled reputation providers. Optional VirusTotal full-file upload support is disabled unless explicitly enabled by the user, and background open/selected-file scanning never uploads full files automatically.
