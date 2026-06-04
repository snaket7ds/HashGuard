# SignPath Foundation Application Notes

Use these notes when applying for free SignPath Foundation signing for HashGuard.

## Project

Project name: HashGuard

Repository:

```text
https://github.com/snaket7ds/HashGuard
```

License: MIT

Release format to sign:

```text
HashGuard.exe
```

Download page:

```text
https://github.com/snaket7ds/HashGuard/releases
```

Code signing policy:

```text
https://github.com/snaket7ds/HashGuard/blob/main/CODE_SIGNING_POLICY.md
```

Privacy policy:

```text
https://github.com/snaket7ds/HashGuard/blob/main/PRIVACY.md
```

## Project Description

HashGuard is a Windows desktop tool that computes SHA-256 hashes for running process executable files and selected files, checks those hashes against user-configured reputation providers, caches clean results locally, and highlights files that need review.

HashGuard is not an exploitation tool, vulnerability scanner, password tool, offensive security framework, or bypass tool. Its purpose is to detect possible malware or unwanted files by reputation lookup.

## Network And Privacy Summary

HashGuard sends file hashes to enabled reputation providers selected by the user:

- VirusTotal
- MetaDefender Cloud
- Team Cymru Malware Hash Registry

HashGuard checks GitHub Releases for updates when update checks are enabled.

Optional VirusTotal full-file upload support is disabled by default and requires explicit user enablement. Background open/selected-file scanning never uploads full files automatically.

## Release Process

1. Publish a Windows release build from a tagged source version.
2. Submit `HashGuard.exe` to SignPath for signing.
3. Verify the signed executable.
4. Generate `HashGuard.exe.sha256` from the signed executable.
5. Attach `HashGuard.exe` and `HashGuard.exe.sha256` to the GitHub Release.

## GitHub Actions

HashGuard includes `.github/workflows/release-build.yml` to build the unsigned Windows executable on GitHub-hosted Windows runners and upload it as a workflow artifact.

After SignPath Foundation accepts the project, extend that workflow with SignPath's `signpath/github-action-submit-signing-request` action using the organization ID, project slug, signing policy slug, and API token from the SignPath project.

## SignPath Terms Checklist

- OSI-approved license: MIT.
- Public source repository: `snaket7ds/HashGuard`.
- Existing release channel: GitHub Releases.
- Project functionality documented in `README.md`.
- Code signing policy documented in `CODE_SIGNING_POLICY.md`.
- Privacy policy documented in `PRIVACY.md`.
- System changes are user-visible setup/settings options.
- Uninstall steps are documented in `PRIVACY.md`.
