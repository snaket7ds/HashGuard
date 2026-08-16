#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PUBLISH_DIR="$ROOT_DIR/bin/Release/net8.0-windows/win-x64/publish"
RELEASE_DIR="$ROOT_DIR/release"
EXE="$PUBLISH_DIR/HashGuard.exe"
VERSION="$(grep -m1 '<Version>' "$ROOT_DIR/HashGuardScanner.csproj" | sed -E 's/.*<Version>([^<]+)<\/Version>.*/\1/')"

cd "$ROOT_DIR"
dotnet publish HashGuardScanner.csproj -c Release -r win-x64 --self-contained true

rm -rf "$RELEASE_DIR"
mkdir -p "$RELEASE_DIR"
cp "$EXE" "$RELEASE_DIR/HashGuard.exe"
sha256sum "$RELEASE_DIR/HashGuard.exe" > "$RELEASE_DIR/HashGuard.exe.sha256"

awk '
  /^## Unreleased/ { capture = 1; next }
  /^## / && capture { exit }
  capture { print }
' CHANGELOG.md | sed '/^[[:space:]]*$/N;/^\n$/D' > "$RELEASE_DIR/RELEASE_NOTES.md"
if [ ! -s "$RELEASE_DIR/RELEASE_NOTES.md" ]; then
  printf 'HashGuard %s local release package.\n' "$VERSION" > "$RELEASE_DIR/RELEASE_NOTES.md"
fi

cat > "$RELEASE_DIR/WINDOWS_QA_CHECKLIST.md" <<'CHECKLIST'
# HashGuard Windows QA Checklist

- Launch HashGuard.exe from this release folder.
- Run a process scan and verify the progress bar, scan count, status text, and scan results table.
- Open Activity Log and verify All, Action Needed, Unknown, Clean, and Errors filters.
- Select a row and verify the reason panel, Copy Hash, Copy Summary, Open File Location, and Open Report.
- Open Quarantine from the home-screen tile and the tray menu.
- Quarantine a harmless test file, then restore it to the original path.
- Quarantine a harmless test file, then restore it to Desktop.
- Delete a quarantined harmless test file.
- Delete a quarantined file outside HashGuard and verify Repair Missing removes the stale manifest entry.
- Open Settings and verify Reputation, Behavior, and Trust tabs.
- Verify provider validation text changes when API keys/providers/options change.
- Toggle right-click scan and verify the Explorer menu entry on a test file.
- Test startup/minimize-to-tray behavior if those settings are enabled.
- If Inno Setup is available, install and uninstall the generated setup package.
CHECKLIST

if command -v iscc >/dev/null 2>&1; then
  iscc "$ROOT_DIR/installer/HashGuard.iss"
  setup_path="$(find "$ROOT_DIR/dist" -maxdepth 1 -type f -name 'HashGuardSetup-*.exe' -printf '%T@ %p\n' | sort -nr | awk 'NR == 1 { $1=""; sub(/^ /, ""); print }')"
  if [ -n "${setup_path:-}" ]; then
    cp "$setup_path" "$RELEASE_DIR/$(basename "$setup_path")"
    sha256sum "$RELEASE_DIR/$(basename "$setup_path")" > "$RELEASE_DIR/$(basename "$setup_path").sha256"
  fi
else
  cat > "$RELEASE_DIR/INSTALLER_NOT_BUILT.txt" <<'INSTALLER'
Inno Setup compiler (iscc) was not found in this environment.
Build the installer on Windows with Inno Setup 6:

  iscc installer\HashGuard.iss

Then copy HashGuardSetup-*.exe and its SHA-256 checksum into this release folder.
INSTALLER
fi

printf 'Release package created at %s\n' "$RELEASE_DIR"
