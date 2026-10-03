#!/usr/bin/env bash
# Run the HashGuard logic test project from any working directory.
#
# The .NET 8 SDK lives in ~/.dotnet on the Linux box used for local checks, so
# add it to PATH when `dotnet` is not already resolvable. Also syntax-checks the
# telemetry worker when node is available.
#
# Usage: scripts/run-tests.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v dotnet >/dev/null 2>&1; then
  if [ -x "$HOME/.dotnet/dotnet" ]; then
    export PATH="$HOME/.dotnet:$PATH"
  else
    echo "dotnet not found. Install the .NET 8 SDK or set PATH to include it." >&2
    exit 1
  fi
fi

echo "dotnet $(dotnet --version)"
echo "== HashGuardScanner.Tests =="
dotnet run --project "$repo_root/tests/HashGuardScanner.Tests/HashGuardScanner.Tests.csproj" -c Release

if command -v node >/dev/null 2>&1; then
  echo "== telemetry worker syntax =="
  node --check "$repo_root/cloudflare/telemetry/src/worker.js" && echo "worker.js: syntax OK"
fi
