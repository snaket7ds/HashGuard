#!/usr/bin/env bash
# Signs a HashGuard release binary for the in-app update check.
#
#   scripts/sign-release.sh <HashGuard.exe> <release-private-key.pem>
#
# Writes HashGuard.exe.sig next to the binary: a DER-encoded ECDSA P-256 / SHA-256
# signature, which UpdateVerifier.VerifyDetachedSignature checks. Upload the .sig
# with the .exe and the .sha256 as release assets.
#
# One-time key setup (keep the private key OUT of the repo):
#   openssl ecparam -name prime256v1 -genkey -noout -out release-private-key.pem
#   openssl ec -in release-private-key.pem -pubout -outform DER | base64 -w0
# Paste that base64 into Updates/UpdateVerifier.cs as ReleasePublicKeyBase64.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <HashGuard.exe> <release-private-key.pem>" >&2
  exit 2
fi

exe="$1"
key="$2"

[ -f "$exe" ] || { echo "no such file: $exe" >&2; exit 1; }
[ -f "$key" ] || { echo "no such key: $key" >&2; exit 1; }

openssl dgst -sha256 -sign "$key" -out "$exe.sig" "$exe"
echo "wrote $exe.sig"
