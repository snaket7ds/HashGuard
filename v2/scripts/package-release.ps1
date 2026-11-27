<#
.SYNOPSIS
    Builds a HashGuard v2 release folder: HashGuard.exe, HashGuard.exe.sha256, HashGuard.exe.sig.

.DESCRIPTION
    The three files v1's (and v2's) updater requires, made in the order that keeps them valid:
      1. publish the single-file, self-contained HashGuard.exe (Release, x64)
      2. Authenticode-sign it with the same local code-signing certificate as v1, if present,
         so the updater's publisher check matches (signing changes the file, so it comes first)
      3. write its SHA-256
      4. write the detached release-key signature (ECDSA P-256), when -ReleaseKey is given;
         without it, updaters refuse the release

    Nothing is uploaded. Publish the files as a GitHub release yourself:
      - a preview (beta) as a *pre-release* with a tag like v2.0.0-beta.1: v1 users don't get it
        (v1 asks GitHub for the latest full release only, and can't read preview tags anyway)
      - the upgrade for everyone as a full release with a plain tag like v2.0.0: v1 offers it

.EXAMPLE
    .\scripts\package-release.ps1 -ReleaseKey C:\keys\release-private-key.pem
#>
param(
    [string]$ReleaseKey,
    [string]$CertificateSubject = "CN=HashGuard Local Code Signing",
    [string]$OpenSsl = "openssl"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root "src\HashGuard.App\HashGuard.App.csproj"
$release = Join-Path $root "release"

Write-Host "Publishing..."
dotnet publish $project -c Release -p:Platform=x64 -r win-x64 --nologo -v q
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed." }

$published = Get-ChildItem (Join-Path $root "src\HashGuard.App\bin\x64\Release") -Recurse -Filter HashGuard.exe |
    Where-Object { $_.DirectoryName -like "*\publish" } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if (-not $published) { throw "Published HashGuard.exe not found." }

if (Test-Path $release) { Remove-Item $release -Recurse -Force }
New-Item -ItemType Directory $release | Out-Null
$exe = Join-Path $release "HashGuard.exe"
Copy-Item $published.FullName $exe

# 2. Authenticode, with v1's certificate so the publisher check passes.
$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq $CertificateSubject -and $_.HasPrivateKey -and $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing" } |
    Sort-Object NotAfter -Descending | Select-Object -First 1
if ($cert) {
    $signature = Set-AuthenticodeSignature -FilePath $exe -Certificate $cert -HashAlgorithm SHA256
    if (-not $signature.SignerCertificate) { throw "Authenticode signing failed: $($signature.StatusMessage)" }
    Write-Host "Authenticode-signed by $($cert.Subject)"
} else {
    Write-Warning "No '$CertificateSubject' certificate: HashGuard.exe is not Authenticode-signed."
}

# 3. SHA-256 (after signing, which changes the file).
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash.ToLowerInvariant()
Set-Content -Path "$exe.sha256" -Value "$sha  HashGuard.exe" -Encoding ASCII

# 4. Detached release-key signature, required by the updater.
if ($ReleaseKey) {
    if (-not (Test-Path $ReleaseKey)) { throw "No such key: $ReleaseKey" }
    & $OpenSsl dgst -sha256 -sign $ReleaseKey -out "$exe.sig" $exe
    if ($LASTEXITCODE -ne 0) { throw "openssl couldn't sign the release." }
    Write-Host "Wrote HashGuard.exe.sig"
} else {
    Write-Warning "No -ReleaseKey: no HashGuard.exe.sig, so updaters will refuse this release."
}

$size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
Write-Host "Release folder: $release ($size MB, SHA-256 $sha)"
