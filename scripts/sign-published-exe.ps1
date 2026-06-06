param(
    [string]$ExePath = "$PSScriptRoot\..\bin\Release\net8.0-windows\win-x64\publish\HashGuard.exe",
    [string]$Subject = "CN=HashGuard Local Code Signing",
    [string]$Sha256Path = "$PSScriptRoot\..\bin\Release\net8.0-windows\win-x64\publish\HashGuard.exe.sha256"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $ExePath)) {
    throw "Executable not found: $ExePath"
}

$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object {
        $_.Subject -eq $Subject -and
        $_.HasPrivateKey -and
        $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing"
    } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if (-not $cert) {
    throw "No code-signing certificate found for $Subject. Run scripts\create-local-code-signing-cert.ps1 first."
}

$signature = Set-AuthenticodeSignature -FilePath $ExePath -Certificate $cert -HashAlgorithm SHA256
if (-not $signature.SignerCertificate) {
    $signature | Format-List Status,StatusMessage,SignerCertificate
    throw "Signing failed: no signer certificate was written."
}

$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $ExePath).Hash.ToLowerInvariant()
Set-Content -Path $Sha256Path -Value "$sha  HashGuard.exe" -Encoding ASCII

Write-Host "Signed $ExePath"
Write-Host "Signature status: $($signature.Status)"
Write-Host "Signature message: $($signature.StatusMessage)"
Write-Host "Signer: $($signature.SignerCertificate.Subject)"
Write-Host "Thumbprint: $($signature.SignerCertificate.Thumbprint)"
Write-Host "SHA-256: $sha"
