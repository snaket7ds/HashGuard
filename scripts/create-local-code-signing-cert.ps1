param(
    [string]$Subject = "CN=HashGuard Local Code Signing",
    [string]$CertificatePath = "$PSScriptRoot\..\certs\HashGuardLocalCodeSigning.cer",
    [int]$YearsValid = 5
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command New-SelfSignedCertificate -ErrorAction SilentlyContinue)) {
    throw "New-SelfSignedCertificate is not available on this system."
}

$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object {
        $_.Subject -eq $Subject -and
        $_.HasPrivateKey -and
        $_.NotAfter -gt (Get-Date).AddDays(30) -and
        $_.EnhancedKeyUsageList.FriendlyName -contains "Code Signing"
    } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if (-not $cert) {
    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $Subject `
        -CertStoreLocation Cert:\CurrentUser\My `
        -KeyAlgorithm RSA `
        -KeyLength 4096 `
        -HashAlgorithm SHA256 `
        -KeyUsage DigitalSignature `
        -NotAfter (Get-Date).AddYears($YearsValid)
}

$certDir = Split-Path -Parent $CertificatePath
New-Item -ItemType Directory -Force -Path $certDir | Out-Null
Export-Certificate -Cert $cert -FilePath $CertificatePath -Force | Out-Null

Import-Certificate -FilePath $CertificatePath -CertStoreLocation Cert:\CurrentUser\TrustedPublisher | Out-Null
Import-Certificate -FilePath $CertificatePath -CertStoreLocation Cert:\CurrentUser\Root | Out-Null

Write-Host "HashGuard local code-signing certificate is installed for the current user."
Write-Host "Subject: $($cert.Subject)"
Write-Host "Thumbprint: $($cert.Thumbprint)"
Write-Host "Public certificate: $CertificatePath"
Write-Host ""
Write-Host "This only establishes trust on this Windows account. Public distribution still needs a real code-signing certificate and SmartScreen reputation."
