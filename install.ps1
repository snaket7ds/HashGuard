# HashGuard installer
#
#   irm https://raw.githubusercontent.com/snaket7ds/HashGuard/main/install.ps1 | iex
#
# Downloads the latest HashGuard release from GitHub (github.com/snaket7ds/HashGuard), checks
# its SHA-256 and HashGuard's release signature, installs it and starts it. If either check
# fails, nothing is installed.
#
#   - Run from an elevated PowerShell: installs to C:\Program Files\HashGuard for all users.
#   - Run normally: installs to %LOCALAPPDATA%\Programs\HashGuard for you only (no admin needed).
#
# Running it again updates HashGuard in place. Read this script before you pipe it into
# PowerShell: https://github.com/snaket7ds/HashGuard/blob/main/install.ps1
#
# Beta: when a beta (a GitHub pre-release) is newer than the latest release, the installer asks
# which one you want; pressing Enter keeps the stable release. To choose without being asked:
#
#   $env:HASHGUARD_CHANNEL = 'beta';   irm https://raw.githubusercontent.com/snaket7ds/HashGuard/main/install.ps1 | iex
#   $env:HASHGUARD_CHANNEL = 'stable'; irm https://raw.githubusercontent.com/snaket7ds/HashGuard/main/install.ps1 | iex
#
# A beta is checked exactly like a release (SHA-256 and release signature). Betas then keep
# offering newer betas; switch back in Settings > Updates > Update channel.

$HashGuardRepo = 'snaket7ds/HashGuard'

# The release signing public key (ECDSA P-256, SubjectPublicKeyInfo). The same key is built into
# HashGuard (Updates/UpdateVerifier.cs) and checks every in-app update.
$HashGuardReleasePublicKey = 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfwGA7L+9aMdccFlReclKz1IghW7PSLqZszoTrLPW86cMkJaAqQsBWowxqhqIQBWBWzp53Qn1lBaE/aoDDTm1Cw=='

function ConvertFrom-HashGuardDerSignature {
    # openssl writes ECDSA signatures as DER SEQUENCE { INTEGER r, INTEGER s }; Windows' APIs
    # take r || s, each left-padded to the curve size (32 bytes for P-256).
    param([byte[]]$Der, [int]$Size = 32)
    $i = 0
    if ($Der.Length -lt 8 -or $Der[$i++] -ne 0x30) { throw 'The release signature is malformed.' }
    $length = [int]$Der[$i++]
    if ($length -band 0x80) {
        $count = $length -band 0x7f
        $length = 0
        for ($k = 0; $k -lt $count; $k++) { $length = ($length -shl 8) -bor $Der[$i++] }
    }

    $raw = New-Object byte[] ($Size * 2)
    foreach ($part in 0, 1) {
        if ($Der[$i++] -ne 0x02) { throw 'The release signature is malformed.' }
        $intLength = [int]$Der[$i++]
        $value = [byte[]]@($Der[$i..($i + $intLength - 1)])
        $i += $intLength
        $start = 0
        while ($start -lt $value.Length - 1 -and $value[$start] -eq 0) { $start++ }
        $trimmed = $value.Length - $start
        if ($trimmed -gt $Size) { throw 'The release signature is malformed.' }
        [Array]::Copy($value, $start, $raw, $part * $Size + ($Size - $trimmed), $trimmed)
    }

    return , $raw
}

function Test-HashGuardReleaseSignature {
    param([byte[]]$Data, [byte[]]$SignatureDer, [string]$PublicKeyBase64 = $HashGuardReleasePublicKey)
    $spki = [Convert]::FromBase64String($PublicKeyBase64)
    $raw = ConvertFrom-HashGuardDerSignature -Der $SignatureDer
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash($Data) } finally { $sha.Dispose() }

    if ($PSVersionTable.PSEdition -eq 'Core') {
        $ecdsa = [Security.Cryptography.ECDsa]::Create()
        try {
            $read = 0
            $null = $ecdsa.ImportSubjectPublicKeyInfo($spki, [ref]$read)
            return $ecdsa.VerifyHash($hash, $raw)
        } finally { $ecdsa.Dispose() }
    }

    # Windows PowerShell 5.1 (.NET Framework): build a CNG P-256 public key blob. A P-256
    # SubjectPublicKeyInfo ends with the uncompressed point 0x04 || X || Y.
    $point = [byte[]]@($spki[($spki.Length - 65)..($spki.Length - 1)])
    if ($point[0] -ne 0x04) { throw 'The release public key is not a P-256 key.' }
    $blob = [byte[]](@(0x45, 0x43, 0x53, 0x31, 0x20, 0x00, 0x00, 0x00) + $point[1..64]) # "ECS1", key size 32
    $key = [Security.Cryptography.CngKey]::Import($blob, [Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
    $ecdsa = New-Object Security.Cryptography.ECDsaCng($key)
    try { return $ecdsa.VerifyHash($hash, $raw) } finally { $ecdsa.Dispose(); $key.Dispose() }
}

function Select-HashGuardRelease {
    # Picks the release to install. $Releases is GitHub's list (newest first), $Latest the latest
    # full release. 'beta' takes the newest published release of any kind; 'stable' the latest
    # full release; '' asks when a beta newer than the latest release exists (Enter = stable).
    param($Releases, $Latest, [string]$Channel, [scriptblock]$Ask)

    $beta = @($Releases | Where-Object { -not $_.draft -and $_.prerelease } |
        Sort-Object { [DateTime]$_.published_at } -Descending) | Select-Object -First 1
    $newerBeta = $beta -and (-not $Latest -or [DateTime]$beta.published_at -gt [DateTime]$Latest.published_at)

    switch ($Channel.Trim().ToLowerInvariant()) {
        'beta' { if ($newerBeta) { return $beta } else { return $Latest } }
        'stable' { return $Latest }
        '' { }
        default { throw "Unknown HASHGUARD_CHANNEL '$Channel': use 'stable' or 'beta'." }
    }

    if (-not $newerBeta) { return $Latest }
    if (-not $Latest) { return $beta }
    $answer = & $Ask $Latest.tag_name $beta.tag_name
    if ("$answer".Trim().ToLowerInvariant() -in 'b', 'beta') { return $beta }
    return $Latest
}

function Install-HashGuard {
    param([string]$Channel = $env:HASHGUARD_CHANNEL)
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'

    if ($env:OS -ne 'Windows_NT') { throw 'HashGuard runs on Windows only.' }
    if (-not [Environment]::Is64BitOperatingSystem) { throw 'HashGuard needs 64-bit Windows.' }
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }

    Write-Host ''
    Write-Host 'HashGuard installer' -ForegroundColor Green
    $headers = @{ 'User-Agent' = 'HashGuard-Installer'; 'Accept' = 'application/vnd.github+json' }
    $latest = $null
    try { $latest = Invoke-RestMethod -Uri "https://api.github.com/repos/$HashGuardRepo/releases/latest" -Headers $headers } catch { }
    $releases = Invoke-RestMethod -Uri "https://api.github.com/repos/$HashGuardRepo/releases?per_page=30" -Headers $headers
    $release = Select-HashGuardRelease -Releases $releases -Latest $latest -Channel "$Channel" -Ask {
        param($stableTag, $betaTag)
        Write-Host "  A beta is available: $betaTag (latest release: $stableTag)"
        try { Read-Host '  Install [S]table or [B]eta? (Enter = Stable)' } catch { 's' }
    }
    if (-not $release) { throw 'No HashGuard release was found on GitHub. Nothing was installed.' }
    $tag = [string]$release.tag_name
    Write-Host ("  Installing: $tag" + $(if ($release.prerelease) { ' (beta)' } else { '' }))

    $work = Join-Path ([IO.Path]::GetTempPath()) ('HashGuard-install-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    try {
        $files = @{}
        foreach ($name in 'HashGuard.exe', 'HashGuard.exe.sha256', 'HashGuard.exe.sig') {
            $asset = $release.assets | Where-Object { $_.name -eq $name } | Select-Object -First 1
            if (-not $asset) { throw "Release $tag is missing $name, so it can't be verified. Nothing was installed." }
            $files[$name] = Join-Path $work $name
            Write-Host "  Downloading $name"
            Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $files[$name] -UseBasicParsing -Headers @{ 'User-Agent' = 'HashGuard-Installer' }
        }

        $expected = ((Get-Content -LiteralPath $files['HashGuard.exe.sha256'] -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
        $actual = (Get-FileHash -LiteralPath $files['HashGuard.exe'] -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($expected -ne $actual) { throw "SHA-256 mismatch (expected $expected, got $actual). Nothing was installed." }
        Write-Host '  SHA-256 matches'

        $exeBytes = [IO.File]::ReadAllBytes($files['HashGuard.exe'])
        $sigBytes = [IO.File]::ReadAllBytes($files['HashGuard.exe.sig'])
        if (-not (Test-HashGuardReleaseSignature -Data $exeBytes -SignatureDer $sigBytes)) {
            throw 'The release signature does not match HashGuard''s signing key. Nothing was installed.'
        }
        Write-Host '  Release signature verified'

        $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $installDir = if ($isAdmin) { Join-Path $env:ProgramFiles 'HashGuard' } else { Join-Path $env:LOCALAPPDATA 'Programs\HashGuard' }
        $target = Join-Path $installDir 'HashGuard.exe'
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null

        $running = Get-Process -Name 'HashGuard' -ErrorAction SilentlyContinue | Where-Object {
            try { $_.Path -and ([IO.Path]::GetFullPath($_.Path) -eq [IO.Path]::GetFullPath($target)) } catch { $false }
        }
        if ($running) {
            Write-Host '  Closing the running HashGuard to update it'
            $running | Stop-Process -Force
            Start-Sleep -Seconds 2
        }

        Copy-Item -LiteralPath $files['HashGuard.exe'] -Destination $target -Force
        Write-Host "  Installed to $installDir"

        $programs = if ($isAdmin) { [Environment]::GetFolderPath('CommonPrograms') } else { [Environment]::GetFolderPath('Programs') }
        try {
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut((Join-Path $programs 'HashGuard.lnk'))
            $shortcut.TargetPath = $target
            $shortcut.WorkingDirectory = $installDir
            $shortcut.Description = 'HashGuard antivirus and firewall'
            $shortcut.Save()
            Write-Host '  Added HashGuard to the Start menu'
        } catch {
            Write-Host '  Could not add a Start menu shortcut (HashGuard is still installed).' -ForegroundColor Yellow
        }

        Start-Process -FilePath $target -WorkingDirectory $installDir
        Write-Host "HashGuard $tag is installed and starting." -ForegroundColor Green
        if (-not $isAdmin) {
            Write-Host 'Tip: run the same command from an elevated PowerShell to install for all users, so HashGuard can block apps in Windows Firewall.'
        }
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($env:HASHGUARD_INSTALLER_TEST -ne '1') {
    Install-HashGuard
}
