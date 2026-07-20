param(
    [Parameter(Mandatory = $true)]
    [string[]]$Paths,

    [switch]$ReplaceExisting
)

$ErrorActionPreference = "Stop"

if (-not $env:WINDOWS_IDENTITY_PFX_BASE64 -or -not $env:WINDOWS_IDENTITY_PFX_PASSWORD) {
    throw "Windows signing certificate secrets are missing"
}

$sdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
$sdk = Get-ChildItem $sdkRoot -Directory |
    Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' -and (Test-Path (Join-Path $_.FullName "x64\signtool.exe")) } |
    Sort-Object { [version]$_.Name } -Descending |
    Select-Object -First 1
if (-not $sdk) {
    throw "Windows SDK SignTool was not found"
}
$signtool = Join-Path $sdk.FullName "x64\signtool.exe"

$signableExtensions = @(".dll", ".exe", ".msi")
$files = foreach ($path in $Paths) {
    $item = Get-Item -LiteralPath $path
    if ($item.PSIsContainer) {
        Get-ChildItem -LiteralPath $item.FullName -Recurse -File |
            Where-Object { $signableExtensions -contains $_.Extension.ToLowerInvariant() }
    } elseif ($signableExtensions -contains $item.Extension.ToLowerInvariant()) {
        $item
    }
}
$files = @($files | Sort-Object FullName -Unique)
if ($files.Count -eq 0) {
    throw "No Windows files were found to sign"
}

$prefix = "mendhands-release-signing-$env:GITHUB_RUN_ID-$env:GITHUB_RUN_ATTEMPT"
$pfxPath = Join-Path $env:RUNNER_TEMP "$prefix.pfx"
$cerPath = Join-Path $env:RUNNER_TEMP "$prefix.cer"
$certMarker = Join-Path $env:RUNNER_TEMP "$prefix.thumbprint"
$cert = $null
$trustedByStep = $false

try {
    [IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($env:WINDOWS_IDENTITY_PFX_BASE64))
    $securePassword = ConvertTo-SecureString $env:WINDOWS_IDENTITY_PFX_PASSWORD -AsPlainText -Force
    $cert = (Get-PfxData -FilePath $pfxPath -Password $securePassword).EndEntityCertificates | Select-Object -First 1
    if (-not $cert -or $cert.Subject -ne "CN=MendHands") {
        throw "Windows signing certificate publisher mismatch"
    }
    Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
    if (-not (Test-Path "Cert:\CurrentUser\TrustedPeople\$($cert.Thumbprint)")) {
        $trustedByStep = $true
        Set-Content -LiteralPath $certMarker -Value $cert.Thumbprint
        Import-Certificate -FilePath $cerPath -CertStoreLocation Cert:\CurrentUser\TrustedPeople | Out-Null
    }

    foreach ($file in $files) {
        $existingSignature = Get-AuthenticodeSignature $file.FullName
        if ($existingSignature.SignerCertificate -and -not $ReplaceExisting) {
            if ($existingSignature.Status -in @("HashMismatch", "NotSigned", "UnknownError", "NotSupported")) {
                throw "Existing signature is invalid: $($file.FullName) [$($existingSignature.Status)]"
            }
            Write-Host "Preserved existing signature on $($file.Name): $($existingSignature.SignerCertificate.Subject)"
            continue
        }
        $signed = $false
        foreach ($timestampUrl in @("http://timestamp.digicert.com", "http://timestamp.sectigo.com")) {
            & $signtool sign /fd SHA256 /tr $timestampUrl /td SHA256 /f $pfxPath /p $env:WINDOWS_IDENTITY_PFX_PASSWORD $file.FullName
            if ($LASTEXITCODE -eq 0) {
                $signed = $true
                break
            }
        }
        if (-not $signed) {
            throw "Signing failed: $($file.FullName)"
        }
        & $signtool verify /pa /all /v $file.FullName
        if ($LASTEXITCODE -ne 0) {
            throw "Signature verification failed: $($file.FullName)"
        }
        $signature = Get-AuthenticodeSignature $file.FullName
        if ($signature.Status -ne "Valid" -or
            -not $signature.SignerCertificate -or
            $signature.SignerCertificate.Thumbprint -ne $cert.Thumbprint -or
            -not $signature.TimeStamperCertificate) {
            throw "Signature identity or timestamp verification failed: $($file.FullName)"
        }
        Write-Host "Signed $($file.Name) with $($cert.Subject) [$($cert.Thumbprint)]"
    }
} finally {
    if ($trustedByStep -and $cert) {
        Remove-Item "Cert:\CurrentUser\TrustedPeople\$($cert.Thumbprint)" -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path "Cert:\CurrentUser\TrustedPeople\$($cert.Thumbprint)")) {
            Remove-Item $certMarker -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item $pfxPath, $cerPath -Force -ErrorAction SilentlyContinue
    if (Test-Path $pfxPath) {
        throw "Windows signing private key cleanup was incomplete"
    }
}
