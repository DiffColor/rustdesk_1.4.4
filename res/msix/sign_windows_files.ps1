param(
    [Parameter(Mandatory = $true)]
    [string[]]$Paths,

    [switch]$ReplaceExisting,

    [switch]$KeepTrust
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

$prefix = "rustdesk-release-signing-$env:GITHUB_RUN_ID-$env:GITHUB_RUN_ATTEMPT"
$pfxPath = Join-Path $env:RUNNER_TEMP "$prefix.pfx"
$cerPath = Join-Path $env:RUNNER_TEMP "$prefix.cer"
$certMarker = Join-Path $env:RUNNER_TEMP "$prefix.thumbprint"
$expectedSignerMarker = Join-Path $env:RUNNER_TEMP "$prefix.expected-thumbprint"
$cert = $null
$trustedByStep = $false
$succeeded = $false

try {
    [IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($env:WINDOWS_IDENTITY_PFX_BASE64))
    $securePassword = ConvertTo-SecureString $env:WINDOWS_IDENTITY_PFX_PASSWORD -AsPlainText -Force
    $cert = (Get-PfxData -FilePath $pfxPath -Password $securePassword).EndEntityCertificates | Select-Object -First 1
    if (-not $cert -or $cert.Subject -ne "CN=RustDesk") {
        throw "Windows signing certificate publisher mismatch"
    }
    Set-Content -LiteralPath $expectedSignerMarker -Value $cert.Thumbprint
    Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
    if (-not (Test-Path "Cert:\CurrentUser\TrustedPeople\$($cert.Thumbprint)")) {
        $trustedByStep = $true
        Set-Content -LiteralPath $certMarker -Value $cert.Thumbprint
        Import-Certificate -FilePath $cerPath -CertStoreLocation Cert:\CurrentUser\TrustedPeople | Out-Null
    }
    foreach ($file in $files) {
        $existingSignature = Get-AuthenticodeSignature $file.FullName
        if ($existingSignature.SignerCertificate -and -not $ReplaceExisting) {
            if ($existingSignature.Status -notin @("Valid", "NotTrusted")) {
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
        $verifyOutput = (& $signtool verify /pa /all /v $file.FullName 2>&1 | Out-String)
        $verifyExitCode = $LASTEXITCODE
        Write-Host $verifyOutput
        $signature = Get-AuthenticodeSignature $file.FullName
        $actualThumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { "none" }
        Write-Host "Authenticode status=$($signature.Status) signer=$actualThumbprint"
        if (-not $signature.SignerCertificate -or
            $signature.SignerCertificate.Thumbprint -ne $cert.Thumbprint) {
            throw "Signature verification failed for $($file.FullName) [$($signature.Status)]"
        }
        if ([regex]::Matches($verifyOutput, '(?m)^\s*Signature Index:').Count -ne 1) {
            throw "Unexpected Authenticode signature count: $($file.FullName)"
        }
        if ($verifyOutput -notmatch '(?m)^\s*The signature is timestamped:' -or $verifyOutput -notmatch '(?m)^\s*Timestamp Verified by:') {
            throw "RFC3161 timestamp verification failed: $($file.FullName)"
        }
        $verifyLines = @(($verifyOutput -split '\r?\n') | Where-Object { $_ -notmatch '^\s*$' })
        $rootErrorIndices = @(for ($i = 0; $i -lt $verifyLines.Count; $i++) { if ($verifyLines[$i] -match '^\s*SignTool Error: A certificate chain processed, but terminated in a root\s*$') { $i } })
        $providerErrorIndices = @(for ($i = 0; $i -lt $verifyLines.Count; $i++) { if ($verifyLines[$i] -match '^\s*certificate which is not trusted by the trust provider\.\s*$') { $i } })
        $signToolErrors = @($verifyLines | Where-Object { $_ -match '^\s*SignTool Error:' })
        $verifiedSummaries = @($verifyLines | Where-Object { $_ -match '^\s*Number of signatures successfully Verified:' })
        $warningSummaries = @($verifyLines | Where-Object { $_ -match '^\s*Number of warnings:' })
        $errorSummaries = @($verifyLines | Where-Object { $_ -match '^\s*Number of errors:' })
        $interposedLines = if ($rootErrorIndices.Count -eq 1 -and $providerErrorIndices.Count -eq 1 -and $providerErrorIndices[0] -gt ($rootErrorIndices[0] + 1)) { @($verifyLines[($rootErrorIndices[0] + 1)..($providerErrorIndices[0] - 1)]) } else { @() }
        $unexpectedInterposedLines = @($interposedLines | Where-Object { $_ -notmatch '^\s*(?:Verifying: .+|Signature Index: 0 \(Primary Signature\)|Hash of file \(sha256\): [0-9A-F]{64}|Signing Certificate Chain:|Issued to: .+|Issued by: .+|Expires:\s+.+|SHA1 hash: [0-9A-F]{40}|The signature is timestamped: .+|Timestamp Verified by:|Number of signatures successfully Verified: 0|Number of warnings: 0|Number of errors: 1)\s*$' })
        $expectedRootTrustFailure = $verifyExitCode -ne 0 -and
            $signToolErrors.Count -eq 1 -and $rootErrorIndices.Count -eq 1 -and
            $providerErrorIndices.Count -eq 1 -and $providerErrorIndices[0] -gt $rootErrorIndices[0] -and $unexpectedInterposedLines.Count -eq 0 -and
            $verifiedSummaries.Count -eq 1 -and $verifiedSummaries[0] -match '^\s*Number of signatures successfully Verified: 0\s*$' -and
            $warningSummaries.Count -eq 1 -and $warningSummaries[0] -match '^\s*Number of warnings: 0\s*$' -and
            $errorSummaries.Count -eq 1 -and $errorSummaries[0] -match '^\s*Number of errors: 1\s*$'
        if ($verifyExitCode -ne 0 -and -not $expectedRootTrustFailure) {
            throw "Unexpected SignTool verification failure: $($file.FullName)"
        }
        $statusAllowed = $signature.Status -in @("Valid", "NotTrusted") -or
            ($signature.Status -eq "UnknownError" -and $expectedRootTrustFailure)
        if (-not $statusAllowed) {
            throw "Signature status was not allowed for $($file.FullName) [$($signature.Status)]"
        }
        Write-Host "Signed $($file.Name) with $($cert.Subject) [$($cert.Thumbprint)]"
    }
    $succeeded = $true
} finally {
    $preserveTrust = $KeepTrust -and $succeeded
    if ($trustedByStep -and $cert -and -not $preserveTrust) {
        Remove-Item "Cert:\CurrentUser\TrustedPeople\$($cert.Thumbprint)" -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path "Cert:\CurrentUser\TrustedPeople\$($cert.Thumbprint)")) {
            Remove-Item $certMarker -Force -ErrorAction SilentlyContinue
        }
    }
    if (-not $preserveTrust) {
        Remove-Item $expectedSignerMarker -Force -ErrorAction SilentlyContinue
    }
    Remove-Item $pfxPath, $cerPath -Force -ErrorAction SilentlyContinue
    $residue = @(@($pfxPath, $cerPath) | Where-Object { Test-Path $_ })
    if (-not $preserveTrust) {
        $residue += @(@($certMarker, $expectedSignerMarker) | Where-Object { Test-Path $_ })
    }
    if ($residue.Count -ne 0) { throw "Windows signing temporary-file cleanup was incomplete: $($residue -join ', ')" }
    if ($trustedByStep -and -not $preserveTrust -and (Test-Path "Cert:\CurrentUser\TrustedPeople\$($cert.Thumbprint)")) {
        throw "Windows signing trust cleanup was incomplete"
    }
}
