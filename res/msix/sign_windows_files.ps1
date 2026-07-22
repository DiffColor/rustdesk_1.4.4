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
    $pfxData = Get-PfxData -FilePath $pfxPath -Password $securePassword
    $cert = $pfxData.EndEntityCertificates | Select-Object -First 1
    $rootCerts = @($pfxData.OtherCertificates | Where-Object {
        $_.Subject -eq $_.Issuer -and ($_.Extensions | Where-Object {
            $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] -and $_.CertificateAuthority
        })
    })
    if (-not $cert -or $cert.Subject -ne "CN=RustDesk") {
        throw "Windows signing certificate publisher mismatch"
    }
    if ($rootCerts.Count -ne 1) {
        throw "Windows signing PFX must contain exactly one self-issued CA root certificate"
    }
    $rootCert = $rootCerts[0]
    $signerSha256 = $cert.GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $rootSha256 = $rootCert.GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256)
    if ($env:RUSTDESK_IDENTITY_SIGNER_SHA256 -notmatch '^[0-9A-F]{64}$' -or $signerSha256 -ne $env:RUSTDESK_IDENTITY_SIGNER_SHA256) {
        throw "Windows signing certificate does not match the signed runtime signer pin"
    }
    if ($env:RUSTDESK_IDENTITY_ROOT_SHA256 -notmatch '^[0-9A-F]{64}$' -or $rootSha256 -ne $env:RUSTDESK_IDENTITY_ROOT_SHA256) {
        throw "Windows signing root does not match the signed runtime root pin"
    }
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.TrustMode = [System.Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
        $chain.ChainPolicy.CustomTrustStore.Add($rootCert)
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        $chainRootSha256 = if ($chain.Build($cert)) { $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.GetCertHashString([System.Security.Cryptography.HashAlgorithmName]::SHA256) } else { "" }
        if ($chainRootSha256 -ne $rootSha256) {
            throw "Windows signing certificate does not chain to the pinned root certificate"
        }
    } finally {
        $chain.Dispose()
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
        $expectedFileSignerThumbprint = $cert.Thumbprint
        if ($existingSignature.SignerCertificate -and -not $ReplaceExisting) {
            $trustedThirdPartySignature = $existingSignature.Status -eq "Valid" -and $existingSignature.TimeStamperCertificate
            $pinnedPrivateSignature = $existingSignature.SignerCertificate.Thumbprint -eq $cert.Thumbprint -and
                $existingSignature.Status -in @("NotTrusted", "UnknownError") -and $existingSignature.TimeStamperCertificate
            if (-not $trustedThirdPartySignature -and -not $pinnedPrivateSignature) {
                throw "Existing signature is invalid: $($file.FullName) [$($existingSignature.Status)]"
            }
            $expectedFileSignerThumbprint = $existingSignature.SignerCertificate.Thumbprint
            Write-Host "Preserved existing signature on $($file.Name): $($existingSignature.SignerCertificate.Subject)"
        } else {
            $signed = $false
            foreach ($timestampUrl in @("http://timestamp.sectigo.com", "http://timestamp.digicert.com")) {
                & $signtool sign /fd SHA256 /tr $timestampUrl /td SHA256 /f $pfxPath /p $env:WINDOWS_IDENTITY_PFX_PASSWORD $file.FullName
                if ($LASTEXITCODE -eq 0) {
                    $signed = $true
                    break
                }
            }
            if (-not $signed) {
                throw "Signing failed: $($file.FullName)"
            }
        }
        $verifyOutput = (& $signtool verify /pa /all /v $file.FullName 2>&1 | Out-String)
        $verifyExitCode = $LASTEXITCODE
        Write-Host $verifyOutput
        $signature = Get-AuthenticodeSignature $file.FullName
        $actualThumbprint = if ($signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint } else { "none" }
        Write-Host "Authenticode status=$($signature.Status) signer=$actualThumbprint"
        if (-not $signature.SignerCertificate -or
            $signature.SignerCertificate.Thumbprint -ne $expectedFileSignerThumbprint) {
            throw "Signature verification failed for $($file.FullName) [$($signature.Status)]"
        }
        if ([regex]::Matches($verifyOutput, '(?m)^\s*Signature Index:').Count -ne 1 -or
            [regex]::Matches($verifyOutput, '(?m)^\s*Signature Index: 0 \(Primary Signature\)\s*$').Count -ne 1) {
            throw "Unexpected Authenticode signature count: $($file.FullName)"
        }
        if (-not $signature.TimeStamperCertificate -or
            [regex]::Matches($verifyOutput, '(?m)^\s*The signature is timestamped:').Count -ne 1 -or
            [regex]::Matches($verifyOutput, '(?m)^\s*Timestamp Verified by:\s*$').Count -ne 1) {
            throw "RFC3161 timestamp verification failed: $($file.FullName)"
        }
        $verifyLines = @(($verifyOutput -split '\r?\n') | Where-Object { $_ -notmatch '^\s*$' })
        $chainBuildErrorIndices = @(for ($i = 0; $i -lt $verifyLines.Count; $i++) { if ($verifyLines[$i] -match '^\s*SignTool Error: WinVerifyTrust returned error: 0x800B010A\s*$') { $i } })
        $chainBuildMessageIndices = @(for ($i = 0; $i -lt $verifyLines.Count; $i++) { if ($verifyLines[$i] -match '^\s*A certificate chain could not be built to a trusted root authority\.\s*$') { $i } })
        $signToolErrors = @($verifyLines | Where-Object { $_ -match '^\s*SignTool Error:' })
        $signToolWarnings = @($verifyLines | Where-Object { $_ -match '^\s*SignTool Warning:' })
        $verifiedSummaries = @($verifyLines | Where-Object { $_ -match '^\s*Number of signatures successfully Verified:' })
        $warningSummaries = @($verifyLines | Where-Object { $_ -match '^\s*Number of warnings:' })
        $errorSummaries = @($verifyLines | Where-Object { $_ -match '^\s*Number of errors:' })
        $validSignature = $verifyExitCode -eq 0 -and $signature.Status -eq "Valid" -and
            $signToolErrors.Count -eq 0 -and $signToolWarnings.Count -eq 0 -and
            $verifiedSummaries.Count -eq 1 -and $verifiedSummaries[0] -match '^\s*Number of signatures successfully Verified: 1\s*$' -and
            $warningSummaries.Count -eq 1 -and $warningSummaries[0] -match '^\s*Number of warnings: 0\s*$' -and
            $errorSummaries.Count -eq 1 -and $errorSummaries[0] -match '^\s*Number of errors: 0\s*$'
        $expectedChainBuildTrustFailure = $verifyExitCode -ne 0 -and
            $signature.Status -eq "UnknownError" -and $signToolWarnings.Count -eq 0 -and
            $signToolErrors.Count -eq 1 -and $chainBuildErrorIndices.Count -eq 1 -and
            $chainBuildMessageIndices.Count -eq 1 -and
            $verifiedSummaries.Count -eq 1 -and $verifiedSummaries[0] -match '^\s*Number of signatures successfully Verified: 0\s*$' -and
            $warningSummaries.Count -eq 1 -and $warningSummaries[0] -match '^\s*Number of warnings: 0\s*$' -and
            $errorSummaries.Count -eq 1 -and $errorSummaries[0] -match '^\s*Number of errors: 1\s*$'
        if (-not $validSignature -and -not $expectedChainBuildTrustFailure) {
            throw "Unexpected SignTool verification failure: $($file.FullName)"
        }
        if ($expectedChainBuildTrustFailure) { $global:LASTEXITCODE = 0 }
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
