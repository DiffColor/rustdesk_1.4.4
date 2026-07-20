[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Install", "Uninstall")]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [string]$RequestId,

    [string]$PackageName = "RustDesk.WebIdentity",
    [string]$PackagePath,
    [string]$CertificatePath,
    [string]$ExternalLocation,
    [Parameter(Mandatory = $true)]
    [string]$StateDirectory
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$OwnershipPath = Join-Path $StateDirectory "owned-certificates"
$DesiredStatePath = Join-Path $StateDirectory "desired-state"

function Get-PackageCertificate {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Sparse MSIX certificate was not found: $Path"
    }

    return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Path)
}

function Add-TrustedPeopleCertificate {
    param([Parameter(Mandatory = $true)]$Certificate)

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $existing = $store.Certificates.Find(
            [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
            $Certificate.Thumbprint,
            $false
        )
        if ($existing.Count -eq 0) {
            $store.Add($Certificate)
            return $true
        }
        return $false
    } finally {
        $store.Close()
    }
}

function Test-TrustedPeopleCertificate {
    param([Parameter(Mandatory = $true)][string]$Thumbprint)

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        return $store.Certificates.Find(
            [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
            $Thumbprint,
            $false
        ).Count -gt 0
    } finally {
        $store.Close()
    }
}

function Remove-TrustedPeopleCertificate {
    param([Parameter(Mandatory = $true)][string]$Thumbprint)

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $matches = $store.Certificates.Find(
            [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
            $Thumbprint,
            $false
        )
        foreach ($match in $matches) {
            $store.Remove($match)
        }
    } finally {
        $store.Close()
    }
}

function Add-OwnedCertificate {
    param([Parameter(Mandatory = $true)][string]$Thumbprint)

    $owned = if (Test-Path -LiteralPath $OwnershipPath -PathType Leaf) {
        @(Get-Content -LiteralPath $OwnershipPath)
    } else {
        @()
    }
    if ($Thumbprint -notin $owned) {
        Add-Content -LiteralPath $OwnershipPath -Value $Thumbprint
    }
}

function Remove-OwnedCertificate {
    param([Parameter(Mandatory = $true)][string]$Thumbprint)

    if (-not (Test-Path -LiteralPath $OwnershipPath -PathType Leaf)) {
        return
    }
    $remaining = @(Get-Content -LiteralPath $OwnershipPath | Where-Object { $_ -ne $Thumbprint })
    if ($remaining.Count -eq 0) {
        Remove-Item -LiteralPath $OwnershipPath -Force -ErrorAction SilentlyContinue
    } else {
        Set-Content -LiteralPath $OwnershipPath -Value $remaining
    }
}

function Remove-OwnedCertificates {
    if (-not (Test-Path -LiteralPath $OwnershipPath -PathType Leaf)) {
        return
    }
    foreach ($thumbprint in Get-Content -LiteralPath $OwnershipPath) {
        if ($thumbprint -match '^[0-9A-Fa-f]{40,128}$') {
            Remove-TrustedPeopleCertificate -Thumbprint $thumbprint
        }
    }
    Remove-Item -LiteralPath $OwnershipPath -Force -ErrorAction SilentlyContinue
}

function Remove-ObsoleteOwnedCertificates {
    param([Parameter(Mandatory = $true)][string]$KeepThumbprint)

    if (-not (Test-Path -LiteralPath $OwnershipPath -PathType Leaf)) {
        return
    }
    $remaining = @()
    foreach ($thumbprint in Get-Content -LiteralPath $OwnershipPath) {
        if ($thumbprint -eq $KeepThumbprint) {
            $remaining += $thumbprint
            continue
        }
        try {
            Remove-TrustedPeopleCertificate -Thumbprint $thumbprint
        } catch {
            Write-Warning "Could not remove obsolete sparse identity certificate $thumbprint"
            $remaining += $thumbprint
        }
    }
    if ($remaining.Count -eq 0) {
        Remove-Item -LiteralPath $OwnershipPath -Force -ErrorAction SilentlyContinue
    } else {
        Set-Content -LiteralPath $OwnershipPath -Value $remaining
    }
}

function Remove-IdentityPackage {
    Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue |
        Remove-AppxPackage -ErrorAction Stop
}

function Test-CurrentRequest {
    return (Test-Path -LiteralPath $DesiredStatePath -PathType Leaf) -and
        ((Get-Content -LiteralPath $DesiredStatePath -Raw).Trim() -eq "$Action|$RequestId")
}

function Invoke-IdentityAction {
    if ($Action -eq "Install") {
        if ([Environment]::OSVersion.Version.Build -lt 19041) {
            Write-Host "Sparse MSIX identity requires Windows build 19041 or newer; skipping registration."
            return
        }
        if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
            throw "Sparse MSIX package was not found: $PackagePath"
        }
        if (-not (Test-Path -LiteralPath $ExternalLocation -PathType Container)) {
            throw "RustDesk installation directory was not found: $ExternalLocation"
        }

        $certificate = Get-PackageCertificate -Path $CertificatePath
        $certificateAdded = $false
        if (-not (Test-TrustedPeopleCertificate -Thumbprint $certificate.Thumbprint)) {
            Add-OwnedCertificate -Thumbprint $certificate.Thumbprint
            try {
                $certificateAdded = Add-TrustedPeopleCertificate -Certificate $certificate
                if (-not $certificateAdded) {
                    Remove-OwnedCertificate -Thumbprint $certificate.Thumbprint
                }
            } catch {
                Remove-OwnedCertificate -Thumbprint $certificate.Thumbprint
                throw
            }
        }
        try {
            Add-AppxPackage `
                -Path $PackagePath `
                -ExternalLocation $ExternalLocation `
                -ForceUpdateFromAnyVersion `
                -ErrorAction Stop

            $registered = Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue
            if ($null -eq $registered) {
                throw "Sparse MSIX identity registration did not produce package $PackageName"
            }
            if (-not (Test-CurrentRequest)) {
                Remove-IdentityPackage
                Remove-OwnedCertificates
                return
            }
            try {
                Remove-ObsoleteOwnedCertificates -KeepThumbprint $certificate.Thumbprint
            } catch {
                Write-Warning "Could not finish obsolete sparse identity certificate cleanup"
            }
            Write-Host "Registered sparse MSIX identity: $($registered.PackageFamilyName)"
        } catch {
            if ($certificateAdded) {
                Remove-TrustedPeopleCertificate -Thumbprint $certificate.Thumbprint
                Remove-OwnedCertificate -Thumbprint $certificate.Thumbprint
            }
            $registered = Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue
            if ($null -ne $registered) {
                if (-not (Test-CurrentRequest)) {
                    Remove-IdentityPackage
                    Remove-OwnedCertificates
                    return
                }
                Write-Warning "Sparse MSIX update was skipped; existing identity remains registered: $($_.Exception.Message)"
                return
            }
            throw
        }
    } else {
        Remove-IdentityPackage
        Remove-OwnedCertificates
        Write-Host "Removed sparse MSIX identity: $PackageName"
    }
}

$mutex = [System.Threading.Mutex]::new($false, "RustDesk.WebIdentity.Operation")
$hasLock = $false
try {
    try {
        $hasLock = $mutex.WaitOne()
    } catch [System.Threading.AbandonedMutexException] {
        $hasLock = $true
    }
    if (-not (Test-CurrentRequest)) {
        Write-Host "A newer sparse MSIX identity request superseded this operation."
        return
    }
    Invoke-IdentityAction
} finally {
    if ($hasLock) {
        $mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}
