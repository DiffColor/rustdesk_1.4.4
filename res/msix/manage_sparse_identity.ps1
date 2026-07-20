[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Install", "Uninstall")]
    [string]$Action,

    [string]$PackageName = "MendHands.RustDesk",
    [string]$PackagePath,
    [string]$CertificatePath,
    [string]$ExternalLocation
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

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

function Remove-TrustedPeopleCertificate {
    param([Parameter(Mandatory = $true)]$Certificate)

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $matches = $store.Certificates.Find(
            [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
            $Certificate.Thumbprint,
            $false
        )
        foreach ($match in $matches) {
            $store.Remove($match)
        }
    } finally {
        $store.Close()
    }
}

function Remove-IdentityPackage {
    Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue |
        Remove-AppxPackage -ErrorAction Stop
}

if ($Action -eq "Install") {
    if ([Environment]::OSVersion.Version.Build -lt 19041) {
        Write-Host "Sparse MSIX identity requires Windows build 19041 or newer; skipping registration."
        exit 0
    }
    if (-not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) {
        throw "Sparse MSIX package was not found: $PackagePath"
    }
    if (-not (Test-Path -LiteralPath $ExternalLocation -PathType Container)) {
        throw "RustDesk installation directory was not found: $ExternalLocation"
    }

    $certificate = Get-PackageCertificate -Path $CertificatePath
    $certificateAdded = Add-TrustedPeopleCertificate -Certificate $certificate
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
        Write-Host "Registered sparse MSIX identity: $($registered.PackageFamilyName)"
    } catch {
        $registered = Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue
        if ($null -ne $registered) {
            Write-Warning "Sparse MSIX update was skipped; existing identity remains registered: $($_.Exception.Message)"
            exit 0
        }
        if ($certificateAdded) {
            Remove-TrustedPeopleCertificate -Certificate $certificate
        }
        throw
    }
} else {
    Remove-IdentityPackage
    if ($CertificatePath -and (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
        $certificate = Get-PackageCertificate -Path $CertificatePath
        Remove-TrustedPeopleCertificate -Certificate $certificate
    }
    Write-Host "Removed sparse MSIX identity: $PackageName"
}
