<#
.SYNOPSIS
    Exports the Windows AutoPilot hardware hash for Windows 10 devices.
.DESCRIPTION
    Installs the required script and dependencies, then exports the hardware hash to a specified file.
.PARAMETER outputFile
    The path to the output CSV file for the hardware hash.
.EXAMPLE
    .\Export-AutoPilotHash.ps1 -outputFile 'C:\HWHash.csv'
.NOTES
    Requires local administrator privileges.
#>

[CmdletBinding()]
param (
    [string]$outputFile = 'C:\HWHash.csv'
)

function Install-NugetProvider {
    if (-not (Get-PackageProvider -Name 'NuGet' -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name 'NuGet' -Force -Confirm:$false
    }
}

function Set-PsGalleryTrusted {
    $psGallery = Get-PSRepository -Name 'PSGallery'
    if ($psGallery.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted'
    }
}

function Install-WindowsAutoPilotScript {
    if (-not (Get-Command 'Get-WindowsAutoPilotInfo' -ErrorAction SilentlyContinue)) {
        Install-Script -Name 'Get-WindowsAutoPilotInfo' -Force -Scope CurrentUser -AllowClobber
    }
}

function Export-AutoPilotHash {
    param (
        [string]$outputFile
    )
    try {
        Get-WindowsAutoPilotInfo -OutputFile $outputFile
        Write-Output "Hardware hash exported to $outputFile"
    } catch {
        Write-Error "Failed to export hardware hash: $($_.Exception.Message)"
    }
}

# --- Script Start ---
# Ensure running as administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Script must be run as an administrator.'
    exit 1
}

Install-NugetProvider
Set-PsGalleryTrusted
Install-WindowsAutoPilotScript

# Use process-level execution policy for this session only
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force

Export-AutoPilotHash -outputFile $outputFile
