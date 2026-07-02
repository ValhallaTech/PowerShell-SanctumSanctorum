<#
.SYNOPSIS
    Fixes BitLocker and SecureBoot key protector issues by resetting the TPM protector.

.DESCRIPTION
    Deletes the existing BitLocker TPM key protector and adds a new one with SecureBoot PCRs.
    Logs all actions using PoShLog.

.NOTES
    File Name: Update-TPMKeys20.ps1
    Version: 2.0.1
    Prerequisite: Requires PowerShell 5.1 or later.
    Author: Fred Smith III
    Copyright 2023: Valhalla Tech

.EXAMPLE
    .\Update-TPMKeys2.ps1
#>

[CmdletBinding()]
param (
    [string]$driveLetter = $env:SystemDrive, # e.g., "C:"
    [string]$logDirectory = "$($env:SystemDrive)\Logs",
    [string]$logFileName = "Update-TPMKeys.log"
)

function Import-ReqModule {
    param (
        [string]$moduleName
    )
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Install-Module -Name $moduleName -Force -Scope CurrentUser
    }
    Import-Module -Name $moduleName -Force
}

function Install-NuGet {
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name "NuGet" -Force
    }
}

function Set-PSGallery {
    $psGallery = Get-PSRepository -Name PSGallery
    if ($psGallery.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }
}

function Get-TpmProtId {
    param (
        [string]$driveLetter
    )
    $volume = Get-CimInstance -Namespace "root/CIMV2/Security/MicrosoftVolumeEncryption" `
        -ClassName 'Win32_EncryptableVolume' -Filter "DriveLetter='$driveLetter'"
    $protectorIds = $volume | Invoke-CimMethod -MethodName GetKeyProtectors
    foreach ($id in $protectorIds.VolumeKeyProtectorID) {
        $typeResult = $volume | Invoke-CimMethod -MethodName GetKeyProtectorType -Arguments @{VolumeKeyProtectorID = $id}
        if ($typeResult.KeyProtectorType -eq 1) {
            return $id
        }
    }
    return $null
}

function Remove-TpmProt {
    param (
        [object]$volume,
        [string]$protectorId
    )
    $result = $volume | Invoke-CimMethod -MethodName DeleteKeyProtector -Arguments @{VolumeKeyProtectorID = $protectorId}
    return $result.ReturnValue -eq 0
}

function Add-TpmProtSB {
    param (
        [object]$volume
    )
    # PCRs 7 and 11 are standard for SecureBoot
    $result = $volume | Invoke-CimMethod -MethodName ProtectKeyWithTPM -Arguments @{FriendlyName="ProtectWithTPM1"; PCRs=(7,11)}
    return $result.ReturnValue -eq 0
}

# --- Main Script ---

# Checking to make sure script is being run in an elevated session
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-ErrorLog "Script must be run as an administrator."
    exit 1
}

Install-NuGet
Set-PSGallery
Import-ReqModule -moduleName "PoShLog"

# Prepare logging (PoShLog will create the directory if needed)
$logFilePath = Join-Path $logDirectory $logFileName
$logger = New-Logger
$logger | Set-MinimumLevel -Value Information | Add-SinkFile -Path $logFilePath | Add-SinkConsole | Start-Logger

Write-InfoLog "Logger initialized."

try {
    $drive = $driveLetter
    Write-InfoLog "Processing drive: $drive"

    $volume = Get-CimInstance -Namespace "root/CIMV2/Security/MicrosoftVolumeEncryption" `
        -ClassName 'Win32_EncryptableVolume' -Filter "DriveLetter='$drive'"
    if (-not $volume) {
        Write-ErrorLog "No BitLocker volume found for $drive."
        exit 1
    }

    $tpmProtectorId = Get-TpmProtId -driveLetter $drive
    if (-not $tpmProtectorId) {
        Write-ErrorLog "No TPM protector found on $drive."
        exit 1
    }

    if (Remove-TpmProt -volume $volume -protectorId $tpmProtectorId) {
        Write-InfoLog "TPM protector $tpmProtectorId removed from $drive."
    } else {
        Write-ErrorLog "Failed to remove TPM protector $tpmProtectorId from $drive."
        exit 1
    }

    if (Add-TpmProtSB -volume $volume) {
        Write-InfoLog "TPM protector with SecureBoot PCRs added to $drive."
    } else {
        Write-ErrorLog "Failed to add TPM protector with SecureBoot PCRs to $drive."
        exit 1
    }

    # Show current protectors for verification
    $protectors = & manage-bde.exe -protectors -get $drive
    Write-InfoLog "Current BitLocker protectors:`n$protectors"
    Write-InfoLog "BitLocker TPM key protector was successfully updated."
}
catch {
    Write-ErrorLog "Error updating BitLocker TPM key protector: $($_.Exception.Message)"
    exit 1
}
finally {
    Close-Logger -Logger $logger
}
