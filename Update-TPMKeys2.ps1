#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Repairs BitLocker TPM key protectors to work correctly with Secure Boot.

.DESCRIPTION
    This script resolves conflicts between BitLocker and Secure Boot that occur when BitLocker
    is activated while Secure Boot is disabled. It will:
      1. Remove the existing TPM key protector from the system drive.
      2. Add a new TPM key protector using PCR values 7 and 11, which are required for
         correct BitLocker operation with Secure Boot enabled.
      3. Log all actions to a structured log file using PoShLog.

    IMPORTANT: Secure Boot must be enabled before running this script. If Secure Boot is
    disabled, the key protectors will revert to incorrect values. Use Edit-BIOSConfig.ps1
    (included in this repository) to enable Secure Boot without booting into UEFI settings.

.NOTES
    File Name      : Update-TPMKeys2.ps1
    Author         : Fred Smith III
    Prerequisite   : PowerShell 5.1
    Copyright 2026 : Valhalla Tech

.EXAMPLE
    .\Update-TPMKeys2.ps1
    Removes the existing TPM key protector and re-adds it with PCR values 7 and 11.
#>

[CmdletBinding(SupportsShouldProcess)]
param ()

Set-StrictMode -Version Latest

#region Helper Functions

function Install-NugetProvider {
    <#
    .SYNOPSIS
        Ensures the NuGet package provider is installed.
    #>
    [CmdletBinding()]
    param ()

    if (-not (Get-PackageProvider -Name 'NuGet' -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name 'NuGet' -Force -Confirm:$false
    }
}

function Set-PsGalleryTrusted {
    <#
    .SYNOPSIS
        Ensures the PSGallery repository is set as trusted.
    #>
    [CmdletBinding()]
    param ()

    $psGallery = Get-PSRepository -Name 'PSGallery'
    if ($psGallery.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted'
    }
}

function Import-RequiredModule {
    <#
    .SYNOPSIS
        Installs and imports a module if it is not already available.
    .PARAMETER ModuleName
        The name of the module to install and import.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ModuleName
    )

    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Install-Module -Name $ModuleName -Force -Scope CurrentUser
    }
    Import-Module -Name $ModuleName -Force
}

function Start-PoShLogger {
    <#
    .SYNOPSIS
        Initializes a PoShLog logger with a file sink and a console sink.
    .DESCRIPTION
        Creates and starts a PoShLog logger configured to write structured log
        messages to both a log file and the console at Information level or above.
        Call Close-Logger in a finally block when the script completes.
    .PARAMETER LogFilePath
        Full path to the log file. The parent directory must already exist.
    .EXAMPLE
        Start-PoShLogger -LogFilePath (Join-Path $env:TEMP 'myScript.log')
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$LogFilePath
    )

    New-Logger |
        Set-MinimumLevel -Value Information |
        Add-SinkFile -Path $LogFilePath |
        Add-SinkConsole |
        Start-Logger
}

#endregion

#region Module Bootstrapping

Install-NugetProvider
Set-PsGalleryTrusted
Import-RequiredModule -ModuleName 'PoShLog'

#endregion

#region Logger Initialization

$logDir = Join-Path -Path $env:SystemDrive -ChildPath 'Logs'
if (-not (Test-Path -Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

$scriptBaseName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$logFileName    = if ($scriptBaseName) { "$scriptBaseName.log" } else { 'Update-TPMKeys2.log' }
$logFilePath    = Join-Path -Path $env:SystemDrive -ChildPath "Logs\$logFileName"

Start-PoShLogger -LogFilePath $logFilePath
Write-InfoLog 'Logger initialized successfully'

#endregion

try {
    # Retrieve the BitLocker volume for the system drive via CIM
    $volume = Get-CimInstance -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption' `
                              -ClassName 'Win32_EncryptableVolume' `
                              -Filter "DriveLetter='C:'" `
                              -ErrorAction Stop

    # Retrieve all key protector IDs
    $keyProtectorResult = Invoke-CimMethod -InputObject $volume `
                                           -MethodName 'GetKeyProtectors' `
                                           -Arguments @{ KeyProtectorType = 0 } `
                                           -ErrorAction Stop

    # Identify the TPM key protector (type 1)
    $tpmProtectorId = $keyProtectorResult.VolumeKeyProtectorID | Where-Object {
        $typeResult = Invoke-CimMethod -InputObject $volume `
                                       -MethodName 'GetKeyProtectorType' `
                                       -Arguments @{ VolumeKeyProtectorID = $_ } `
                                       -ErrorAction Stop
        $typeResult.KeyProtectorType -eq 1
    }

    if (-not $tpmProtectorId) {
        Write-WarningLog 'No TPM key protector found on the system drive. Nothing to replace.'
    }
    else {
        Write-InfoLog 'Found TPM key protector {ProtectorId}. Removing it.' -PropertyValues $tpmProtectorId

        if ($PSCmdlet.ShouldProcess('C:', 'Delete existing TPM key protector')) {
            Invoke-CimMethod -InputObject $volume `
                             -MethodName 'DeleteKeyProtector' `
                             -Arguments @{ VolumeKeyProtectorID = $tpmProtectorId } `
                             -ErrorAction Stop | Out-Null
            Write-InfoLog 'Existing TPM key protector removed successfully.'
        }

        if ($PSCmdlet.ShouldProcess('C:', 'Add TPM key protector with PCR values 7 and 11')) {
            Invoke-CimMethod -InputObject $volume `
                             -MethodName 'ProtectKeyWithTPM' `
                             -Arguments @{
                                 FriendlyName              = 'ProtectWithTPM1'
                                 PlatformValidationProfile = [uint8[]](7, 11)
                             } `
                             -ErrorAction Stop | Out-Null
            Write-InfoLog 'TPM key protector added with PCR values 7 and 11.'
        }

        # Verify active protectors via manage-bde.exe and log the output
        $bdeOutput = manage-bde.exe -protectors -get $env:SystemDrive
        if ($LASTEXITCODE -ne 0) {
            Write-ErrorLog 'manage-bde.exe exited with code {ExitCode}.' -PropertyValues $LASTEXITCODE
        }
        else {
            Write-InfoLog 'manage-bde.exe output:{Output}' -PropertyValues ($bdeOutput -join "`n")
        }

        Write-InfoLog 'BitLocker TPM key protector update completed successfully.'
    }
}
catch {
    Write-ErrorLog 'Error updating BitLocker TPM key protector: {ErrorMessage}' -PropertyValues $_.Exception.Message
    exit 1
}
finally {
    Close-Logger
}

exit 0
