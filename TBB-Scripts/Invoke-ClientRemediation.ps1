<#
.SYNOPSIS
    Controller script for troubleshooting and migrating Windows 10 clients post-SCCM tenant change.
.DESCRIPTION
    Automates SCCM onboarding and connectivity remediation steps for Windows 10 clients.
    Uses PoShLog for logging and follows PowerShell best practices.
.PARAMETER hostname
    The hostname or serial number of the affected device (for logging/reference).
.EXAMPLE
    .\Invoke-ClientRemediation.ps1 -hostname 'PC12345'
.NOTES
    Author: Fred Smith III
    Version: 1.0.0
    Requires: PoShLog module
#>

[CmdletBinding()]
param (
    [string]$hostname = $env:COMPUTERNAME
)

# --- Elevation Check ---
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Output 'Script is not running as administrator. Relaunching with elevated privileges...'
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -hostname `"$hostname`""
    $psi.Verb = 'runas'
    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
    }
    catch {
        Write-Error 'Failed to relaunch script as administrator.'
    }
    exit
}

# --- Helper Functions for Module Management ---

function Install-NugetProvider {
    if (-not (Get-PackageProvider -Name 'NuGet' -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name 'NuGet' -Force
    }
}

function Set-PsGalleryTrusted {
    $psGallery = Get-PSRepository -Name 'PSGallery'
    if ($psGallery.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted'
    }
}

function Import-RequiredModule {
    param (
        [string]$moduleName
    )
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Install-Module -Name $moduleName -Force -Scope CurrentUser
    }
    Import-Module -Name $moduleName -Force
}

# --- Module Preparation ---
Install-NugetProvider
Set-PsGalleryTrusted
Import-RequiredModule -moduleName 'PoShLog'

# --- Logging Setup ---
$logFilePath = "$env:SystemDrive\Logs\ClientRemediation.log"
$logger = New-Logger
$logger |
Set-MinimumLevel -Value Information |
Add-SinkFile -Path $logFilePath |
Add-SinkConsole |
Start-Logger

Write-InfoLog "Starting remediation for device: $hostname"

function Start-SCCMOnboarding {
    <#
    .SYNOPSIS
        Runs the DT SCCM onboarding scripts in sequence.
    #>
    try {
        Write-InfoLog 'Starting SCCM client uninstall...'
        & "$PSScriptRoot\Uninstall SCCM Client.ps1"
        Write-InfoLog 'Stopping services...'
        & "$PSScriptRoot\Stop Services.ps1"
        Write-InfoLog 'Running InstallV2...'
        & "$PSScriptRoot\InstallV2.ps1"
        Write-InfoLog 'Running LookupMP...'
        & "$PSScriptRoot\LookupMP.ps1"
        Write-InfoLog 'SCCM onboarding scripts completed.'
    }
    catch {
        Write-ErrorLog "SCCM onboarding failed: $($_.Exception.Message)"
        throw
    }
}

function Start-WiFiRemediation {
    <#
    .SYNOPSIS
        Runs the AppViewX EST installer for Wi-Fi remediation.
    #>
    try {
        Write-InfoLog 'Running AppViewX EST installer for Wi-Fi remediation...'
        & "$PSScriptRoot\installer.bat"
        Write-InfoLog 'AppViewX EST installer executed.'
    }
    catch {
        Write-ErrorLog "Wi-Fi remediation failed: $($_.Exception.Message)"
        throw
    }
}

function Start-VPNRemediation {
    <#
    .SYNOPSIS
        Runs the DTCorpVPN installer script for VPN remediation.
    #>
    try {
        Write-InfoLog 'Running DTCorpVPN installer for VPN remediation...'
        & "$PSScriptRoot\DTCorpVPN.ps1"
        Write-InfoLog 'DTCorpVPN installer executed.'
    }
    catch {
        Write-ErrorLog "VPN remediation failed: $($_.Exception.Message)"
        throw
    }
}

# --- Main Controller Logic ---

try {
    # Step 1: DT SCCM Onboarding
    Start-SCCMOnboarding

    # Step 2: Connectivity Remediation
    Start-WiFiRemediation
    Start-VPNRemediation

    Write-InfoLog 'Remediation process completed.'
}
catch {
    Write-ErrorLog "Remediation process failed: $($_.Exception.Message)"
    throw
}
finally {
    Close-Logger
    if ($Host.Name -eq 'ConsoleHost' -and $MyInvocation.InvocationName -eq '.') {
        Read-Host 'Press Enter to exit'
    }
}
