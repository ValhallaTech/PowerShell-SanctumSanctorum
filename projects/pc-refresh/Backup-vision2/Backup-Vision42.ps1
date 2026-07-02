<#
.SYNOPSIS
    This script uses the RobocopyPS module to wrap Robocopy in a PowerShell cmdlet. It quickly backs up the user folders of the logged on user to the vision file server.

.DESCRIPTION
    This script will:
        1. Pull the name of the logged on user (even if running elevated)
        2. Backup the user folders to the file server
        3. Log everything to a log file

.NOTES
    File Name: Backup-Vision2.ps1
    Version: 4.2.0
    Author: Fred Smith III
    Prerequisite: PowerShell v5
    Copyright 2023: Valhalla Tech

.EXAMPLE
    .\Backup-Vision2.ps1
#>

[CmdletBinding()]
param (
    [int]$threads = 16,
    [string]$logDirectory = "$env:SystemDrive\Logs"
)

# Get the username of the active console session (even if running as another user)
$activeSession = (Get-CimInstance -ClassName Win32_ComputerSystem).UserName
if (-not $activeSession) {
    Write-Error "Could not determine the active logged-in user."
    exit 1
}
$userName = $activeSession.Split('\')[-1]

# Set source and destination paths based on the actual logged-in user
$sourcePath = "$env:SystemDrive\Users\$userName"
$destinationPath = "\\vision2\backups\$userName"

# Ensure NuGet provider is installed for unattended usage
if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name "NuGet" -Force
}
# Ensure PSGallery is trusted for unattended usage
$psGallery = Get-PSRepository -Name PSGallery
if ($psGallery.InstallationPolicy -ne 'Trusted') {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
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

# Ensure required modules
Import-RequiredModule -moduleName "PoShLog"
Import-RequiredModule -moduleName "RobocopyPS"

# Configure logger
$logFilePath = Join-Path $logDirectory "Backup-Vision41.log"
$logger = New-Logger
$logger | Set-MinimumLevel -Value Information | Add-SinkFile -Path $logFilePath | Add-SinkConsole | Start-Logger

Write-InfoLog -Logger $logger -Message "Modules imported and logger configured"
Write-InfoLog -Logger $logger -Message "Backing up profile for user: $userName"

# Robocopy parameters
$roboParams = @{
    Source      = $sourcePath
    Destination = $destinationPath
    Force       = $true
    Threads     = $threads
    Retry       = 0
    Recurse     = $true
    Verbose     = $true
}

try {
    Write-InfoLog -Logger $logger -Message "Executing Robocopy command"
    Invoke-RoboCopy @roboParams -DirectoryCopyFlags D, A, T -ExcludeFileName *.DAT*, *.dll* -ExcludeDirectory *OneDrive*, *AppData*, *Application*
    Write-InfoLog -Logger $logger -Message "Robocopy command completed successfully"
}
catch {
    Write-ErrorLog -Logger $logger -Level Error -Message $_.Exception.Message
}
finally {
    Close-Logger
}
