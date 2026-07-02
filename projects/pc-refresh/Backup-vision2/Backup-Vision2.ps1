# User BackerUpper 4.0.0
# Backup-Vision2.ps1

<#
.SYNOPSIS
    This script uses the RobocopyPS module to wrap Robocopy in a PowerShell cmdlet. It quickly backs up the user folders of the logged on user to the vision file server.

.DESCRIPTION
    This script will:
        1. Pull the name of the logged on user
        2. Backup the user folders to the file server
        3. Log everything to a log file

.NOTES
    File Name: Backup-Vision2.ps1
    Version: 4.0.0
    Author: Fred Smith III
    Prerequisite: PowerShell v5
    Copyright 2023: Valhalla Tech

.EXAMPLE
    This example shows how to run the script:
    .\Backup-Vision2.ps1
#>

# Get the username of the logged-on user
$usrLoggedon = Get-Process -IncludeUserName | Select-Object -Property username -Unique | Where-Object { $_ -match "WSSUMITS" }
$usrString = $usrLoggedon.UserName.Replace("WSSUMITS\","")

# Install Nuget Provider, if not already installed
Install-PackageProvider -Name "NuGet" -Force
# Set PSGallery as a trusted repository
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

# Variables for RobocopyPS and PoShLog
$modRobocopy = "RobocopyPS"
$chkRobocopy = Get-Module -Name $modRobocopy
$modPoShLog = "PoShLog"
$chkPoShLog = Get-Module -Name $modPoShLog

# Check if PoShLog module is installed and if not install the current version
if (-not $chkPoShLog) {
    Install-Module -Name $modPoShLog
}

# Import PoShLog module
Import-Module -Name $modPoShLog

# Configure variables for logging
$logFileName = "Backup-Vision2.log"
$logFilePath = "$systemDrive\Logs\$logFileName"

# Create logger instance
$logger = New-Logger

# Configure logger instance
$logger |
    Set-MinimumLevel -Value Information |
    Add-SinkFile -Path $logFilePath |
    Add-SinkConsole |
    Start-Logger

Write-InfoLog "PoShLog module imported and logger configured"

    # Check if RobocopyPS module is installed and if not install the current version
    if (-not $chkRobocopy) {
        Install-Module -Name $modRobocopy
    }
        Write-InfoLog -Logger $logger -Message "RobocopyPS module installed"
    else {
        Write-InfoLog -Logger $logger -Message "RobocopyPS module already installed"
    }
        # Import RobocopyPS module
    Import-Module -Name $modRobocopy
        Write-InfoLog -Logger $logger -Message "RobocopyPS module imported"

    # Create parameters for Robocopy
    $paramRobo = @{
        Source = "C:\Users\$usrString"
        Destination = "\\vision2\backups\$usrString"
        Force = $true
        Threads = 16
        Retry = 0
        Recurse = $true
        Verbose = $true
    }

try {
    # Execute Robocopy command
    Write-InfoLog -Logger $Log -Message "Executing Robocopy command"
    Invoke-RoboCopy @paramRobo -DirectoryCopyFlags D,A,T -ExcludeFileName *.DAT*,*.dll* -ExcludeDirectory *OneDrive*,*AppData*,*Application*
    Write-InfoLog -Logger $Log -Message "Robocopy command completed successfully"

} catch {
    # Log any errors that occur
    Write-ErrorLog -Logger $Log -Level Error -Message $_.Exception.Message
    Close-Logger
}

Close-Logger
