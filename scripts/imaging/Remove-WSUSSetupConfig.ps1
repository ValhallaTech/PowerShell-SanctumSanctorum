<#
.SYNOPSIS
    Removes the Setupconfig.ini file in the WSUS folder, if it exists.

.DESCRIPTION
    The Remove-WSUSSetupConfig script checks for the existence of the Setupconfig.ini file in the WSUS folder and deletes it if found.
    This may fix error 0xc190010a when trying to install Windows updates.
    Any actions and potential errors are logged using PoShLog.

.NOTES
    Author: Fred Smith III
    Version: 1.0.0

.EXAMPLE
    .\Remove-WSUSSetupConfig.ps1
    This will run the script and remove the Setupconfig.ini file if it exists in the WSUS folder.
#>

# Remove-WSUSSetupConfig.ps1

# General Variables
$systemDrive = $env:SystemDrive

# Variables for PoShLog checking
$modPoShLog = "PoShLog"
$chkPoShLog = Get-Module -Name $modPoShLog

# Check if PoShLog module is installed and if not install the current version
if (-not $chkPoShLog) {
    Install-Module -Name $modPoShLog
}

# Import PoShLog module
Import-Module -Name $modPoShLog

# Configure variables for logging
$logFileName = "Remove-WSUSSetupConfig.log"
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

# Define the file path
$filePath = "$systemDrive\Users\Default\AppData\Local\Microsoft\Windows\WSUS\Setupconfig.ini"

# Check if the Setupconfig.ini file exists and delete it if it does
try {
    if (Test-Path -Path $filePath) {
        Remove-Item -Path $filePath -Force -ErrorAction Stop
        Write-InfoLog "Setupconfig.ini file deleted successfully."
    } else {
        Write-WarningLog "Setupconfig.ini file not found."
    }
} catch {
    # Log any errors that occur
    Write-ErrorLog "An error occurred while attempting to delete the Setupconfig.ini file: $($_.Exception.Message)"
}

# Stop the logger
Stop-Logger
