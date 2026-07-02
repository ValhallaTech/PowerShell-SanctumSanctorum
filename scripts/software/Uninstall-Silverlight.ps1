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
$logFileName = "Uninstall-Silverlight.log"
$logFilePath = "C:\Logs\$logFileName"

# Create logger instance
$logger = New-Logger

# Configure logger instance
$logger |
    Set-MinimumLevel -Value Information |
    Add-SinkFile -Path $logFilePath |
    Add-SinkConsole |
    Start-Logger

Write-InfoLog "PoShLog module imported"

# Uninstalls Microsoft Silverlight

# Ensure the script runs with Administrator privileges
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-WarningLog "This script requires Administrator privileges. Please, run as Administrator."
    Exit
}

# Find Microsoft Silverlight
try {
    $Silverlight = Get-WmiObject -Class Win32_Product -Filter "Name = 'Microsoft Silverlight'"
} catch {
    Write-ErrorLog "Failed to query Microsoft Silverlight. Exception: $($_.Exception.Message)"
    Exit
}

if ($Silverlight) {
    # Uninstall Silverlight
    Write-InfoLog "Uninstalling Microsoft Silverlight..."

    try {
        $UninstallResult = $Silverlight.Uninstall()
    } catch {
        Write-ErrorLog "Failed to uninstall Microsoft Silverlight. Exception: $($_.Exception.Message)"
        Exit
    }

    # Check for successful uninstallation
    if ($UninstallResult.ReturnValue -eq 0) {
        Write-InfoLog "Microsoft Silverlight has been successfully uninstalled."
    } else {
        Write-ErrorLog "An error occurred during the uninstallation. Error code: $($UninstallResult.ReturnValue)"
    }
} else {
    Write-WarningLog "Microsoft Silverlight not found on this system."
}
