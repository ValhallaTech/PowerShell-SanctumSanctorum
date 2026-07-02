# PoShLog Module API 1.0.0
# General Vaiables
$modPoShLog = "PoShLog"
$chkPoShLog = Get-Module -Name $modRobocopy

# Check to see if PoShLog is installed. If not, the most current version will be installed
if (-Not $chkPoShLog) {
    Install-Module -Name $modPoShLog
}

# Import PoShLog into current PowerShell session
Import-Module PoShLog

# Configure variables for logging
$logFileName = "xxx.log"
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
