# General variables
$systemDrive = $env:SystemDrive
$invokeDefProf = ".\Invoke-DefProf.ps1"

# Install Nuget Provider, if not already installed
Install-PackageProvider -Name "NuGet" -Force

# Set PSGallery as a trusted repository
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

# Check if PoShLog module is installed and if not install the current version
$modPoShLog = "PoShLog"
$chkPoShLog = Get-InstalledModule -Name $modPoShLog -ErrorAction SilentlyContinue

if (-not $chkPoShLog) {
    Install-Module -Name $modPoShLog
}

# Import PoShLog module
Import-Module -Name $modPoShLog

# Configure variables for logging

$logFileName = "Invoke-PostImageTasks.log"
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


try {
    Invoke-Command -ScriptBlock { & $invokeDefProf } -ArgumentList $invokeDefProf
    Write-InfoLog "Successfully ran $invokeDefProf"
}
catch {
    $errorMessage = "Could not run $invokeDefProf"
    Write-ErrorLog $errorMessage
}

Close-Logger
