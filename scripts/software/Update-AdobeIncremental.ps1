#Update-AdobeIncremental 1.0.0

# General Variables
$systemDrive = $env:SystemDrive
$workingDir = "$systemDrive\AdobeUpdate-Tools\AUSST"

# Install Nuget Provider, if not already installed
Install-PackageProvider -Name "NuGet" -Force

# Set PSGallery as a trusted repository
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted

$modPoShLog = "PoShLog"
$chkPoShLog = Get-Module -Name $modPoShLog

# Check if PoShLog module is installed and if not install the current version
if (-not $chkPoShLog) {
    Install-Module -Name $modPoShLog -Repository "PSGallery" -Confirm:$false -Force
}

# Import PoShLog module
Import-Module -Name $modPoShLog

# Configure variables for logging
$logFileName = ""
$logFilePath = "$systemDrive\Logs\$logFileName"
$updateDir = "$systemDrive\inetpub\wwwroot\updates"

# Create logger instance
$logger = New-Logger

# Configure logger instance
$logger |
    Set-MinimumLevel -Value Information |
    Add-SinkFile -Path $logFilePath |
    Add-SinkConsole |
    Start-Logger

Write-InfoLog "PoShLog module imported and logger configured"


# Set the location to the directory that the AdobeUpdateServerSetupTool.exe is in
Push-Location -Path $workingDir

try {
    # Run the Adobe update command
    & .\AdobeUpdateServerSetupTool.exe --root=$updateDir --incremental
    Write-InfoLog "Adobe update command executed successfully."
}
catch {
    # Handle and log the error
    Write-ErrorLog "Failed to run the Adobe update command. Error: $_" -ErrorAction Stop
    Close-Logger
}

# Go back to the directory before the Push-Location
Pop-Location

# Close the logger
Close-Logger
