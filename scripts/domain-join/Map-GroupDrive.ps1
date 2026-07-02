$systemDrive = $env:SystemDrive

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
$logFileName = "Remove-UserProfiles.log"
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

# Splatting Variables
$driveParams = @{
    Name = "G"
    PSProvider = "FileSystem"
    Root = "\\wssu.edu\ramfile\groups"
    Persist = $true
}

try {
    # Map group drive
    New-PSDrive @driveParams -ErrorAction Stop
    Write-InfoLog "Mapped group drive successfully."
}
catch {
    Write-ErrorLog "Failed to map group drive: $_"
}

Close-Logger
