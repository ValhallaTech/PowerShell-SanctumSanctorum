# Variables for PoShLog
modPoShLog = PoShLog
chkPoShLog = Get-Module -Name modRobocopy
# Check if PoShLog module is installed and if not install the current version
if (-not $chkPoShLog) {
    Install-Module -Name $modPoShLog
}
    Write-Log -Logger $logger -Message "PoShLog module installed"
else {
    Write-Log -Logger $logger -Message "PoShLog module already installed"
}
    # Import PoShLog module
Import-Module -Name $modPoShLog
    Write-Log -Logger $logger -Message "PoShLog module imported"

# Set the logging configuration
Set-LoggerConfiguration -MinimumLevel Warning -LogPath "C:\Logs\Remove-UserProfiles.log"

# General variables
$acctsExcluded = "ramadmin"
$localHost = $env:COMPUTERNAME

try {
    Get-CimInstance -ComputerName $localHost -Class Win32_UserProfile | Where-Object { $_.LocalPath.split('\')[-1] -notin $acctsExcluded } | Remove-CimInstance -ErrorAction Stop
    Write-Log -Message "User profiles removed successfully."
}
catch {
    Write-Log -Message "Failed to remove user profiles. Error: $_" -Level Error
}
