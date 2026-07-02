# Rename-Machine 1.0.0

<#
.SYNOPSIS
Renames the computer based on department/building abbreviation and the system's service tag.

.DESCRIPTION
This script will prompt the user for a department or building abbreviation. If provided, the new name of the computer will be the abbreviation followed by a hyphen and the system's service tag (or serial number). If no abbreviation is provided, the name will be just the service tag. The script will log its activities using the PoShLog module.

.NOTES
File Name      : Rename-Machine.ps1
Version        : 1.0.0
Prerequisite   : PowerShell V3, Administrative Rights, PoShLog Module
Author         : Fred Smith III
Copyright 2023 : Valhalla Tech

.EXAMPLE
.\Rename-Machine.ps1
This will execute the script, prompting the user for the department or building abbreviation, then rename the computer and log the actions.
#>

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
$logFileName = "Rename-Machine.log"
$logFilePath = "C:\Logs\$logFileName"

# Create logger instance
$logger = New-Logger

# Configure logger instance
$logger |
    Set-MinimumLevel -Value Information |
    Add-SinkFile -Path $logFilePath |
    Add-SinkConsole |
    Start-Logger

Write-InfoLog "PoShLog module imported and logger configured"

# Save the old computer name to the log file
$oldName = $env:COMPUTERNAME
Write-InfoLog "Old computer name: $oldName"

# Prompt the user for the department or building abbreviation
$namePrefix = Read-Host "Please enter the department or building abbreviation (leave blank if not applicable)"

# Fetch the Dell Service Tag (or the system's serial number if not a Dell)
$serviceTag = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber

# Construct the new computer name based on the naming convention
$newName = if (-not [string]::IsNullOrWhiteSpace($namePrefix)) {
    "$namePrefix-$serviceTag"
} else {
    $serviceTag
}

# Try to rename the computer
Write-InfoLog "Attempt to rename the computer to $newName"
try {
    # Rename the computer
    Rename-Computer -NewName $newName -Force

    # Inform the user of the change
    Write-InfoLog "The computer name has been changed to $newName. Please restart the computer for the changes to take effect."
} catch {
    Write-Error "Failed to rename the computer. Error: $_"
}

Close-Logger
