# Initialize-Autologon

<#
.SYNOPSIS
Configures a system for automatic logon and adjusts various system settings.

.DESCRIPTION
The `Initialize-Autologon` script automates the setup for system autologon, configures logging, and modifies specific registry entries. 
The script also ensures required modules are installed and trusted sources are set.

.PARAMETER autologonUsername
The username for the autologon process.

.PARAMETER autologonDomain
The domain name of the network.

.PARAMETER autologonPasswordSecure
The password for the autologon process saved as a secure string.

.PARAMETER autologonPassword
The password in a readable format for Autologon.

.PARAMETER autologonEULA
Automatically accepts the EULA for Autologon.

.NOTES
File Name      : Initialize-Autologon.ps1
Version        : 2.0.0
Prerequisites  : Requires administrative privileges, PoShLog module.
Author         : Fred Smith III
Copyright 2023 : Valhalla Tech

.EXAMPLE
.\Initialize-Autologon.ps1

This example prompts the user for a username and password and then initializes the autologon process and related configurations.
#>

# Install Nuget Provider, if not already installed
Install-PackageProvider -Name "NuGet" -Force

# Set PSGallery as a trusted repository
Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
...
# Remaining script content
...


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
$logFileName = "Initialize-AutoLogon.log"
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

# General variables
$systemDrive = $env:SystemDrive
$procExplorer = Get-Process "explorer"
$taniumSoftware = "$systemDrive\Tanium_Software"

# Registry path names
$macLockScreenPath = "HKLM:Software\Policies\Microsoft\Windows\Personalization"
$usrPowerCommandsPath = "HKCU:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$usrScreenSaverPath = "HKCU:Software\Policies\Microsoft\Windows\Control Panel\Desktop"
$macRegPoliciesPath = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$macRegWinlogonPath = "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$usrDesktopIcons = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

# Registry policy names
$screenSaveActive = "ScreenSaveActive"
$noClose = "NoClose"
$lockScreenImage = "LockScreenImage"
$lockScreenOverlaysdisabled = "LockscreenOverylaysDisabled"
$poldisablecad = "disablecad"
$poLLegalNoticeText = "LegalNoticeText"
$polLegalNoticeCaption = "LegalNoticeCaption"
$polHideIcons = "HideIcons"

# Autologon Variables
$autologonPath = "$taniumSoftware\CTS-ToolBox\Setup-GeneralAutoLogon\Autologon64.exe"
$autologonUsername = Read-Host -Prompt "Please enter the username"
$autologonDomain = "wssu.edu"
$autologonPasswordSecure = Read-Host -Prompt "Please enter the password for the user" -AsSecureString
$autologonPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($autologonPasswordSecure))
$autologonEULA = "/accepteula"

Write-InfoLog = "User credentials configured successfully"
Write-InfoLog "Updating registry to enable autologon ..."

# Testing registry paths. If they do not exist, then creating them
if (-Not (Test-Path $macLockScreenPath)) {New-Item -Path $macLockScreenPath -ItemType RegistryKey -Force
}
if (-Not (Test-Path $usrPowerCommandsPath)) {New-Item -Path $usrPowerCommandsPath -ItemType RegistryKey -Force
}
if (-Not (Test-Path $usrScreenSaverPath)) {New-Item -Path $usrScreenSaverPath -ItemType RegistryKey -Force
}
if (-Not (Test-Path $macRegPoliciesPath)) {New-Item -Path $macRegPoliciesPath -ItemType RegistryKey -Force
}
if (-Not (Test-Path $macRegWinlogonPath)) {New-Item -Path $macRegWinlogonPath -ItemType RegistryKey -Force
}
if (-Not (Test-Path $usrDesktopIcons)) {New-Item -Path $usrDesktopIcons -ItemType RegistryKey -Force
}

# Digital signage default settings
# Machine policies
Remove-ItemProperty -Path $maclockScreenPath -Name $lockScreenImage
Set-ItemProperty -Path $maclockScreenPath -Name $lockScreenOverlaysdisabled -Type DWord -Value "1"
Set-ItemProperty -Path $macRegPoliciesPath -Name $poldisablecad -Value "1"
Remove-ItemProperty -Path $macRegPoliciesPath -Name $polLegalNoticeText
Remove-ItemProperty -Path $macRegPoliciesPath -Name $polLegalNoticeCaption

# User policies
Set-ItemProperty -Path $usrPowerCommandsPath -Name $noClose -Type DWord -Value "1"
Set-ItemProperty -Path $usrScreenSaverPath -Name $screenSaveActive -Value "0"
Set-ItemProperty -Path $usrDesktopIcons -Name $polHideIcons -Value "1"

Write-InfoLog "Registry updated"

# Cycle explorer
Stop-Process $procExplorer

# Utilize Autologon app
try {
    Start-Process -FilePath $autologonPath -ArgumentList $autologonUsername, $autologonDomain, $autologonPassword, $autologonEULA -ErrorAction Stop
}
catch {
    Write-ErrorLog "Autologon was not able to run successfully"
    Close-Logger
}

Write-InfoLog "Autologon successfully configured"

# Close PoShLog instance
Close-Logger
