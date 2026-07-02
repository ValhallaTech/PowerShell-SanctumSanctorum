# General variables
$systemDrive = $env:SystemDrive
$procExplorer = Get-Process "explorer"

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

Write-Host ""
Write-Host "Updating registry to enable autologon ..."
Write-Host ""

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
# User policies
Set-ItemProperty -Path $usrPowerCommandsPath -Name $noClose -Type DWord -Value "1"
Set-ItemProperty -Path $usrScreenSaverPath -Name $screenSaveActive -Value "0"
Set-ItemProperty -Path $usrDesktopIcons -Name $polHideIcons -Value "1"

# Cycle explorer
Stop-Process $procExplorer

# Utilize Autologon app
Set-ItemProperty -Path $macRegPoliciesPath -Name $poldisablecad -Value "1"
Remove-ItemProperty -Path $macRegPoliciesPath -Name $polLegalNoticeText
Remove-ItemProperty -Path $macRegPoliciesPath -Name $polLegalNoticeCaption
.\Autologon64.exe
