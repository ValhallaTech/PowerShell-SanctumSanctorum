# General variables
$computerName = HOSTNAME.EXE
$adminUSR = "DSAdmin01"
$adminPWD = "InitPass1"
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
$polAutoAdminLogon = "AutoAdminLogon"
$polDefaultUserName = "DefaultUserName"
$polDefaultPassword = "DefaultPassword"
$polDefaultDomainName = "DefaultDomainName"
$polForceAutoLogon = "ForceAutoLogon"
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

# Autologon initialization
Set-ItemProperty -Path $macRegPoliciesPath -Name $poldisablecad -Value "1"
Remove-ItemProperty -Path $macRegPoliciesPath -Name $polLegalNoticeText
Remove-ItemProperty -Path $macRegPoliciesPath -Name $polLegalNoticeCaption
Set-ItemProperty -Path $macRegWinlogonPath -Name $polAutoAdminLogon -Value "1"
Set-ItemProperty -Path $macRegWinlogonPath -Name $polDefaultUserName -Value "$adminUSR"
Set-ItemProperty -Path $macRegWinlogonPath -Name $polDefaultPassword -Value "$adminPWD"
Set-ItemProperty -Path $macRegWinlogonPath -Name $polDefaultDomainName -Value "$computerName"
New-ItemProperty -Path $macRegWinlogonPath -Name $polForceAutoLogon -PropertyType DWord -Value "1"
