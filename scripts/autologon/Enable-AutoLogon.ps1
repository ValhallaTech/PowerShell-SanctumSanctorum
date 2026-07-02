$computerName = HOSTNAME.EXE
$regPolicies = "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$regWinlogon = "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$poldisablecad = "disablecad"
$poLLegalNoticeText = "LegalNoticeText"
$polLegalNoticeCaption = "LegalNoticeCaption"
$polAutoAdminLogon = "AutoAdminLogon"
$polDefaultUserName = "DefaultUserName"
$polDefaultPassword = "DefaultPassword"
$polDefaultDomainName = "DefaultDomainName"
$polForceAutoLogon = "ForceAutoLogon"

Write-Host ""
Write-Host "Updating registry to enable autologon ..."
Write-Host ""

Set-ItemProperty -Path $regPolicies -Name $poldisablecad -Value "1"
Remove-ItemProperty -Path $regPolicies -Name $polLegalNoticeText
Remove-ItemProperty -Path $regPolicies -Name $polLegalNoticeCaption
Set-ItemProperty -Path $regWinlogon -Name $polAutoAdminLogon -Value "1"
Set-ItemProperty -Path $regWinlogon -Name $polDefaultUserName -Value "DSAdmin01"
Set-ItemProperty -Path $regWinlogon -Name $polDefaultPassword -Value "Initpass1"
Remove-ItemProperty -Path $regWinlogon -Name $polDefaultDomainName -Value "$computerName"
New-ItemProperty -Path $regWinlogon -Name $polForceAutoLogon -PropertyType DWord -Value "1"
