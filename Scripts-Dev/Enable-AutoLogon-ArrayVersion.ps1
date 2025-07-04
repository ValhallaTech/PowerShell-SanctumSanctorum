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
$testdisablecad = Test-Path "$regPolicies\$poldisablecad"
$testLegalNoticeText = Test-Path "$regPolicies\$polLegalNoticeText"
$testLegalNoticeCaption = Test-Path "$regPolicies\$polLegalNoticeCaption"
$testAutoAdminLogon = Test-Path "$regWinlogon\$polAutoAdminLogon"
$testDefaultUserName = Test-Path "$regWinlogon\$polDefaultUserName"
$testDefaultPassword = Test-Path "$regWinlogon\$polDefaultPassword"
$testDefaultDomainName = Test-Path "$regWinlogon\$polDefaultDomainName"
$testForceAutoLogon = Test-Path "$regWinlogon\$polForceAutoLogon"
$testPoliciesArray = New-Object 

Write-Host "Updating registry to enable autologon ..."

Set-ItemProperty -Path $regPolicies -Name "disablecad" -Value "1"
Remove-ItemProperty -Path $regPolicies -Name "LegalNoticeText"
Remove-ItemProperty -Path $regPolicies -Name "LegalNoticeCaption"
Set-ItemProperty -Path $regWinlogon -Name "AutoAdminLogon" -Value "1"
Set-ItemProperty -Path $regWinlogon -Name "DefaultUserName" -Value "DSAdmin01"
Set-ItemProperty -Path $regWinlogon -Name "DefaultPassword" -Value "Initpass1"
Remove-ItemProperty -Path $regWinlogon -Name "DefaultDomainName" -Value "$computerName"
New-ItemProperty -Path $regWinlogon -Name "ForceAutoLogon" -PropertyType DWord -Value "1"
