$usrLoggedon = Get-Process -IncludeUserName | Select-Object -Property username -Unique | Where-Object { $_ -match "WSSUMITS" }
$usrString = $usrLoggedon.UserName.Replace("WSSUMITS\","")
$modRobocopy = "RobocopyPS"
$checkRobocopy = Get-Module -Name $modRobocopy

# Installing and importing RobocopyPS module
if (-Not $checkRobocopy) {
    Install-Module -Name $modRobocopy
}
Write-Host ""
Write-Host "RobocopyPS is installed"
Write-Host ""
Import-Module -Name $modRobocopy
Write-Host ""
Write-Host "RobocopyPS is imported to this session"
Write-Host ""

#Invoke-RoboCopy will wrap the RoboCopy command in PowerShell syntax
Write-Host ""
Write-Host "Executing Robocopy command"
Write-Host ""
Invoke-RoboCopy -Source "C:\Users\$usrString" -Destination "\\vision2\backups\$usrString" -Force -ExcludeFileName *.DAT*,*.dll* -ExcludeDirectory *OneDrive*,*AppData*,*Application* -DirectoryCopyFlags D,A,T -Threads 16 -Retry 0 -Verbose
