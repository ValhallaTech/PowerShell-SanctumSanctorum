$password = Read-Host "Enter new password" -AsSecureString

Write-Host ""
Write-Host "Creating RAMSPRINT user account ..."
Write-Host ""
New-LocalUser "RAMSPRINT" -Password $password -FullName "RAMSPRINT" -Description "RAMSPRINT" -Verbose

Write-Host ""
Write-Host "Adding RAMSPRINT to Local Administrators group ..."
Write-Host ""
Add-LocalGroupMember -Group "Administrators" -Member "RAMSPRINT" -Verbose

logoff.exe
