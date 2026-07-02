$password = Read-Host "Enter new password" -AsSecureString

Write-Host ""
Write-Host "Creating DSAdmin01 user account ..."
Write-Host ""
New-LocalUser "DSAdmin01" -Password $password -FullName "DSAdmin01" -Description "DSAdmin01" -Verbose

Write-Host ""
Write-Host "Adding DSAdmin01 to Local Administrators group ..."
Write-Host ""
Add-LocalGroupMember -Group "Administrators" -Member "DSAdmin01" -Verbose

logoff.exe
