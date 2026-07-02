$password = Read-Host "Enter new password" -AsSecureString

Write-Host ""
Write-Host "Creating mmts user account ..."
Write-Host ""
New-LocalUser "mmts" -Password $password -FullName "Mutimedia Account" -Description "Mutimedia Account" -Verbose
