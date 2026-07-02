$user = "RAMSPRINTKIOSK"
$password = Read-Host "Enter new password" -AsSecureString

Write-Host ""
Write-Host "Creating RAMSPRINTKIOSK user account ..."
Write-Host ""
New-LocalUser $user -Password $password -FullName $user -Description "Locked down account for the use of PaperCut" -Verbose
