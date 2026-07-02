# General variables
$user = Read-Host "Enter username"
$password = Read-Host "Enter new password" -AsSecureString

# Creates a local user account
Write-Host "Creating $user account ..."
New-LocalUser "$user" -Password $password -FullName "$user" -Description "$user" -Verbose

# Adds the created user to the local admin group
Write-Host "Adding $user to Local Administrators group ..."
Add-LocalGroupMember -Group "Administrators" -Member "$user" -Verbose
