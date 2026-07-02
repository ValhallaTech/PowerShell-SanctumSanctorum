# Default Profile and Default App Association Script
# by Fred Smith III
# Version 1.0.0

Set-Variable $systemDrive = $env:SystemDrive
Set-Variable $userProfile = $env:USERPROFILE

Write-Host "Creating temporary working directory and copying necessary files ..."
New-item -Path '$userProfile' -Name "Data" -ItemType "directory"
Copy-Item -Path xxx -Destination '$userProfile\data'
Write-Host "Copying complete"

Write-host "Importing appropriate XML files ..."
Import-StartLayout -LayoutPath '$userProfile\data\DefaultLayout.xml' -MountPath '$systemDrive'
dism /online /Import-DefaultAppAssociations: '$userProfile\data\DefaultAppAssociations'
Write-Host "Importing complete"

Write-Host "Initiating clean-up ..."
Remove-Item -LiteralPath '$userProfile\data' -Force -Recurse
Write-Host "Process Complete"
Write-Host "Exiting process"
Exit-PSHostProcess
