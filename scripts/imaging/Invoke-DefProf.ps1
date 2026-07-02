$systemDrive = $env:SystemDrive
$scriptPath = [System.IO.Path]::Combine("$systemDrive\", "Tanium_Software")
$defProf = ".\DefProf.exe"
$user = "Ramadmin"

Write-Host ""
Write-Host "Running DefProf for specified user ..."
& $defProf $user
