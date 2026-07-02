# App variables
$appDuoAuth = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "Duo Authentication for Windows Logon x64"}
$appMSUpdateHealthTools = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "Microsoft Update Health Tools"}
$appZoom = Get-Package -Provider Programs | Where-Object{$_.Name -eq "Zoom"}
$appFirefox = Get-Package -Provider Programs | Where-Object{$_.name -eq "Mozilla Firefox (x64 en-US)"}
$appOneDrive = Get-Package -Provider Programs | Where-Object{$_.Name -eq "Microsoft OneDrive"}
$appNotepadplusplus = Get-Package -Provider Programs | Where-Object{$_.Name -eq "Notepad++ (64-bit x64)"}

# App arrays
$arrWmiApps = @($appDuoAuth,$appMSUpdateHealthTools)
$arrPackageApps = @($appZoom,$appFirefox,$appOneDrive,$appNotepadplusplus)

Write-Host ""
Write-Host "Uninstalling unnecessary apps ..."
Write-Host ""

#
# ForEach loop method 1: This will go through the apps array and Get-WmiObject uninstall method
#
$arrWmiApps | ForEach-Object {$_.uninstall()}

#
# Uninstall method 2: This will go through the apps array and run the Get-Package uninstall method
#
$arrPackageApps | ForEach-Object {Uninstall-Package}
