# General variables
$systemDrive = $env:SystemDrive
$pathLaptopBIOSExe = "$systemDrive\Tanium_Software\BIOSConf-Laptop_x64"
$pathDesktopBIOSExe = "$systemDrive\Tanium_Software\BIOSConf-Desktop_x64"
$rkSecureBoot = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
$valSecureBoot = Get-ItemPropertyValue -Path $rkSecureBoot -Name UEFISecureBootEnabled

# Conditional variables that will set the parameters that will be checked later
$isLaptop = [bool](Get-WmiObject -Class Win32_SystemEnclosure |
    Where-Object ChassisTypes -in '{9}', '{10}', '{14}')
$chassisType = if ($isLaptop -eq $true){
    "Laptop"}
else {"Desktop"
}
$statusSecureBoot = if ( $valSecureBoot -eq 1) {
    $true
}
else {
    $false
}

# Output parameters
Write-Host "***" "" "This machine is a $chassisType" "" "***"
if ($statusSecureBoot -eq $true) {
    Write-Host "***" "" "BIOS Configuration: Secure boot is on" "" "***"
}
else {
    Write-Host "***" "" "BIOS Configuration: Secure boot is off" "" "***"
}

# Check parameters to determine if the .exe needs to run to re-configure the BIOS and which configuration needs to run based on chassis type
if ($chassisType -eq "Laptop" -AND $statusSecureBoot -eq $false ) {
    $pathLaptopBIOSExe
}
elseif ($chassisType -eq "Desktop" -AND $statusSecureBoot -eq $false) {
    $pathDesktopBIOSExe
}
