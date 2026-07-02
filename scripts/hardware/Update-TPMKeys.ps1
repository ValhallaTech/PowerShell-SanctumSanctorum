# General Variables
$systemDrive = $env:SystemDrive

# Get the BitLocker volume for the operating system partition and find the ID of the TPM key protector
$volume = Get-WMIObject -Namespace "root/CIMV2/Security/MicrosoftVolumeEncryption" -Class 'Win32_EncryptableVolume' -Filter "DriveLetter='C:'"
$tpmProtectorID = $volume.getkeyprotectors().VolumeKeyProtectorID | Where-Object {$volume.getkeyprotectortype($_).keyprotectortype -eq 1}

# Delete the TPM key protector
$volume.DeleteKeyProtector($TPMprotectorID) | out-null
$volume.getkeyprotectors().VolumeKeyProtectorID | Where-Object {$volume.getkeyprotectortype($_).keyprotectortype -eq 1}

# Add the TPM key protector with settings specified, as a parameter, for Secure Boot
$volume.ProtectKeyWithTPM("ProtectWithTPM1", (7,11))

#Displays avtive PCR values and verfies that the script was successful
manage-bde.exe -protectors -get $systemDrive
