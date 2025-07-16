<#
.SYNOPSIS
    Installs Ricoh and Zebra printer drivers from external media and connects multiple printers by IP address.
.DESCRIPTION
    Detects the drive letter for the Ricoh and Zebra driver folders, stages and installs the drivers, and adds printers by IP using the installed drivers. Printers are named in uppercase according to their official names. All actions are logged.
.NOTES
    Compatible with PowerShell 5.1
    Author: Fred Smith III
#>

function Get-ExternalDriveLetter {
    <#
    .SYNOPSIS
        Finds the drive letter containing the specified driver folder.
    .PARAMETER driverFolder
        The relative path to the driver folder.
    .OUTPUTS
        [string] The drive letter if found, otherwise $null.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$driverFolder
    )
    foreach ($drive in Get-PSDrive -PSProvider 'FileSystem') {
        $fullPath = Join-Path $drive.Root $driverFolder
        if (Test-Path $fullPath) {
            return $drive.Name
        }
    }
    return $null
}

function Install-PrinterDriver {
    <#
    .SYNOPSIS
        Installs a printer driver using pnputil.exe and Add-PrinterDriver, if not already installed.
    .PARAMETER infPath
        The full path to the printer driver INF file.
    .PARAMETER driverName
        The name of the printer driver as it should appear in Windows.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$infPath,
        [Parameter(Mandatory)]
        [string]$driverName
    )
    # Check if the driver is already installed
    if (Get-PrinterDriver -Name $driverName -ErrorAction SilentlyContinue) {
        Write-Output "Printer driver '$driverName' is already installed. Skipping installation."
        return
    }
    try {
        Write-Output "Staging driver from $infPath..."
        pnputil.exe /add-driver "$infPath" /install | Write-Output
        Write-Output "Installing printer driver '$driverName'..."
        Add-PrinterDriver -Name $driverName
        Write-Output "Printer driver '$driverName' installed and available."
    } catch {
        Write-Error "Failed to install printer driver '$driverName'. $_"
        exit 1
    }
}

function Add-PrinterByIP {
    <#
    .SYNOPSIS
        Adds a printer by IP address using the specified driver.
    .PARAMETER printerName
        The name to assign to the printer (will be uppercased).
    .PARAMETER ipAddress
        The IP address of the printer.
    .PARAMETER driverName
        The name of the printer driver.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$printerName,
        [Parameter(Mandatory)]
        [string]$ipAddress,
        [Parameter(Mandatory)]
        [string]$driverName
    )
    $printerName = $printerName.ToUpper()
    $portName = "IP_$ipAddress"
    # Create TCP/IP port if it doesn't exist
    if (-not (Get-PrinterPort -Name $portName -ErrorAction SilentlyContinue)) {
        Add-PrinterPort -Name $portName -PrinterHostAddress $ipAddress
    }
    # Add printer using the specified driver
    if (-not (Get-Printer -Name $printerName -ErrorAction SilentlyContinue)) {
        try {
            Add-Printer -Name $printerName -PortName $portName -DriverName $driverName
            Write-Output "Added printer '$printerName' at $ipAddress."
        } catch {
            Write-Error "Failed to add printer '$printerName' at $ipAddress. $_"
        }
    } else {
        Write-Output "Printer '$printerName' already exists."
    }
}

# --- Script Start ---

# Ricoh printers: IP => Name
$ricohPrinters = @{
    '53.243.83.32'  = 'PTBBC031'
    '53.243.83.31'  = 'PTBBC032'
    '53.243.83.30'  = 'PTBBM033'
    '53.243.83.28'  = 'PTBBB086'
    '53.243.85.220' = 'PTBBC042'
    '53.243.85.221' = 'PTBBC048'
    '53.243.85.49'  = 'PTBBMC26'
    '53.243.85.39'  = 'PTBBM045'
    '53.243.85.44'  = 'PTBBC030'
    '53.243.85.50'  = 'PTBBBM032'
    '53.243.85.41'  = 'PTBBM024'
    '53.243.85.54'  = 'PTBBB032'
}

# Zebra printers: IP => @{ Name = ..., Driver = ... }
$zebraPrinters = @{
    '53.243.85.209' = @{ Name = 'PTBBL006'; Driver = 'ZDesigner ZT411-203dpi ZPL' }
    '53.243.85.210' = @{ Name = 'PTBBL012'; Driver = 'ZDesigner ZT411-203dpi ZPL' }
    '53.243.85.207' = @{ Name = 'PTBBL068'; Driver = 'ZDesigner ZT410-300dpi ZPL' }
    '53.243.85.206' = @{ Name = 'PTBBBL019'; Driver = 'ZDesigner ZT411-203dpi ZPL' }
}

# Driver info
$ricohDriverFolder = 'TBB-Tools\Daimler\Tools\Ricoh drivers - z03919L1b\disk1'
$ricohInfFileName = 'oemsetup.inf'
$ricohDriverName = 'RICOH PCL6 UniversalDriver V4.41'

$zebraDriverFolder = 'TBB-Tools\Daimler\Tools\Zebra Drivers'
$zebraInfFileName = 'ZDesigner.inf'
# Zebra driver names are specified per printer above

# Find external drive letters
$ricohDriveLetter = Get-ExternalDriveLetter -driverFolder $ricohDriverFolder
if (-not $ricohDriveLetter) {
    Write-Error "Ricoh driver folder not found on any attached drive."
    exit 1
}
$zebraDriveLetter = Get-ExternalDriveLetter -driverFolder $zebraDriverFolder
if (-not $zebraDriveLetter) {
    Write-Error "Zebra driver folder not found on any attached drive."
    exit 1
}

$ricohInfPath = Join-Path "$ricohDriveLetter`:" (Join-Path $ricohDriverFolder $ricohInfFileName)
$zebraInfPath = Join-Path "$zebraDriveLetter`:" (Join-Path $zebraDriverFolder $zebraInfFileName)

# Install Ricoh driver
Install-PrinterDriver -infPath $ricohInfPath -driverName $ricohDriverName

# Install all unique Zebra drivers needed
$uniqueZebraDrivers = $zebraPrinters.Values | ForEach-Object { $_.Driver } | Select-Object -Unique
foreach ($driver in $uniqueZebraDrivers) {
    Install-PrinterDriver -infPath $zebraInfPath -driverName $driver
}

# Add Ricoh printers
foreach ($ip in $ricohPrinters.Keys) {
    $printerName = $ricohPrinters[$ip]
    Add-PrinterByIP -printerName $printerName -ipAddress $ip -driverName $ricohDriverName
}

# Add Zebra printers
foreach ($ip in $zebraPrinters.Keys) {
    $printerInfo = $zebraPrinters[$ip]
    Add-PrinterByIP -printerName $printerInfo.Name -ipAddress $ip -driverName $printerInfo.Driver
}
