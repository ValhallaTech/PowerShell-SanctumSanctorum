<#
.SYNOPSIS
    Installs Ricoh and Zebra printer drivers and adds network printers by IP address.
.DESCRIPTION
    This script automatically detects external drive containing printer drivers,
    installs the required drivers, and configures network printers with proper naming.
    Supports both Ricoh PCL6 and Zebra ZDesigner drivers.
.NOTES
    Compatible with PowerShell 5.1+
    Requires Administrator privileges for driver installation and printer management.
    Author: Fred Smith III
    Version: 1.0
#>

[CmdletBinding()]
param()

function Test-IPAddress {
    <#
    .SYNOPSIS
        Validates if a string is a valid IP address.
    #>
    param([string]$ipAddress)
    return $ipAddress -match '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
}

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
        [ValidateNotNullOrEmpty()]
        [string]$driverFolder
    )
    
    foreach ($drive in Get-PSDrive -PSProvider FileSystem) {
        $fullPath = Join-Path $drive.Root $driverFolder
        if (Test-Path $fullPath) {
            Write-Verbose "Found driver folder at: $fullPath"
            return $drive.Name
        }
    }
    Write-Warning "Driver folder '$driverFolder' not found on any attached drive."
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
        [ValidateScript({ Test-Path $_ })]
        [string]$infPath,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$driverName
    )
    
    # Check if the driver is already installed
    if (Get-PrinterDriver -Name $driverName -ErrorAction SilentlyContinue) {
        Write-Output "Printer driver '$driverName' is already installed. Skipping installation."
        return
    }
    
    try {
        Write-Output "Staging driver from $infPath..."
        $pnpResult = pnputil.exe /add-driver "`"$infPath`"" /install
        Write-Verbose ($pnpResult | Out-String)
        
        Write-Output "Installing printer driver '$driverName'..."
        Add-PrinterDriver -Name $driverName
        Write-Output "Printer driver '$driverName' installed and available."
    }
    catch {
        Write-Error "Failed to install printer driver '$driverName'. $($_.Exception.Message)"
        throw
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
        [ValidateNotNullOrEmpty()]
        [string]$printerName,
        
        [Parameter(Mandatory)]
        [ValidateScript({ Test-IPAddress $_ })]
        [string]$ipAddress,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$driverName
    )
    
    $printerName = $printerName.ToUpper()
    $portName = "IP_$ipAddress"
    
    # Create TCP/IP port if it doesn't exist
    if (-not (Get-PrinterPort -Name $portName -ErrorAction SilentlyContinue)) {
        $portParams = @{
            Name = $portName
            PrinterHostAddress = $ipAddress
        }
        Add-PrinterPort @portParams
    }
    
    # Add printer using the specified driver
    if (-not (Get-Printer -Name $printerName -ErrorAction SilentlyContinue)) {
        try {
            $printerParams = @{
                Name = $printerName
                PortName = $portName
                DriverName = $driverName
            }
            Add-Printer @printerParams
            Write-Output "Added printer '$printerName' at $ipAddress."
        }
        catch {
            Write-Error "Failed to add printer '$printerName' at $ipAddress. $($_.Exception.Message)"
        }
    }
    else {
        Write-Output "Printer '$printerName' already exists."
    }
}

# --- Script Start ---

try {
    # Ricoh printers: IP => Name
    $ricohPrinters = @{
        '53.243.85.220' = 'PTBBC042'
        '53.243.85.221' = 'PTBBC048'
        '53.243.85.49'  = 'PTBBMC26'
        '53.243.85.39'  = 'PTBBM045'
        '53.243.85.44'  = 'PTBBC030'
        '53.243.85.50'  = 'PTBBBM032'
        '53.243.85.41'  = 'PTBBM024'
        '53.243.85.54'  = 'PTBBB032'
        '53.243.83.28'  = 'PTBBB086'
        '53.243.83.32'  = 'PTBBC031'
        '53.243.83.31'  = 'PTBBC032'
        '53.243.83.30'  = 'PTBBM033'
        '53.243.80.23'  = 'PTBBC028'
        '53.243.80.29'  = 'PTBBM027'
        '53.243.80.24'  = 'PTBBM042'
    }

    # Zebra printers: IP => @{ Name = ..., Driver = ... }
    $zebraPrinters = @{
        '53.243.85.209' = @{ Name = 'PTBBL006'; Driver = 'ZDesigner ZT411-203dpi ZPL' }
        '53.243.85.210' = @{ Name = 'PTBBL012'; Driver = 'ZDesigner ZT411-203dpi ZPL' }
        '53.243.85.207' = @{ Name = 'PTBBL068'; Driver = 'ZDesigner ZT410-300dpi ZPL' }
        '53.243.85.206' = @{ Name = 'PTBBBL019'; Driver = 'ZDesigner ZT411-203dpi ZPL' }
    }

    # Driver configuration
    $ricohDriverFolder = 'TBB-Tools\Daimler\Tools\Ricoh drivers - z03919L1b\disk1'
    $ricohInfFileName = 'oemsetup.inf'
    $ricohDriverName = 'RICOH PCL6 UniversalDriver V4.41'

    $zebraDriverFolder = 'TBB-Tools\Daimler\Tools\Zebra Drivers'
    $zebraInfFileName = 'ZDesigner.inf'

    # Find external drive letters
    $ricohDriveLetter = Get-ExternalDriveLetter -driverFolder $ricohDriverFolder
    if (-not $ricohDriveLetter) {
        throw 'Ricoh driver folder not found on any attached drive.'
    }

    $zebraDriveLetter = Get-ExternalDriveLetter -driverFolder $zebraDriverFolder
    if (-not $zebraDriveLetter) {
        throw 'Zebra driver folder not found on any attached drive.'
    }

    $ricohInfPath = Join-Path "$ricohDriveLetter`:" (Join-Path $ricohDriverFolder $ricohInfFileName)
    $zebraInfPath = Join-Path "$zebraDriveLetter`:" (Join-Path $zebraDriverFolder $zebraInfFileName)

    # Install drivers
    Write-Output 'Installing printer drivers...'
    Install-PrinterDriver -infPath $ricohInfPath -driverName $ricohDriverName

    $uniqueZebraDrivers = $zebraPrinters.Values | ForEach-Object { $_.Driver } | Select-Object -Unique
    foreach ($driver in $uniqueZebraDrivers) {
        Install-PrinterDriver -infPath $zebraInfPath -driverName $driver
    }

    # Add printers
    Write-Output 'Adding Ricoh printers...'
    $ricohCount = 0
    foreach ($ip in $ricohPrinters.Keys) {
        $ricohCount++
        Write-Progress -Activity 'Adding Ricoh Printers' -Status "Processing $ip" -PercentComplete (($ricohCount / $ricohPrinters.Count) * 100)
        Add-PrinterByIP -printerName $ricohPrinters[$ip] -ipAddress $ip -driverName $ricohDriverName
    }

    Write-Output 'Adding Zebra printers...'
    $zebraCount = 0
    foreach ($ip in $zebraPrinters.Keys) {
        $zebraCount++
        Write-Progress -Activity 'Adding Zebra Printers' -Status "Processing $ip" -PercentComplete (($zebraCount / $zebraPrinters.Count) * 100)
        $printerInfo = $zebraPrinters[$ip]
        Add-PrinterByIP -printerName $printerInfo.Name -ipAddress $ip -driverName $printerInfo.Driver
    }

    Write-Output 'Printer installation completed successfully.'
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    exit 1
}
finally {
    Write-Progress -Activity 'Adding Printers' -Completed
}
