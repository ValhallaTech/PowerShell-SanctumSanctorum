<#
.SYNOPSIS
    Installs and configures logging and parallel processing modules, then retrieves a list of all installed software on the system.

.DESCRIPTION
    This script ensures the NuGet provider and PSGallery repository are available and trusted, installs and imports the PoShLog and PSParallel modules,
    configures logging to both file and console, and defines a function to scan the registry for installed software (optionally filtered by name).
    Results are logged and displayed. The script uses best practices for PowerShell scripting, including modularization, error handling, and clear logging.

.PARAMETER Name
    Optional filter to limit results to software names containing this string. Supports wildcard matching.

.NOTES
    Author: Fred Smith III
    Version: 1.2.0
    Requires: PowerShell 5.1+, PoShLog, PSParallel

.EXAMPLE
    .\Get-InstalledSoftware120.ps1
    Retrieves and logs all installed software on the system.

.EXAMPLE
    .\Get-InstalledSoftware120.ps1 -Name 'Microsoft'
    Retrieves and logs all installed software with names containing 'Microsoft'.
#>

[CmdletBinding()]
param(
    [string]$Name
)

# Ensure NuGet provider is installed
function Install-NugetProvider {
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name 'NuGet' -Force -Confirm:$false
    }
}

# Ensure PSGallery is trusted
function Set-PsGalleryTrusted {
    $psGallery = Get-PSRepository -Name 'PSGallery'
    if ($psGallery.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted'
    }
}

# Helper to install and import modules if not already available
function Import-RequiredModule {
    param (
        [string]$moduleName
    )
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Install-Module -Name $moduleName -Force -Scope CurrentUser
    }
    Import-Module -Name $moduleName -Force
}

# --- Script Start ---
# Install NuGet provider and trust PSGallery for unattended module installation
Write-Output "Setting up NuGet provider and PSGallery repository..."
Install-NugetProvider
Set-PsGalleryTrusted

# Import PoShLog and PSParallel modules
Write-Output "Importing required modules..."
Import-RequiredModule -moduleName 'PoShLog'
Import-RequiredModule -moduleName 'PSParallel'

# Configure logging
$logFileName = 'Get-InstalledSoftware.log'
$logFilePath = "$env:SystemDrive\Logs\$logFileName"

# Start logger
$logger = New-Logger
$logger |
Set-MinimumLevel -Value Information |
Add-SinkFile -Path $logFilePath |
Add-SinkConsole |
Start-Logger

Write-InfoLog 'PoShLog module imported and logger configured'
Write-InfoLog 'PSParallel module imported'

function Get-InstalledSoftware {
    <#
    .SYNOPSIS
        Retrieves a list of all software installed on the system.
    .DESCRIPTION
        Scans the Windows registry to find installed software GUIDs and display names.
        Searches both machine-level and user-level installation locations.
    .PARAMETER Name
        Optional filter to limit results to software names containing this string.
        Supports partial matches (e.g., 'Microsoft' will match 'Microsoft Office').
    .EXAMPLE
        Get-InstalledSoftware
        Returns all installed software on the system.
    .EXAMPLE
        Get-InstalledSoftware -Name 'Microsoft'
        Returns only software with names containing 'Microsoft'.
    .OUTPUTS
        [PSCustomObject[]] Array of objects containing GUID and Name properties.
    #>
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    param (
        [string]$Name
    )
    # Registry paths to search for installed software
    $uninstallKeys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    
    # Add user-specific uninstall keys
    $hkuDrive = $null
    try {
        $hkuDrive = New-PSDrive -Name HKU -PSProvider Registry -Root 'Registry::HKEY_USERS' -ErrorAction Stop
        $userKeys = Get-ChildItem HKU: -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } |
            ForEach-Object { "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
        $uninstallKeys += $userKeys
    }
    catch {
        Write-WarningLog "Failed to access user registry hives: $($_.Exception.Message)"
    }

    if (-not $uninstallKeys) {
        Write-InfoLog 'No software registry keys found'
        return @()
    }

    # Query each uninstall key in parallel
    if ($PSBoundParameters.ContainsKey('Name') -and $Name) {
        # Filter by name
        $results = $uninstallKeys | Invoke-Parallel -ThrottleLimit 16 -ScriptBlock {
            $uninstallKey = $_
            $nameFilter = $args[0]
            
            $gciParams = @{
                Path        = $uninstallKey
                ErrorAction = 'SilentlyContinue'
            }
            $selectProperties = @(
                @{n = 'GUID'; e = { $_.PSChildName } },
                @{n = 'Name'; e = { $_.GetValue('DisplayName') } }
            )
            
            Get-ChildItem @gciParams | 
                Where-Object { ($_.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$') -and ($_.GetValue('DisplayName') -like "*$nameFilter*") } | 
                Select-Object -Property $selectProperties
        } $Name
    } else {
        # No filter - get all software
        $results = $uninstallKeys | Invoke-Parallel -ThrottleLimit 16 -ScriptBlock {
            $uninstallKey = $_
            
            $gciParams = @{
                Path        = $uninstallKey
                ErrorAction = 'SilentlyContinue'
            }
            $selectProperties = @(
                @{n = 'GUID'; e = { $_.PSChildName } },
                @{n = 'Name'; e = { $_.GetValue('DisplayName') } }
            )
            
            Get-ChildItem @gciParams | 
                Where-Object { ($_.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$') -and ($_.GetValue('DisplayName')) } | 
                Select-Object -Property $selectProperties
        }
    }

    # Clean up HKU drive if created
    if ($hkuDrive) {
        try {
            Remove-PSDrive -Name HKU -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-WarningLog "Failed to remove HKU drive: $($_.Exception.Message)"
        }
    }

    # Sort results alphabetically by software name
    $results = $results | Sort-Object -Property Name

    Write-InfoLog "Get-InstalledSoftware - Found $($results.Count) software entries"
    $results | ForEach-Object {
        Write-InfoLog "Name: $($_.Name) - GUID: $($_.GUID)"
    }

    return $results
}

try {
    # Run the function with script parameter (only pass Name if it has a value)
    if ($PSBoundParameters.ContainsKey('Name') -and $Name) {
        Get-InstalledSoftware -Name $Name
    } else {
        Get-InstalledSoftware
    }
}
catch {
    Write-ErrorLog "Script failed: $($_.Exception.Message)"
    throw
}
finally {
    Close-Logger
}
