<#
.SYNOPSIS
    Installs and configures logging and parallel processing modules, then retrieves a list of all installed software on the system.

.DESCRIPTION
    This script ensures the NuGet provider and PSGallery repository are available and trusted, installs and imports the PoShLog and PSParallel modules,
    configures logging to both file and console, and defines a function to scan the registry for installed software (optionally filtered by name).
    Results are logged and displayed. The script uses best practices for PowerShell scripting, including modularization, error handling, and clear logging.

.NOTES
    Author: Fred Smith III
    Version: 1.1.0
    Requires: PowerShell 5.1+, PoShLog, PSParallel

.EXAMPLE
    .\Get-InstalledSoftware.ps1

.EXAMPLE
    .\Get-InstalledSoftware.ps1 -name 'Microsoft'
    Retrieves and logs all installed software with names starting with 'Microsoft'.
#>

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
Install-NugetProvider
Set-PsGalleryTrusted

# Import PoShLog and PSParallel modules
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

# Retrieves a list of all installed software
function Get-InstalledSoftware {
    <#
        .SYNOPSIS
            Retrieves a list of all software installed.
        .DESCRIPTION
            Scans the registry to find the GUID of software installed on the computer.
        .EXAMPLE
            Get-InstalledSoftware
        .PARAMETER name
            The software title you'd like to limit the query to. Accepts partial matches, e.g. 'Microsoft'.
        .EXAMPLE
            Get-InstalledSoftware -name 'Microsoft'
        #>
    [OutputType([System.Management.Automation.PSObject])]
    [CmdletBinding()]
    param (
        [string]$name
    )
    # Registry paths to search for installed software
    $uninstallKeys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    # Add user-specific uninstall keys
    $null = New-PSDrive -Name HKU -PSProvider Registry -Root 'Registry::HKEY_USERS'
    $uninstallKeys += Get-ChildItem HKU: -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'S-\d-\d+-(\d+-){1,14}\d+$' } |
    ForEach-Object { "HKU:\$($_.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall" }

    if (-not $uninstallKeys) {
        Write-InfoLog -Message 'No software registry keys found'
        return
    }
        # Query each uninstall key in parallel (Boe Prox's Invoke-Parallel pattern)
        if ($PSBoundParameters.ContainsKey('name') -and $null -ne $name -and $name -ne '') {
            $results = $uninstallKeys | Invoke-Parallel -ThrottleLimit 16 -ScriptBlock {
                $uninstallKey = $_
                $name = $args[0]
                if ($name) {
                    $whereBlock = { ($_.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$') -and ($_.GetValue('DisplayName') -like "$name*") }
                } else {
                    $whereBlock = { ($_.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$') -and ($_.GetValue('DisplayName')) }
                }
                $gciParams = @{
                    Path        = $uninstallKey
                    ErrorAction = 'SilentlyContinue'
                }
                $selectProperties = @(
                    @{n = 'GUID'; e = { $_.PSChildName } },
                    @{n = 'Name'; e = { $_.GetValue('DisplayName') } }
                )
                Get-ChildItem @gciParams | Where-Object $whereBlock | Select-Object -Property $selectProperties
            } $name
        } else {
            $results = $uninstallKeys | Invoke-Parallel -ThrottleLimit 16 -ScriptBlock {
                $uninstallKey = $_
                $name = $args[0]
                if ($name) {
                    $whereBlock = { ($_.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$') -and ($_.GetValue('DisplayName') -like "$name*") }
                } else {
                    $whereBlock = { ($_.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$') -and ($_.GetValue('DisplayName')) }
                }
                $gciParams = @{
                    Path        = $uninstallKey
                    ErrorAction = 'SilentlyContinue'
                }
                $selectProperties = @(
                    @{n = 'GUID'; e = { $_.PSChildName } },
                    @{n = 'Name'; e = { $_.GetValue('DisplayName') } }
                )
                Get-ChildItem @gciParams | Where-Object $whereBlock | Select-Object -Property $selectProperties
            }
        }

        Write-InfoLog 'Get-InstalledSoftware - List of software found:'
        $results | ForEach-Object {
            Write-InfoLog "Name: $($_.Name) - GUID: $($_.GUID)"
        }

        return $results
    }

try {
    # Run the function
    Get-InstalledSoftware
}
catch {
    Write-Error "Script failed: $($_.Exception.Message)"
}
finally {
    Close-Logger
}
