#Requires -Version 5.1

<#
.SYNOPSIS
    Deletes user profiles on a computer, excluding specified accounts.

.DESCRIPTION
    This script deletes all user profiles on a computer except those listed in the
    ExcludedAccounts parameter. It verifies that the WinRM service is running and
    configures it if necessary.

    Prerequisite operations (NuGet provider, PSGallery trust, and PoShLog module
    installation) always run because they are required for the script to function.
    Specify -WhatIf to preview which profiles would be removed and whether WinRM
    would be reconfigured, without committing any of those state-changing operations.

.PARAMETER ExcludedAccounts
    An array of account usernames or SIDs to exclude from the removal process.
    Defaults to 'ramadmin' and the built-in SYSTEM, LOCAL SERVICE, and NETWORK
    SERVICE accounts.

.PARAMETER LogPath
    Full path to the log file. The parent directory must already exist.
    Defaults to C:\Logs\Remove-UserProfiles.log.

.EXAMPLE
    .\Remove-UserProfiles.ps1

    Removes all user profiles not present in the default exclusion list.

.EXAMPLE
    .\Remove-UserProfiles.ps1 -WhatIf

    Previews which profiles would be removed and whether WinRM would be configured,
    without making any changes to user profiles or WinRM state.

.EXAMPLE
    .\Remove-UserProfiles.ps1 -ExcludedAccounts @('jdoe', 'S-1-5-18', 'S-1-5-19', 'S-1-5-20') -LogPath 'D:\Logs\profiles.log'

    Removes all user profiles except jdoe and the built-in service accounts,
    writing the log to a custom path.

.NOTES
    Version: 2.1.0
    Author: Fred Smith
    Creation Date: 04/10/2023

    Invoke-WinRM:
    A function that checks if the WinRM service is running and, if it is not,
    configures and starts the service. WinRM is required for the script to work.

    Additional notes:
    WARNING: Be aware that this is a very powerful and destructive script. It will
    delete all user profiles and everything saved under them locally. Do not run it
    unless you know what you are doing.
    Make sure you run the script in an elevated PowerShell session.
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()]
    [string[]]$ExcludedAccounts = @(
        'ramadmin',
        'S-1-5-18', # SYSTEM
        'S-1-5-19', # LOCAL SERVICE
        'S-1-5-20'  # NETWORK SERVICE
    ),

    [Parameter()]
    [string]$LogPath = 'C:\Logs\Remove-UserProfiles.log'
)

Set-StrictMode -Version Latest

# Elevation check runs first - before any side effects (module installs, logger
# setup) so we fail fast without leaving partial state behind. The logger is not
# yet available here, so Write-Error is used instead of Write-ErrorLog.
try {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Error 'Script must be run as an administrator. Exiting script.'
        exit 1
    }
} catch {
    Write-Error "Failed to check administrative privileges: $_"
    exit 1
}

# Install NuGet provider only if not already available
if (-not (Get-PackageProvider -Name 'NuGet' -ListAvailable -ErrorAction SilentlyContinue)) {
    Install-PackageProvider -Name 'NuGet' -Force
}

# Trust PSGallery only if it is not already trusted
$psGallery = Get-PSRepository -Name 'PSGallery'
if ($psGallery.InstallationPolicy -ne 'Trusted') {
    Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
}

# Install PoShLog if not already available
if (-not (Get-Module -ListAvailable -Name 'PoShLog')) {
    Install-Module -Name 'PoShLog' -Repository 'PSGallery' -Confirm:$false -Force
}

# Import PoShLog module
Import-Module -Name 'PoShLog'

# Function to verify WinRM is running; configures it if it is not.
# Uses SupportsShouldProcess so Set-WSManQuickConfig is gated by -WhatIf.
function Invoke-WinRM {
    <#
    .SYNOPSIS
        Ensures the WinRM service is running and properly configured.
    .DESCRIPTION
        Checks the WinRM service status and calls Set-WSManQuickConfig if the
        service is not running. Supports -WhatIf: when specified, reports what
        would be configured without making any changes. Exits the script with
        code 1 on failure.
    .EXAMPLE
        Invoke-WinRM
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param ()

    Write-InfoLog 'Checking if WinRM service is running and configured'
    try {
        $winrmService = Get-Service -Name 'WinRM' -ErrorAction Stop
    } catch {
        Write-ErrorLog "Failed to query WinRM service status: $_"
        exit 1
    }

    if ($winrmService.Status -ne 'Running') {
        Write-InfoLog 'WinRM service is not running. Configuring...'
        try {
            if ($PSCmdlet.ShouldProcess('WinRM', 'Configure WinRM service')) {
                Set-WSManQuickConfig -Force -ErrorAction Stop
                Write-InfoLog 'WinRM has been configured successfully.'
            }
        } catch {
            Write-ErrorLog "An error occurred while configuring WinRM: $_"
            exit 1
        }
    } else {
        Write-InfoLog 'WinRM service is running.'
    }
}

# Wrap the main script body in try/finally to guarantee Close-Logger is always
# called, even if an unexpected terminating error occurs. The logger is
# initialised inside this guarded region so teardown is always reached.
try {
    # Initialise the logger inside the guarded region so Close-Logger is
    # guaranteed on any exit path, including failures during logger setup.
    New-Logger |
        Set-MinimumLevel -Value Information |
        Add-SinkFile -Path $LogPath |
        Add-SinkConsole |
        Start-Logger

    Write-InfoLog 'PoShLog module imported and logger configured'

    Invoke-WinRM
    Write-InfoLog 'WinRM service check completed'

    # Remove all user profiles not present in the exclusion list
    Write-InfoLog 'Removing user profiles...'
    try {
        Get-CimInstance -Class Win32_UserProfile -ErrorAction Stop | Where-Object {
            ($null -ne $_.LocalPath) -and
            ($_.LocalPath.Split('\')[-1] -notin $ExcludedAccounts) -and
            ($_.SID -notin $ExcludedAccounts)
        } | ForEach-Object {
            if ($PSCmdlet.ShouldProcess($_.LocalPath, 'Remove user profile')) {
                Remove-CimInstance -InputObject $_ -ErrorAction Stop
            }
        }
        Write-InfoLog 'User profiles removed successfully.'
    } catch {
        Write-ErrorLog "Failed to remove one or more user profiles: $_"
        exit 1
    }

    Write-InfoLog 'Script completed'
} finally {
    Close-Logger
}
