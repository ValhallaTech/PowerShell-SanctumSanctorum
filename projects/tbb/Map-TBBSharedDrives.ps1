<#
.SYNOPSIS
    Maps specific TBB network drives using alternate credentials and logs all actions.
.DESCRIPTION
    Ensures console credential prompting is enabled, prompts for alternate credentials, and maps the specified TBB network shares to drive letters persistently. All actions are logged using PoShLog.
.NOTES
    Author: Fred Smith III
    Version: 1.0.0
    Compatible with: PowerShell 5.1
#>

# --- Helper Functions for NuGet, PSGallery, and Module Import ---

function Install-NugetProvider {
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name 'NuGet' -Force -Confirm:$false
    }
}

function Set-PsGalleryTrusted {
    $psGallery = Get-PSRepository -Name 'PSGallery'
    if ($psGallery.InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy 'Trusted'
    }
}

function Import-RequiredModule {
    param (
        [string]$moduleName
    )
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Install-Module -Name $moduleName -Force -Scope CurrentUser
    }
    Import-Module -Name $moduleName -Force
}

function Test-ConsolePrompting {
    [CmdletBinding()]
    param ()
    $regPath = 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds'
    $regName = 'ConsolePrompting'
    try {
        $value = (Get-ItemProperty -Path $regPath -Name $regName -ErrorAction Stop).ConsolePrompting
        if ($value -ieq 'True') {
            return $true
        } else {
            return $false
        }
    } catch {
        return $false
    }
}

function Set-ConsolePrompting {
    [CmdletBinding()]
    param ()
    $command = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds' -Name 'ConsolePrompting' -Value $true"
    $psiParams = @{
        FilePath     = 'powershell.exe'
        ArgumentList = "-NoProfile -Command `"& { $command }`""
        Verb         = 'runas'
        Wait         = $true
        WindowStyle  = 'Hidden'
    }
    try {
        Start-Process @psiParams
        Write-Output 'ConsolePrompting registry key set (elevated).'
    } catch {
        Write-Error 'Failed to set ConsolePrompting registry key. Please run this script as administrator.'
        exit 1
    }
}

function Remove-ShareConnections {
    param (
        [Parameter(Mandatory)]
        [string]$server
    )
    try {
        $existingConnections = net use | Select-String "\\$server"
        foreach ($conn in $existingConnections) {
            $parts = $conn -split '\s+'
            if ($parts[1]) {
                net use $parts[1] /delete /y | Out-Null
                Write-InfoLog "Disconnected existing connection: $($parts[1])"
            }
        }
    } catch {
        Write-ErrorLog "Failed to remove existing connections to $server. $_"
    }
}

function New-TBBShareMapping {
    <#
    .SYNOPSIS
        Maps a TBB network share to a drive letter using alternate credentials.
        Disconnects all connections to the server before mapping.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$driveLetter,
        [Parameter(Mandatory)]
        [string]$sharePath,
        [Parameter(Mandatory)]
        [string]$shareName,
        [pscredential]$credential
    )

    # Build net use command
    if ($credential) {
        $username = $credential.UserName
        $password = $credential.GetNetworkCredential().Password
        $cmd = "net use ${driveLetter}: `"$sharePath`" $password /user:$username /persistent:yes"
    } else {
        $cmd = "net use ${driveLetter}: `"$sharePath`" /persistent:yes"
    }

    try {
        Invoke-Expression $cmd
        Write-InfoLog "Mapped $shareName ($sharePath) to ${driveLetter}:"
    } catch {
        Write-ErrorLog "Failed to map $shareName ($sharePath) to $driveLetter. $_"
    }
}

# --- Script Start ---

Write-Output 'Setting up unattended module installation...'

Install-NugetProvider
Set-PsGalleryTrusted
Import-RequiredModule -moduleName 'PoShLog'

# Configure variables for logging
$logFileName = 'Map-TBBSharedDrives.log'
$logFilePath = "$env:SystemDrive\Logs\$logFileName"

# Start logger
$logger = New-Logger
$logger |
    Set-MinimumLevel -Value Information |
    Add-SinkFile -Path $logFilePath |
    Add-SinkConsole |
    Start-Logger

Write-InfoLog 'PoShLog module imported and logger configured'

try {
    # Ensure console credential prompting is enabled
    if ((Test-ConsolePrompting) -ne $true) {
        Write-Warning 'ConsolePrompting registry key not found or not enabled. Attempting to set it with elevation...'
        Set-ConsolePrompting

        # Wait for the key to be set (up to 10 seconds)
        $maxWait = 10
        $waited = 0
        while (-not (Test-ConsolePrompting) -and $waited -lt $maxWait) {
            Start-Sleep -Seconds 1
            $waited++
        }

        if (-not (Test-ConsolePrompting)) {
            Write-ErrorLog 'ConsolePrompting registry key could not be set. Exiting.'
            exit 1
        }
    }

    # Prompt for alternate credentials
    $credential = Get-Credential -Message 'Enter credentials for network share access'
    if (-not $credential) {
        Write-ErrorLog 'No credentials provided. Exiting.'
        exit 1
    }

    # Define TBB shares to map
    $shares = @(
        @{ Drive = 'P'; Path = '\\stnaftbbw005.us605.corpintra.net\Public';  Name = 'PUBLIC'  }
        @{ Drive = 'Q'; Path = '\\stnaftbbw005.us605.corpintra.net\Quality'; Name = 'QUALITY' }
        @{ Drive = 'U'; Path = '\\stnaftbbw005.us605.corpintra.net\Common';  Name = 'COMMON'  }
    )

    # Remove all connections to the server ONCE before mapping
    $server = 'stnaftbbw005.us605.corpintra.net'
    Remove-ShareConnections -server $server

    # Map the first share with credentials
    $firstShare = $shares[0]
    New-TBBShareMapping -driveLetter $firstShare.Drive -sharePath $firstShare.Path -shareName $firstShare.Name -credential $credential

    # Map the remaining shares WITHOUT credentials
    for ($i = 1; $i -lt $shares.Count; $i++) {
        $share = $shares[$i]
        New-TBBShareMapping -driveLetter $share.Drive -sharePath $share.Path -shareName $share.Name
    }
} catch {
    Write-ErrorLog "Script failed: $($_.Exception.Message)"
}
finally {
    Close-Logger
}
