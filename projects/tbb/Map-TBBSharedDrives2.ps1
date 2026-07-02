<#
.SYNOPSIS
    Maps specific TBB network drives using alternate credentials and logs all actions.
.DESCRIPTION
    Ensures console credential prompting is enabled, prompts for alternate credentials, and maps the specified TBB network shares to drive letters persistently. All actions are logged using PoShLog.
.NOTES
    Author: Fred Smith III
    Version: 1.0.1
    Compatible with: PowerShell 5.1
#>

[CmdletBinding()]
param()

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
        throw 'ConsolePrompting registry key configuration failed'
    }
}

function Remove-ShareConnections {
    <#
    .SYNOPSIS
        Removes existing network connections to a specified server.
    .PARAMETER server
        The server name to disconnect from.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
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
        Write-ErrorLog "Failed to remove existing connections to $server. $($_.Exception.Message)"
        throw
    }
}

function New-TBBShareMapping {
    <#
    .SYNOPSIS
        Maps a TBB network share to a drive letter using alternate credentials.
    .DESCRIPTION
        Maps a network share to a drive letter with persistent connection.
        Uses secure credential handling to avoid exposing passwords in command line.
    .PARAMETER driveLetter
        The drive letter to map the share to (without colon).
    .PARAMETER sharePath
        The UNC path to the network share.
    .PARAMETER shareName
        The friendly name of the share for logging purposes.
    .PARAMETER credential
        The PSCredential object containing username and password.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$driveLetter,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$sharePath,
        
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$shareName,
        
        [pscredential]$credential
    )

    try {
        if ($credential) {
            $username = $credential.UserName
            $password = $credential.GetNetworkCredential().Password
            $netUseParams = @(
                "${driveLetter}:"
                "`"$sharePath`""
                $password
                "/user:$username"
                '/persistent:yes'
            )
        } else {
            $netUseParams = @(
                "${driveLetter}:"
                "`"$sharePath`""
                '/persistent:yes'
            )
        }

        # Execute net use command and capture output
        $netUseCommand = 'net.exe'
        $netUseArgs = @('use') + $netUseParams
        
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $netUseCommand
        $processInfo.Arguments = $netUseArgs -join ' '
        $processInfo.UseShellExecute = $false
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.CreateNoWindow = $true

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo
        
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        
        if ($process.ExitCode -eq 0) {
            Write-InfoLog "Successfully mapped $shareName ($sharePath) to ${driveLetter}:"
        } else {
            $errorMessage = if ($stderr.Trim()) { $stderr.Trim() } else { "Exit code: $($process.ExitCode)" }
            Write-ErrorLog "Failed to map $shareName ($sharePath) to ${driveLetter}: $errorMessage"
            throw "Drive mapping failed: $errorMessage"
        }
    } catch {
        Write-ErrorLog "Failed to map $shareName ($sharePath) to ${driveLetter}: $($_.Exception.Message)"
        throw
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
            throw 'ConsolePrompting registry key configuration failed'
        }
    }

    # Prompt for alternate credentials
    $credential = Get-Credential -Message 'Enter credentials for network share access'
    if (-not $credential) {
        Write-ErrorLog 'No credentials provided. Exiting.'
        throw 'No credentials provided'
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
    foreach ($share in $shares[1..($shares.Count - 1)]) {
        New-TBBShareMapping -driveLetter $share.Drive -sharePath $share.Path -shareName $share.Name
    }
} catch {
    Write-ErrorLog "Script failed: $($_.Exception.Message)"
}
finally {
    Close-Logger
}
