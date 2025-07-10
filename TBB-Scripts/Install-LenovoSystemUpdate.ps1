<#
.SYNOPSIS
    Installs Chocolatey if needed, then installs Lenovo System Update and runs its main executable.
.DESCRIPTION
    Checks for admin rights, installs Chocolatey and Lenovo System Update if missing, and runs the Lenovo System Update application.
#>

[CmdletBinding()]
param ()

function Test-ChocolateyInstalled {
    $chocoPath = "$env:SystemDrive\ProgramData\chocolatey\bin\choco.exe"
    $chocoInPath = Get-Command -Name 'choco' -ErrorAction SilentlyContinue
    if (Test-Path $chocoPath) { return $true }
    if ($null -ne $chocoInPath) { return $true }
    return $false
}

function Write-Result {
    param (
        [bool]$isInstalled
    )
    if ($isInstalled) {
        Write-Output 'Chocolatey is installed.'
    }
    else {
        Write-Output 'Chocolatey is not installed.'
    }
}

function Install-Chocolatey {
    Write-Output 'Installing Chocolatey...'
    $execPolicyParams = @{
        Scope           = 'Process'
        ExecutionPolicy = 'Bypass'
        Force           = $true
    }
    Set-ExecutionPolicy @execPolicyParams
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    try {
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        Write-Output 'Chocolatey installation complete.'
    }
    catch {
        Write-Error "Chocolatey installation failed: $($_.Exception.Message)"
        throw
    }
}

function Test-AdminRights {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $currentIdentity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-LenovoSystemUpdate {
    Write-Output 'Installing Lenovo System Update (lenovo-thinkvantage-system-update) via Chocolatey...'
    $chocoInstallParams = @{
        FilePath     = 'choco'
        ArgumentList = 'install lenovo-thinkvantage-system-update -y --ignore-checksums'
        Wait         = $true
        NoNewWindow  = $true
    }
    try {
        Start-Process @chocoInstallParams
        Write-Output 'Lenovo System Update installation complete.'
    }
    catch {
        Write-Error "Lenovo System Update installation failed: $($_.Exception.Message)"
        throw
    }
}

function Invoke-LenovoSystemUpdateSetup {
    if (-not (Test-AdminRights)) {
        Write-Error 'This script must be run as administrator.'
        exit 1
    }

    $isInstalled = Test-ChocolateyInstalled
    Write-Result -isInstalled $isInstalled

    if (-not $isInstalled) {
        Install-Chocolatey
    }

    Install-LenovoSystemUpdate

    $possiblePaths = @(
        'C:\Program Files\Lenovo\System Update\TVSU.exe',
        'C:\Program Files (x86)\Lenovo\System Update\TVSU.exe'
    )
    $systemUpdatePath = $possiblePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($systemUpdatePath) {
        try {
            Start-Process -FilePath $systemUpdatePath
            Write-Output "Lenovo System Update launched from '$systemUpdatePath'."
        }
        catch {
            Write-Error "Failed to launch Lenovo System Update: $($_.Exception.Message)"
        }
    }
    else {
        Write-Error "System Update executable not found in either Program Files directory."
    }
}

# Main logic
Invoke-LenovoSystemUpdateSetup
