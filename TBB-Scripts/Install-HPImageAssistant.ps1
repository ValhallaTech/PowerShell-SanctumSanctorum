<#
.SYNOPSIS
    Installs Chocolatey if needed, then installs HP Image Assistant and runs its main executable.
.DESCRIPTION
    Checks for admin rights, installs Chocolatey and HP Image Assistant if missing, and runs the HP Image Assistant application.
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

function Invoke-HPImageAssistantSetup {
    if (-not (Test-AdminRights)) {
        Write-Error 'This script must be run as administrator.'
        exit 1
    }

    $isInstalled = Test-ChocolateyInstalled
    Write-Result -isInstalled $isInstalled

    if (-not $isInstalled) {
        Install-Chocolatey
    }

    Write-Output 'Installing HP Image Assistant (hpimageassistant) via Chocolatey...'
    $chocoInstallParams = @{
        FilePath     = 'choco'
        ArgumentList = 'install hpimageassistant -y --ignore-checksums'
        Wait         = $true
        NoNewWindow  = $true
    }
    try {
        Start-Process @chocoInstallParams
        Write-Output 'HP Image Assistant installation complete.'
    }
    catch {
        Write-Error "HP Image Assistant installation failed: $($_.Exception.Message)"
        throw
    }

    $hpiaPath = 'C:\ProgramData\chocolatey\lib\hpimageassistant\tools\HPImageAssistant.exe'
    if (Test-Path $hpiaPath) {
        try {
            Start-Process -FilePath $hpiaPath
            Write-Output "HP Image Assistant launched from '$hpiaPath'."
        }
        catch {
            Write-Error "Failed to launch HP Image Assistant: $($_.Exception.Message)"
        }
    }
    else {
        Write-Error "HP Image Assistant executable not found at $hpiaPath"
    }
}

# Main logic
Invoke-HPImageAssistantSetup