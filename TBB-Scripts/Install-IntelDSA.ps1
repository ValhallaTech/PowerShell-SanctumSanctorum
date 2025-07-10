<#
.SYNOPSIS
    Installs Chocolatey if needed, then installs Intel DSA and runs its service helper.
.DESCRIPTION
    Checks for admin rights, installs Chocolatey and Intel DSA if missing, and runs the Intel DSA Service Helper.
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

function Install-IntelDSA {
    Write-Output 'Installing Intel Driver & Support Assistant (intel-dsa) via Chocolatey...'
    $chocoInstallParams = @{
        FilePath     = 'choco'
        ArgumentList = 'install intel-dsa -y --ignore-checksums'
        Wait         = $true
        NoNewWindow  = $true
    }
    try {
        Start-Process @chocoInstallParams
        Write-Output 'Intel DSA installation complete.'
    }
    catch {
        Write-Error "Intel DSA installation failed: $($_.Exception.Message)"
        throw
    }
}

function Invoke-IntelDSASetup {
    if (-not (Test-AdminRights)) {
        Write-Error 'This script must be run as administrator.'
        exit 1
    }

    $isInstalled = Test-ChocolateyInstalled
    Write-Result -isInstalled $isInstalled

    if (-not $isInstalled) {
        Install-Chocolatey
    }

    Install-IntelDSA

    $dsaHelperPath = 'C:\Program Files (x86)\Intel\Driver and Support Assistant\x86\DSAServiceHelper.exe'
    if (Test-Path $dsaHelperPath) {
        try {
            Start-Process -FilePath $dsaHelperPath -ArgumentList installstartup
            Write-Output 'Intel DSA Service Helper launched.'
        }
        catch {
            Write-Error "Failed to launch Intel DSA Service Helper: $($_.Exception.Message)"
        }
    }
    else {
        Write-Error "DSAServiceHelper.exe not found at $dsaHelperPath"
    }
}

# Main logic
Invoke-IntelDSASetup
