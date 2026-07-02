<#
.SYNOPSIS
    Installs Chocolatey if needed, then installs HP Image Assistant and runs its main executable.
.DESCRIPTION
    Checks for admin rights, installs Chocolatey and HP Image Assistant if missing, and runs the HP Image Assistant application.
#>

[CmdletBinding()]
param ()

function Test-ChocolateyInstalled {
    $chocoPath = Join-Path $env:ProgramData 'chocolatey\bin\choco.exe'
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

function Ensure-ElevatedSession {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        return
    }

    Write-Output 'Script is not running as administrator. Relaunching with elevated privileges...'

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb = 'runas'

    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
    }
    catch {
        Write-Error 'Failed to relaunch script as administrator.'
    }

    exit
}

function Invoke-HPImageAssistantSetup {
    Ensure-ElevatedSession

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

    $hpiaPath = Join-Path $env:ProgramData 'chocolatey\lib\hpimageassistant\tools\HPImageAssistant.exe'
    if (Test-Path $hpiaPath) {
        try {
            $hpiaParams = @{
                FilePath     = $hpiaPath
                ArgumentList = '/Operation:Analyze /Selection:All /Categories:All /Action:Install /ReportFolder:C:\HPIA\Reports /SoftpaqDownloadFolder:C:\HPIA\Downloads /NonInteractive'
                Wait         = $true
                NoNewWindow  = $true
            }
            Start-Process @hpiaParams
            Write-Output 'HP Image Assistant analysis and installation complete.'
        }
        catch {
            Write-Error "Failed to run HP Image Assistant: $($_.Exception.Message)"
        }
    }
    else {
        Write-Error "HP Image Assistant executable not found at $hpiaPath"
    }
}

# Main logic
Invoke-HPImageAssistantSetup
