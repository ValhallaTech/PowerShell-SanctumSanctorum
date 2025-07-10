<#
.SYNOPSIS
    Adds credentials to a list of remote servers using cmdkey, ensuring ConsolePrompting is enabled.
.DESCRIPTION
    Checks for the ConsolePrompting registry key. If missing, launches an elevated session to set it, then continues.
#>

function Ensure-ConsolePrompting {
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

function Set-ConsolePromptingElevated {
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

# Main logic
if ((Ensure-ConsolePrompting) -ne $true) {
    Write-Warning 'ConsolePrompting registry key not found or not enabled. Attempting to set it with elevation...'
    Set-ConsolePromptingElevated

    # Wait for the key to be set (up to 10 seconds)
    $maxWait = 10
    $waited = 0
    while (-not (Ensure-ConsolePrompting) -and $waited -lt $maxWait) {
        Start-Sleep -Seconds 1
        $waited++
    }

    if (-not (Ensure-ConsolePrompting)) {
        Write-Error 'ConsolePrompting registry key could not be set. Exiting.'
        exit 1
    }
}

function Set-ServerCredential {
    [CmdletBinding()]
    param (
        [string[]]$servers
    )
    $credential = Get-Credential
    $username = $credential.UserName
    $password = $credential.GetNetworkCredential().Password

    foreach ($server in $servers) {
        try {
            cmdkey /add:$server /user:$username /pass:$password
            Write-Information "Credential added to $server"
        } catch {
            Write-Error "Failed to add credential to $server. $_"
        }
    }
}

# Define server list
$servers = @(
    'stnaatbbw016.us605.corpintra.net',
    'stnaatbbw017.us605.corpintra.net',
    'powerbi-dtna.app.corpintra.net',
    'stnaatbbw066.us605.corpintra.net',
    'tbbreports.us605.corpintra.net',
    'stnaatbbw005.us605.corpintra.net',
    'stnaftbbw004.us605.corpintra.net',
    'stnaatbbw033.us605.corpintra.net'
)

# Call the function
Set-ServerCredential -servers $servers
