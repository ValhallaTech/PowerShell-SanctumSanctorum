#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Registers a Scheduled Task that launches Microsoft Edge to a fixed URL whenever any
    user logs on to the machine.

.DESCRIPTION
    Creates (or replaces) a Windows Scheduled Task named 'Launch-NxPortal-OnLogon' that
    fires on every interactive user logon and opens Microsoft Edge (msedge.exe) navigated
    to https://nx.pg.com.

    Trigger/principal design decision:
    A New-ScheduledTaskTrigger -AtLogOn call with NO -User parameter fires for ANY user
    logging on to the machine (this is standard Task Scheduler behaviour - omitting -User
    is the documented way to target "all users" rather than a specific account). The task
    principal is set to the built-in 'BUILTIN\Users' group running at Limited privileges
    (non-elevated). This is the correct choice here because:
      - The action (opening a browser) does not require elevation, and running it as
        SYSTEM would launch Edge under the SYSTEM account's non-interactive session
        context, not the logged-on user's desktop session, so the browser window would
        never actually become visible to the user.
      - Running as the 'Users' group with -RunLevel Limited ensures the task executes in
        each interactive user's own session with their own credentials/profile, which is
        required for a GUI application like Edge to display on their desktop.

    This script itself only needs to be run once by an administrator to register the task;
    the registration step (Register-ScheduledTask) requires local admin rights, which is
    why #Requires -RunAsAdministrator is declared above. The task it creates does NOT run
    elevated - it runs at Limited (standard user) rights in each user's own logon session.

.PARAMETER TaskName
    Name of the scheduled task to create. Defaults to 'Launch-NxPortal-OnLogon'.

.PARAMETER TargetUrl
    The URL that Microsoft Edge will be launched against. Defaults to https://nx.pg.com.

.EXAMPLE
    .\Register-EdgeLogonTask.ps1

    Registers (or re-registers) the default task using the built-in defaults.

.EXAMPLE
    .\Register-EdgeLogonTask.ps1 -TaskName 'Launch-Portal' -TargetUrl 'https://example.com'

    Registers the task under a custom name pointed at a different URL.

.NOTES
    Requires an elevated (Administrator) PowerShell session because Register-ScheduledTask
    needs administrative rights to create a task that applies to all users. Target host
    must be running Windows PowerShell 5.1 or later with the built-in ScheduledTasks module.
#>
[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TaskName = 'Launch-NxPortal-OnLogon',

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$TargetUrl = 'https://nx.pg.com'
)

# Enable strict mode to catch uninitialized variables and invalid property references.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
    Resolves the full path to msedge.exe, checking both standard install locations.
.DESCRIPTION
    Microsoft Edge can install to either the 64-bit Program Files directory or the
    Program Files (x86) directory depending on the install channel/architecture used
    at deployment time. This function checks both known locations and returns the
    first one found, rather than hardcoding a single path.
.EXAMPLE
    $edgePath = Resolve-EdgeExecutablePath
#>
function Resolve-EdgeExecutablePath {
    [CmdletBinding()]
    param ()

    # Standard 64-bit / per-machine install location.
    $candidatePaths = @(
        (Join-Path -Path $env:ProgramFiles -ChildPath 'Microsoft\Edge\Application\msedge.exe'),
        (Join-Path -Path ${env:ProgramFiles(x86)} -ChildPath 'Microsoft\Edge\Application\msedge.exe')
    )

    foreach ($candidatePath in $candidatePaths) {
        if (Test-Path -Path $candidatePath -PathType Leaf) {
            Write-Verbose -Message "Resolved Edge executable at '$candidatePath'."
            return $candidatePath
        }
    }

    throw 'Could not locate msedge.exe in either Program Files or Program Files (x86). Verify Microsoft Edge is installed.'
}

<#
.SYNOPSIS
    Registers the logon-triggered Microsoft Edge scheduled task, replacing any existing
    task of the same name.
.DESCRIPTION
    Builds the scheduled task action, trigger, principal, and settings, then registers
    the task. If a task with the same name already exists it is unregistered first so
    the script is idempotent and safe to re-run.
.PARAMETER TaskName
    Name of the scheduled task to register.
.PARAMETER EdgePath
    Full path to msedge.exe to use as the task action executable.
.PARAMETER TargetUrl
    URL to pass as the argument to msedge.exe.
.EXAMPLE
    Register-EdgeLogonScheduledTask -TaskName 'Launch-NxPortal-OnLogon' -EdgePath $edgePath -TargetUrl 'https://nx.pg.com'
#>
function Register-EdgeLogonScheduledTask {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TaskName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EdgePath,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetUrl
    )

    # Idempotency check: remove any pre-existing task of the same name rather than
    # erroring out on a duplicate registration.
    $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $existingTask) {
        if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister existing scheduled task')) {
            Write-Verbose -Message "Existing scheduled task '$TaskName' found. Removing before re-registration."
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }
    }

    # Action: launch Edge directly at the target URL.
    $actionArguments = @{
        Execute  = $EdgePath
        Argument = $TargetUrl
    }
    $taskAction = New-ScheduledTaskAction @actionArguments

    # Trigger: -AtLogOn with no -User targets ANY user logging on to the machine, per the
    # documented ScheduledTasks module behaviour (see comment-based help above).
    $taskTrigger = New-ScheduledTaskTrigger -AtLogOn

    # Principal: run as the built-in Users group at Limited (non-elevated) rights so the
    # task executes inside each user's own interactive logon session and Edge is visible
    # on their desktop. Running as SYSTEM would not produce a visible browser window.
    $principalArguments = @{
        GroupId   = 'BUILTIN\Users'
        RunLevel  = 'Limited'
    }
    $taskPrincipal = New-ScheduledTaskPrincipal @principalArguments

    # Settings: allow the task to run on battery and not stop if the machine switches to
    # battery power, since a logon can happen on a laptop that is unplugged.
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    $registrationArguments = @{
        TaskName    = $TaskName
        Action      = $taskAction
        Trigger     = $taskTrigger
        Principal   = $taskPrincipal
        Settings    = $taskSettings
        Description = "Launches Microsoft Edge to $TargetUrl for any user logging on to this machine."
    }

    if ($PSCmdlet.ShouldProcess($TaskName, 'Register scheduled task')) {
        Register-ScheduledTask @registrationArguments | Out-Null
        Write-Verbose -Message "Scheduled task '$TaskName' registered successfully."
    }
}

# ----- Script execution -----
try {
    Write-Verbose -Message 'Resolving Microsoft Edge executable path.'
    $edgeExecutablePath = Resolve-EdgeExecutablePath

    Write-Verbose -Message "Registering scheduled task '$TaskName' targeting '$TargetUrl'."
    $registerArguments = @{
        TaskName = $TaskName
        EdgePath = $edgeExecutablePath
        TargetUrl = $TargetUrl
    }
    Register-EdgeLogonScheduledTask @registerArguments

    Write-Output "Scheduled task '$TaskName' registered successfully. It will launch Edge at '$TargetUrl' for any user logging on to this machine."
    exit 0
}
catch {
    Write-Error -Message "Failed to register scheduled task '$TaskName': $($_.Exception.Message)"
    exit 1
}
