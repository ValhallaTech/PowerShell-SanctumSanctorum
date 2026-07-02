function Start-DeploymentBitsTransfer {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory)]
        [string]$LocalPath = "$env:USERPROFILE\Data",

        [Parameter(Mandatory)]
        [string]$RemoteMachine = {Read-Host -Prompt "Enter target hostname or IP address" | Write-Output $remoteMachine},

        [Parameter(Mandatory)]
        [string]$remotePath = "\\$remoteMachine\Public\Downloads",

        [Parameter(Mandatory)]
        [string]$Source01 = "$localPath\defprof.exe",

        [Parameter(Mandatory)]
        [string]$Source02 = "$localPath\Invoke-DefProf.ps1",

        [Parameter(Mandatory)]
        [string]$Source03 = "$localPath\Invoke-PostImageTasks",

        [Parameter(Mandatory)]
        [string]$Source04 = "$localPath\Update-McAfee",

        [Parameter(Mandatory)]
        [string]$Destination = $remotePath
    )

        Start-BitsTransfer -Source $Source01 -Destination $Destination -TransferType Upload
        Start-BitsTransfer -Source $Source02 -Destination $Destination -TransferType Upload
        Start-BitsTransfer -Source $Source03 -Destination $Destination -TransferType Upload
        Start-BitsTransfer -Source $Source04 -Destination $Destination -TransferType Upload
}
