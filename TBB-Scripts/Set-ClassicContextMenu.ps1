<#
.SYNOPSIS
    Reverts Windows 11 to the classic context menu by adding a registry key, then restarts Explorer.
.DESCRIPTION
    Adds a specific registry key under HKCU to enable the classic context menu in Windows 11.
    Prompts the user before restarting Explorer. Includes an undo function.
.NOTES
    Author: Fred Smith III
    Tested on: PowerShell 5.1
#>

function Set-ClassicContextMenu {
    <#
    .SYNOPSIS
        Adds the registry key for the classic context menu.
    #>
    [CmdletBinding()]
    param ()
    $regKeyPath = 'Software\\Classes\\CLSID\\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\\InprocServer32'
    try {
        $userRoot = [Microsoft.Win32.Registry]::CurrentUser
        $key = $userRoot.CreateSubKey($regKeyPath)
        if ($key) {
            $key.SetValue($null, '', [Microsoft.Win32.RegistryValueKind]::String)
            $key.Close()
            Write-Output 'Classic context menu registry key set successfully.'
        } else {
            Write-Error 'Failed to create or open the registry key.'
        }
    } catch {
        Write-Error "Failed to set registry key: $($_.Exception.Message)"
    }
}

function Remove-ClassicContextMenu {
    <#
    .SYNOPSIS
        Removes the registry key for the classic context menu.
    #>
    [CmdletBinding()]
    param ()
    $regPath = 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}'
    try {
        if (Test-Path $regPath) {
            Remove-Item -Path $regPath -Recurse -Force
            Write-Output 'Classic context menu registry key removed.'
        } else {
            Write-Output 'Classic context menu registry key does not exist.'
        }
    } catch {
        Write-Error "Failed to remove registry key: $($_.Exception.Message)"
    }
}

function Restart-ExplorerProcess {
    <#
    .SYNOPSIS
        Restarts the Windows Explorer process.
    #>
    [CmdletBinding()]
    param ()
    $confirm = Read-Host 'Restarting Explorer will close open folders and windows. Continue? (Y/N)'
    if ($confirm -match '^[Yy]$') {
        try {
            Stop-Process -Name 'explorer' -Force -ErrorAction Stop
            Start-Process -FilePath 'explorer.exe'
            Write-Output 'Explorer restarted successfully.'
        } catch {
            Write-Error "Failed to restart Explorer: $($_.Exception.Message)"
        }
    } else {
        Write-Output 'Explorer restart cancelled by user.'
    }
}

# Main script logic
Set-ClassicContextMenu
Restart-ExplorerProcess

# To undo, run:
# Remove-ClassicContextMenu
