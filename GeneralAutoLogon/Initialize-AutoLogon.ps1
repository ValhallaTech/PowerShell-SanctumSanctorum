<#
.SYNOPSIS
    Configures a system for automatic logon and adjusts various system settings.
.DESCRIPTION
    Automates the setup for system autologon, configures logging, and modifies specific registry entries.
    Ensures required modules are installed and trusted sources are set.
.PARAMETER Username
    The username for the autologon process.
.PARAMETER Domain
    The domain name for the autologon process. Defaults to 'wssu.edu'.
.PARAMETER AutologonPath
    Path to the Autologon executable. Defaults to '.\Autologon64.exe'.
.NOTES
    File Name      : Initialize-Autologon.ps1
    Version        : 2.1.0
    Prerequisites  : Requires administrative privileges, PoShLog module.
    Author         : Fred Smith III
.EXAMPLE
    .\Initialize-Autologon.ps1 -Username 'serviceaccount' -Domain 'contoso.com'
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Username,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Domain = 'wssu.edu',

    [Parameter()]
    [ValidateScript({ Test-Path $_ })]
    [string]$AutologonPath = '.\Autologon64.exe'
)

# --- Helper Functions for NuGet, PSGallery, and Module Import ---

function Install-NugetProvider {
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name 'NuGet' -Force
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

function Initialize-Logging {
    <#
    .SYNOPSIS
        Configures the PoShLog logging system.
    #>
    $logFileName = 'Initialize-AutoLogon.log'
    $logFilePath = "$env:SystemDrive\Logs\$logFileName"

    # Ensure log directory exists
    $logDir = Split-Path $logFilePath -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }

    $logger = New-Logger
    $logger |
        Set-MinimumLevel -Value Information |
        Add-SinkFile -Path $logFilePath |
        Add-SinkConsole |
        Start-Logger

    Write-InfoLog 'PoShLog module imported and logger configured'
}

function Test-RegistryPath {
    <#
    .SYNOPSIS
        Tests and creates registry paths if they don't exist.
    .PARAMETER Path
        The registry path to test and create.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        try {
            New-Item -Path $Path -ItemType RegistryKey -Force | Out-Null
            Write-InfoLog "Created registry path: $Path"
        }
        catch {
            Write-ErrorLog "Failed to create registry path $Path`: $($_.Exception.Message)"
            throw
        }
    }
}

function Set-RegistryValue {
    <#
    .SYNOPSIS
        Safely sets a registry value with error handling.
    .PARAMETER Path
        The registry path.
    .PARAMETER Name
        The value name.
    .PARAMETER Value
        The value data.
    .PARAMETER Type
        The value type.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        $Value,

        [Parameter()]
        [string]$Type = 'String'
    )

    try {
        $setParams = @{
            Path = $Path
            Name = $Name
            Value = $Value
        }
        if ($Type -ne 'String') {
            $setParams.Type = $Type
        }

        Set-ItemProperty @setParams
        Write-InfoLog "Set registry value: $Path\$Name = $Value"
    }
    catch {
        Write-ErrorLog "Failed to set registry value $Path\$Name`: $($_.Exception.Message)"
        throw
    }
}

function Remove-RegistryValue {
    <#
    .SYNOPSIS
        Safely removes a registry value with error handling.
    .PARAMETER Path
        The registry path.
    .PARAMETER Name
        The value name.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name
    )

    try {
        if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {
            Remove-ItemProperty -Path $Path -Name $Name -Force
            Write-InfoLog "Removed registry value: $Path\$Name"
        }
    }
    catch {
        Write-ErrorLog "Failed to remove registry value $Path\$Name`: $($_.Exception.Message)"
    }
}

function Set-DigitalSignageSettings {
    <#
    .SYNOPSIS
        Configures registry settings for digital signage mode.
    #>
    # Registry paths
    $macLockScreenPath = 'HKLM:Software\Policies\Microsoft\Windows\Personalization'
    $usrPowerCommandsPath = 'HKCU:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    $usrScreenSaverPath = 'HKCU:Software\Policies\Microsoft\Windows\Control Panel\Desktop'
    $macRegPoliciesPath = 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $macRegWinlogonPath = 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $usrDesktopIcons = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'

    # Create registry paths if they don't exist
    $registryPaths = @(
        $macLockScreenPath, $usrPowerCommandsPath, $usrScreenSaverPath,
        $macRegPoliciesPath, $macRegWinlogonPath, $usrDesktopIcons
    )

    foreach ($path in $registryPaths) {
        Test-RegistryPath -Path $path
    }

    # Configure machine policies
    Remove-RegistryValue -Path $macLockScreenPath -Name 'LockScreenImage'
    Set-RegistryValue -Path $macLockScreenPath -Name 'LockscreenOverlaysDisabled' -Value 1 -Type 'DWord'
    Set-RegistryValue -Path $macRegPoliciesPath -Name 'disablecad' -Value 1
    Remove-RegistryValue -Path $macRegPoliciesPath -Name 'LegalNoticeText'
    Remove-RegistryValue -Path $macRegPoliciesPath -Name 'LegalNoticeCaption'

    # Configure user policies
    Set-RegistryValue -Path $usrPowerCommandsPath -Name 'NoClose' -Value 1 -Type 'DWord'
    Set-RegistryValue -Path $usrScreenSaverPath -Name 'ScreenSaveActive' -Value '0'
    Set-RegistryValue -Path $usrDesktopIcons -Name 'HideIcons' -Value 1

    Write-InfoLog 'Digital signage registry settings configured'
}

function Restart-Explorer {
    <#
    .SYNOPSIS
        Safely restarts Windows Explorer.
    #>
    try {
        $explorerProcess = Get-Process -Name 'explorer' -ErrorAction SilentlyContinue
        if ($explorerProcess) {
            Stop-Process -Name 'explorer' -Force
            Write-InfoLog 'Explorer process stopped'

            # Wait a moment then start explorer again
            Start-Sleep -Seconds 2
            Start-Process -FilePath 'explorer.exe'
            Write-InfoLog 'Explorer process restarted'
        }
    }
    catch {
        Write-ErrorLog "Failed to restart Explorer: $($_.Exception.Message)"
    }
}

function Start-AutologonConfiguration {
    <#
    .SYNOPSIS
        Configures autologon using the Autologon executable.
    .PARAMETER Username
        The username for autologon.
    .PARAMETER Domain
        The domain for autologon.
    .PARAMETER Password
        The secure string password.
    .PARAMETER AutologonPath
        Path to the Autologon executable.
    #>
    param (
        [Parameter(Mandatory)]
        [string]$Username,

        [Parameter(Mandatory)]
        [string]$Domain,

        [Parameter(Mandatory)]
        [SecureString]$Password,

        [Parameter(Mandatory)]
        [string]$AutologonPath
    )

    try {
        # Convert SecureString to plain text for Autologon.exe (required by the tool)
        $credential = New-Object System.Management.Automation.PSCredential($Username, $Password)
        $plainPassword = $credential.GetNetworkCredential().Password

        $processParams = @{
            FilePath = $AutologonPath
            ArgumentList = @($Username, $Domain, $plainPassword, '/accepteula')
            Wait = $true
            ErrorAction = 'Stop'
        }

        Start-Process @processParams
        Write-InfoLog 'Autologon successfully configured'
    }
    catch {
        Write-ErrorLog "Autologon configuration failed: $($_.Exception.Message)"
        throw
    }
    finally {
        # Clear the plain text password from memory (best effort security)
        if ($plainPassword) {
            $plainPassword = $null
            [System.GC]::Collect()
        }
    }
}

# --- Script Execution ---

try {
    Write-Output 'Setting up unattended module installation...'

    # Install required modules and configure logging using standardized functions
    Install-NugetProvider
    Set-PsGalleryTrusted
    Import-RequiredModule -moduleName 'PoShLog'

    Initialize-Logging

    # Get user credentials securely
    $passwordSecure = Read-Host -Prompt "Please enter the password for user '$Username'" -AsSecureString
    Write-InfoLog 'User credentials configured successfully'

    # Configure system settings
    Write-InfoLog 'Updating registry to enable autologon...'
    Set-DigitalSignageSettings

    # Restart Explorer to apply changes
    Restart-Explorer

    # Configure autologon
    Start-AutologonConfiguration -Username $Username -Domain $Domain -Password $passwordSecure -AutologonPath $AutologonPath

    Write-InfoLog 'Autologon initialization completed successfully'
}
catch {
    Write-ErrorLog "Script execution failed: $($_.Exception.Message)"
    throw
}
finally {
    Close-Logger
}
