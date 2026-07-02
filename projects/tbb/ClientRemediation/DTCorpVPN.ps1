<#
	.SYNOPSIS
		Create nativ Windows VPN connection
	
	.DESCRIPTION
		Create nativ Windows VPN connection
	
	.PARAMETER LogPath
		Path to Logfile
	
	.PARAMETER Name
		Name of the VPN connection
	
	.PARAMETER GW
		Gateway of VPN connection
	
	.PARAMETER RemoveConnection
		A description of the RemoveConnection parameter.
	
	.PARAMETER Proxy
		Proxy Proxy of VPN connection
	
	.PARAMETER DestinationPrefixList
		Array list of prefixes as "x.x.x.x/y"
	
	.PARAMETER VPNConnectionPreFix
		Default prefix of any connection name; needed to identify existing VPN connections
	
	.NOTES
		===========================================================================
		Created on:   	27.02.2020 19:30
		Created by:   	RS-Solutions
		Organization: 	RS-Solutions
		Filename:     	AlwaysOn4Corona.ps1
		===========================================================================
		
		.EXITCODES
		0: Replacements evaluated successfully
		90: Error while Check-ScriptPrerequisites
		91: Error while Eval-VPNConnection
		92: Error while Process-VPNConnection
		93: Error while Delete-VPNConnection
		94: Error while Modify-VPNConnectionMetric
		99: general error
		
		.ChangeLog
		1.0.0.0: Initial version
		1.1.0.0: Change PFSGroup
		1.2.0.0: Add possibility to update the gateway of an existing connection
		1.2.0.1: Add logging current username
		1.3.0.0: Add changing the VPN interface metric to 1. Changed the parameters $UpdateGatewayOnly and $ForceReconnect from [bool] to [switch].
		1.4.0.0: Add removing a VPN connection. Changed $GW parameter to Mandatory = $false.
		1.4.0.1: Initialize the variable $Script:LogInit with $false to prevent errors in StrictMode.
		1.5.0.0: Add check for Netskope Client and Split Tunnel VPN connection configuration; dis- and reconnect VPN if connected for faster update; optimizations
		1.6.0.0: redesign (eval, create, update, reconnect, remove)
#>
[CmdletBinding()]
param
(
	[string]$LogPath,
	[string]$Name = 'DTCorp_VPN',
	[string]$GW = 'nine.sea.tbinter.net',
	[Parameter(Mandatory = $false)]
	[switch]$RemoveConnection = $false,
	[Parameter(Mandatory = $false)]
	[string]$Proxy = (Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name AutoConfigURL -ErrorAction SilentlyContinue).AutoConfigURL,
	[Parameter(Mandatory = $false)]
	[array]$DestinationPrefixList = @("10.0.0.0/8", "53.0.0.0/9", "53.128.0.0/12", "53.144.0.0/12", "53.176.0.0/12", "53.192.0.0/10", "170.2.0.0/19", "170.2.32.0/21", "170.2.48.0/22", "170.2.54.0/23", "170.2.56.0/21", "170.2.64.0/20", "170.2.80.0/21", "170.2.88.0/23", "170.2.96.0/20", "170.2.112.0/21", "170.2.136.0/21", "170.2.144.0/22", "170.2.152.0/21", "170.2.160.0/19", "170.2.192.0/19", "170.2.224.0/21", "170.2.242.0/23"),
	[Parameter(Mandatory = $false)]
	[String]$VPNConnectionPreFix = 'SEA'
)

#region Function Log-ScriptEvent
Function Log-ScriptEvent {
	
	#Define and validate parameters
	[CmdletBinding()]
	Param (
		#Path to the log file
		[parameter(Mandatory = $false)]
		[String]$NewLog = $logfile,
		#The information to log

		[parameter(Mandatory = $True)]
		[String]$Value,
		#The source of the error

		[parameter(Mandatory = $False)]
		[String]$Component = (Get-Item $MyInvocation.ScriptName).Name,
		#		[String]$Component = (Get-Item $MyInvocation.ScriptName).Name + ':' + $MyInvocation.ScriptLineNumber,

		#The severity (1 - Information, 2- Warning, 3 - Error)

		[parameter(Mandatory = $True)]
		[ValidateSet("INFO", "WARNING", "ERROR")]
		[String]$Severity,
		# 'MaxLogSize' has to be specified by the very first call to this

		[parameter(Mandatory = $false)]
		[ValidateRange(10240, 104857600)]
		[Int]$MaxLogSize = 5MB
		
	)
	
	# Convert 'Type' to its corresponding integer value
	switch ($Severity) {
		"INFO" {
			$TypeNum = 1; break
		}
		"WARNING" {
			$TypeNum = 2; break
		}
		"ERROR" {
			$TypeNum = 3; break
		}
		default {
			$TypeNum = 1; break
		}
	}
	
	#Obtain UTC offset
	$DateTime = New-Object -ComObject WbemScripting.SWbemDateTime
	$DateTime.SetVarDate($(Get-Date))
	$UtcValue = $DateTime.Value
	$UtcOffset = $UtcValue.Substring(21, $UtcValue.Length - 21)
	
	
	#Create the line to be logged
	$Script:LogInit = $false
	$component = $component + ':' + $MyInvocation.ScriptLineNumber
	$LogLine = "<![LOG[[$ScriptPhase] :: $Value]LOG]!>" + `
		"<time=`"$(Get-Date -Format HH:mm:ss.fff)$($UtcOffset)`" " + `
		"date=`"$(Get-Date -Format M-d-yyyy)`" " + `
		"component=`"$Component`" " + `
		"context=`"$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + `
		"type=`"$TypeNum`" " + `
		"thread=`"$([Threading.Thread]::CurrentThread.ManagedThreadId)`" " + `
		"file=`"`">"
	
	#Check log folder and filesize
	If (-not $Script:LogInit) {
		$Path = Split-Path -Path $newLog -Parent
		if (!(Test-Path -Path $Path)) { New-Item -Path $Path -ItemType directory | Out-Null }
		
		$LogFileObj = Get-Item $newLog -ErrorAction SilentlyContinue
		
		if ($LogFileObj.Length -ge $MaxLogSize) {
			
			Remove-Item -Path ($LogFileObj.DirectoryName + '\' + $LogFileObj.BaseName + '.lo_') -Force -ErrorAction SilentlyContinue
			Rename-Item -Path $LogFileObj.FullName -NewName ($LogFileObj.BaseName + '.lo_') -Force -ErrorAction SilentlyContinue
		}
		$script:LogInit = $true
	}
	
	#Write the line to the passed log file
	$LogLine | Out-File -FilePath $NewLog -Append -Force -Encoding ASCII -ErrorAction SilentlyContinue
	
	
}
#endregion

#region Function Exit-Script
function Exit-Script {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory = $true)]
		[ValidateNotNullorEmpty()]
		[string]$ExitCode
	)
	
	## Get the name of this function
	[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
	
	if (@('0', '1') -notcontains $ExitCode) {
		$Severity = 'ERROR'
	}
	else { $Severity = 'INFO' }
	Log-ScriptEvent -Value "$component ended with exit code [$ExitCode]" -Severity $Severity -Component $CmdletName
	Log-ScriptEvent -Value "################################### Exit $component ###################################" -Severity 'INFO' -Component $CmdletName
	Exit $ExitCode
}
#endregion

#region Function Check-RunningProcess
function Check-RunningProcess {
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		[string]$ProcessName
	)
	
	## Get the name of this function
	[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
	
	try {
		if ($Process = (Get-Process -name $ProcessName -ErrorAction SilentlyContinue)) {
			Log-ScriptEvent -Value "Found running process: [$($Process.Name)] [$($Process.Description)] [$($Process.ProductVersion)]." -Severity 'INFO' -Component $CmdletName
			Write-Output -InputObject $true; return
		}
		else {
			Log-ScriptEvent -Value "No running process with name [$ProcessName] found" -Severity 'INFO' -Component $CmdletName
			Write-Output -InputObject $false; return
		}
	}
	catch {
		Log-ScriptEvent -Value "Error while checking for processname [$ProcessName]. `n$($_.Exception.Message)" -Severity 'ERROR' -Component $CmdletName
		Write-Output -InputObject $false; return
	}
}
#endregion

#region Module Check-ScriptPrerequisites
function Check-ScriptPrerequisites {
	[CmdletBinding()]
	param ()
	
	[string]$ScriptPhase = 'Check-ScriptPrerequisites'
	[int]$ModuleErrorCode = 90
	
	## Get the name of this function and write header
	[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
	
	Write-Output -InputObject 0; return
}
#endregion

#region Module Eval-VPNConnections
function Eval-VPNConnections {
	[CmdletBinding()]
	param ()
	
	[string]$ScriptPhase = 'Eval-VPNConnections'
	[int]$ModuleErrorCode = 91
	[Array]$script:VPNConnections = @()
	
	## Get the name of this function and write header
	[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
	
	$SplitVPN = $false
	$reconnectVPN = $false
	
	try {
		#region check Netskope Client
		if (!($RemoveConnection)) {
			If ((Check-RunningProcess -ProcessName 'stagentsvc') -and (Check-RunningProcess -ProcessName 'stagentui')) {
				Log-ScriptEvent -Value "Netskope Client found; VPN will be initialized with Split Tunneling" -Severity 'INFO' -Component $CmdletName
				$SplitVPN = $true
			}
			else {
				Log-ScriptEvent -Value "Netskope Client not found; VPN will be initialized without Split Tunneling" -Severity 'INFO' -Component $CmdletName
			}
		}
		#endregion
		
		#region check existing VPN connections
		[Array]$ExistingVPNConnections = Get-VpnConnection -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $VPNConnectionPreFix }
		
		Log-ScriptEvent -Value "[$($ExistingVPNConnections.count)] VPN connections found: [$($ExistingVPNConnections.Name -join ',')]" -Severity 'INFO' -Component $CmdletName
		if ($Name -notin $ExistingVPNConnections.Name) {
			Log-ScriptEvent -Value "[$Name]: not exists; will be created" -Severity 'INFO' -Component $CmdletName
			$script:VPNConnections += New-Object -TypeName 'PSObject' -Property @{
				Name                  = $Name
				ServerAddress         = $GW
				SplitTunneling        = $SplitVPN
				DestinationPrefixList = $DestinationPrefixList
				Proxy                 = $Proxy
				Process               = 'Create'
				Reconnect             = $false
			}
		}
		foreach ($ExistingVPNConnection in $ExistingVPNConnections) {
			if ($ExistingVPNConnection.Name -eq $Name) {
				Log-ScriptEvent -Value "[$Name][Gateway]: Current [$($ExistingVPNConnection.ServerAddress)], Target [$GW]" -Severity 'INFO' -Component $CmdletName
				Log-ScriptEvent -Value "[$Name][SplitTunneling]: Current [$($ExistingVPNConnection.SplitTunneling)], Target [$SplitVPN]" -Severity 'INFO' -Component $CmdletName
				Log-ScriptEvent -Value "[$Name][DestinationPreFix]: Current [$(($ExistingVPNConnections.routes).destinationprefix -join ', ')], Target [$($DestinationPrefixList -join ', ')]" -Severity 'INFO' -Component $CmdletName
				Log-ScriptEvent -Value "[$Name][Proxy]: Current [$($ExistingVPNConnection.Proxy.AutoConfigurationScript)], Target [$Proxy]" -Severity 'INFO' -Component $CmdletName
				if (($GW -ne $ExistingVPNConnection.ServerAddress) -or ($SplitVPN -ne $ExistingVPNConnection.SplitTunneling) -or ($SplitVPN -and (!(($ExistingVPNConnections.routes).destinationprefix) -or (Compare-Object ($ExistingVPNConnections.routes).destinationprefix $DestinationPrefixList)))) {
					$updateVPN = $true
					$reconnectVPN = $true
				}
				if ($Proxy -ne $ExistingVPNConnection.Proxy.AutoConfigurationScript) { $updateVPN = $true }
				
				if ($updateVPN) {
					Log-ScriptEvent -Value "[$Name]: exists; update required" -Severity 'INFO' -Component $CmdletName
					$script:VPNConnections += New-Object -TypeName 'PSObject' -Property @{
						Name                  = $Name
						ServerAddress         = $GW
						ConnectionStatus      = $ExistingVPNConnection.ConnectionStatus
						SplitTunneling        = $SplitVPN
						DestinationPrefixList = $DestinationPrefixList
						Proxy                 = $Proxy
						Process               = 'Update'
						Reconnect             = $reconnectVPN
					}
				}
				else { Log-ScriptEvent -Value "[$Name]: exists; no update required" -Severity 'INFO' -Component $CmdletName }
			}
			else {
				Log-ScriptEvent -Value "[$($ExistingVPNConnection.Name)]: exists; will be removed" -Severity 'INFO' -Component $CmdletName
				$script:VPNConnections += New-Object -TypeName 'PSObject' -Property @{
					Name             = $ExistingVPNConnection.Name
					Process          = 'Remove'
					Reconnect        = $true
					ConnectionStatus = $ExistingVPNConnection.ConnectionStatus
				}
			}
		}
		#endregion
	}
	catch {
		Log-ScriptEvent -Value "Error while evaluating VPN connections. `n$($_.Exception.Message)" -Severity 'ERROR' -Component $CmdletName
		Write-Output -InputObject $ModuleErrorCode; return
	}
	
	Write-Output -InputObject 0; return
}
#endregion

#region Module Process-VPNConnection
function Process-VPNConnection {
	[CmdletBinding()]
	param ()
	
	[string]$ScriptPhase = 'Process-VPNConnection'
	[int]$ModuleErrorCode = 92
	
	## Get the name of this function and write header
	[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
	
	try {
		#Disconnect VPN connection
		$ConnectionWasDisconnected = $false
		foreach ($VPNConnection in ($script:VPNConnections | Where-Object { ($_.Reconnect -eq $true) -and ($_.ConnectionStatus -eq 'Connected') })) {
			Log-ScriptEvent -Value "[$($VPNConnection.Name)]: Disconnecting VPN connection." -Severity 'INFO' -Component $CmdletName
			$result = rasdial $VPNConnection.Name /DISCONNECT
			Log-ScriptEvent -Value "[$($VPNConnection.Name)]: Return value for 'rasdial [$VPNConnection.Name] /DISCONNECT': [$result]." -Severity 'INFO' -Component $CmdletName
			$ConnectionWasDisconnected = $true
		}
		
		#Remove VPN connections
		foreach ($VPNConnection in ($script:VPNConnections | Where-Object { ($_.Process -eq 'Remove') -or (($_.Process -eq 'Update') -and ($_.Reconnect -eq $true)) })) {
			try {
				Remove-VpnConnection -Name $VPNConnection.Name -force -ErrorAction Stop
				Log-ScriptEvent -Value "[$($VPNConnection.Name)]: Successfully removed VPN connection." -Severity 'INFO' -Component $CmdletName
			}
			catch {
				Log-ScriptEvent -Value "[$($VPNConnection.Name)]: Error while removing VPN connection. `n$($_.Exception.Message)" -Severity 'ERROR' -Component $CmdletName
				Write-Output -InputObject $ModuleErrorCode; return
			}
		}
		
		#Create/Recreate VPN connection
		foreach ($VPNConnection in ($script:VPNConnections | Where-Object { ($_.Process -eq 'Create') -or (($_.Process -eq 'Update') -and ($_.Reconnect -eq $true)) })) {
			#creating VPN connection
			try {
				Add-VpnConnection -name $VPNConnection.Name `
					-TunnelType Ikev2 `
					-AuthenticationMethod MachineCertificate `
					-ServerAddress $VPNConnection.ServerAddress `
					-Force `
					-ErrorAction Stop
				Log-ScriptEvent -Value "[$($VPNConnection.Name)]: Successfully add VPN connection." -Severity 'INFO' -Component $CmdletName
			}
			catch {
				Log-ScriptEvent -Value "[$($VPNConnection.Name)]: Error while adding VPN connection. `n$($_.Exception.Message)" -Severity 'ERROR' -Component $CmdletName
				Write-Output -InputObject $ModuleErrorCode; return
			}
			#set VPN connection parameter
			if ($VPNConnection.SplitTunneling) {
				try {
					Set-VpnConnection -Name $VPNConnection.Name `
						-SplitTunneling $VPNConnection.SplitTunneling `
						-ErrorAction Stop
					Log-ScriptEvent -Value "[$($VPNConnection.Name)]: Successfully set VPN connection parameter." -Severity 'INFO' -Component $CmdletName
				}
				catch {
					Log-ScriptEvent -Value "[$($VPNConnection.Name)]: Error while setting VPN connection parameter. `n$($_.Exception.Message)" -Severity 'ERROR' -Component $CmdletName
					Write-Output -InputObject $ModuleErrorCode; return
				}
			}
			#set VPN connection route parameter
			if ($VPNConnection.SplitTunneling) {
				try {
					foreach ($DestinationPreFix in $VPNConnection.DestinationPrefixList) {
						Add-VpnConnectionRoute -ConnectionName $VPNConnection.Name `
							-DestinationPrefix $DestinationPreFix `
							-RouteMetric 2 `
							-ErrorAction Stop
						Log-ScriptEvent -Value "[$($VPNConnection.Name)]: Successfully add VPN route metric [$DestinationPreFix]." -Severity 'INFO' -Component $CmdletName
					}
				}
				catch {
					Log-ScriptEvent -Value "[$($VPNConnection.Name)]: Error while adding VPN route metric [$DestinationPreFix]. `n$($_.Exception.Message)" -Severity 'ERROR' -Component $CmdletName
					Write-Output -InputObject $ModuleErrorCode; return
				}
			}
			#set VPN connection IPSec parameter
			try {
				Set-VpnConnectionIPsecConfiguration -name $VPNConnection.Name `
					-AuthenticationTransformConstants SHA256128 `
					-CipherTransformConstants AES256 `
					-EncryptionMethod AES256 `
					-IntegrityCheckMethod SHA256 `
					-DHGroup Group14 `
					-PfsGroup PFS2048 `
					-Force `
					-ErrorAction Stop
				Log-ScriptEvent -Value "[$($VPNConnection.Name)]: Successfully set VPN connection IPSec configuration." -Severity 'INFO' -Component $CmdletName
			}
			catch {
				Log-ScriptEvent -Value "[$($VPNConnection.Name)]: Error while set VPN connection IPSec configuration. `n$($_.Exception.Message)" -Severity 'ERROR' -Component $CmdletName
				Write-Output -InputObject $ModuleErrorCode; return
			}
		}
		
		#Update VPN connection
		foreach ($VPNConnection in ($script:VPNConnections | Where-Object { ($_.Process -ne 'Remove') })) {
			#set VPN connection proxy
			try {
				Set-VPnConnectionProxy -ConnectionName $VPNConnection.Name `
					-AutoConfigurationScript $VPNConnection.Proxy `
					-ErrorAction Stop
				Log-ScriptEvent -Value "[$($VPNConnection.Name)]: Successfully set VPN connection Proxy." -Severity 'INFO' -Component $CmdletName
			}
			catch {
				Log-ScriptEvent -Value "[$($VPNConnection.Name)]: Error while set VPN connection Proxy. `n$($_.Exception.Message)" -Severity 'ERROR' -Component $CmdletName
				Write-Output -InputObject $ModuleErrorCode; return
			}
		}
		
		#reconnect VPN connection
		if ($ConnectionWasDisconnected) {
			foreach ($VPNConnection in ($script:VPNConnections | Where-Object { ($_.Process -ne 'Remove') })) {
				Log-ScriptEvent -Value "[$($VPNConnection.Name)]: Connecting existing VPN connection." -Severity 'INFO' -Component $CmdletName
				$result = rasdial $VPNConnection.Name
				Log-ScriptEvent -Value "[$($VPNConnection.Name)]: Return value for 'rasdial [$VPNConnection.Name]': [$result]." -Severity 'INFO' -Component $CmdletName
			}
		}
	}
	catch {
		Log-ScriptEvent -Value "Error while creating VPN connection. `n$($_.Exception.Message)" -Severity 'ERROR' -Component $CmdletName
		Write-Output -InputObject $ModuleErrorCode; return
	}
	Write-Output -InputObject 0; return
}
#endregion

#region Module Delete-VPNConnection
function Delete-VPNConnection {
	[CmdletBinding()]
	param ()
	
	[string]$ScriptPhase = 'Delete-VPNConnection'
	[int]$ModuleErrorCode = 93
	
	## Get the name of this function and write header
	[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
	
	try {
		if (($ExistingConnectionName = (Get-VpnConnection -ErrorAction SilentlyContinue).Name) -eq $Name) {
			foreach ($ConnectionName in $ExistingConnectionName) {
				Log-ScriptEvent -Value "[$ConnectionName]: VPN connection exists." -Severity 'INFO' -Component $CmdletName
				
				$vpn = Get-VpnConnection -name $ConnectionName
				if ($vpn.ConnectionStatus -eq "Connected") {
					Log-ScriptEvent -Value "[$ConnectionName]: Disconnecting VPN connection." -Severity 'INFO' -Component $CmdletName
					$result = rasdial $ConnectionName /DISCONNECT
					Log-ScriptEvent -Value "[$ConnectionName]: Return value for 'rasdial [$ConnectionName] /DISCONNECT': [$result]." -Severity 'INFO' -Component $CmdletName
				}
				Remove-VpnConnection -Name $ConnectionName -Force -ErrorAction Stop
				Log-ScriptEvent -Value "[$ConnectionName]: VPN connection successfully removed." -Severity 'INFO' -Component $CmdletName
			}
		}
		else {
			Log-ScriptEvent -Value "[$Name]: VPN connection not exists and therefore cannot be removed." -Severity 'INFO' -Component $CmdletName
		}
	}
	catch {
		Log-ScriptEvent -Value "[$Name]: Error while removing VPN connection. `n$($_.Exception.Message)" -Severity 'ERROR' -Component $CmdletName
		Write-Output -InputObject $ModuleErrorCode; return
	}
	Write-Output -InputObject 0; return
}
#endregion

#region module Modify-VPNConnection Metric
function Modify-VPNConnectionMetric {
	[CmdletBinding()]
	param ()
	
	[string]$ScriptPhase = 'Modify-VPNConnectionMetric'
	[int]$ModuleErrorCode = 94
	
	## Get the name of this function and write header
	[string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
	
	## Functions parameters
	[string]$PBKFilepath = $env:APPDATA + '\Microsoft\Network\Connections\Pbk\rasphone.pbk'
	[bool]$bolChanged = $false
	[bool]$bolStart = $false
	[int]$intLine = 0
	[Array]$newContent = @()
	
	try {
		If (Test-Path -Path $PBKFilepath -PathType leaf) {
			Log-ScriptEvent -Value "VPN configuration file exists [$PBKFilepath]" -Severity 'INFO' -Component $CmdletName
			#Read file
			try {
				$content = Get-Content -Path $PBKFilepath -Force -ErrorAction Stop
			}
			catch {
				Log-ScriptEvent -Value "Error while open INI file. `n$($_.Exception.Message)" -Severity 'ERROR' -Component $CmdletName
				Write-Output -InputObject $ModuleErrorCode; return
			}
			
			#Check each line in the INI file
			try {
				$content | ForEach-Object {
					$intLine += 1
					If ($_.StartsWith("[" + $VPNConnectionPreFix)) {
						$bolStart = $true
						Log-ScriptEvent -Value "VPN connection [$_] section found in line [$intLine]" -Severity 'INFO' -Component $CmdletName
					}
					elseif ($_.StartsWith("[")) {
						$bolStart = $false
					}
					If ($bolStart -and $_ -eq "IpInterfaceMetric=0") {
						$newContent += "IpInterfaceMetric=1"
						$bolChanged = $true
						Log-ScriptEvent -Value "Daimler VPN connection metric changed in line [$intLine]" -Severity 'INFO' -Component $CmdletName
					}
					else {
						$newContent += $_
					}
				}
			}
			catch {
				Log-ScriptEvent -Value "Error while reading INI file. `n$($_.Exception.Message)" -Severity 'ERROR' -Component $CmdletName
				Write-Output -InputObject $ModuleErrorCode; return
			}
			
			#INI file must be changed, replace existing file
			if ($bolChanged) {
				try {
					#Save file as backup
					Copy-Item -Path $PBKFilepath -Destination $PBKFilepath".old" -Force -ErrorAction Stop
					Log-ScriptEvent -Value "Backup VPN configuration file" -Severity 'INFO' -Component $CmdletName
				}
				catch {
					Log-ScriptEvent -Value "Error while backup VPN configuration file. `n$($_.Exception.Message)" -Severity 'ERROR' -Component $CmdletName
					Write-Output -InputObject $ModuleErrorCode; return
				}
				try {
					#Create new configuration file
					$newContent | Set-Content -Path $PBKFilepath -Force -ErrorAction Stop
					Log-ScriptEvent -Value 'VPN configuration file succesfully updated.' -Severity 'INFO' -Component $CmdletName
				}
				catch {
					Log-ScriptEvent -Value "Error while create new VPN configuration file. `n$($_.Exception.Message)" -Severity 'ERROR' -Component $CmdletName
					Write-Output -InputObject $ModuleErrorCode; return
				}
			}
			else {
				Log-ScriptEvent -Value 'No change in VPN configuration file required.' -Severity 'INFO' -Component $CmdletName
			}
		}
		else {
			Log-ScriptEvent -Value "VPN configuration file does not exists [$PBKFilepath]" -Severity 'WARNING' -Component $CmdletName
			#Write-Output -InputObject $ModuleErrorCode; return - Return code required for non existing VPN?
		}
	}
	catch {
		Log-ScriptEvent -Value "Error while remove VPN connection. `n$($_.Exception.Message)" -Severity 'ERROR' -Component $CmdletName
		Write-Output -InputObject $ModuleErrorCode; return
	}
	Write-Output -InputObject 0; return
}
#endregion

#region Variables
[Version]$Version = '1.6.0.0'
[string]$component = [io.path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
#if (!($LogPath)) { $LogPath = 'C:\ITM\SWDeployLogs' }
if (!($LogPath)) { $LogPath = "$env:SystemDrive\Logs" }
[string]$logfile = "$LogPath\$component.log"
[string]$scriptRoot = Split-Path -Path ($MyInvocation.MyCommand.Definition) -Parent
[string]$ScriptPhase = 'MAIN'
[string]$PBKFilepath = $env:APPDATA + '\Microsoft\Network\Connections\Pbk\rasphone.pbk'
[boolean]$LogInit = $false
#endregion


Log-ScriptEvent -Value "################################### $component $Version ###################################" -Severity 'INFO'
Log-ScriptEvent -Value "Parameter: VPNName: $Name" -Severity 'INFO'
Log-ScriptEvent -Value "Parameter: VPNGW: $GW" -Severity 'INFO'
Log-ScriptEvent -Value "Parameter: ProxyScript: $Proxy" -Severity 'INFO'
Log-ScriptEvent -Value "Parameter: DestinationPrefixList: $($DestinationPrefixList -join ', ')" -Severity 'INFO'
Log-ScriptEvent -Value "Parameter: RemoveConnection: $RemoveConnection" -Severity 'INFO'
Log-ScriptEvent -Value "Parameter: VPNConnectionPreFix: $VPNConnectionPreFix" -Severity 'INFO'
Log-ScriptEvent -Value "Environment: Current Username: $env:USERNAME" -Severity 'INFO'

#region Execute Modules
If (($ModuleReturnCode = Check-ScriptPrerequisites) -ne 0) { Exit-Script -ExitCode $ModuleReturnCode }
If ($RemoveConnection -eq $false) { if (($ModuleReturnCode = Eval-VPNConnections) -ne 0) { Exit-Script -ExitCode $ModuleReturnCode } }
If ($RemoveConnection -eq $false) { if (($ModuleReturnCode = Process-VPNConnection) -ne 0) { Exit-Script -ExitCode $ModuleReturnCode } }
If ($RemoveConnection -eq $false) { if (($ModuleReturnCode = Modify-VPNConnectionMetric) -ne 0) { Exit-Script -ExitCode $ModuleReturnCode } }
If ($RemoveConnection -eq $true) { if (($ModuleReturnCode = Delete-VPNConnection) -ne 0) { Exit-Script -ExitCode $ModuleReturnCode } }
#endregion Execute Modules

Exit-Script -ExitCode 0

# SIG # Begin signature block
# MIIocAYJKoZIhvcNAQcCoIIoYTCCKF0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAfbqA3626PEerb
# EAUfQ4ODNkJtABBCMD+dpPsZlCVtj6CCIW0wggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggawMIIEmKADAgECAhAIrUCyYNKcTJ9ezam9k67ZMA0GCSqG
# SIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0zNjA0MjgyMzU5NTlaMGkx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEzODQg
# MjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDVtC9C0Cit
# eLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0JAfhS0/TeEP0F9ce2vnS
# 1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJrQ5qZ8sU7H/Lvy0daE6ZM
# swEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhFLqGfLOEYwhrMxe6TSXBC
# Mo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+FLEikVoQ11vkunKoAFdE3
# /hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh3K3kGKDYwSNHR7OhD26j
# q22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJwZPt4bRc4G/rJvmM1bL5
# OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQayg9Rc9hUZTO1i4F4z8ujo
# 7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbIYViY9XwCFjyDKK05huzU
# tw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchApQfDVxW0mdmgRQRNYmtwm
# KwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRroOBl8ZhzNeDhFMJlP/2NP
# TLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IBWTCCAVUwEgYDVR0TAQH/
# BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+YXsIiGX0TkIwHwYDVR0j
# BBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8E
# PDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEEATANBgkq
# hkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql+Eg08yy25nRm95RysQDK
# r2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFFUP2cvbaF4HZ+N3HLIvda
# qpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1hmYFW9snjdufE5BtfQ/g+
# lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3RywYFzzDaju4ImhvTnhOE7a
# brs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5UbdldAhQfQDN8A+KVssIhdXNS
# y0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw8MzK7/0pNVwfiThV9zeK
# iwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnPLqR0kq3bPKSchh/jwVYb
# KyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatEQOON8BUozu3xGFYHKi8Q
# xAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bnKD+sEq6lLyJsQfmCXBVm
# zGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQjiWQ1tygVQK+pKHJ6l/aCn
# HwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbqyK+p/pQd52MbOoZWeE4w
# gga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBH
# NDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1
# c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0Zo
# dLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi
# 6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNg
# xVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiF
# cMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJ
# m/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvS
# GmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1
# ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9
# MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7
# Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bG
# RinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6
# X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAd
# BgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJx
# XWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGln
# aWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJo
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNy
# bDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQEL
# BQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxj
# aaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0
# hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0
# F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnT
# mpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKf
# ZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzE
# wlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbh
# OhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOX
# gpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EO
# LLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wG
# WqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWg
# AwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# MB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEy
# NTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3
# zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8Tch
# TySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWj
# FDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2Uo
# yrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjP
# KHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KS
# uNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7w
# JNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vW
# doUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOg
# rY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K
# 096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCf
# gPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zy
# Me39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezL
# TjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsG
# AQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNy
# dDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5j
# cmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEB
# CwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZ
# D9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/
# ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu
# +WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4o
# bEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2h
# ECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasn
# M9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol
# /DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgY
# xQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3oc
# CVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcB
# ZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzCCB3swggVj
# oAMCAQICEAjQXG/3OxcKfUoCFFMn1rgwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENB
# MTAeFw0yNDEwMTYwMDAwMDBaFw0yNTEwMTUyMzU5NTlaMIGCMQswCQYDVQQGEwJE
# RTEbMBkGA1UECAwSQmFkZW4tV8O8cnR0ZW1iZXJnMSAwHgYDVQQHExdMZWluZmVs
# ZGVuLUVjaHRlcmRpbmdlbjEZMBcGA1UEChMQRGFpbWxlciBUcnVjayBBRzEZMBcG
# A1UEAxMQRGFpbWxlciBUcnVjayBBRzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAPpo9RrT/8pxiKmCXBkcB06GH/ndroFfNRP27rGUoEcQnHVn7g6CkbWs
# OvVYIC6bABe431rc8ihaqTyCAUEbXypESKravpKutd2lg9roBupB57xc8aQAsSXI
# JKpK8r2S6dWXXhS6cO1cn44oxFHsDchQyrVkq5a1fa8gmi9rvhhZZz8GK0DdaFm7
# KgKgYHSilC5ePHZiKYjDw3FLv9sFDZHBDnpzo26LL0CWaG7lnWpRuqPl1fd969B5
# LJi3rPJMWfOQUcA3paRZDpjq6hnx4b2wOvh+WPQC/XO/9+D4Z3hMUmX4U+3HnALj
# 6Vmm1Zp6BQz5eOZ07O0euC7DsnhvgucFdojVaK27Wq4QUS8KVTnBJHHuH9GGKidW
# 3xXQ+6DmOR1og7kXBIrwz4ClzVQ9AFRSK7CcSyi7+qfQnF9S+WWWnGTRfXVuCKBy
# eyr+NIwczkaRNJSo47TZTzfvryeJJtlLKw76TeH1xyYSe+cDRxNHtIBFwD8OS1BI
# nXp3W6CreMFJXlAdVcsrsW8aF4VrRJMFF4NA+BP0+eit2+n2gtyWiH+m4SIOD2t6
# /NfzhLsh/vpRtFN0uSHjElRHSTof22q/1oPXbLurzfEefHSVB/VBzRwK9enNBDqb
# 4R21yvnVtgFZOGKvss2KjCBH9kce/iEX1hY/9xu6LrAmwOJ39X9DAgMBAAGjggID
# MIIB/zAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiIZfROQjAdBgNVHQ4EFgQU
# rw8vACpdU3HpWs1pKx3LNfpoMDowPgYDVR0gBDcwNTAzBgZngQwBBAEwKTAnBggr
# BgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMA4GA1UdDwEB/wQE
# AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0fBIGtMIGqMFOgUaBPhk1o
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2ln
# bmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGgT4ZNaHR0cDovL2NybDQu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2
# U0hBMzg0MjAyMUNBMS5jcmwwgZQGCCsGAQUFBwEBBIGHMIGEMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYBBQUHMAKGUGh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5n
# UlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQCMAAwDQYJKoZIhvcNAQEL
# BQADggIBABcsVq/8or5+BBaKprtentyA473O484bthU/yWoZNpCgPaFipIn3w4rm
# UWUYvPQmE10NOJwpAswy0XkY8bT6VsgG5S6vXUxZzXpyZo9hy+BS7moTZE2/jG8D
# xOJg8VqSkO+qkgir2/ti7lEqmu3zyAqsEKMNrMnSnhRe+9n2Kba1oX//5zxul4He
# V1YvEKypw3d09LixangOYaQL7F0/Rlcnf1LQqAEWHM8gxIa6aUE1OCiPjehZrjOR
# Sh4hGwD50JpL+f4NCZLSIRNGCF3lm0jC8Sib+nacgiwFnvCfT1bcbhu7/6dk9ioL
# YtdHWMPI8KoaeoP259Bpe9W7K0+yuaLDfTOMsVQvQwB+adQOJRZL3sPpbWR4MZop
# DvLyUQ7STko6ITW9je5Kyw7Qo/S71FobC52U9LluZWGPQOWG3iUoFUW9/B9wMwMl
# FqkXm6ensfOgNsS3znMk0unOhYrmGmOcJCLw7F1Oc/YEUgNb4aGiFkIGyw7t7puE
# dF84dG2/G40bm8ZNnVs+sGVXdAJ/nGUjMocVRLJLo677bYNxLGhzjDbA36f/1vme
# yqWyFDl7qRIMhEHxKybnxYFT4s44igyyHePCtFEGRDnooSitTWC4G5nmDbTAgo50
# cNm5cp6CJo/aSOkhnzMNsvcEicrQpsESJlEaAxBXimmlppzsaqCzMYIGWTCCBlUC
# AQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/
# BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYg
# U0hBMzg0IDIwMjEgQ0ExAhAI0Fxv9zsXCn1KAhRTJ9a4MA0GCWCGSAFlAwQCAQUA
# oIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisG
# AQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcN
# AQkEMSIEIDJwvt+h9nTd6eMmolCqUU+yisOT0c5WOanypL03KSepMA0GCSqGSIb3
# DQEBAQUABIICAJeAlVJtKeC89kkFO/K3dZZBgt2jfwHpHd0zUebscaEXUMqqjVYz
# jP2gbko+Rka1uzxcMkuxoqqqM2LZxexUWOsAOVNc7agt0AARrjPlbtrzfYrbRVDu
# RW1f94WsAzoPZm4pQ4cn10tfsX2YDXPqr0rCcOBONbBycHZfBtrOc2rDkPXAKmQD
# t5tbv3I+OFDLz5NsHrXxb3EXuQNdqgOJVZdObqII/Au8YZ7cla8Kio3lKuyR10Jf
# snJogfh6kNyxvdLjmnpoiHkCzjLFdXupwRnsNSyivPGuejjh1WeKBpOXzjR8f5z0
# x9nHfSVVPIVn31JqHUEWRphbwJRhkF4yntr2rC5gLrXmUpcdWZuqHgUvBmLmaIKS
# HumB/XycpUZYktii+gFuhf1IYwQE4v8mLxm5SBYsbi17ZgmbleC/FLSsuO5nygp3
# ycTZIXPL+oF2xjW2OgNIHXGOxD6hPgLPLezT01XwpD0bNXfFvBiGEuDw3lNJfdLz
# wTCZMRNBdVlQghFnCP8k3YaLH4l5Xl1KeM6vWa+3BmEOoS6LD3mvAyhylNsmwuR7
# gRz1q0F+4HUlNIs0f4q4Jn+mxMg50ZAG49MDwSdzenpoQ2P1H5Z1kbPPAM0tkYIv
# 2fwtfPJfp/qpLz+obSurMIs8PHHNqWuyYHGK7hPfDGEvX1hp8Sd46Fc5oYIDJjCC
# AyIGCSqGSIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0
# IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC
# 0cR2p5V0aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0B
# BwEwHAYJKoZIhvcNAQkFMQ8XDTI1MDYxODE2NTgzMlowLwYJKoZIhvcNAQkEMSIE
# IKfWeYdTzqu04iH8VzN6oooLn7bJlQp+9JITqqWeuCexMA0GCSqGSIb3DQEBAQUA
# BIICAHrkIN2reV4zgYiJ90ZvxVqhz0W2nPDrubzgtZzN9R8+RRr5b+PwpIO8mpM6
# 7bTkKJgvKq+r0Eiyq9yj/Cor47U0aIfvZitEg0KFk0/Gsg6ZIUmJn4WToa0NZec6
# /KpPeMkVZHYXKfxa2DDndQv0uvHfm735OYAtPQvTlrz53rFkDSzRG3ehDARZsHIU
# eR7Hij7lu6Vli68ahfufXZpRURWU6WhcnFVq0XA6BAw19OazWSUJDtgSEUHt7i16
# xQa1NVtPHmONI8eleLzXSoHQq2iBhc3GP2S62avjmjmCLseyWK8+43MKxUidJE29
# rzzR0X4h2oQWVbkUy4iQiKlwp/E4qlm78dhCfnTufIsENpuqVLQh3JUhlLimWoEq
# xgPd+7pLs94kOzL/nSGbL/wRwoC/5gnjYzHn/tUaDyPg+V+cSMZYWplvfAzlkLDn
# Lp5loo5AfqnccSzdIB/WmdRLFDjr4Mb1Jni8i4Pa4q98FowIAAMGlhDYRIBKPHh+
# feJIUN4Xx4i/l6Z0Uc6DAhFlUs3K3TPQRHY/wE3YzH+l4Zb2zpmJILAoUW7DHf2s
# Z8pzhtg/6nNfC6nB+H5VWyMH7D4OsdEWJIMs+5sdmdqcqvCWeonE0Vy4bZBZ/B/Y
# vjFrMHNXYDoYdYfU6BYSRDLxW/ZmjEPsdVzCP0uV5F5oNywl
# SIG # End signature block
