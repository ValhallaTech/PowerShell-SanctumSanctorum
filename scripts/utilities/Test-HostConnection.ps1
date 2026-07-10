#Requires -Version 5.1

<#
.SYNOPSIS
Pings a list of IP addresses or hostnames read from a .txt or .csv file and reports connectivity results.

.DESCRIPTION
Reads target addresses from a plain-text file (one address per line, blank lines and lines starting
with '#' are ignored) or a CSV file (uses a column named IPAddress, ComputerName, Hostname, or Address
if present, otherwise falls back to the first column). Each address is pinged and the reachability plus
average response time is reported. Results can optionally be exported to a CSV file.

.PARAMETER Path
Path to the input .txt or .csv file containing the addresses to ping.

.PARAMETER OutputPath
Optional path to a CSV file where results will be exported.

.PARAMETER Count
Number of echo requests to send per host. Default is 2.

.EXAMPLE
.\Test-HostConnection.ps1 -Path .\hosts.txt

Pings every address listed in hosts.txt and displays the results.

.EXAMPLE
.\Test-HostConnection.ps1 -Path .\hosts.csv -OutputPath .\results.csv -Count 4

Pings every address listed in hosts.csv four times each and exports the results to results.csv.

.NOTES
File Name      : Test-HostConnection.ps1
Author         : Fred Smith III
Prerequisite   : PowerShell 5.1
Copyright 2026: Valhalla Tech
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$Path,

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [ValidateRange(1, 10)]
    [int]$Count = 2
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Get-TargetAddress {
    <#
    .SYNOPSIS
    Parses target addresses from a .txt or .csv file.

    .PARAMETER Path
    Path to the input file.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    $extension = [System.IO.Path]::GetExtension($Path).ToLowerInvariant()

    switch ($extension) {
        '.csv' {
            $rows = Import-Csv -Path $Path
            if (-not $rows) {
                return @()
            }

            $columnName = $rows[0].PSObject.Properties.Name |
                Where-Object { $_ -in @('IPAddress', 'ComputerName', 'Hostname', 'Address') } |
                Select-Object -First 1

            if (-not $columnName) {
                $columnName = $rows[0].PSObject.Properties.Name | Select-Object -First 1
            }

            return $rows | ForEach-Object { $_.$columnName } | Where-Object { $_ }
        }
        '.txt' {
            return Get-Content -Path $Path |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -and -not $_.StartsWith('#') }
        }
        default {
            throw "Unsupported file extension '$extension'. Provide a .txt or .csv file."
        }
    }
}

function Test-HostConnection {
    <#
    .SYNOPSIS
    Pings a single target and returns a connectivity result object.

    .PARAMETER TargetAddress
    The IP address or hostname to ping.

    .PARAMETER Count
    Number of echo requests to send.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$TargetAddress,

        [Parameter(Mandatory)]
        [int]$Count
    )

    $pingParams = @{
        ComputerName = $TargetAddress
        Count        = $Count
        ErrorAction  = 'SilentlyContinue'
    }

    $replies = Test-Connection @pingParams
    $successfulReplies = $replies | Where-Object { $_.StatusCode -eq 0 }

    $averageResponseMs = $null
    if ($successfulReplies) {
        $averageResponseMs = [math]::Round(($successfulReplies | Measure-Object -Property ResponseTime -Average).Average, 0)
    }

    [PSCustomObject]@{
        TargetAddress     = $TargetAddress
        Reachable         = [bool]$successfulReplies
        AverageResponseMs = $averageResponseMs
        Timestamp         = Get-Date
    }
}

# Execution
$targetAddresses = Get-TargetAddress -Path $Path

if (-not $targetAddresses) {
    Write-Warning "No target addresses were found in '$Path'."
    return
}

Write-Output "Pinging $($targetAddresses.Count) target(s)..."

$results = foreach ($targetAddress in $targetAddresses) {
    Test-HostConnection -TargetAddress $targetAddress -Count $Count
}

$results | Format-Table -AutoSize

if ($OutputPath) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Output "Results exported to '$OutputPath'."
}
