# Pulls information about the specified computers.

[CmdletBinding()]
param(
    [Parameter(
        Mandatory=$true,
        ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true,
        HelpMessage="The. Computer. Name."
    )]
    [Alias('Hostname', 'cn')]
    [string[]]$ComputerName
)
BEGIN {}
PROCESS {
foreach ($Computer in $ComputerName) {
    try {
        $session = New-CimSession -ComputerName $Computer -ErrorAction Stop
        $os = Get-CimInstance -ClassName win32_operatingsystem -CimSession $session
        $cs = Get-CimInstance -ClassName win32_computersystem -CimSession $session
        $properties = @{
            ComputerName = $Computer
            Status       = 'Connected'
            Username     = $cs.UserName
            OSVersion    = $os.Version
            Model        = $cs.Model
            Mfgr         = $cs.Manufacturer
        }
    }
    catch {
        Write-Verbose "Could not connect to $computer"
        $properties = @{
            ComputerName = $Computer
            Status       = 'Not Connected'
            Username     = $null
            OSVersion    = $null
            Model        = $null
            Mfgr         = $null
        }
    }
    finally {
        $obj = New-Object -TypeName psobject -Property $properties
        Write-Output $obj
    }
}
}
END {}
