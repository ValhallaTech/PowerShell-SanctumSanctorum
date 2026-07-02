<#
.SYNOPSIS
    Adds credentials to a list of remote servers using cmdkey.
.DESCRIPTION
    Prompts for credentials and adds them to each specified server using the cmdkey utility.
.PARAMETER servers
    An array of server names to add credentials for.
.EXAMPLE
    .\SiteCredentials.ps1
.NOTES
    Author: Fred Smith III
    Version: 1.0.0
    Date: 2024-06-26
    Company: Valhalla Tech
#>

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
            Write-Output "Credential added to $server"
        } catch {
            Write-Error "Failed to add credential to $server. $_" -Category NotImplemented
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
