<#
 # {Store operating system query and information needed in variable}
#>
$queryOS = Get-CimInstance -ClassName Win32_OperatingSystem
$comDescription = Read-Host -Prompt "Enter what you want to set the computer description to."

<#
 # {Set computer description to $comDescription variable}
#>
$queryOS.Description = $comDescription

<#
 # {Save modification method}
#>
$queryOS.put()
