$credential = Get-Credential
$parameters = @{
    Name = "vision2bak"
    PSProvider = "Filesystem"
    Root = "\\vision2\backups"
    Credential = $credential
}

Write-Host ""
Write-Host "Mapping vision2 folder ..."
Write-Host ""

try {
    New-PSDrive @parameters
}
catch
{
    Write-Error -Exception ([System.UnauthorizedAccessException]::new('Unauthorized Access')) -ErrorAction Stop
}
