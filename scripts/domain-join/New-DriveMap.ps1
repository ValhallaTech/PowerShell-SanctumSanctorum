$localPath = V:
$remotePath = \\vision2\backups
$credential = Get-Credential

Write-Host "Mapping vision2 folder ..."
try {
    New-SmbMapping -LocalPath $localPath -RemotePath $remotePath -UserName $credential.UserName -Password $credential.GetNetworkCredential().Password
}
catch 
{
    Write-Error -Exception ([System.UnauthorizedAccessException]::new('Unauthorized Access')) -ErrorAction Stop
}

Write-Host "Calling Copy-vision2.bat ..."
Start-Process -FilePath ".\Copy-vision2.bat"
