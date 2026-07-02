$localPath = "V:"
$remotePath = "\\vision2\backups"
$credential = Get-Credential
New-SmbMapping -LocalPath $localPath -RemotePath $remotePath -UserName $credential.UserName -Password $credential.GetNetworkCredential().Password