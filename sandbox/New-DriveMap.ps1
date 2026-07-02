$username = Read-Host "What is your username?"
Pause

New-SmbMapping -LocalPath V: -RemotePath \\vision2\backups -UserName $username -WhatIf