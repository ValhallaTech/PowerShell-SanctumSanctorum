$env:Filezilla = "C:\Program Files\FileZilla FTP Client"
$protocol = "sftp"
$server = "sfs.seanc.org"
$port = "22"
$username = "wssu"
$connection = [System.String]::Concat($protocol + '://' + $username + ':' + $secretKey + '@' + $server + ':' + $port)

try {
    $secretKey = Read-Host -Prompt "Enter password" -AsSecureString
}
catch {
    if ($null -eq $secretKey) {
    }
}

Pause

filezilla.exe $connection
