$displayName = "BitsTransfer-Test"
$source = "C:\Users\smithfre_sp\Data\Creative Cloud"
$destination = "\\vision2\backups"
$priority = Foreground
$retryInterval = 60
$transferType = Upload

Get-ChildItem -Path $source -Recurse | foreach {$destination}
Start-BitsTransfer -Source $source -Destination $destination -DisplayName $displayName -Priority $priority -RetryInterval $retryInterval -TransferType $transferType
