$version = "1.1.0"
$systemDrive = $env:SystemDrive
$userProfile = "Ramadmin"
$WebCache = "$systemDrive\users\$userProfile\AppData\Local\Microsoft\Windows\WebCache"
$taskhostProcess = "taskhostw"

Write-Host "WebCache Directory Eradicator"
Write-Host $version
Write-Host "By Fred Smith III"

try {
    Stop-Process -Name $taskhostProcess
}
catch {
    "$taskhostProcess could not be stopped."
}
finally {
    if (Test-Path -Path $WebCache)
    {
        Write-Host "Deleting WebCache folder ..."
        Remove-Item -Path $WebCache -Recurse -Force
        Write-Host "WebCache folder deleted"
    }
    else {
        Write-Host "WebCache directory does not exist."
    }
}
