$public = $env:PUBLIC
$domainname = "WSSUMITS"
$params = @{
    TaskName = "Enable-winkill"
    Action = New-ScheduledTaskAction -Execute "$public\WinKill.exe"
    Trigger = New-ScheduledTaskTrigger -AtLogon
    Force = $true
    User = "$domainname\RAMSPRINT"
}

Register-ScheduledTask @params
