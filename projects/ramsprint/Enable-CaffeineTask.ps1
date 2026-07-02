$public = $env:PUBLIC
$domainname = "WSSUMITS"
$params = @{
    TaskName = "Enable-Caffeine"
    Action = New-ScheduledTaskAction -Execute "$public\Start-Caffeine.bat"
    Trigger = New-ScheduledTaskTrigger -AtLogon
    Force = $true
    User = "$domainname\RAMSPRINT"
}

Register-ScheduledTask @params
