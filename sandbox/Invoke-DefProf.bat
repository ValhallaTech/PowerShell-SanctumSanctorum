@ECHO off
set powerShell = "powershell"
set pubPath = "%Public%\Downloads"
set script = "Invoke-DefProf.ps1"
set scriptPath = "%pubPath%\%script%"

ECHO Running PowerShell script, Remove-Webcache.ps1 with Execution Policy set to bypass ...
%powerShell% %scriptPath%
