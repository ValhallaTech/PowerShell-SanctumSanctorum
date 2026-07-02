# Repair-Printing

<#
.SYNOPSIS
Stops the print spooler, clears the print queue, and restarts the print spooler.

.DESCRIPTION
This script will:
1. Stop the Print Spooler service.
2. Empty the directory C:\Windows\System32\spool\printers, which clears the print queue.
3. Restart the Print Spooler service.

.NOTES
File Name      : Repair-Printing.ps1
Author         : Fred Smith III
Prerequisite   : PowerShell V2
Copyright 2023: Valhalla Tech

.EXAMPLE
This example shows how to run the script:
.\ClearPrintQueue.ps1
#>

# General Variables
# Print queue folder with wildcard
$queueFolder = "C:\Windows\System32\spool\printers\*"

# Stop the Print Spooler service
Stop-Service -Name Spooler -Force

# Empty the directory C:\Windows\System32\spool\printers
Get-ChildItem $queueFolder -File | Remove-Item -Force

# Restart the Print Spooler service
Start-Service -Name Spooler
