# BitsTransfer.ps1
# PowerShell Bits Transfer

$ErrorActionPreference = "Stop"

Import-Module BitsTransfer

# URL to your large download file here
# EXAMPLE: Windows Server 2008 R2 SP1 Release Candidate
$src  = "http://download.microsoft.com/download/0/A/F/0AFB5316-3062-494A-AB78-7FB0D4461357/windows6.1-KB976932-X86.exe"

# Local file path here
$dest = "C:\Users\username\Downloads\"

# We make a unique display name for the transfer so that it can be uniquely
# referenced by name and will not return an array of jobs if we have run the
# script multiple times simultaneously.
$displayName = "MyBitsTransfer " + (Get-Date)
Start-BitsTransfer `
    -Source $src `
    -Destination $dest `
    -DisplayName $displayName `
    -Asynchronous
$job = Get-BitsTransfer $displayName

# Create a holding pattern while we wait for the connection to be established
# and the transfer to actually begin.  Otherwise the next Do...While loop may
# exit before the transfer even starts.  Print the job status as it changes
# from Queued to Connecting to Transferring.
# If the download fails, remove the bad job and exit the loop.
$lastStatus = $job.JobState
Do {
    If ($lastStatus -ne $job.JobState) {
        $lastStatus = $job.JobState
        $job
    }
    If ($lastStatus -like "*Error*") {
        Remove-BitsTransfer $job
        Write-Host "Error connecting to download."
        Exit
    }
}
while ($lastStatus -ne "Transferring")
$job

# Print the transfer status as we go:
#   Date & Time   BytesTransferred   BytesTotal   PercentComplete
do {
    Write-Host (Get-Date) $job.BytesTransferred $job.BytesTotal `
        ($job.BytesTransferred/$job.BytesTotal*100)
    Start-Sleep -s 10
}
while ($job.BytesTransferred -lt $job.BytesTotal)

# Print the final status once complete.
Write-Host (Get-Date) $job.BytesTransferred $job.BytesTotal `
    ($job.BytesTransferred/$job.BytesTotal*100)

Complete-BitsTransfer $job

# Ashley McGlone
# November, 2010
# https://blogs.technet.microsoft.com/ashleymcglone/2010/11/17/big-downloads-with-powershell/

# Original PowerShell & BITS article by Jeffrey Snover here:
#   https://devblogs.microsoft.com/powershell/transferring-large-files-using-bits/
# Mr. Snover's article was based on pre-release code.
# This version uses the updated RTM syntax.
# This version does a checking loop to see if the file has completed transfer yet,
# and automatically completes the transfer if it is done.
# It also displays progress of the download.