# 1. Automatically find the installation folder
$WinGetPath = Get-ChildItem -Path "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Filter "claude.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty DirectoryName
$NativePath = "$env:USERPROFILE\.local\bin"

# 2. Determine which folder exists
if ($WinGetPath) { $TargetDir = $WinGetPath } elseif (Test-Path $NativePath) { $TargetDir = $NativePath } else { Write-Error "Claude Code binary folder not found."; return }

# 3. Permanently append it to your User PATH
$OldPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
if ($OldPath -notlike "*$TargetDir*") {
    [System.Environment]::SetEnvironmentVariable("Path", "$OldPath;$TargetDir", "User")
    $env:Path += ";$TargetDir"
    Write-Host "Successfully added $TargetDir to PATH!" -ForegroundColor Green
} else {
    Write-Host "Folder already in PATH registry. Try restarting your terminal." -ForegroundColor Yellow
}
