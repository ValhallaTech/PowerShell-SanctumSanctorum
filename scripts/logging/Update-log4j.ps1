# Update-log4j.ps1

# General Variables
$systemDrive = $env:SystemDrive

# Variables for PoShLog checking
$modPoShLog = "PoShLog"
$chkPoShLog = Get-Module -Name $modPoShLog

# Check if PoShLog module is installed and if not install the current version
if (-not $chkPoShLog) {
    Install-Module -Name $modPoShLog
}

# Import PoShLog module
Import-Module -Name $modPoShLog

# Configure variables for logging
$logFileName = "log4j-updater.log"
$logFilePath = "$systemDrive\Logs\$logFileName"

# Create logger instance
$logger = New-Logger

# Configure logger instance
$logger |
    Set-MinimumLevel -Value Information |
    Add-SinkFile -Path $logFilePath |
    Add-SinkConsole |
    Start-Logger

Write-InfoLog "PoShLog module imported and logger configured"

# Variables for PSThreadJob checking
$modPSThreadJob = "PSThreadJob"
$chkPSThreadJob = Get-Module -Name $modPSThreadJob

# Check if PSThreadJob module is installed and if not install the current version
if (-not $chkPSThreadJob) {
    Install-Module -Name $modPSThreadJob
}

# Import PSThreadJob module
Import-Module -Name $modPSThreadJob

Write-InfoLog "PSThreadJob module imported"

$currentVersionPath = "$systemDrive/Tanium_Files/log4j-core-current.jar"
$minVersion = [System.Version]::Parse("2.20.0")

function New-TemporaryFolder {
    $parent = [System.IO.Path]::GetTempPath()
    [string]$name = [System.Guid]::NewGuid()
    New-Item -ItemType Directory -Path (Join-Path $parent $name)
}

function Get-Log4jVersion($jarPath) {
    $tempFolder = New-TemporaryFolder
    try {
        Expand-Archive -LiteralPath $jarPath -DestinationPath $tempFolder.FullName
        $manifestFile = Join-Path -Path $tempFolder.FullName -ChildPath "META-INF\MANIFEST.MF"
        if (Test-Path $manifestFile) {
            $manifestContent = Get-Content $manifestFile
            $versionLine = $manifestContent | Where-Object { $_ -match "Implementation-Version" }
            if ($versionLine) {
                $version = ($versionLine -split ":")[1].Trim()
                return $version
            }
        }
    } finally {
        Remove-Item $tempFolder.FullName -Force -Recurse
    }
    return $null
}

function Rename-OldJar ($jarPath) {
    $backupPath = $jarPath -replace ".jar", "_old.jar"
    $counter = 1
    while (Test-Path $backupPath) {
        $backupPath = $jarPath -replace ".jar", ("_old{0}.jar" -f $counter)
        $counter++
    }
    Rename-Item $jarPath $backupPath
}

try {
    Get-ChildItem -Path "$systemDrive\" -Filter "*log4j-core*.jar" -Recurse -ErrorAction SilentlyContinue | ForEach-Object -Parallel {
        $jarPath = $_.FullName
        $jarVersion = Get-Log4jVersion $jarPath
        if ($jarVersion -and $jarVersion -lt $minVersion) {
            Write-InfoLog "Updating $($jarPath) (version $($jarVersion))"
            Rename-OldJar $jarPath
            Copy-Item $currentVersionPath $jarPath
        }
    } -ThrottleLimit 8
} catch {
    Write-ErrorLog "An error occurred while updating log4j JAR files: $($_.Exception.Message)"
}

# Stop the logger
Stop-Logger
