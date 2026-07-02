# Install-ChocolateyIfNotExists.ps1

# Check for Chocolatey in the default installation folder
$chocoPath = "$env:SystemDrive\ProgramData\chocolatey\bin\choco.exe"

# Check for Chocolatey in the environment path
$chocoInPath = Get-Command -Name "choco" -ErrorAction SilentlyContinue

# Function to print the result
function Print-Result ($isInstalled) {
    if ($isInstalled) {
        Write-Host "Chocolatey is installed."
    } else {
        Write-Host "Chocolatey is not installed."
    }
}

# Function to install Chocolatey
function Install-Chocolatey {
    Write-Host "Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    Write-Host "Chocolatey installation complete."
}

# Check if Chocolatey is installed and install if not
if (Test-Path $chocoPath) {
    Print-Result $true
} elseif ($null -ne $chocoInPath) {
    Print-Result $true
} else {
    Print-Result $false
    Install-Chocolatey
}
