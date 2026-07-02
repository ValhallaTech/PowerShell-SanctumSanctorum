# Load assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Function to run a PowerShell script
function Run-Script($scriptPath) {
    try {
        & $scriptPath
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Error running script: `n$($_.Exception.Message)", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
}

# Create form
$form = New-Object System.Windows.Forms.Form
$form.Text = 'PowerShell Script Runner'
$form.Size = New-Object System.Drawing.Size(300, 200)

# Create button
$button = New-Object System.Windows.Forms.Button
$button.Text = 'Run Script'
$button.AutoSize = $true
$button.Location = New-Object System.Drawing.Point(100, 70)
$button.Add_Click({
    $scriptPath = Join-Path $PSScriptRoot 'sample-script.ps1'
    Run-Script $scriptPath
})
$form.Controls.Add($button)

# Show form
[void]$form.ShowDialog()
