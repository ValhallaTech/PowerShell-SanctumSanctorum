# Load assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create form
$form = New-Object System.Windows.Forms.Form
$form.Text = 'My PowerShell GUI'
$form.Size = New-Object System.Drawing.Size(400, 300)

# Create label
$label = New-Object System.Windows.Forms.Label
$label.Text = 'Hello, this is a simple GUI!'
$label.AutoSize = $true
$label.Location = New-Object System.Drawing.Point(10, 10)
$form.Controls.Add($label)

# Create button
$button = New-Object System.Windows.Forms.Button
$button.Text = 'Click me!'
$button.AutoSize = $true
$button.Location = New-Object System.Drawing.Point(10, 40)
$button.Add_Click({
    [System.Windows.Forms.MessageBox]::Show('You clicked the button!', 'Information', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})
$form.Controls.Add($button)

# Show form
[void]$form.ShowDialog()
