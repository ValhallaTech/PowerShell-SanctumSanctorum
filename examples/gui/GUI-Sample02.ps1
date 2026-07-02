Add-Type -AssemblyName System.Windows.Forms

$formObject = [System.Windows.Forms.Form]
$labelObject = [System.Windows.Forms.Label]
$buttonObject = [System.Windows.Forms.Button]

$hellowWorldForm = New-Object $formObject
$hellowWorldForm.ClientSize = '500,300'
$hellowWorldForm.Text = 'Hellow World - Tutorial'
$hellowWorldForm.BackColor = "#ffffff"

$lblTitle = New-Object $labelObject
$lblTitle.Text = 'Hello World!'
$lblTitle.Autosize = $true
$lblTitle.Font = 'Verdana, 24, style=Bold'
$lblTitle.Location = New-Object System.Drawing.Point(120,120)

$btnHello = New-Object $buttonObject
$btnHello.Text = 'Say hello!'
$btnHello.Autosize = $true
$btnHello.Font = 'Verdana,14'
$btnHello.Location = New-Object System.Drawing.Point(185,180)

$HellowWorldForm.Controls.AddRange(@($lblTitle,$btnHello))

function sayHello {
    if ($lblTitle.Text -eq '') {
        $lblTitle.Text = 'Hello World!'
    }else {
        $lblTitle.Text = ''
    }
}

$btnHello.Add_Click({sayHello})

$HellowWorldForm.ShowDialog()



$HellowWorldForm.Dispose()
