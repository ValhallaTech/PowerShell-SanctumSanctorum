# Store service tag in variable
$serviceTag = Get-CimInstance win32_SystemEnclosure | Select-Object SerialNumber -ExpandProperty SerialNumber

$serviceTag
