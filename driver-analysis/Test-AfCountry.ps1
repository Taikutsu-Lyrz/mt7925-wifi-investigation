# Explicit Afghanistan country-selection diagnostic for the investigated adapter.
$ErrorActionPreference = 'Stop'
$out = Join-Path $PSScriptRoot ('country-repro-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $out | Out-Null
$idPrefix = 'PCI\VEN_14C3&DEV_7925&SUBSYS_E0FF17AA&REV_00\'
$devices = @(Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like ($idPrefix + '*') })
if ($devices.Count -ne 1) { throw 'Expected one present matching MediaTek device.' }
$id = $devices[0].InstanceId
try {
    & "$PSScriptRoot\Trace-Mt7925.ps1" -Action Start -OutputDirectory $out *> "$out\test.txt"
    Set-NetAdapterAdvancedProperty -Name Wi-Fi -RegistryKeyword CountryRegionString -RegistryValue AF -AllProperties -NoRestart
    Get-NetAdapterAdvancedProperty -Name Wi-Fi -AllProperties | Select-Object RegistryKeyword,RegistryValue | ConvertTo-Json -Depth 5 | Set-Content "$out\settings.json"
    pnputil /restart-device $id >> "$out\test.txt" 2>&1
    Start-Sleep -Seconds 5
    Get-PnpDevice -InstanceId $id | Select-Object Status,Problem,Present | ConvertTo-Json | Set-Content "$out\result.json"
} catch { $_ | Out-String | Add-Content "$out\test.txt" } finally {
    & "$PSScriptRoot\Trace-Mt7925.ps1" -Action Stop >> "$out\test.txt" 2>&1
    $problem = (Get-PnpDeviceProperty -InstanceId $id -KeyName DEVPKEY_Device_ProblemCode).Data
    if ($problem -eq 10) { & "$PSScriptRoot\Repair-Mt7925.ps1" >> "$out\test.txt" 2>&1 }
    Get-PnpDevice -InstanceId $id | Select-Object Status,Problem,Present | ConvertTo-Json | Set-Content "$out\final.json"
    'Done' | Set-Content "$out\complete.txt"
}
