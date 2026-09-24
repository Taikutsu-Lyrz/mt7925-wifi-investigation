# User-requested BR configuration experiment. Not a signed driver binary patch.
[CmdletBinding()]
param([ValidateSet('Apply','Restore')][string]$Action = 'Apply')
$ErrorActionPreference = 'Stop'
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run in administrator PowerShell.' }
$idPrefix = 'PCI\VEN_14C3&DEV_7925&SUBSYS_E0FF17AA&REV_00\'
$devices = @(Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like ($idPrefix + '*') })
if ($devices.Count -ne 1) { throw 'Expected one present matching MediaTek device; no changes were made.' }
$id = $devices[0].InstanceId
$device = $devices[0]
if ($device.Status -ne 'OK') { throw 'Recover the adapter before applying or restoring this experiment.' }
$adapter = @(Get-NetAdapter | Where-Object { $_.PnPDeviceID -eq $id -and $_.Status -in @('Up','Disconnected') })
if ($adapter.Count -ne 1) { throw 'One present, enabled Wi-Fi adapter is required.' }
$adapter = $adapter[0]
$backup = Join-Path $PSScriptRoot 'country-override-original.clixml'
$log = Join-Path $PSScriptRoot 'country-override-result.txt'
$desired = [ordered]@{CountryRegionString='BR'; DynamicCountryDecisionEn='0'; CountryRoamingEn='0'; SmartCountryDecisionEn='0'}
$properties = @(Get-NetAdapterAdvancedProperty -Name $adapter.Name -AllProperties | Where-Object { $desired.Contains($_.RegistryKeyword) })
if ($properties.Count -ne $desired.Count) { throw 'Required driver properties are missing.' }
if ($Action -eq 'Apply') {
    if (-not (Test-Path -LiteralPath $backup)) { $properties | Select-Object RegistryKeyword,RegistryValue | Export-Clixml $backup }
    $settings = foreach ($key in $desired.Keys) { [pscustomobject]@{RegistryKeyword=$key; RegistryValue=@($desired[$key])} }
} else {
    $settings = Import-Clixml $backup
}
try {
    foreach ($setting in $settings) {
        Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword $setting.RegistryKeyword -RegistryValue $setting.RegistryValue -AllProperties -NoRestart
    }
    & pnputil /restart-device $id | Set-Content $log
    if ($LASTEXITCODE -ne 0) { throw 'Device restart command failed.' }
    Start-Sleep -Seconds 8
    if ((Get-PnpDevice -InstanceId $id).Status -ne 'OK') { throw 'Adapter failed after settings change.' }
    Get-NetAdapterAdvancedProperty -Name $adapter.Name -AllProperties | Where-Object { $desired.Contains($_.RegistryKeyword) } | Format-List RegistryKeyword,RegistryValue | Out-String | Add-Content $log
    Get-NetAdapter -Name $adapter.Name | Format-List Status,LinkSpeed | Out-String | Add-Content $log
    'Completed ' + $Action | Add-Content $log
} catch {
    $failure = $_
    foreach ($setting in $properties) {
        Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword $setting.RegistryKeyword -RegistryValue $setting.RegistryValue -AllProperties -NoRestart -ErrorAction Continue
    }
    & pnputil /restart-device $id | Add-Content $log
    $failure | Out-String | Add-Content $log
    throw $failure
}
