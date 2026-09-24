# Recovery workaround for the verified MT7925 Code 10 failure; not a binary patch.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script in an administrator PowerShell.'
}
$idPrefix = 'PCI\VEN_14C3&DEV_7925&SUBSYS_E0FF17AA&REV_00\'
$matches = @(Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like ($idPrefix + '*') })
if ($matches.Count -ne 1) { throw 'Expected one present matching MediaTek device; no changes were made.' }
$id = $matches[0].InstanceId
$device = $matches[0]
$problem = (Get-PnpDeviceProperty -InstanceId $id -KeyName 'DEVPKEY_Device_ProblemCode').Data
if ($problem -ne 10) {
    Write-Output "No repair performed: expected Code 10, found $problem ($($device.Status))."
    return
}
$out = Join-Path $PSScriptRoot ('recovery-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $out | Out-Null
Get-PnpDeviceProperty -InstanceId $id | Export-Clixml (Join-Path $out 'before.xml')
& wevtutil epl System (Join-Path $out 'System.evtx')
if ($LASTEXITCODE -ne 0) { throw 'Could not preserve System log; repair stopped.' }
# Retain the installed signed driver package; remove only this exact Wi-Fi devnode.
& pnputil /remove-device $id | Tee-Object (Join-Path $out 'remove.txt')
if ($LASTEXITCODE -ne 0) { throw 'Device removal failed. See recovery log.' }
& pnputil /scan-devices | Tee-Object (Join-Path $out 'scan.txt')
if ($LASTEXITCODE -ne 0) { throw 'Hardware scan failed. Run pnputil /scan-devices as administrator.' }
$recovered = $false
foreach ($attempt in 1..15) {
    Start-Sleep -Seconds 2
    $device = Get-PnpDevice -InstanceId $id -ErrorAction SilentlyContinue
    if ($device -and $device.Status -eq 'OK') { $recovered = $true; break }
}
$device | Export-Clixml (Join-Path $out 'after.xml')
if (-not $recovered) { throw "Adapter did not recover. Evidence: $out" }
Write-Output "Wi-Fi device recovered. Reconnect to your network if needed. Evidence: $out"
