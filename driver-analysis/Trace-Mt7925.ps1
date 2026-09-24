<#
Diagnostic logging only: this script does not patch, reinstall, restart, or reconfigure Wi-Fi.
Run Start before a reproduction, then Stop after it fails. SmokeTest records five seconds.
The session is capped at 64 MB, is not persistent across reboot, and has no scheduled task.
#>
[CmdletBinding()]
param(
    [ValidateSet('Start','Stop','Status','SmokeTest')]
    [string]$Action = 'Status',
    [string]$OutputDirectory = $PSScriptRoot
)
$ErrorActionPreference = 'Stop'
$traceName = 'MT7925_Internal_PatchInvestigation'
if ($Action -eq 'Status') {
    & logman.exe query $traceName -ets
    return
}
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this diagnostic script in an administrator PowerShell.'
}
if ($Action -eq 'Stop') {
    & logman.exe stop $traceName -ets
    if ($LASTEXITCODE -ne 0) { throw 'Could not stop the named diagnostic session; inspect logman output.' }
    return
}
$existing = & logman.exe query $traceName -ets 2>&1
if ($LASTEXITCODE -eq 0) { throw 'The diagnostic session already exists. Stop it before starting another.' }
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDirectory) { throw 'Run from the saved script file so its metadata can be found.' }
$metadata = Get-Content -LiteralPath (Join-Path $scriptDirectory 'internal-trace-metadata.json') -Raw | ConvertFrom-Json
$providerFile = Join-Path $scriptDirectory 'internal-trace-providers.txt'
$servicePath = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\mtkwecx').ImagePath -replace '^\\SystemRoot',$env:SystemRoot
if ((Get-FileHash -LiteralPath $servicePath -Algorithm SHA256).Hash -ne $metadata.driver_sha256) {
    throw 'Installed driver differs from the analyzed binary. Regenerate metadata for the new driver.'
}
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$traceFile = Join-Path (Resolve-Path -LiteralPath $OutputDirectory).Path ('internal-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.etl')
& logman.exe create trace $traceName -o $traceFile -f bincirc -max 64 -pf $providerFile -ets
if ($LASTEXITCODE -ne 0) { throw 'Trace start failed; no driver changes were made.' }
Write-Output ('Trace file: ' + $traceFile)
if ($Action -eq 'SmokeTest') {
    try { Start-Sleep -Seconds 5 }
    finally {
        & logman.exe stop $traceName -ets
        if ($LASTEXITCODE -ne 0) { throw 'Smoke trace stop failed; stop the named session manually.' }
    }
}
