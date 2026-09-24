<# Diagnostic branch identification for SYS SHA256 01b1c4399edaec37fbe5decdb8f5ff5da94e3d8993a9d70755e068c4d64582c0.
Descriptions are inferred from static control flow, not MediaTek's private TMF text.
Payload argument values cannot be recovered by this script without additional metadata.
#>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$TracePath, [string]$OutputPath)
$ErrorActionPreference = 'Stop'
$branchMap = @{}
$powerGuid = '99a39866-83dd-3ada-0a57-90cabd1e0858'
$bootstrapGuid = 'cea3c0f5-7cb4-320a-0935-37f0a1209327'
$ownershipGuid = '1cc9eb33-7b4f-322b-4a1c-3602a3995196'
function Add-Branch([string]$Guid, [int]$Id, [string]$Kind, [string]$Meaning) {
    $branchMap[($Guid + ':' + $Id)] = @{ Kind=$Kind; Meaning=$Meaning }
}
Add-Branch $powerGuid 0xf6 'Progress' 'EvtDeviceD0Entry entered'
Add-Branch $powerGuid 0xf8 'Progress' 'D0Entry selected previous-state-5 path'
Add-Branch $powerGuid 0xf9 'ErrorPath' 'Initial firmware ownership call returned nonzero; bootstrap retry follows'
Add-Branch $powerGuid 0xfa 'ErrorPath' 'Bootstrap callback retry returned nonzero'
Add-Branch $powerGuid 0x106 'ErrorPath' 'D0Entry selects STATUS_UNSUCCESSFUL after nonzero result'
Add-Branch $powerGuid 0x109 'Progress' 'D0Entry is returning; return value unavailable without payload decoding'
Add-Branch $powerGuid 0xe5 'Progress' 'EvtDeviceD0EntryPostInterruptsEnabled entered'
Add-Branch $powerGuid 0xe8 'ErrorPath' 'MTCxSetPowerState returned failing status'
Add-Branch $powerGuid 0xe9 'ErrorPath' 'NdisWdiInitFwHwSw returned nonzero during initial start'
Add-Branch $powerGuid 0xea 'ErrorPath' 'Device capability configuration failed'
Add-Branch $powerGuid 0xeb 'ErrorPath' 'Station capability configuration failed'
Add-Branch $powerGuid 0xec 'ErrorPath' 'Band capability configuration failed'
Add-Branch $powerGuid 0x4a 'ErrorPath' 'Band-1 channel allocation output is null; capability initialization exits early'
Add-Branch $powerGuid 0x67 'ErrorPath' 'Band-capability initialization flag is zero; returns STATUS_UNSUCCESSFUL before Windows API'
Add-Branch $powerGuid 0xed 'ErrorPath' 'PHY capability configuration failed'
Add-Branch $powerGuid 0xee 'ErrorPath' 'Wi-Fi Direct capability configuration failed'
Add-Branch $powerGuid 0xf1 'Progress' 'Post-interrupts callback is returning; return value unavailable'
Add-Branch $bootstrapGuid 0x36 'Progress' 'MT7925PreFirmwareDownloadInit entered'
Add-Branch $bootstrapGuid 0x3a 'ErrorPath' 'Bootstrap helper at RVA 0xd510 returned nonzero'
Add-Branch $bootstrapGuid 0x3b 'ErrorPath' 'Firmware synchronization polling exhausted its retry bound'
Add-Branch $bootstrapGuid 0x3d 'Progress' 'MT7925PreFirmwareDownloadInit is returning; return value unavailable'
Add-Branch $ownershipGuid 0x1d1 'Progress' 'AsicConnac3xHifPciPmSetDriverOwn entered'
Add-Branch $ownershipGuid 0x1d6 'Progress' 'Firmware ownership acknowledgement success branch'
Add-Branch $ownershipGuid 0x1d8 'ErrorPath' 'Firmware ownership acknowledgement still absent on failure path'
Add-Branch $ownershipGuid 0x1da 'Progress' 'Firmware ownership routine is returning; return value unavailable'
$decodeErrors = @()
$records = @(Get-WinEvent -Path (Resolve-Path -LiteralPath $TracePath).Path -Oldest -ErrorAction SilentlyContinue -ErrorVariable +decodeErrors | ForEach-Object {
    if ($_.ProviderId -eq [guid]::Empty) {
        $xmlText = $_.ToXml()
        if ($xmlText -match 'GUID=([0-9a-fA-F-]{36})') {
            $formatGuid = $Matches[1].ToLowerInvariant()
            $key = $formatGuid + ':' + $_.Id
            if ($branchMap.ContainsKey($key)) {
                [pscustomobject]@{TimeCreated=$_.TimeCreated; FormatGuid=$formatGuid; Id=$_.Id; Kind=$branchMap[$key].Kind; InferredBranch=$branchMap[$key].Meaning}
            }
        }
    }
})
if ($OutputPath) { ConvertTo-Json -InputObject $records -Depth 4 | Set-Content -LiteralPath $OutputPath -Encoding UTF8 }
if ($decodeErrors.Count) { Write-Warning ('Event reader reported ' + $decodeErrors.Count + ' decoding errors. Missing records are not evidence of success.') }
$records | Group-Object Id,Kind,InferredBranch | Select-Object Count,Name
