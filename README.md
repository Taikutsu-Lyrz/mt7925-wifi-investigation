# MediaTek MT7925 Code 10: findings and workaround

Technical findings from a Windows Code 10 failure involving the MediaTek MT7925: startup traces, country-table behavior, a persistent configuration workaround, and an **uninstalled experimental binary candidate**.

**Status updated 2026-09-24:** My persistent BR configuration override survived a full reboot; immediately afterward the adapter reported OK and Wi-Fi connected at 1.2 Gbps. I have used the laptop for several days and repeatedly tried to reproduce the triggers that used to break Wi-Fi, but it has continued working normally. I did not collect a continuous trace or a formal test log during those days. This is good real-world evidence that the workaround is effective on my laptop. The original signed driver remains installed; **no patched driver is installed.**

This report documents a single-system case study, not a universal MT7925 fix or a vendor-supported driver distribution. Recorded evidence, static-analysis inferences, and reported symptoms are distinguished below.

## Problem and hardware

Reported symptoms included Wi-Fi disappearing after restart, closing/moving the laptop, sleep, or VPN disconnect/reconnect. In some VPN cases Wi-Fi briefly returned, disconnected again, and required manual network selection. Deleting and reinstalling the same driver restored operation. Bluetooth continued working; its separate USB interface means that observation does not rule out a Wi-Fi-specific power or hardware problem.

| Item | Investigated system |
| --- | --- |
| Laptop | Lenovo Legion Pro 5 16ADR10, type 83LT |
| BIOS | RLCN32WW, 2025-11-25 |
| OS | Windows 11 Home, build 26200 |
| Adapter | MediaTek Wi-Fi 7 MT7925 |
| PCI hardware identity | VEN_14C3, DEV_7925 (MediaTek MT7925) |
| Package | 26.40.3.65, dated 2026-06-11 |
| Driver/service | mtkwecx.sys / mtkwecx |
| SYS version | 5.7.0.6028 |
| SYS SHA-256 | `01b1c4399edaec37fbe5decdb8f5ff5da94e3d8993a9d70755e068c4d64582c0` |
| Sleep | S3 supported; no Modern Standby |
| Physical country | Afghanistan |
| VPN context | Surfshark service and VPN adapters observed; causation unproven |

The parent PCIe port reported OK while the Wi-Fi device failed. Old, non-present Wi-Fi interfaces also existed and shared the same device instance ID; scripts must distinguish the present adapter from these stale entries.

## Findings and follow-up

1. The failing, present Wi-Fi device reported **Code 10 / CM_PROB_FAILED_START**, with `ProblemStatus=0xC000009E` (`STATUS_DEVICE_POWER_FAILURE`).
2. A targeted `pnputil /restart-device` returned command success but did **not** restore the failed adapter. Command success is not proof of device health.
3. A vendor WPP trace captured a failing start after successful firmware-ownership acknowledgement. The later band-capability initialization path failed.
4. Removing only the exact Wi-Fi devnode and rescanning restored **Status OK / Problem 0**, retaining the existing signed driver package.
5. Saved advanced properties differed before/after recovery: `CountryRegionString` changed from `AF` to `BR`; the other compared changes were interface identity and installation timestamp.
6. Static analysis of this exact binary found an all-zero AF selection mask in a shared 2.4/5 GHz country table. BR's mask selects ten subbands.
7. A live AF-setting experiment did **not** reproduce Code 10: the adapter restarted successfully, and the saved country was BR afterward. During the AF test, network discovery was reported to show only one device/network and stop discovering normally. No scan-count measurement was captured to independently verify that observation.
8. After I applied the BR override, I rebooted the laptop. The country settings remained BR with automatic country selection disabled, the adapter reported OK, and Wi-Fi connected at 1.2 Gbps. I have used it for several days and repeatedly tried to reproduce the previous failures; Wi-Fi continued working. I did not collect a new ETL capture or timestamped test log during this follow-up.

These findings support an empty-country/channel-data hypothesis, but do not prove the complete failure chain in every reported incident. The source of BR selection, any role of VPN geolocation, and the reason for the AF table contents remain unresolved.

## Timeline and experiments

| Date | Experiment | Result and limits |
| --- | --- | --- |
| Sep 18 | Changed exposed LowPowerEnable from Auto (1) to Disabled (0) | Did not prevent later failure. Power plan was already maximum performance; UAPSD was off. |
| Sep 19 | Captured failed state and targeted restart | Code 10 persisted. Earlier PnP evidence showed load/init followed by failed device start after about 14.3 seconds. |
| Sep 20 | Compared recovered installation | Same SYS hash worked after reinstall; exposed advanced settings were reset by reinstall. |
| Sep 20 | Built and smoke-tested vendor WPP tracing | About 12,808 vendor events in a five-second smoke capture. No symbols/private TMF available. |
| Sep 21 | Started tracing at 01:19 after boot around 01:13 | Original capture missed the failing boot; contained no useful vendor startup sequence. |
| Sep 21 | Restarted failed device under vendor trace at 01:22 | Firmware ownership succeeded; capability initialization failed; device stayed Code 10. |
| Sep 21 | Removed Wi-Fi devnode and rescanned at 01:27 | Recovered without deleting the driver package; Wi-Fi connected at 1.2 Gbps. |
| Sep 21 | Attempted AF setting through advanced-property API | First attempt omitted AllProperties and failed without changing settings. Corrected attempt at 01:35 restarted successfully; country returned to BR. |
| Sep 21 | Applied persistent BR override | Four saved properties verified after adapter restart; Wi-Fi connected at 1.2 Gbps. |
| Sep 21 | Built offline AF-mask replacement | Exact byte checks passed; original retained; signature became HashMismatch; candidate not installed. |
| Sep 21 | Rebooted after applying BR override | Country remained BR, automatic selection settings remained disabled, and Wi-Fi was up at 1.2 Gbps. |
| Through Sep 24 | Used the laptop and repeatedly attempted to recreate prior failure | I had no recurrence over several days. I did not keep a continuous capture or formal test log. |

Times above use the test system's timezone (Asia/Kabul). A trace started after the failure cannot reconstruct the preceding startup.

## Reverse-engineering findings

Offsets below apply **only** to the exact SYS hash above. Routine names are inferred from embedded diagnostic strings; private symbols and formatted WPP arguments were unavailable.

| Routine / location | Finding |
| --- | --- |
| `DomainGetDomainInfo2g5g`, RVA `0x192b30` | Looks up country selection records and copies selected subbands. AF and BR use base table 4 in the static lookup. |
| AF record, RVA `0x262bb0` | Two-byte country identifier followed by twelve zero selection bytes. |
| BR record, RVA `0x2623d0` | Selection mask `01 01 01 01 01 01 01 01 01 01 00 00`. |
| `DomainBuildChannelList`, RVA `0x190e48` | Builds channel entries from selected subbands. |
| Leaf routine, RVA `0x1929cc` | Counts channel entries for the requested internal band. |
| `AllocationMemoryWithMetaData`, RVA `0xff94` | Rejects zero-byte requests with STATUS_INVALID_PARAMETER; allocation can also fail for other reasons. |
| `MTCxInitWiFiCapabilities`, RVA `0x85930` | Requests band-1 channel count, allocates count × 8 bytes, exits early if output pointer is null. |
| `MTCxSetBandCapabilities`, RVA `0x88a04` | Returns STATUS_UNSUCCESSFUL when internal flag at context+0x1158 is zero, before calling Windows' capability API. |
| `Ndis6CommonUpdateCountry`, RVA `0x4e7c0` | Writes the active country to saved configuration when dynamic country decision is enabled. Upstream country source remains unresolved. |
| `DomainGetDomainInfo6g`, RVA `0x193470` | Includes static and runtime/BIOS table paths and platform checks; not covered by the candidate patch. |

**Structure-layout clarification:** context+0x1158 is not the band count. The 16-byte WIFI_BAND_CAPABILITIES structure starts at +0x1148; NumBands is at +0x114c. Control flow suggests +0x1158 is an internal completion flag.

The offline base-table reconstruction yields no selected 2.4/5 GHz subbands for AF, versus 13 internal band-1 channels and 25 band-2 channels for BR. BIOS overrides and runtime mutations are not modeled. The captured null-allocation branch alone cannot distinguish a zero request size from actual allocation failure.

### Vendor trace interpretation

Format GUID `99a39866-83dd-3ada-0a57-90cabd1e0858`:

| Event ID | Meaning inferred from exact binary control flow |
| --- | --- |
| `0x4a` / 74 | Channel allocation output null; capability initializer exits early. |
| `0x67` / 103 | Internal band-capability completion flag zero. |
| `0xec` / 236 | Outer post-interrupt startup callback reports band-capability configuration failure. |

Firmware ownership success uses format GUID `1cc9eb33-7b4f-322b-4a1c-3602a3995196`, ID `0x1d6`. Bootstrap events use `cea3c0f5-7cb4-320a-0935-37f0a1209327`.

WPP IDs and format GUIDs were matched to disassembly. This is not full payload decoding: return values and other dynamic arguments are unavailable in the summarizer. The firmware-timeout hypothesis was not supported by the successful ownership step in this failure.

## Applied workaround and rollback

The original signed driver remains installed with these persistent advanced properties:

| Registry keyword | Previous | Applied |
| --- | --- | --- |
| CountryRegionString | BR at time of backup | BR |
| DynamicCountryDecisionEn | 1 | 0 |
| CountryRoamingEn | 1 | 0 |
| SmartCountryDecisionEn | 0 | 0 |

**Verified:** the values survived an adapter restart and a full reboot. Wi-Fi was connected at 1.2 Gbps after each. The user reports several days of normal use and repeated reproduction attempts without recurrence. These tests suggest the workaround is effective for the reported failure on this machine. Sleep/wake and VPN reconnect behavior were not separately documented in a controlled log, and 6 GHz operation has not been validated. Reinstallation or driver updates may reset settings. No scheduled repair task is installed. BR's channel/power settings have not been validated for Afghanistan; observing nearby Wi-Fi does not establish permitted radio settings.

The repair scripts identify the investigated Lenovo subsystem and require exactly one matching present Wi-Fi device. Review and adapt them before using on other hardware. From an administrator PowerShell in this repository:

```powershell
# Apply the configuration experiment, preserving the first original backup.
.\driver-analysis\Set-Mt7925CountryOverride.ps1 -Action Apply

# Restore that saved configuration.
.\driver-analysis\Set-Mt7925CountryOverride.ps1 -Action Restore

# Only for an existing Code 10: preserve System log, remove devnode, rescan.
.\driver-analysis\Repair-Mt7925.ps1
```

The rollback backup remains local and is intentionally excluded from Git. A fresh clone cannot restore settings without that backup. Restoration returns the settings present when the override was applied, not the earlier failing AF state. Recovery can reset per-device properties; reconnecting may be necessary. Recovery does not guarantee prevention.

## Diagnostic tools

```powershell
.\driver-analysis\Trace-Mt7925.ps1 -Action Start
# Exercise the specific failure trigger; capture before reinstalling.
.\driver-analysis\Trace-Mt7925.ps1 -Action Stop
.\driver-analysis\Summarize-Mt7925Trace.ps1 -TracePath 'PATH-TO-CAPTURE.etl'
```

Tracing needs administrator privileges. The named session is `MT7925_Internal_PatchInvestigation`; it is circular, capped at 64 MB, and does not survive reboot. Stop reports an error if no matching session exists. Status and SmokeTest actions are also provided. These scripts do not change adapters merely by tracing.

Python analysis uses `pefile==2024.8.26` and `capstone==5.0.9`. Install them in your own environment or in driver-analysis/vendor (ignored). To reproduce analysis, supply your own matching driver at `wifi-failure-20260919-234915/driver-package/mtkwecx.sys` relative to the repository root. The full extracted country table is generated locally and excluded from this repository. No vendor binaries are distributed here.

```powershell
python .\driver-analysis\inspect_driver.py
python .\driver-analysis\inspect_country_tables.py
python .\driver-analysis\disassemble_functions.py 85930 88a04 193470
```

Some analysis tools require outputs from inspect_driver.py. Leaf routines without unwind metadata are bounded to 512 bytes by the disassembler, which may include the next function; review RET boundaries manually.

`Test-AfCountry.ps1` intentionally changes settings and restarts Wi-Fi, and tries recovery on Code 10. It is a disruptive diagnostic for this case, not routine maintenance.

## Experimental binary candidate

`build_af_br_candidate.py` constructs an offline copy from the exact original hash. It replaces AF's selection mask with BR's and recalculates the PE checksum. It changes ten mask bytes and two checksum bytes; AF's country identifier stays AF.

Candidate SHA-256: `95f3e5d8ad9f0a297b625a5cc7300c666fe22590d8cf2780e4f2adb0b8721d43`.

Checks passed for source identity, original record bytes, permitted byte changes, equal AF/BR masks, expected offline channel counts, unchanged file length, and PE checksum. The original source binary was preserved unchanged. **These are offline checks, not hardware validation.**

Limitations:

- Only the shared 2.4/5 GHz table is changed. It is not an entire AF → BR remap.
- No 6 GHz, runtime-transition, VPN, sleep, or reboot behavior has been validated for the modified binary.
- No promise of restart-free operation is supported.
- Authenticode reports **HashMismatch**. A checksum is not a signature; the existing package catalog is also invalid for the changed binary.
- The candidate was not installed, test-signed, or submitted to Microsoft. Secure Boot and signing policy were not changed.

Personal use does not waive Windows signing requirements. A controlled test package would require appropriate binary/catalog signing and test-machine preparation. The working configuration experiment remains in use; the untested kernel binary was not deployed.

## Evidence handling

Raw ETL/EVTX captures, full device/registry dumps, network identities, certificate keys, original driver packages, and patched binaries remain local and excluded from Git. This repository contains findings, source tools, provider metadata, and country-table reconstruction, not a wholesale system-log upload.

Key local evidence sets:

- `wifi-failure-20260919-234915`: initial failure state, exported matching driver, PnP evidence.
- `wifi-working-20260920-000333`: working-driver comparison.
- `wifi-failure-20260921/internal-20260921-012233.etl`: failed restart with vendor branches.
- `wifi-failure-20260921/internal-20260921-012722.etl`: removal/rescan recovery.
- `wifi-failure-20260921/settings-before.json` and `settings-after.json`: country-property comparison.
- `driver-analysis/country-repro-20260921-013513`: AF-setting test, successful adapter status, trace.
- `driver-analysis/country-override-result.txt`: applied values and connected status.
- `driver-analysis/af-br-candidate/manifest.json`: candidate byte diff and hashes.

## Open questions and next validation steps

1. Validate the persistent workaround through normal reboot, S3 resume, and VPN reconnects; capture any recurrence before reinstalling.
2. Identify the source and timing of AF/BR country changes. A boot-capable capture is needed for failures before ordinary tracing starts.
3. Decode relevant dynamic WPP arguments or obtain vendor symbols to distinguish empty channel counts from allocation failures conclusively.
4. Ask the vendor to audit AF country data, validate empty-band selections before allocation, and propagate initialization failures instead of continuing with incomplete capabilities.
5. Validate country transitions against current capabilities and persisted state, including BIOS/firmware 6 GHz paths and appropriate regional radio data.

The available evidence does not establish that Afghanistan deliberately restricted Wi-Fi 7, that MediaTek intentionally omitted it for legal reasons, or that VPN software alone caused the fault. Those explanations remain unproven.

## References

- [Microsoft: WIFI_BAND_CAPABILITIES layout](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wificx/ns-wificx-wifi_band_capabilities)
- [Microsoft: kernel driver signing policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-)
- [Microsoft: test-signing driver packages](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/test-signing-driver-packages)
- [Microsoft: loading test-signed code](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)
- [Linux upstream MT7925 PCI driver](https://github.com/torvalds/linux/blob/master/drivers/net/wireless/mediatek/mt76/mt7925/pci.c): open-source reference, not a drop-in Windows WiFiCx driver.

No redistribution license for MediaTek binaries is granted by this repository. No vendor endorsement or certified regional configuration is claimed.
