"""Build an uninstalled experimental AF -> BR 2.4/5 GHz table candidate.
No signing, installation, security-policy changes, or runtime-driver writes.
"""
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'vendor'))
import pefile

SOURCE = ROOT.parent / 'wifi-failure-20260919-234915/driver-package/mtkwecx.sys'
EXPECTED = '01b1c4399edaec37fbe5decdb8f5ff5da94e3d8993a9d70755e068c4d64582c0'
OUT = ROOT / 'af-br-candidate'
original = SOURCE.read_bytes()
if hashlib.sha256(original).hexdigest() != EXPECTED:
    raise RuntimeError('Source hash mismatch: these offsets are version-specific.')
pe = pefile.PE(data=original)
af = pe.get_offset_from_rva(0x262bb0)
br = pe.get_offset_from_rva(0x2623d0)
if original[af:af+14] != struct.pack('<H', 0x4146) + bytes(12):
    raise RuntimeError('AF record did not match the reverse-engineered layout.')
if original[br:br+14] != struct.pack('<H', 0x4252) + bytes([1]*10+[0]*2):
    raise RuntimeError('BR record did not match the expected reference mask.')
candidate = bytearray(original)
# Preserve the AF identifier; copy BR selection flags into AF's existing record.
# Both identifiers select the same base subband table in this exact binary.
candidate[af+2:af+14] = original[br+2:br+14]
checksum_offset = pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
new_checksum = pefile.PE(data=bytes(candidate)).generate_checksum()
struct.pack_into('<I', candidate, checksum_offset, new_checksum)
changed = [i for i,(a,b) in enumerate(zip(original,candidate)) if a != b]
allowed = set(range(af+2,af+12)) | set(range(checksum_offset,checksum_offset+4))
if not set(changed) <= allowed or len(candidate) != len(original):
    raise RuntimeError('Unexpected binary modification.')
rebuilt = pefile.PE(data=bytes(candidate))
if not rebuilt.verify_checksum():
    raise RuntimeError('PE checksum validation failed.')
if candidate[af+2:af+14] != candidate[br+2:br+14]:
    raise RuntimeError('AF/BR mask equivalence check failed.')
# Independently reconstruct selected channel counts from the shared base table.
table = rebuilt.get_data(0x289140 + 4*0x78, 0x78)
counts = {}
for i,flag in enumerate(candidate[af+2:af+14]):
    if flag:
        entry = table[24+i*8:32+i*8]
        counts[str(entry[1])] = counts.get(str(entry[1]),0) + entry[4]
if counts != {'1':13, '2':25}:
    raise RuntimeError(f'Unexpected channel counts: {counts}')
OUT.mkdir(exist_ok=True)
target = OUT / 'mtkwecx-af-br-experimental.sys'
target.write_bytes(candidate)
manifest = {
    'status':'EXPERIMENTAL, UNINSTALLED, INVALID ORIGINAL SIGNATURE',
    'scope':'AF uses BR selection flags in the shared 2.4/5 GHz table only',
    'limitations':['Not a full country remap', '6 GHz unchanged', 'Runtime transition behavior untested',
                   'BR regulatory suitability for Afghanistan not verified', 'No restart-free guarantee'],
    'source':str(SOURCE), 'source_sha256':EXPECTED,
    'candidate':str(target), 'candidate_sha256':hashlib.sha256(candidate).hexdigest(),
    'af_record_rva':'0x262bb0', 'br_record_rva':'0x2623d0',
    'channel_counts_by_internal_band':counts,
    'changes':[{'file_offset':hex(i),'before':original[i],'after':candidate[i]} for i in changed],
    'checks':['Exact source hash', 'Expected country record bytes', 'Only AF mask and PE checksum changed',
              'AF/BR mask equality', 'Expected offline channel counts', 'Valid PE checksum'],
}
(OUT/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
if SOURCE.read_bytes() != original:
    raise RuntimeError('Original file changed unexpectedly.')
print(json.dumps({'candidate':str(target),'sha256':manifest['candidate_sha256'],
                  'changed_bytes':len(changed),'checks':'passed'},indent=2))
