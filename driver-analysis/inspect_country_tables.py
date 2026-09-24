"""Read-only reconstruction of the basic country table lookup at RVA 0x192b30.
Does not emulate BIOS overrides or runtime mutations of the tables.
"""
from pathlib import Path
import sys, struct, json, hashlib
root = Path(__file__).resolve().parent
sys.path.insert(0, str(root / 'vendor'))
import pefile
pe = pefile.PE(str(root.parent / 'wifi-failure-20260919-234915/driver-package/mtkwecx.sys'))
assert hashlib.sha256(pe.__data__).hexdigest() == '01b1c4399edaec37fbe5decdb8f5ff5da94e3d8993a9d70755e068c4d64582c0', 'Offsets apply only to the analyzed driver'
base = pe.OPTIONAL_HEADER.ImageBase
def data(va, size):
    return pe.get_data(va-base, size)
def country(value):
    return chr(value >> 8) + chr(value & 255)
tables = []
for index in range(8):
    va = base + 0x289140 + index * 0x78
    raw = data(va, 0x78)
    countries_ptr, count, mask_count, masks_ptr = struct.unpack_from('<QIIQ', raw)
    codes = list(struct.unpack('<'+'H'*count, data(countries_ptr, count*2))) if count else []
    masks = {}
    mask_locations = {}
    for j in range(mask_count):
        entry = data(masks_ptr + j*14, 14)
        masks[country(struct.unpack_from('<H', entry)[0])] = list(entry[2:])
        mask_locations[country(struct.unpack_from('<H', entry)[0])] = hex(masks_ptr + j*14 - base)
    subbands = []
    for j in range(12):
        entry = raw[24+j*8:32+j*8]
        subbands.append({'band':entry[1], 'step':entry[2], 'first':entry[3], 'count':entry[4]})
    tables.append({'index':index, 'countries':[country(c) for c in codes], 'masks':masks, 'mask_locations':mask_locations, 'subbands':subbands})
result = {}
for code in ['AF','BR']:
    table = next((t for t in tables if code in t['countries']), tables[7])
    mask = table['masks'].get(code)
    selected = [b for i,b in enumerate(table['subbands']) if mask is None or mask[i]]
    result[code] = {'table':table['index'], 'matched':code in table['countries'], 'mask':mask, 'record_rva':table['mask_locations'].get(code),
                    'subbands':selected, 'band1_channel_count':sum(b['count'] for b in selected if b['band']==1)}
(root/'country-table-analysis.json').write_text(json.dumps({'results':result,'tables':tables},indent=2))
print(json.dumps(result,indent=2))
