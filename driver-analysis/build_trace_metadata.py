"""Build a diagnostic provider list from this exact INF and validate against SYS."""
from pathlib import Path
import hashlib
import json
import re
import sys
import uuid
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'vendor'))
import pefile
package=ROOT.parent/'wifi-failure-20260919-234915/driver-package'
binary=(package/'mtkwecx.sys').read_bytes()
pe=pefile.PE(data=binary)
inf=(package/'mtkwecx.inf').read_bytes().decode('utf-16')
section=inf.split('[Wpp2.reg]',1)[1].split('\n[',1)[0]
guids=sorted(set(re.findall(r'\{[0-9A-Fa-f-]{36}\}',section)))
providers=[]
for guid in guids:
    offset=binary.find(uuid.UUID(guid).bytes_le)
    if offset<0:
        raise RuntimeError('INF trace GUID missing from exact binary: '+guid)
    providers.append({'guid':guid,'file_offset':hex(offset)})
providers.extend([
    {'guid':'{9C205A39-1250-487D-ABD7-E831C6290539}','name':'Microsoft-Windows-Kernel-PnP'},
    {'guid':'{CDEAD503-17F5-4A3E-B7AE-DF8CC2902EB9}','name':'Microsoft-Windows-NDIS'},
])
(ROOT/'internal-trace-providers.txt').write_text('\n'.join(p['guid']+' 0x7fffffff 5' for p in providers)+'\n',encoding='ascii')
formats={name:str(uuid.UUID(bytes_le=pe.get_data(rva,16))) for name,rva in [('power_callbacks',0x259c40),('mt7925_bootstrap',0x264740),('firmware_ownership',0x264370)]}
metadata={'driver_sha256':hashlib.sha256(binary).hexdigest(),'providers':providers,'wpp_format_guids':formats,'diagnostic_only':True,'notes':'Addresses and message meanings inferred from static disassembly; not proof that a branch ran during the failure.'}
(ROOT/'internal-trace-metadata.json').write_text(json.dumps(metadata,indent=2),encoding='utf-8')
print(json.dumps(metadata,indent=2))
