"""Read-only PE inspection of the preserved MT7925 driver; never patches it."""
from pathlib import Path
import bisect
import hashlib
import json
import re
import struct
import sys
import uuid

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'vendor'))
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

DRIVER = ROOT.parent / 'wifi-failure-20260919-234915/driver-package/mtkwecx.sys'
data = DRIVER.read_bytes()
pe = pefile.PE(data=data)
base = pe.OPTIONAL_HEADER.ImageBase
functions = sorted((e.struct.BeginAddress, e.struct.EndAddress) for e in pe.DIRECTORY_ENTRY_EXCEPTION)
starts = [a for a, b in functions]

def owner(va):
    rva = va - base
    i = bisect.bisect_right(starts, rva) - 1
    if i >= 0 and rva < functions[i][1]:
        return functions[i]
    return None

imports = {}
for descriptor in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []):
    for imp in descriptor.imports:
        imports[imp.address] = descriptor.dll.decode() + '!' + (imp.name.decode() if imp.name else str(imp.ordinal))

strings = []
for pattern, encoding in [(rb'[\x20-\x7e]{5,}', 'ascii'), (rb'(?:[\x20-\x7e]\x00){5,}', 'utf-16-le')]:
    for m in re.finditer(pattern, data):
        try:
            rva = pe.get_rva_from_offset(m.start())
            if rva is None:
                continue
            va = base + rva
        except pefile.PEFormatError:
            continue
        strings.append({'va': hex(va), 'offset': hex(m.start()), 'text': m.group().decode(encoding)})
interesting = [s for s in strings if re.search(r'D0|D3|power|timeout|reset|firmware|\.pdb|aspm|l1ss|fwown|drvown|Wdf|^[A-Za-z_][A-Za-z0-9_]{4,}$', s['text'], re.I)]
string_by_va = {int(s['va'], 16): s for s in strings}

pdbs = []
for d in getattr(pe, 'DIRECTORY_ENTRY_DEBUG', []):
    if d.struct.Type == 2:
        raw = data[d.struct.PointerToRawData:d.struct.PointerToRawData+d.struct.SizeOfData]
        if raw.startswith(b'RSDS'):
            pdbs.append({'guid': uuid.UUID(bytes_le=raw[4:20]).hex.upper(), 'age': struct.unpack_from('<I', raw, 20)[0], 'path': raw[24:].split(b'\0')[0].decode(errors='replace')})

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
status_refs = []
string_refs = []
call_refs = []
interesting_vas = {int(s['va'], 16) for s in interesting}
for begin, end in functions:
    code = pe.get_data(begin, end-begin)
    for insn in md.disasm(code, base+begin):
        for op in insn.operands:
            if op.type == X86_OP_IMM and (op.imm & 0xffffffff) == 0xc000009e:
                status_refs.append({'va': hex(insn.address), 'function_rva': hex(begin), 'asm': insn.mnemonic+' '+insn.op_str})
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                target = insn.address + insn.size + op.mem.disp
                if target in interesting_vas:
                    string_refs.append({'va': hex(insn.address), 'function_rva': hex(begin), 'string': string_by_va[target]['text'], 'asm': insn.mnemonic+' '+insn.op_str})
                if target in imports:
                    call_refs.append({'va': hex(insn.address), 'function_rva': hex(begin), 'import': imports[target], 'asm': insn.mnemonic+' '+insn.op_str})

report = {'driver': str(DRIVER), 'sha256': hashlib.sha256(data).hexdigest(), 'image_base': hex(base), 'entry_rva': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), 'sections': [{'name': s.Name.rstrip(b'\0').decode(), 'rva': hex(s.VirtualAddress), 'virtual_size': s.Misc_VirtualSize, 'raw_size': s.SizeOfRawData} for s in pe.sections], 'pdb': pdbs, 'imports': {hex(k): v for k,v in imports.items()}, 'function_count': len(functions), 'power_failure_immediates': status_refs, 'interesting_strings': interesting, 'string_refs': string_refs, 'import_refs': call_refs}
(ROOT/'inspection.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
(ROOT/'all-strings.json').write_text(json.dumps(strings, indent=2), encoding='utf-8')
print(json.dumps({k: report[k] for k in ['sha256','image_base','entry_rva','sections','pdb','function_count','power_failure_immediates']}, indent=2))
print('Interesting strings:', len(interesting), 'string references:', len(string_refs), 'import references:', len(call_refs))
for s in interesting[:90]:
    print(s['va'], s['text'][:180])
