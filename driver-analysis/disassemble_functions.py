"""Annotated read-only disassembly, using string references as tentative labels."""
from pathlib import Path
import bisect
import json
import sys
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT/'vendor'))
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
pe = pefile.PE(str(ROOT.parent/'wifi-failure-20260919-234915/driver-package/mtkwecx.sys'))
base = pe.OPTIONAL_HEADER.ImageBase
report = json.loads((ROOT/'inspection.json').read_text())
strings = {int(s['va'],16): s['text'] for s in json.loads((ROOT/'all-strings.json').read_text())}
imports = {int(k,16):v for k,v in report['imports'].items()}
labels = {}
for s in report['string_refs']:
    labels.setdefault(int(s['function_rva'],16),set()).add(s['string'])
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
functions = {e.struct.BeginAddress:e.struct.EndAddress for e in pe.DIRECTORY_ENTRY_EXCEPTION}
for arg in sys.argv[1:]:
    rva = int(arg,16)
    if rva not in functions:
        containing = next((a for a,b in functions.items() if a <= rva < b), None)
        if containing is not None:
            rva = containing
        else:
            # Leaf routines may have no unwind entry. Bound inspection to 512 bytes.
            functions[rva] = rva + 512
    lines = [f'; Function RVA {rva:#x}, end {functions[rva]:#x}', '; Tentative labels: '+repr(sorted(labels.get(rva,[])))]
    for ins in md.disasm(pe.get_data(rva,functions[rva]-rva),base+rva):
        comments=[]
        for op in ins.operands:
            if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                target = ins.address+ins.size+op.mem.disp
                if target in strings: comments.append(repr(strings[target]))
                if target in imports: comments.append(imports[target])
            if op.type == X86_OP_IMM and ins.mnemonic == 'call':
                if op.imm-base in labels: comments.append('tentative '+repr(sorted(labels[op.imm-base])))
        lines.append(f'{ins.address-base:08x}  {ins.mnemonic:8} {ins.op_str}' + (' ; '+' | '.join(comments) if comments else ''))
    (ROOT/f'function-{rva:x}.asm').write_text('\n'.join(lines),encoding='utf-8')
    print(f'RVA {rva:#x}: {len(lines)-2} instructions, tentative labels {sorted(labels.get(rva,[]))}')
