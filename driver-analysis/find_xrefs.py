"""Find references to selected struct offsets or function addresses."""
from pathlib import Path
import json
import sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'vendor'))
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_64
from capstone.x86 import X86_OP_MEM,X86_OP_IMM,X86_REG_RIP
pe=pefile.PE(str(ROOT.parent/'wifi-failure-20260919-234915/driver-package/mtkwecx.sys'))
base=pe.OPTIONAL_HEADER.ImageBase
report=json.loads((ROOT/'inspection.json').read_text())
labels={}
for s in report['string_refs']: labels.setdefault(int(s['function_rva'],16),set()).add(s['string'])
targets={int(x,16) for x in sys.argv[1:]}
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
results=[]
for e in pe.DIRECTORY_ENTRY_EXCEPTION:
    start,end=e.struct.BeginAddress,e.struct.EndAddress
    ins=list(md.disasm(pe.get_data(start,end-start),base+start))
    for i,x in enumerate(ins):
        for op in x.operands:
            hit=None
            if op.type==X86_OP_MEM:
                val=(x.address+x.size+op.mem.disp-base) if op.mem.base==X86_REG_RIP else op.mem.disp
                if val in targets: hit=val
            if op.type==X86_OP_IMM and op.imm-base in targets: hit=op.imm-base
            if hit is not None:
                results.append({'target':hex(hit),'function_rva':hex(start),'labels':sorted(labels.get(start,[])), 'context':[f'{n.address-base:08x} {n.mnemonic} {n.op_str}' for n in ins[max(0,i-4):i+4]]})
(ROOT/'xrefs.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
for r in results: print(json.dumps(r))
