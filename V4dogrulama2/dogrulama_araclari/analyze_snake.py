#!/usr/bin/env python3
# TinySnake GameLoop (RVA 0x1158) disassembly + SITE kapsama denetimi
import pefile, capstone, re, sys

UNP = "/home/z/my-project/download/V4Dogrulama/MiniOyun/TinySnake.x64.unpack.exe"
PRO = "/home/z/my-project/download/V4Dogrulama/MiniOyun/TinySnake.x64.protected.exe"
MAP = "/home/z/my-project/download/V4Dogrulama/MiniOyun/Snake_Map.txt"

pe = pefile.PE(UNP)
ib = pe.OPTIONAL_HEADER.ImageBase
print(f"ImageBase=0x{ib:X}  Machine=0x{pe.FILE_HEADER.Machine:X}  DllChar=0x{pe.OPTIONAL_HEADER.DllCharacteristics:X}")
for s in pe.sections:
    print(f"  sec {s.Name.decode().rstrip(chr(0)):8} VA=0x{s.VirtualAddress:05X} VS=0x{s.Misc_VirtualSize:05X} raw=0x{s.PointerToRawData:05X} rs=0x{s.SizeOfRawData:05X} ch=0x{s.Characteristics:08X}")

data = pe.get_memory_mapped_image()
FN_RVA, FN_SZ = 0x1158, 696
code = data[FN_RVA:FN_RVA+FN_SZ]

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

# rel8 / rel32 / rip-rel / r12 envanteri
rel8, rel32, riprel, other = [], [], [], []
addr_list = []
for ins in md.disasm(code, ib + FN_RVA):
    addr_list.append(ins)
    grp = None
    for op in ins.operands:
        if op.type == capstone.x86.X86_OP_IMM and ins.group(capstone.x86.X86_GRP_JUMP) or \
           op.type == capstone.x86.X86_OP_IMM and ins.group(capstone.x86.X86_GRP_CALL):
            pass
    m = ins.mnemonic
    is_br = m.startswith('j') or m in ('call','loop','loope','loopne','jecxz','jrcxz')
    if is_br and ins.operands and ins.operands[0].type == capstone.x86.X86_OP_IMM:
        tgt = ins.operands[0].imm
        ins_len = ins.size
        if ins_len <= 2 and m != 'call':
            rel8.append((ins.address - ib, ins.mnemonic + ' ' + ins.op_str, ins_len, tgt - ib))
        else:
            rel32.append((ins.address - ib, ins.mnemonic + ' ' + ins.op_str, ins_len, tgt - ib))
        continue
    # rip-relative bellek erisimi
    for op in ins.operands:
        if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
            riprel.append((ins.address - ib, m + ' ' + ins.op_str, ins.size))
            break

print(f"\n=== GameLoop RVA 0x{FN_RVA:X}..0x{FN_RVA+FN_SZ:X}  ({len(addr_list)} komut) ===")
print(f"rel8 dallanmalar : {len(rel8)}")
for a,t,l,tg in rel8: print(f"   0x{a:05X} [{l}B] {t}   -> 0x{tg:X}")
print(f"rel32 dallanma   : {len(rel32)}")
for a,t,l,tg in rel32: print(f"   0x{a:05X} [{l}B] {t}   -> 0x{tg:X}")
print(f"rip-relative     : {len(riprel)}")
for a,t,l in riprel: print(f"   0x{a:05X} [{l}B] {t}")

# r12 kullanimi
r12use = [i for i in addr_list if 'r12' in i.op_str or 'r12' in i.mnemonic]
print(f"r12 kullanan komut: {len(r12use)}")
for i in r12use[:20]: print(f"   0x{i.address-ib:05X} {i.mnemonic} {i.op_str}")

# tum komut listesi (kisa)
print("\n=== TAM LISTE ===")
for i in addr_list:
    print(f"0x{i.address-ib:05X}: {i.bytes.hex():24} {i.mnemonic} {i.op_str}")
