#!/usr/bin/env python3
# Snake_Map.txt SITE kapsama + dogruluk denetimi
# Her dallanma/rip-rel komutu icin SITE kaydini bul; THUNK hedefinin dogru
# block'a gittigini, RIP/MODUL hedeflerinin dogru RVA oldugunu kontrol et.
import pefile, capstone, re, sys
from collections import defaultdict

UNP = "/home/z/my-project/download/V4Dogrulama/MiniOyun/TinySnake.x64.unpack.exe"
MAP = "/home/z/my-project/download/V4Dogrulama/MiniOyun/Snake_Map.txt"
FN_RVA, FN_SZ = 0x1158, 696

pe = pefile.PE(UNP)
ib = pe.OPTIONAL_HEADER.ImageBase
data = pe.get_memory_mapped_image()

# --- BLK kayitlari ---
blocks = []  # (idx, rvaStart, rvaEnd, len, ops)
for line in open(MAP, encoding='utf-8', errors='replace'):
    m = re.match(r'BLK (\d+) enc=0x([0-9A-Fa-f]+) len=\s*(\d+) ops=\s*(\d+) rva=0x([0-9A-Fa-f]+)\.\.0x([0-9A-Fa-f]+)', line.strip())
    if m:
        blocks.append((int(m.group(1)), int(m.group(5),16), int(m.group(6),16), int(m.group(3)), int(m.group(4))))
blocks.sort(key=lambda b: b[0])
print(f"BLK sayisi: {len(blocks)}")

# --- SITE kayitlari ---
sites = defaultdict(list)  # blk -> [(off, kind, val)]
nsite = 0
for line in open(MAP, encoding='utf-8', errors='replace'):
    m = re.match(r'SITE blk=(\d+) \+0x([0-9A-Fa-f]+) kind=(\w+) val=0x([0-9A-Fa-f]+)', line.strip())
    if m:
        sites[int(m.group(1))].append((int(m.group(2),16), m.group(3), int(m.group(4),16)))
        nsite += 1
print(f"SITE sayisi: {nsite}")

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

def blk_of(rva):
    for (i, s, e, l, o) in blocks:
        if s <= rva < e: return i
    return None

# --- komutlari gez, her reloc gerektiren komut icin SITE ar ---
problems = []
ok_thunk = ok_rip = ok_modul = 0
insns = list(md.disasm(data[FN_RVA:FN_RVA+FN_SZ], ib+FN_RVA))
for ins in insns:
    rva = ins.address - ib
    b = blk_of(rva)
    if b is None:
        problems.append(f"0x{rva:05X} {ins.mnemonic} {ins.op_str} : HICBIR BLK ICINDE DEGIL!")
        continue
    m = ins.mnemonic
    is_br = (m.startswith('j') and m != 'jmp' and not m.startswith('jrcxz')) or m in ('jmp','call','loop','loope','loopne','jecxz','jrcxz')
    site_candidates = []
    if is_br and ins.operands and ins.operands[0].type == capstone.x86.X86_OP_IMM:
        tgt = ins.operands[0].imm - ib
        disp_off_in_piece = (rva + ins.size - 4) - blocks[b][1] if ins.size >= 5 else (rva + ins.size - 1) - blocks[b][1]
        site_candidates = [s for s in sites[b] if s[1] in ('THUNK','MODUL') ]
        # disp32'nin parca-ici offset'i (genisletme sonrasi degisebilir -> esnek eslesme)
        match = None
        for (off, kind, val) in sites[b]:
            if kind == 'THUNK':
                tb = val if val < 0xF0 else None
                if tb is None or tb >= len(blocks): continue
                tgt_rva = blocks[tb][1]
                if tgt_rva == tgt: match = ('THUNK', off, val); ok_thunk += 1; break
                # kayit VAR ama hedef YANLIS
                problems.append(f"0x{rva:05X} [{ins.mnemonic} {ins.op_str}] THUNK val=0x{val:X} -> parca{tb} (rva 0x{tgt_rva:05X}) GERCEK HEDEF 0x{tgt:05X} !!")
                problems.append(f"      (blk{b} siteleri: {sites[b]})")
                match = ('THUNK-BAD', off, val); break
            elif kind == 'MODUL':
                if val == tgt: match = ('MODUL', off, val); ok_modul += 1; break
        if not match and not site_candidates:
            problems.append(f"0x{rva:05X} [{ins.mnemonic} {ins.op_str}] (blk{b}) SITE YOK! hedef=0x{tgt:05X}")
        continue
    # rip-relative
    rip = False
    for op in ins.operands:
        if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
            rip = True
            tgt = ins.address + ins.size + op.mem.disp - ib
            break
    if rip:
        found = None
        for (off, kind, val) in sites[b]:
            if kind == 'RIP':
                if val == tgt: found = off; ok_rip += 1; break
                problems.append(f"0x{rva:05X} [{ins.mnemonic} {ins.op_str}] RIP val=0x{val:X} GERCEK 0x{tgt:X} !! (blk{b} siteleri: {sites[b]})")
                found = -1; break
        if found is None:
            problems.append(f"0x{rva:05X} [{ins.mnemonic} {ins.op_str}] (blk{b}) RIP SITE YOK! hedef=0x{tgt:05X}")

print(f"\nOK: THUNK={ok_thunk} MODUL={ok_modul} RIP={ok_rip}")
print(f"PROBLEM: {len(problems)}")
for p in problems[:60]: print(" ", p)

# BLK kapsama: tum komut adresleri bloklarin icinde mi? bosluk var mi?
covered = set()
for (i,s,e,l,o) in blocks: covered.update(range(s,e))
missing = [hex(r) for r in range(FN_RVA, FN_RVA+FN_SZ) if r not in covered]
print(f"\nBLK kapsam disi bayt: {len(missing)} {missing[:40]}")
