#!/usr/bin/env python3
# V4.2 blob dogrulamasi - header-surumlu (offsetler header'dan okunur)
import pefile, capstone, struct, re, sys
from collections import defaultdict

P   = "/home/z/my-project/download/V4Dogrulama/MiniOyun/TinySnake.x64.protected.v42.exe"
U   = "/home/z/my-project/download/V4Dogrulama/MiniOyun/TinySnake.x64.unpack.exe"
MAP = "/home/z/my-project/download/V4Dogrulama/Snake_Map_v42.txt"

IB   = 0x400000
pe = pefile.PE(P); data = pe.get_memory_mapped_image()
pu = pefile.PE(U); du = pu.get_memory_mapped_image()

# blob RVA: MZE3 magic -4
BLOB = None
for s in pe.sections:
    raw = s.get_data()
    j = raw.find(b'MZE3')
    if j >= 0: BLOB = s.VirtualAddress + j - 4; break
assert BLOB
K = data[BLOB+8:BLOB+16]
nPieces, = struct.unpack_from("<I", data, BLOB)
blockTblOff, = struct.unpack_from("<I", data, BLOB+0x1C)
nSites, = struct.unpack_from("<I", data, BLOB+0x2C)
sitesOff, = struct.unpack_from("<I", data, BLOB+0x30)
edgeTblOff, = struct.unpack_from("<I", data, BLOB+0x3C)
print(f"blob=0x{BLOB:X} nPieces={nPieces} blockTbl=0x{blockTblOff:X} sites=0x{sitesOff:X}({nSites}) edge=0x{edgeTblOff:X} K={K.hex()}")

blocks = []
for i in range(nPieces):
    encOff, ln, siteFirst, packed = struct.unpack_from("<IIII", data, BLOB + blockTblOff + i*16)
    blocks.append((encOff, ln, siteFirst, packed & 0xFF, packed >> 8))

sites = []
for i in range(nSites):
    fo, kind, val = struct.unpack_from("<III", data, BLOB + sitesOff + i*12)
    sites.append((fo, kind, val))

def crc8(bs):
    c = 0
    for b in bs:
        c ^= b
        for _ in range(8):
            c = ((c << 1) ^ 0x07) & 0xFF if (c & 0x80) else (c << 1) & 0xFF
    return c

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64); md.detail = True

# map'ten blk rva araliklari
blk_rva = {}
for line in open(MAP, encoding='utf-8', errors='replace'):
    m = re.match(r'BLK (\d+) .*rva=0x([0-9A-Fa-f]+)\.\.0x([0-9A-Fa-f]+)', line.strip())
    if m: blk_rva[int(m.group(1))] = (int(m.group(2),16), int(m.group(3),16))
fn_rva, fn_size = None, None
for line in open(MAP, encoding='utf-8', errors='replace'):
    m = re.match(r'FUNC (\S+) (\d+) (\d+)', line.strip())
    if m: fn_rva, fn_size = int(m.group(2)), int(m.group(3))
orig = {}
for ins in md.disasm(bytes(du[fn_rva:fn_rva+fn_size]), IB+fn_rva):
    orig[ins.address - IB] = ins

pieces = {}
for i, (encOff, ln, siteFirst, nS, crc) in enumerate(blocks):
    span = bytes(data[BLOB+encOff:BLOB+encOff+ln])
    dec = bytes(b ^ K[j % 8] for j, b in enumerate(span))
    pieces[i] = (encOff, ln, dec, siteFirst, nS, crc)

crc_bad = [(i, crc8(dec[:ln]), crc) for i,(encOff,ln,dec,siteFirst,nS,crc) in pieces.items() if crc8(dec[:ln]) != crc]
print(f"CRC-8 uyusmayan parca: {len(crc_bad)} {crc_bad[:5]}")

def widen_expected(start_rva, end_rva):
    out = bytearray()
    a = start_rva
    while a < end_rva:
        ins = orig.get(a)
        if ins is None: return None
        b = bytes(du[a:a+ins.size])
        op0 = b[0]
        if ins.size == 2 and op0 == 0xEB and ins.mnemonic == 'jmp':
            out += b[0:1] + b'\x00\x00\x00\x00' + b'\xCC'*3
        else:
            out += b
        a += ins.size
    return bytes(out)

errors = []
for i, (encOff, ln, dec, siteFirst, nS, crc) in pieces.items():
    if i not in blk_rva: errors.append(f"blk{i}: map'te rva yok"); continue
    s, e = blk_rva[i]
    exp = widen_expected(s, e)
    if exp is None: continue
    # disp alanlarini normalize et: bilinen site fieldOff'lari + widened rel8 disp -> 0'a cek
    body = bytearray(dec[:len(exp)])
    expn = bytearray(exp)
    for k in range(nS):
        fo = sites[siteFirst + k][0]
        for q in range(4):
            if fo+q < len(body): body[fo+q] = 0
            if fo+q < len(expn): expn[fo+q] = 0
    # widened EB disp (genisletme sonrasi: EB'nin disp32'si site ile eslesmeyebilir -> EB sonrasi 4 bayt)
    a = s
    idx = 0
    while a < e:
        ins = orig.get(a)
        b = bytes(du[a:a+ins.size])
        if ins.size == 2 and b[0] == 0xEB:
            # genisletilmis: idx+1..idx+5 disp (site kaydinda VAR - yukarida sifirlandi eger site varsa)
            for q in range(1,5):
                if idx+q < len(expn): expn[idx+q] = 0
                if idx+q < len(body): body[idx+q] = 0
        idx += ins.size
        a += ins.size
    diffs = [(k, body[k], expn[k]) for k in range(min(len(body),len(expn))) if body[k] != expn[k]]
    if diffs:
        k = diffs[0][0]
        errors.append(f"blk{i} rva=0x{s:X}: +0x{k:X} {body[k:k+6].hex()} vs {expn[k:k+6].hex()} ({len(diffs)} bayt)")
print(f"parca-icerik farklari: {len(errors)}")
for e in errors[:15]: print("  ", e)

# site formulu: stored == target - srcVA - (fieldOff+4)
# V4.2: THUNK hedefi ARTIK THUNK ADRESI DEGIL - disp'in hedefi THUNK (E9 thunk'a atlar!)
BLOBVA = IB + BLOB
site_err = 0
for i, (encOff, ln, dec, siteFirst, nS, crc) in pieces.items():
    s, e = blk_rva[i]
    srcVA = BLOBVA + encOff
    for k in range(nS):
        fo, kind, val = sites[siteFirst + k]
        stored = struct.unpack_from("<i", dec, fo)[0]
        if kind == 1:
            thunkIdx = val if val < 0xF0 else nPieces + (0xFE - val)
            target = BLOBVA + edgeTblOff + thunkIdx * 12
        else:
            target = IB + val
        need = (target - srcVA - (fo + 4)) & 0xFFFFFFFF
        if (stored & 0xFFFFFFFF) != need:
            site_err += 1
            if site_err <= 5: print(f"  siteHATA blk{i} k={k} kind={kind} val=0x{val:X}: stored=0x{stored&0xFFFFFFFF:08X} need=0x{need:08X}")
print(f"site-formul hatalari: {site_err}")
