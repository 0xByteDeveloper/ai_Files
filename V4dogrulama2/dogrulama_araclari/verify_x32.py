#!/usr/bin/env python3
# V4.2-X86 blob dogrulamasi (TinySnake.x32.protected.exe)
import pefile, capstone, struct, re
P   = "/home/z/my-project/download/V4Dogrulama/MiniOyun/TinySnake.x32.protected.exe"
U   = "/home/z/my-project/download/V4Dogrulama/MiniOyun/TinySnake.x32.unpack.exe"
MAP = "/home/z/my-project/download/V4Dogrulama/Snake_Map_x32.txt"

pe = pefile.PE(P); data = pe.get_memory_mapped_image()
pu = pefile.PE(U); du = pu.get_memory_mapped_image()
IB = pe.OPTIONAL_HEADER.ImageBase

BLOB = None
for s in pe.sections:
    raw = s.get_data()
    j = raw.find(b'MZE3')
    if j >= 0: BLOB = s.VirtualAddress + j - 4; break
K = data[BLOB+8:BLOB+16]
nPieces, = struct.unpack_from("<I", data, BLOB)
blockTblOff, = struct.unpack_from("<I", data, BLOB+0x1C)
nSites, = struct.unpack_from("<I", data, BLOB+0x2C)
sitesOff, = struct.unpack_from("<I", data, BLOB+0x30)
edgeTblOff, = struct.unpack_from("<I", data, BLOB+0x3C)
fnRva, = struct.unpack_from("<I", data, BLOB+0x14)
fnSize, = struct.unpack_from("<I", data, BLOB+0x18)
print(f"blob=0x{BLOB:X} nPieces={nPieces} sites={nSites} edge=0x{edgeTblOff:X} fn=0x{fnRva:X}+{fnSize} K={K.hex()}")

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

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32); md.detail = True
orig = {}
for ins in md.disasm(bytes(du[fnRva:fnRva+fnSize]), IB+fnRva):
    orig[ins.address - IB] = ins

crc_bad = 0
pieces = {}
for i, (encOff, ln, siteFirst, nS, crc) in enumerate(blocks):
    span = bytes(data[BLOB+encOff:BLOB+encOff+ln])
    dec = bytes(b ^ K[j % 8] for j, b in enumerate(span))
    pieces[i] = (encOff, ln, dec, siteFirst, nS, crc)
    if crc8(dec[:ln]) != crc: crc_bad += 1
print(f"CRC-8 uyusmayan parca: {crc_bad}")

# BLK rva araliklari map'ten
blk_rva = {}
for line in open(MAP, encoding='utf-8', errors='replace'):
    m = re.match(r'BLK (\d+) .*rva=0x([0-9A-Fa-f]+)\.\.0x([0-9A-Fa-f]+)', line.strip())
    if m: blk_rva[int(m.group(1))] = (int(m.group(2),16), int(m.group(3),16))

errors = []
BLOBVA = IB + BLOB
site_err = 0
for i, (encOff, ln, dec, siteFirst, nS, crc) in pieces.items():
    if i not in blk_rva: continue
    s, e = blk_rva[i]
    # beklenen imaj: original + EB->E9 genisletme + 7x->0F8x genisletme
    exp = bytearray()
    a = s
    while a < e:
        ins = orig.get(a)
        if ins is None: break
        b = bytes(du[a:a+ins.size])
        op0 = b[0]
        if ins.size == 2 and op0 == 0xEB:
            exp += b'\xE9\x00\x00\x00\x00' + b'\xCC'*3
        elif ins.size == 2 and 0x70 <= op0 <= 0x7F:
            exp += b'\x0F' + bytes([0x80 | (op0 - 0x70)]) + b'\x00\x00\x00\x00'
        else:
            exp += b
        a += ins.size
    body = bytearray(dec[:len(exp)])
    # site fieldlarini sifirla (disp degerleri farkli olacak)
    for k in range(nS):
        fo = sites[siteFirst + k][0]
        for q in range(4):
            if fo+q < len(body): body[fo+q] = 0
            if fo+q < len(exp): exp[fo+q] = 0
    # genisletilen dali disp sifirla
    a = s; idx = 0
    while a < e:
        ins = orig.get(a)
        if ins is None: break
        b = bytes(du[a:a+ins.size])
        if ins.size == 2 and (b[0] == 0xEB or 0x70 <= b[0] <= 0x7F):
            off = idx + (2 if 0x70 <= b[0] <= 0x7F else 1)
            for q in range(4):
                if off+q < len(exp): exp[off+q] = 0
                if off+q < len(body): body[off+q] = 0
        idx += ins.size; a += ins.size
    diffs = [(k, body[k], exp[k]) for k in range(min(len(body), len(exp))) if body[k] != exp[k]]
    if diffs:
        k = diffs[0][0]
        errors.append(f"blk{i} rva=0x{s:X}: +0x{k:X} {body[k:k+6].hex()} vs {exp[k:k+6].hex()} ({len(diffs)} bayt)")
    # site formulu
    srcVA = BLOBVA + encOff
    for k in range(nS):
        fo, kind, val = sites[siteFirst + k]
        stored = struct.unpack_from("<i", dec, fo)[0]
        if kind == 1:
            thunkIdx = val if val < 0xF0 else nPieces + (0xFE - val)
            target = BLOBVA + edgeTblOff + thunkIdx * 11
        else:
            target = IB + val
        need = (target - srcVA - (fo + 4)) & 0xFFFFFFFF
        if (stored & 0xFFFFFFFF) != need:
            site_err += 1
            if site_err <= 5: print(f"  siteHATA blk{i} k={k} kind={kind} val=0x{val:X}: stored=0x{stored&0xFFFFFFFF:08X} need=0x{need:08X}")

print(f"parca-icerik farklari: {len(errors)}")
for e in errors[:12]: print("  ", e)
print(f"site-formul hatalari: {site_err}")

# .reloc kontrolu
rel = pe.OPTIONAL_HEADER.DATA_DIRECTORY[5]
print(f".reloc dir: VA=0x{rel.VirtualAddress:X} Size=0x{rel.Size:X}")
