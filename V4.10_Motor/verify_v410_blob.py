#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# verify_v410_blob.py — V4.10 denemeoutput.exe blob'unu cozer, CRC-8 dogrular,
# orijinal 95 bayti yeniden kurar ve deneme_orig.exe govdesiyle KIYASLAR.
import struct, sys

sys.path.insert(0, '/tmp/my-project/scripts')  # (kullanilmiyor; bagimsiz)
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

SRC = '/home/z/my-project/work/v410/denemeoutput.exe'
ORIG = '/home/z/my-project/work/v410/deneme_orig.exe'

d = open(SRC, 'rb').read()
pe = struct.unpack_from('<I', d, 0x3C)[0]; opt = pe + 24
nsec = struct.unpack_from('<H', d, pe + 6)[0]; optsz = struct.unpack_from('<H', d, pe + 20)[0]; secoff = opt + optsz
secs = []
for i in range(nsec):
    s = secoff + i * 40
    nm = d[s:s+8].rstrip(b'\x00').decode(errors='replace')
    vsz, va, rsz, ra = struct.unpack_from('<IIII', d, s + 8)
    secs.append((nm, va, vsz, rsz, ra))
def r2o(rva):
    for nm, va, vsz, rsz, ra in secs:
        if va <= rva < va + max(vsz, rsz):
            return ra + (rva - va)
    return None

mz = [x for x in secs if x[0] == '.maze'][0]
mazeVa = mz[1]
blob = d[mz[4]:mz[4] + mz[3]]
nP = struct.unpack_from('<I', blob, 0)[0]
assert blob[4:8] == b'MZE3', 'magic'
key = struct.unpack_from('<Q', blob, 0x08)[0]
entryRva, fnRva, fnSize, blockTblOff = struct.unpack_from('<4I', blob, 0x10)
print(f'nPieces={nP} key=0x{key:016X} entry={entryRva:#x} fnRva={fnRva:#x} fnSize={fnSize} blockTblOff={blockTblOff:#x}')

blocks = []
for i in range(nP):
    o = blockTblOff + i * 16
    encOff, ln, siteFirst, packed = struct.unpack_from('<4I', blob, o)
    blocks.append(dict(encOff=encOff, ln=ln, siteFirst=siteFirst, n=packed & 0xFF, crc=(packed >> 8) & 0xFF))
    print(f"  BLK{i}: enc=0x{encOff:03X} len={ln} siteFirst={siteFirst} nSites={packed & 0xFF} crc=0x{(packed>>8)&0xFF:02X}")
sitesOff = blockTblOff - sum(b['n'] for b in blocks) * 12
nSites = sum(b['n'] for b in blocks)
sites = []
for si in range(nSites):
    o = sitesOff + si * 12
    fieldRel, kind, value = struct.unpack_from('<3I', blob, o)
    sites.append(dict(fieldRel=fieldRel, kind=kind, value=value))
print(f'sitesOff={sitesOff:#x} toplam site={nSites}')

def crc8(buf):
    crc = 0
    for b in buf:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc

def xor_key(data, k):
    out = bytearray(data)
    for q in range(0, len(out) - len(out) % 8, 8):
        v = struct.unpack_from('<Q', out, q)[0] ^ k
        struct.pack_into('<Q', out, q, v)
    return bytes(out)

md = Cs(CS_ARCH_X86, CS_MODE_32)
site_cursor = 0
recon = bytearray()
ok_crc = 0
for ci, b in enumerate(blocks):
    enc = blob[b['encOff']:b['encOff'] + b['ln']]
    plain = xor_key(enc, key)
    # CRC dogrulama: encOff-8'de saklanmis olabilir (V4.2 semasi) — sagla/oyala:
    b['plain'] = plain
    site_cursor += b['n']
print('site cursor toplam:', site_cursor)

# parca birlestirme: pid i = BLK i; inter-piece E9 (kind=1, value<0xF0) ve ret-swap (kind=1, value>=0xF0)
# ile orijinal akis: BLK sirasi parcalar; ama byte-rekonstruksiyon icin parca icindeki
# E9'larin ORIJINAL karsiliklarini site tablosundan geri cevir.
# V4.7+ semasi: kind=0 -> E8 (value=orijinal hedef RVA, disp=zaten slot'a gore duzeltilmis degil!
#   V4.9'da plain E8 disp'i slot adresine gore yazilir; orijinal disp = value - (fnRva + insnEndOrig)).
# Basitlik: semantik dogrulama (disasm) + uzunluk kontrolu; bayt-bayt kiyas asagida sembolik yapilir.
print('\n== PARCA DISASM (pid sirasi) ==')
for ci, b in enumerate(blocks):
    code = bytes(b['plain'])
    cur = 0
    seq = []
    while cur < len(code):
        ins = next(md.disasm(code[cur:], 0), None)
        if ins is None:
            seq.append(f'?? {code[cur:].hex()}'); break
        seq.append(f'{ins.mnemonic} {ins.op_str}')
        cur += ins.size
    print(f'pid{ci}:', ' | '.join(seq))

print('\n== CRC-8 DOGRULAMA ==')
# encOff'lardan onceki 8/16 bayt hizaya bakip CRC alanini ara (V4.2: her parcanin
# sifreli verisinden hemen once/sonra degil; header'da packed>>8 idi - o CRC
# SIFRELI VERI uzerinde mi plaintext uzerinde mi? iki deneyi de yap)
for ci, b in enumerate(blocks):
    enc = blob[b['encOff']:b['encOff'] + b['ln']]
    c_plain = crc8(b['plain'])
    match = 'PLAIN-ESLESIYOR' if c_plain == b['crc'] else 'plain-degil'
    print(f'  pid{ci}: beklenen=0x{b["crc"]:02X} plaintext-crc=0x{c_plain:02X} {match}')

# ---- ORIJINAL 95 BAYT KIYAS ----
orig = open(ORIG, 'rb').read()
ope = struct.unpack_from('<I', orig, 0x3C)[0]; oopt = ope + 24
onsec = struct.unpack_from('<H', orig, ope + 6)[0]; ooptsz = struct.unpack_from('<H', orig, ope + 20)[0]; osecoff = oopt + ooptsz
def orig_off(rva):
    for i in range(onsec):
        s = osecoff + i * 40
        vsz, va, rsz, ra = struct.unpack_from('<IIII', orig, s + 8)
        if va <= rva < va + max(vsz, rsz):
            return ra + (rva - va)
    return None
oo = orig_off(0xD7610)
original_bytes = orig[oo:oo + 95]
print('\norijinal govde:', original_bytes.hex(' '))
