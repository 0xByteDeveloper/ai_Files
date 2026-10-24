#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# rebuild_deneme_orig.py — V4.6 denemeoutput.exe'den ORIJINAL metin2 deneme.exe'yi geri insa eder
#
# V4.6'nin yaptiklari (tersine cevriliyor):
#   1) govde RVA 0xD7610 +95 bayt -> E9 3B BA 46 00 + 0xCC dolgu   (geri yaziliyor)
#   2) DllCharacteristics DYNAMICBASE (0x40) temizlendi            (geri konuyor)
#   3) .mpimp (+0x200 raw) ve .maze (+0x800 raw) section'lari eklendi (kirpiliyor)
#   4) NumberOfSections 6->8, SizeOfImage 0x542000->0x544000        (geri aliniyor)
#   5) checksum guncellenmis olabilir                              (sifirlaniyor)
# .reloc DOKUNULMAMIS olmali (V4.6 reloc yazmiyor) -> govde reloc'u (0xD764C)
# otomatik olarak orijinal halinde kalir. Asagida dogrulanir.
import struct, sys

SRC = '/home/z/my-project/upload/denemeoutput.exe'
OUT = '/tmp/my-project/work/task1/deneme_orig.exe'
OUT2 = '/home/z/my-project/work/v410/deneme_orig.exe'
BODY_RVA = 0xD7610
BODY_LEN = 95
ORIG_SECTIONS = 6
ORIG_IMG_SIZE = 0x542000
ORIG_FILE_END = 0x4F9800   # .reloc raw sonu (0x4CEE00 + 0x2AA00)
# V4.6 encoder dir[1]'i .mpimp'e repoint etti; ORIJINAL import dizini .rdata'da:
# V4.6 .mpimp kopyasindaki 19-descriptor dizisi .rdata'da bulundu (RVA 0x4497C8).
ORIG_IMPORT_RVA = 0x4497C8
ORIG_IMPORT_SIZE = 0x190   # 19 descriptor + NULL

# --- V4.6 parcalari + site tablosundan KESINLESTIRILEN orijinal 95 bayt ---
# pid0 [D7610,D7620) : 55 8BEC 83EC08 56 8BF1 E8 DC1A0 84C0
# pid1 [D7620,D762B) : 75 09 (jne D762B) B001 5E 8BE5 5D C2 08 00
# pid2 [D762B,D763E) : 8A4508 8845F9 8B450C 8945FA 8D45F8 50 51 8BCE
# pid3 [D763E,D764B) : C645F802 E8 D7670 84C0 75 16 (jne D7661)
# pid4 [D764B,D765E) : 68 8033BC E8 141660 83C404 32C0 5E 8BE5 5D
# pid5 [D765E,D7661) : C2 08 00
# pid6 [D7661,D766F) : 8BCE E8 152520 5E 8BE5 5D C2 08 00
def rel32(src_end, target):
    return struct.pack('<i', target - src_end)

body = b''
body += bytes.fromhex('55 8BEC 83EC08 56 8BF1'.replace(' ', ''))          # 11
body += b'\xE8' + rel32(0xD761E, 0xDC1A0) + bytes.fromhex('84C0')          # 5+2 -> 18? (11+5+2=18) [D7610..D7622) degil!
# DİKKAT: yukarida yanlis kesim var; dogrusu asagida tek tek kuruluyor.
body = b''
body += b'\x55'                                  # D7610 push ebp
body += b'\x8B\xEC'                              # D7611 mov ebp, esp
body += b'\x83\xEC\x08'                          # D7613 sub esp, 8
body += b'\x56'                                  # D7616 push esi
body += b'\x8B\xF1'                              # D7617 mov esi, ecx
body += b'\xE8' + rel32(0xD761E, 0xDC1A0)        # D7619 call 0xDC1A0
body += b'\x84\xC0'                              # D761E test al, al
body += b'\x75\x09'                              # D7620 jne short 0xD762B
body += b'\xB0\x01'                              # D7622 mov al, 1
body += b'\x5E'                                  # D7624 pop esi
body += b'\x8B\xE5'                              # D7625 mov esp, ebp
body += b'\x5D'                                  # D7627 pop ebp
body += b'\xC2\x08\x00'                          # D7628 ret 8
body += b'\x8A\x45\x08'                          # D762B mov al, [ebp+8]
body += b'\x88\x45\xF9'                          # D762E mov [ebp-7], al
body += b'\x8B\x45\x0C'                          # D7631 mov eax, [ebp+0xC]
body += b'\x89\x45\xFA'                          # D7634 mov [ebp-6], eax
body += b'\x8D\x45\xF8'                          # D7637 lea eax, [ebp-8]
body += b'\x50'                                  # D763A push eax
body += b'\x51'                                  # D763B push ecx
body += b'\x8B\xCE'                              # D763C mov ecx, esi
body += b'\xC6\x45\xF8\x02'                      # D763E mov byte [ebp-8], 2
body += b'\xE8' + rel32(0xD7647, 0xD7670)        # D7642 call 0xD7670
body += b'\x84\xC0'                              # D7647 test al, al
body += b'\x75\x16'                              # D7649 jne short 0xD7661
body += b'\x68' + struct.pack('<I', 0x8033BC)    # D764B push "Send Battle Attack Packet Error"
body += b'\xE8' + rel32(0xD7655, 0x141660)       # D7650 call 0x141660
body += b'\x83\xC4\x04'                          # D7655 add esp, 4
body += b'\x32\xC0'                              # D7658 xor al, al
body += b'\x5E'                                  # D765A pop esi
body += b'\x8B\xE5'                              # D765B mov esp, ebp
body += b'\x5D'                                  # D765D pop ebp
body += b'\xC2\x08\x00'                          # D765E ret 8
body += b'\x8B\xCE'                              # D7661 mov ecx, esi
body += b'\xE8' + rel32(0xD7668, 0x152520)       # D7663 call 0x152520
body += b'\x5E'                                  # D7668 pop esi
body += b'\x8B\xE5'                              # D7669 mov esp, ebp
body += b'\x5D'                                  # D766B pop ebp
body += b'\xC2\x08\x00'                          # D766C ret 8
assert len(body) == BODY_LEN, f"govde {len(body)} != {BODY_LEN}"

d = bytearray(open(SRC, 'rb').read())
pe = struct.unpack_from('<I', d, 0x3C)[0]
opt = pe + 24
nsec_off = pe + 6
optsz = struct.unpack_from('<H', d, pe + 20)[0]
secoff = opt + optsz
imgsz_off = opt + 56
dllchar_off = opt + 70
chk_off = opt + 64

def r2o(rva):
    for i in range(struct.unpack_from('<H', d, nsec_off)[0]):
        s = secoff + i * 40
        vsz, va, rsz, ra = struct.unpack_from('<IIII', d, s + 8)
        if va <= rva < va + max(vsz, rsz):
            return ra + (rva - va)
    raise SystemExit('RVA bulunamadi')

# --- .reloc dogrulamasi: govde icinde 0xD764C HIGHLOW OLMALI (orijinal ASLR'liydi) ---
ra, rsz = 0x4CEE00, 0x2A838
off = ra; hits = []
while off < ra + rsz - 8:
    pageRva, blkSz = struct.unpack_from('<II', d, off)
    if blkSz == 0: break
    for i in range((blkSz - 8) // 2):
        e = struct.unpack_from('<H', d, off + 8 + i * 2)[0]
        t, o = e >> 12, e & 0xFFF
        if t == 0: continue
        rva = pageRva + o
        if 0xD7610 <= rva < 0xD7670: hits.append((hex(rva), t))
    off += blkSz
print('govde-reloc girisleri (denemeoutput):', hits)
assert (hex(0xD764C), 3) in hits or (hex(0xD764C), 10) in hits, '0xD764C reloc YOK!'

# --- 1) govde geri yazimi ---
o = r2o(BODY_RVA)
cur = bytes(d[o:o + BODY_LEN])
print('mevcut govde:', cur[:8].hex(' '), '...')
d[o:o + BODY_LEN] = body
print('yeni govde  :', body[:8].hex(' '), '...')

# --- 2) DllCharacteristics: DYNAMICBASE geri ---
dc = struct.unpack_from('<H', d, dllchar_off)[0]
print(f'DllCharacteristics: 0x{dc:04X} ->', end=' ')
dc |= 0x0040
struct.pack_into('<H', d, dllchar_off, dc)
print(f'0x{dc:04X}')

# --- 3/4) section sayisi + SizeOfImage ---
n = struct.unpack_from('<H', d, nsec_off)[0]
print(f'NumberOfSections: {n} -> {ORIG_SECTIONS}')
struct.pack_into('<H', d, nsec_off, ORIG_SECTIONS)
sz = struct.unpack_from('<I', d, imgsz_off)[0]
print(f'SizeOfImage: 0x{sz:X} -> 0x{ORIG_IMG_SIZE:X}')
struct.pack_into('<I', d, imgsz_off, ORIG_IMG_SIZE)

# --- 5) checksum sifirla ---
struct.pack_into('<I', d, chk_off, 0)

# --- 6) import dizini ORIJINAL .rdata tablasina geri ---
old_imp = struct.unpack_from('<II', d, opt + 104)
struct.pack_into('<II', d, opt + 104, ORIG_IMPORT_RVA, ORIG_IMPORT_SIZE)
print(f'importDir: {old_imp[0]:#x}/{old_imp[1]:#x} -> {ORIG_IMPORT_RVA:#x}/{ORIG_IMPORT_SIZE:#x}')

# --- kirpma ---
d = d[:ORIG_FILE_END]
open(OUT, 'wb').write(d)
open(OUT2, 'wb').write(d)
print('yazildi:', OUT, 've', OUT2, len(d), 'bayt')

# --- dogrulama: 6 section, govde disasm ozeti ---
n = struct.unpack_from('<H', d, nsec_off)[0]
print('final NumberOfSections =', n, ' SizeOfImage =', hex(struct.unpack_from('<I', d, imgsz_off)[0]))
