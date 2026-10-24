#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# build_harness_v410.py — V4.10 denemeoutput.exe uzerine gercek-fonksiyon relay harness'i kurar.
#   harness_m2_*.exe   : EP -> .mpimp bosluk stub -> call 0xD7610 (korunmus, maze uzerinden)
#   harness_base_*.exe : ayni dosyada govde ORIJINAL 95 bayta geri yazilir (stub direkt cagirir)
# Varyantlar (E8 hedef stub degerleri): x1=DC1A0, x2=D7670, x3=141660, x4=152520
#   A: x1=0                          -> erken cikis al=1 (exit 1)
#   B: x1=1 x2=0                     -> hata yolu (string push + 141660 + xor al,al) (exit 0)
#   C: x1=1 x2=1 x4=1                -> basari yolu (152520 -> al=1) (exit 1)
#   D: x1=1 x2=1 x4=0                -> basari yolu (al=0) (exit 0)
#   L: 400 dongu (x1=1 x2=0)         -> leak/fb tespiti (exit 0x2A=42)
import struct, sys, os

SRC = '/home/z/my-project/work/v410/denemeoutput.exe'
OUT = '/home/z/my-project/work/v410'
FN_RVA = 0xD7610
E8T = [0xDC1A0, 0xD7670, 0x141660, 0x152520]
ORIG_BODY = bytes.fromhex(
    '55 8b ec 83 ec 08 56 8b f1 e8 82 4b 00 00 84 c0 75 09 b0 01 5e 8b e5 5d c2 08 00'
    ' 8a 45 08 88 45 f9 8b 45 0c 89 45 fa 8d 45 f8 50 51 8b ce c6 45 f8 02 e8 29 00 00 00'
    ' 84 c0 75 16 68 bc 33 80 00 e8 0b a0 06 00 83 c4 04 32 c0 5e 8b e5 5d c2 08 00'
    ' 8b ce e8 b8 ae 07 00 5e 8b e5 5d c2 08 00'.replace(' ', ''))
assert len(ORIG_BODY) == 95

STUB_RVA = 0x5438C0          # .maze sayfa boslugu (vsz 0x8B1 < 0x8C0 < raw 0xA00; V4.6-harness ayni yontem)

def parse(f):
    pe = struct.unpack_from('<I', f, 0x3C)[0]; opt = pe + 24
    nsec = struct.unpack_from('<H', f, pe + 6)[0]
    optsz = struct.unpack_from('<H', f, pe + 20)[0]
    return pe, opt, nsec, opt + optsz

def r2o(f, rva):
    pe, opt, nsec, secoff = parse(f)
    for i in range(nsec):
        s = secoff + i * 40
        vsz, va, rsz, ra = struct.unpack_from('<IIII', f, s + 8)
        if va <= rva < va + max(vsz, rsz):
            return ra + (rva - va)
    return None

def find_iat(f, name):
    impRva, impSz = struct.unpack_from('<II', f, parse(f)[1] + 104)  # dir[1]=IMPORT (opt+96 tabanli)
    o = r2o(f, impRva)
    if o is None: return None
    while True:
        oft, tds, fc, nameRva, fthunk = struct.unpack_from('<IIIII', f, o)
        if oft == 0 and nameRva == 0: break
        tn = r2o(f, nameRva)
        nm0 = f[tn:tn+48].split(b'\0')[0].decode(errors='replace') if tn else '?'
        use = oft if oft else fthunk          # OFT varsa isimleri ORDAN oku (IAT bound olabilir)
        t = r2o(f, use)
        if t is None:
            print(f'  (atlanir: {nm0} thunk RVA haritalanamadi)')
        else:
            j = 0
            while True:
                v = struct.unpack_from('<I', f, t)[0]
                if v == 0: break
                if not (v & 0x80000000):
                    hn = r2o(f, v)
                    nm = f[hn+2:hn+2+48].split(b'\0')[0].decode(errors='replace') if hn else '?'
                    if nm == name:
                        return (fthunk if fthunk else oft) + j * 4  # FT tabani + j (FT'ye cozulur; OFT degil!)
                j += 1
                t += 4
        o += 20
    return None


def _finish(f, opt, sRva, out):
    old_ep = struct.unpack_from('<I', f, opt + 16)[0]
    struct.pack_into('<I', f, opt + 16, sRva)
    tlsRva, tlsSz = struct.unpack_from('<II', f, opt + 96 + 9 * 8)
    if tlsRva:
        to = r2o(f, tlsRva)
        if to is not None:
            cbVa = struct.unpack_from('<I', f, to + 12)[0]
            cbo = r2o(f, cbVa - 0x400000) if cbVa else None
            if cbo is not None:
                f[cbo:cbo+8] = b'\x00' * 8
    open(out, 'wb').write(bytes(f))
    print(f'{os.path.basename(out)}: EP {old_ep:#x}->{sRva:#x} stub yazildi')

def build(variant, protected, out):
    f = bytearray(open(SRC, 'rb').read())
    pe, opt, nsec, secoff = parse(f)
    ep_iat = find_iat(f, 'ExitProcess')
    assert ep_iat, 'ExitProcess IAT yok'
    # x degerleri
    xs = dict(A=[0, None, None, None], B=[1, 0, 0, None],
              C=[1, 1, None, 1],   D=[1, 1, None, 0], L=[1, 0, 0, None], Z=[None, None, None, None], B2=[1, 0, 0, None], L2=[1, 0, 0, None])[variant]
    # E8 hedef stub'lari
    for i, t in enumerate(E8T):
        if xs[i] is None: continue
        o = r2o(f, t)
        f[o:o+3] = bytes([0xB0, xs[i], 0xC3])   # mov al,x; ret
    if not protected:
        o = r2o(f, FN_RVA)
        f[o:o+95] = ORIG_BODY
    # cagri stub
    sRva = STUB_RVA
    sVa = 0x400000 + sRva
    fnVa = 0x400000 + FN_RVA
    code = bytearray()
    code += bytes([0x68]) + struct.pack('<I', 0x22)          # push 0x22 (arg2)
    code += bytes([0x68]) + struct.pack('<I', 0x11)          # push 0x11 (arg1)
    if variant == 'B2':
        # ebx-korunumu sondaji: ebx=0x77 yaz, 1 cagri, exit ebx&0xFF (119=OK)
        code = bytes([0xBB]) + struct.pack('<I', 0x77)      # mov ebx,0x77
        code += bytes([0x68]) + struct.pack('<I', 0x22)     # push 0x22
        code += bytes([0x68]) + struct.pack('<I', 0x11)     # push 0x11
        code += bytes([0xB9]) + struct.pack('<I', 0x5BD2A0) # mov ecx,this
        rel = fnVa - (sVa + len(code) + 5)
        code += bytes([0xE8]) + struct.pack('<i', rel)      # call fn
        code += bytes([0x0F, 0xB6, 0xC3])                   # movzx eax,bl
        code += bytes([0x50])                               # push eax
        code += bytes([0xFF, 0x15]) + struct.pack('<I', 0x400000 + ep_iat)
        o = r2o(f, sRva)
        f[o:o+len(code)] = code
        _finish(f, opt, sRva, out)
        return
    if variant == 'Z':
        # bisect: sadece ExitProcess(0x5A) — EP/IAT yolu sag mi?
        code = bytes([0xB8]) + struct.pack('<I', 0x5A) + bytes([0xFF, 0x15]) + struct.pack('<I', 0x400000 + ep_iat) + bytes([0x0F, 0x0B])  # mov eax,0x5A; call [ExitProcess]; ud2
        code += bytes([0xFF, 0x15]) + struct.pack('<I', 0x400000 + ep_iat)  # call [ExitProcess]
    elif variant == 'L':
        # 400 dongu: her iterasyonda args TEKRAR push edilir (stdcall ret 8 tuketir)
        code += bytes([0xBB]) + struct.pack('<I', 400)       # mov ebx,400
        loop_top = len(code)
        code += bytes([0x68]) + struct.pack('<I', 0x22)      # push 0x22
        code += bytes([0x68]) + struct.pack('<I', 0x11)      # push 0x11
        code += bytes([0xB9]) + struct.pack('<I', 0x5BD2A0)  # mov ecx,this
        rel = fnVa - (sVa + len(code) + 5)
        code += bytes([0xE8]) + struct.pack('<i', rel)       # call fn (ret 8)
        code += bytes([0x4B])                                # dec ebx
        rel2 = (sVa + loop_top) - (sVa + len(code) + 2)
        code += bytes([0x75]) + bytes([rel2 & 0xFF])         # jnz loop_top
        if variant == 'L2':
            code += bytes([0x0F, 0xB6, 0xC3])                # movzx eax,bl -> exit=kalan sayac
        else:
            code += bytes([0xB8]) + struct.pack('<I', 0x2A)  # mov eax,0x2A (hepsi dondu)
    else:
        code += bytes([0xB9]) + struct.pack('<I', 0x5BD2A0)  # mov ecx,this
        rel = fnVa - (sVa + len(code) + 5)
        code += bytes([0xE8]) + struct.pack('<i', rel)       # call fn (stdcall ret 8)
    code += bytes([0x0F, 0xB6, 0xC0])                        # movzx eax,al (deterministik cikis)
    code += bytes([0x50])                                    # push eax
    code += bytes([0xFF, 0x15]) + struct.pack('<I', 0x400000 + ep_iat)  # call [ExitProcess]
    o = r2o(f, sRva)
    f[o:o+len(code)] = code
    _finish(f, opt, sRva, out)
    print(f'{os.path.basename(out)}: stub {len(code)}B iat={0x400000+ep_iat:#x}')

if __name__ == '__main__':
    for v in ['A', 'B', 'C', 'D', 'L', 'Z', 'B2', 'L2']:
        build(v, True,  f'{OUT}/harness_m2_{v}.exe')
        build(v, False, f'{OUT}/harness_base_{v}.exe')
