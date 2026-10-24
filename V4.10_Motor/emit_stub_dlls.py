#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# emit_stub_dlls.py — .def alias yontemiyle bos DLL'ler (her export icin 1 dummy govde)
import struct, subprocess, os

EXE = '/home/z/my-project/work/v410/denemeoutput.exe'
OUTDIR = '/home/z/my-project/work/v410/stubdlls'
os.makedirs(OUTDIR, exist_ok=True)
f = open(EXE, 'rb').read()
pe = struct.unpack_from('<I', f, 0x3C)[0]; opt = pe + 24
nsec = struct.unpack_from('<H', f, pe + 6)[0]
optsz = struct.unpack_from('<H', f, pe + 20)[0]; secoff = opt + optsz
def r2o(rva):
    for i in range(nsec):
        s = secoff + i * 40
        vsz, va, rsz, ra = struct.unpack_from('<IIII', f, s + 8)
        if va <= rva < va + max(vsz, rsz):
            return ra + (rva - va)
    return None
impRva, _ = struct.unpack_from('<II', f, opt + 104)
o = r2o(impRva)
need = {}
while True:
    oft, tds, fc, nameRva, fthunk = struct.unpack_from('<IIIII', f, o)
    if oft == 0 and nameRva == 0: break
    tn = r2o(nameRva)
    nm = f[tn:tn+48].split(b'\0')[0].decode(errors='replace')
    use = oft if oft else fthunk
    t = r2o(use)
    names = []
    if t:
        j = 0
        while True:
            v = struct.unpack_from('<I', f, t + j * 4)[0]
            if v == 0: break
            if v & 0x80000000:
                names.append('#%d' % (v & 0xFFFF))
            else:
                hn = r2o(v)
                names.append(f[hn+2:hn+2+96].split(b'\0')[0].decode(errors='replace') if hn else '?')
            j += 1
            if j > 400: break
    need[nm] = names
    o += 20

for nm in ['python27.dll', 'DevIL.dll', 'granny2.dll', 'mss32.dll', 'SpeedTreeRT.dll']:
    base = nm[:-4]
    names = need.get(nm, [])
    n = len(names)
    csrc = os.path.join(OUTDIR, base + '_body.c')
    with open(csrc, 'w') as g:
        g.write('int g_dummy;\n')
        for i in range(n):
            g.write('int mp_s%d(void){ return ++g_dummy; }\n' % i)
    defp = os.path.join(OUTDIR, base + '.def')
    with open(defp, 'w') as g:
        g.write('LIBRARY %s\nEXPORTS\n' % base)
        for i, fn in enumerate(names):
            g.write('    %s = mp_s%d\n' % (fn, i))
    dll = os.path.join(OUTDIR, base + '.dll')
    r = subprocess.run(['/home/z/mingw64/bin/i686-w64-mingw32-gcc', '-O0', '-shared',
                        csrc, defp, '-o', dll], capture_output=True, text=True)
    print(base, n, 'export', 'OK' if r.returncode == 0 else 'HATA: ' + r.stderr[-150:])
