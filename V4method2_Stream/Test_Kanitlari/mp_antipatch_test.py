#!/usr/bin/env python3
# mp_antipatch_test.py - G2 CRC-8 anti-patch negatif testi:
# Stream EXE'nin .maze'indeki SIFRELI bir span baytini cevirir -> runtime'da
# cozulen parca farkli -> CRC eslesmez -> fail-closed ExitProcess(0xDE) beklenir.
import struct, sys, os, subprocess
import pefile

SRC = sys.argv[1] if len(sys.argv) > 1 else "/tmp/my-project/scripts/v3test/MazeGame_Sifreli_ArenaV4_Stream.exe"
DST = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "MazeGame_AntiPatch_Test.exe")

pe = pefile.PE(SRC)
maze_sec = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".maze")
raw = bytearray(open(SRC, "rb").read())

# .maze'in dosya ofseti + blob basi (span'ler blob+0x3C0..0x470 bolgesinde)
sec_raw_ptr = maze_sec.PointerToRawData
# MZE3 header'dan blk0'in encOff'unu oku (header blob basinda = sec basi)
b = raw[sec_raw_ptr:sec_raw_ptr + 0x40]
nBlocks, magic = struct.unpack_from("<II", b, 0)
blockTblOff, = struct.unpack_from("<I", b, 0x1C)
blob = bytearray(raw[sec_raw_ptr:sec_raw_ptr + len(maze_sec.get_data())])
encOff0, ln0 = struct.unpack_from("<II", bytes(blob), blockTblOff)
print(f"[TEST] blk0 encOff=0x{encOff0:X} len={ln0} -> sifreli bayt ceviriliyor")
# sifreli span'in ORTA bir baytini cevir (0x7F ^ 0xFF)
flip_pos = encOff0 + ln0 // 2
blob[flip_pos] ^= 0xFF
raw[sec_raw_ptr:sec_raw_ptr + len(blob)] = blob
# checksum'u sifirla (emulator takmaz ama tutarli olsun)
open(DST, "wb").write(bytes(raw))
print(f"[TEST] bozuk kopya yazildi: {DST} (bayt @{flip_pos:#x} cevirildi)")

os.environ["MP_NOTRACE"] = "1"
r = subprocess.run([sys.executable, "/tmp/my-project/scripts/unicorn_run.py", DST, "auto"],
                   capture_output=True, text=True, timeout=900)
out = r.stdout
print("[TEST] cikti:")
print("\n".join(out.splitlines()[:6]))
exit_code = None
for ln in out.splitlines():
    if ln.startswith("=== SONUC: exit="):
        exit_code = int(ln.split("exit=")[1].split()[0])
ok = (exit_code == 0xDE)
print(f"[TEST] SONUC: exit={exit_code} - {'G2 FAIL-CLOSED CALISIYOR (0xDE) PASS' if ok else 'BEKLENEN 0xDE DEGIL -> FAIL'}")
sys.exit(0 if ok else 1)
