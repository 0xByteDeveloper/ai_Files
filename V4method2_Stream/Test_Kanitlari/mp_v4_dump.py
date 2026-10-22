#!/usr/bin/env python3
# mp_v4_dump.py - V4 Stream EXE'nin .maze MZE3 yapisini cozer + CRC dogrular
# Kullanim: python3 mp_v4_dump.py <exe>
import sys, struct, pefile

def crc8(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = ((c << 1) ^ 0x07) & 0xFF if (c & 0x80) else ((c << 1) & 0xFF)
    return c

def main():
    exe = sys.argv[1]
    pe = pefile.PE(exe)
    maze = None
    for s in pe.sections:
        if s.Name.rstrip(b'\0') == b'.maze':
            maze = s.get_data()
            maze_rva = s.VirtualAddress
    if maze is None:
        print(".maze yok"); return 1
    nBlocks, magic = struct.unpack_from("<II", maze, 0)
    K, = struct.unpack_from("<Q", maze, 8)
    entryRva, fnRva, fnSize = struct.unpack_from("<III", maze, 0x10)
    blockTblOff, decFlag, encBytes, slotSize, nSites, sitesOff, imgSize = struct.unpack_from("<IIIIIIII"[0:7], maze, 0x1C) if False else struct.unpack_from("<IIIIIII", maze, 0x1C)
    jmpSlot, edgeTblOff = struct.unpack_from("<QQ"[0:1]+"I", maze, 0x38) if False else (struct.unpack_from("<Q", maze, 0x38)[0], struct.unpack_from("<I", maze, 0x38+0)[0])
    # header 0x38 jmpSlot(u64), 0x40 edgeTblOff -> blob 0x40'dan buyuk; header TASIYICIDA
    # gercekkte blob 0x40'da bitiyor; edgeTblOff 0x3C'de
    edgeTblOff2, = struct.unpack_from("<I", maze, 0x3C)
    print(f"MZE3: nBlocks={nBlocks} magic={magic:08X} K={K:016X}")
    print(f"  entryRva=0x{entryRva:X} fnRva=0x{fnRva:X} fnSize={fnSize} blockTblOff=0x{blockTblOff:X}")
    print(f"  decFlag={decFlag} encBytes={encBytes} slotSize={slotSize} nSites={nSites} sitesOff=0x{sitesOff:X}")
    print(f"  imgSize=0x{imgSize:X} jmpSlot=0x{jmpSlot:X} edgeTblOff=0x{edgeTblOff2:X}")
    print(f"  .maze RVA=0x{maze_rva:X} blob toplam={len(maze)}")
    # thunk tablosu
    nThunk = (sitesOff - edgeTblOff2) // 9 if edgeTblOff2 and sitesOff > edgeTblOff2 else 0
    print(f"--- THUNK TABLOSU ({nThunk} x 9B @0x{edgeTblOff2:X}) ---")
    for i in range(nThunk):
        o = edgeTblOff2 + i * 9
        pid = struct.unpack_from("<I", maze, o + 2)[0]
        print(f"  thunk[{i}] @maze+0x{o:X}: mov r10d,0x{pid:X}; jmp conv")
    # site tablosu
    print(f"--- SITE TABLOSU ({nSites} x 12B @0x{sitesOff:X}) ---")
    for i in range(nSites):
        o = sitesOff + i * 12
        fieldRel, kind, value = struct.unpack_from("<IBI", maze, o)
        print(f"  site[{i}]: fieldRel=0x{fieldRel:X} kind={kind} value=0x{value:X}")
    # blk tablosu + CRC dogrulama
    print(f"--- BLK TABLOSU ({nBlocks} x 16B @0x{blockTblOff:X}) ---")
    okcrc = 0
    for i in range(nBlocks):
        o = blockTblOff + i * 16
        encOff, ln, siteFirst, packed = struct.unpack_from("<IIII", maze, o)
        crc, ns = packed >> 8, packed & 0xFF
        span = maze[encOff:encOff + ln]
        dec = bytes(b ^ K[i % 8] for i, b in enumerate(span)) if False else span
        # sifreli: XOR K (8B blok)
        dec = b"".join(bytes(x ^ y for x, y in zip(span[j:j+8], K.to_bytes(8, 'little'))) for j in range(0, len(span), 8))
        c = crc8(dec)
        stat = "OK " if c == crc else "PAS"
        okcrc += (c == crc)
        print(f"  blk[{i}]: encOff=0x{encOff:X} len={ln} siteFirst={siteFirst} nSites={ns} crc=0x{crc:02X} hesap=0x{c:02X} {stat}")
        # ilk 16 cozulmus bayt + capstone quick
        print(f"         dec[:16]={dec[:16].hex()}")
    print(f"CRC: {okcrc}/{nBlocks} eslesti")
    return 0

if __name__ == "__main__":
    sys.exit(main())
