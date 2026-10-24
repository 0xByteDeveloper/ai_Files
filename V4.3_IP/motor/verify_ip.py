#!/usr/bin/env python3
# verify_ip.py - V4.3 IP korumasini bayt-bayt dogrular
# 1) CB alanlari tutarli mi (magic/seed/boyutlar/state=0)
# 2) Sifreli govde, seed ile Python'da cozulunce ORIJINAL govdeye esit mi
# 3) Trambolin E9 -> handler mi
# 4) Proxy komutlari orijinal bas komutlariyla ayni mi (mnemonic bazinda)
# 5) Handler yapisal kontrol (lock bts, xor dongusu, ret)
import struct, sys, pefile
from capstone import *

def ks_stream(seed, n):
    st = seed
    out = bytearray()
    for _ in range(n):
        st ^= (st << 13) & 0xFFFFFFFF; st &= 0xFFFFFFFF
        st ^= st >> 17
        st ^= (st << 5) & 0xFFFFFFFF; st &= 0xFFFFFFFF
        out.append((st >> 16) & 0xFF)
    return bytes(out)

def sec_data(pe, name):
    for s in pe.sections:
        if s.Name.rstrip(b'\0') == name.encode():
            return s.VirtualAddress, s.get_data()
    return None, None

def main(orig_path, prot_path, map_path):
    orig = pefile.PE(orig_path)
    prot = pefile.PE(prot_path)
    base = prot.OPTIONAL_HEADER.ImageBase
    oimg = bytearray(orig.__data__)
    pimg = bytearray(prot.__data__)
    # raw'dan VA'ya cevirici
    def off2va(pefile_obj, off):
        for s in pefile_obj.sections:
            if s.PointerToRawData <= off < s.PointerToRawData + s.SizeOfRawData:
                return s.VirtualAddress + (off - s.PointerToRawData)
        return None
    # orijinali VA-uzayina ac
    def to_va_image(pe_obj, raw):
        img = bytearray(pe_obj.OPTIONAL_HEADER.SizeOfImage)
        hdr = min(pe_obj.OPTIONAL_HEADER.SizeOfHeaders, len(raw))
        img[0:hdr] = raw[0:hdr]
        for s in pe_obj.sections:
            if s.SizeOfRawData:
                n = min(s.SizeOfRawData, s.Misc_VirtualSize if hasattr(s,'Misc_VirtualSize') else s.Misc_VirtualSize)
                n = min(s.SizeOfRawData, len(raw) - s.PointerToRawData)
                if n > 0: img[s.VirtualAddress:s.VirtualAddress+n] = raw[s.PointerToRawData:s.PointerToRawData+n]
        return img
    oimg = to_va_image(orig, orig.__data__)
    pimg = to_va_image(prot, prot.__data__)

    funcs = []
    for line in open(map_path):
        if line.startswith("FUNC "):
            t = line.split()
            # FUNC isim fnRva fnSize cbRva proxyRva handlerRva seedHex method
            funcs.append(dict(name=t[1], fnRva=int(t[2]), fnSize=int(t[3]),
                              cbRva=int(t[4]), proxyRva=int(t[5]), handlerRva=int(t[6]),
                              seed=int(t[7], 16), method=int(t[8])))
        elif line.startswith("IPINFO "):
            t = line.split()
            d = dict(x.split('=') for x in t[1:])
            funcs[-1].update(headLen=int(d['headLen']), bodyLen=int(d['bodyLen']),
                             retsRva=int(d['retsRva'], 16) if d['retsRva'].startswith('0x') else int(d['retsRva'], 16),
                             crc=int(d['crc'], 16))
    md64 = Cs(CS_ARCH_X86, CS_MODE_64); md64.detail = False
    md32 = Cs(CS_ARCH_X86, CS_MODE_32); md32.detail = False
    md = md64 if prot.FILE_HEADER.Machine == 0x8664 else md32

    allOk = True
    for f in funcs:
        ok = True; notes = []
        cb = pimg[f['cbRva']:f['cbRva']+0x40]
        if cb[0:4] != b'MZI5': ok=False; notes.append("CB magic yok")
        depth, lock, state = struct.unpack_from('<III', cb, 4)
        fnRva2, fnSize2, headLen2, seed2, bodyLen2, method2 = struct.unpack_from('<6I', cb, 0x10)
        if depth or lock or state: ok=False; notes.append(f"CB state temiz degil d={depth} l={lock} s={state}")
        if fnRva2 != f['fnRva'] or fnSize2 != f['fnSize']: ok=False; notes.append("CB fnRva/Size uyusmaz")
        if seed2 != f['seed']: ok=False; notes.append(f"CB seed {seed2:08X} != map {f['seed']:08X}")
        # govde cozumu
        enc = bytes(pimg[f['fnRva']+f['headLen'] : f['fnRva']+f['fnSize']])
        dec = bytes(a ^ b for a, b in zip(enc, ks_stream(seed2, len(enc))))
        ori = bytes(oimg[f['fnRva']+f['headLen'] : f['fnRva']+f['fnSize']])
        if dec != ori: ok=False; notes.append(f"GOVDE COZUMU UYUSMUYOR (ilk fark @ {next((i for i,(x,y) in enumerate(zip(dec,ori)) if x!=y), -1)})")
        # trambolin
        tr = pimg[f['fnRva']:f['fnRva']+5]
        if tr[0] != 0xE9: ok=False; notes.append("trambolin E9 degil")
        else:
            tgt = f['fnRva'] + 5 + struct.unpack_from('<i', tr, 1)[0]
            if tgt != f['handlerRva']: ok=False; notes.append(f"trambolin hedef 0x{tgt:X} != handler 0x{f['handlerRva']:X}")
        # bas: orijinal bas + CC dolgu
        if bytes(pimg[f['fnRva']+5 : f['fnRva']+f['headLen']]) != b'\xCC' * (f['headLen']-5):
            notes.append("UYARI: bas dolgusu CC degil")
        # proxy mnemonic karsilastirma
        oriHead = bytes(oimg[f['fnRva']:f['fnRva']+f['headLen']])
        proxy = bytes(pimg[f['proxyRva']:f['proxyRva']+f['headLen']+16])
        oIns = [i.mnemonic for i in md.disasm(oriHead, f['fnRva'])]
        pIns = [i.mnemonic for i in md.disasm(proxy, f['proxyRva'])]
        # proxy = bas komutlari + kuyruk E9 (govdeye atla) + handler baslangici
        # -> sadece ilk len(oIns) mnemonic karsilastirilir
        if oIns != pIns[:len(oIns)]: ok=False; notes.append(f"proxy mnemonic uyusmaz: {oIns} vs {pIns[:len(oIns)+2]}")
        print(f"{'OK ' if ok else 'HATA'} {f['name']:16s} seed={seed2:08X} bas={f['headLen']} govde={f['bodyLen']} proxyIns={len(pIns)} {'; '.join(notes)}")
        allOk &= ok
    print("=== SONUC:", "TUM DOGRULAMALAR GECTI" if allOk else "HATALAR VAR", "===")
    return 0 if allOk else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3]))
