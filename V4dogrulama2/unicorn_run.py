#!/usr/bin/env python3
# unicorn_run.py - Windows x64 PE'yi Unicorn ile emule eder (kernel32/user32 stub'li)
# Kullanim: python3 unicorn_run.py <exe> [komut-satiri]
# Cikti: emule edilen WriteFile cikti + exit code + mem hatasi raporu
import sys, struct, os, pefile
from unicorn import *
from unicorn.x86_const import *

API_BASE   = 0x70000000
STACK_BASE = 0x00200000
STACK_SIZE = 0x200000
HEAP_BASE  = 0x00400000
CMDL_ADDR  = 0x00080000
GS_BASE    = 0x00090000

class Emu:
    def __init__(self, path, cmdline=""):
        self.pe = pefile.PE(path)
        self.img_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.img_size = (self.pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF
        self.out = bytearray()
        self.heap = HEAP_BASE
        self.tick = 0x1000
        self.exit_code = None
        self.error = None
        self.api_calls = {}
        self.apis = []  # (name, sentinel)
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.uc = uc
        uc.mem_map(self.img_base, self.img_size, UC_PROT_ALL)
        # header + section'lari kopyala
        uc.mem_write(self.img_base, self.pe.header)
        for s in self.pe.sections:
            data = s.get_data()
            if data:
                uc.mem_write(self.img_base + s.VirtualAddress, bytes(data))
        # IAT sentinel'leri
        idx = 0
        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            for d in self.pe.DIRECTORY_ENTRY_IMPORT:
                for imp in d.imports:
                    sent = API_BASE + idx * 8
                    self.apis.append((imp.name.decode() if imp.name else f"ord{imp.ordinal}", sent))
                    uc.mem_write(imp.address, struct.pack("<Q", sent))
                    idx += 1
        # API sayfasi (ret ile dolu - hook calismazsa guvenli donus)
        uc.mem_map(API_BASE, 0x10000, UC_PROT_ALL)
        uc.mem_write(API_BASE, b"\xC3" * 0x10000)
        # komut satiri
        uc.mem_map(CMDL_ADDR & ~0xFFF, 0x2000, UC_PROT_ALL)
        cmd = (f"{path} {cmdline}").encode() + b"\x00"
        uc.mem_write(CMDL_ADDR, cmd)
        # heap: tek buyuk bolge + donen havuz
        # V4.1: ImageBase cakismasinda heap'i kaydir (TinySnake gibi yabanci PE'ler)
        hb = HEAP_BASE
        if not (self.img_base + self.img_size <= hb or self.img_base >= hb + 0x800000):
            hb = ((self.img_base + self.img_size + 0xFFFFFF) & ~0xFFFFFF)  # sonraki 16MB hizasina
        uc.mem_map(hb, 0x800000, UC_PROT_ALL)
        self.heap_next = hb
        self.free_pages = []
        uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
        uc.mem_map(GS_BASE & ~0xFFF, 0x1000, UC_PROT_ALL)
        try:
            uc.reg_write(UC_X86_REG_GS_BASE, GS_BASE)
        except Exception:
            pass
        # PEB: gs:[0x60] -> PEB; PEB+0x10 = ImageBaseAddress (arena stub/cleanup okur)
        gs_page = GS_BASE & ~0xFFF
        peb = gs_page + 0x80
        uc.mem_write(gs_page + 0x60, struct.pack("<Q", peb))
        uc.mem_write(peb + 0x10, struct.pack("<Q", self.img_base))
        # arena takibi (VirtualAlloc/VirtualFree) - Windows benzeri live/free durum makinesi
        self.arena_live = {}       # addr -> size (su an sahipli)
        self.arena_free = {}       # addr -> size (MEM_RELEASE edildi, yeniden kullanilabilir)
        self.fail_alloc_left = int(os.environ.get("MP_FAIL_ALLOC", "0"))  # fallback testi
        uc.reg_write(UC_X86_REG_RSP, STACK_BASE + STACK_SIZE - 0x1000)
        uc.reg_write(UC_X86_REG_RSP, (STACK_BASE + STACK_SIZE - 0x1000) & ~0xF)
        # hook'lar
        uc.hook_add(UC_HOOK_BLOCK, self._api_hook, begin=API_BASE, end=API_BASE + 0xFFFF)
        uc.hook_add(UC_HOOK_MEM_INVALID, self._mem_fault)
        uc.hook_add(UC_HOOK_INTR, self._intr)
        self.trace = []
        if not os.environ.get("MP_NOTRACE"):   # izleme cok yavaslatir - yalniz hata ayiklamada
            # V4.1: ImageBase'e gore dinamik aralik (yabanci PE'ler: TinySnake 0x400000)
            uc.hook_add(UC_HOOK_CODE, self._trace, begin=self.img_base + 0x1000, end=self.img_base + self.img_size)
            hi_lo, hi_hi = 0x140400000, 0x142000000   # tum arena hint zinciri
            uc.hook_add(UC_HOOK_CODE, self._trace, begin=hi_lo, end=hi_hi)
        # V4.1: RVA frekans modu — yabanci PE'de "hangi fonksiyon calisiyor" tespiti
        if os.environ.get("MP_RVAFREQ"):
            self.rvafreq = {}
            lo, hi = self.img_base + 0x1000, self.img_base + self.img_size
            uc.hook_add(UC_HOOK_CODE, self._rvafreq_hook, begin=lo, end=hi)
        if os.environ.get("MP_WATCH"):
            lo, hi = [int(x, 16) for x in os.environ["MP_WATCH"].split("-")]
            uc.hook_add(UC_HOOK_MEM_WRITE, self._watch, begin=lo, end=hi)
        if os.environ.get("MP_PROBE"):
            plo, phi = [int(x, 16) for x in os.environ["MP_PROBE"].split("-")]
            uc.hook_add(UC_HOOK_CODE, self._probe, begin=plo, end=phi)

    def _probe(self, uc, address, size, user_data):
        r = lambda n: uc.reg_read(globals()['UC_X86_REG_' + n])

    def _rvafreq_hook(self, uc, address, size, user_data):
        b = (address - self.img_base) >> 6   # 64B kova
        self.rvafreq[b] = self.rvafreq.get(b, 0) + 1

    def _trace(self, uc, address, size, user_data):
        self.trace.append(address)
        cap = int(os.environ.get('MP_TRACE_N', '40'))
        if len(self.trace) > cap: self.trace.pop(0)

    def _watch(self, uc, access, address, size, value, user_data):
        print(f"[WATCH] yazma @0x{address:X} size={size} val=0x{value:X} rip=0x{uc.reg_read(UC_X86_REG_RIP):X}",
              file=sys.stderr)

    def _intr(self, uc, intno, user_data):
        if intno == 3:
            rip = uc.reg_read(UC_X86_REG_RIP)
            rsp = uc.reg_read(UC_X86_REG_RSP)
            try:
                ret = struct.unpack("<Q", bytes(uc.mem_read(rsp, 8)))[0]
            except Exception:
                ret = 0
            if not self.error:
                self.error = f"INT3 @ rip=0x{rip:X} (donus adresi=[rsp]=0x{ret:X}) - oluv govdeye atlanmis!"
            uc.emu_stop()

    def _mem_fault(self, uc, access, address, size, value, user_data):
        if not self.error:
            regs = {r: uc.reg_read(globals()['UC_X86_REG_' + r]) for r in
                    ('RAX','RCX','RDX','RBX','RSP','RBP','RSI','RDI','R8','R9','R10','R11','R12','R13','R14','R15')}
            self.error = (f"MEM-FAULT tip={access} addr=0x{address:X} size={size} rip=0x{uc.reg_read(UC_X86_REG_RIP):X} " +
                          " ".join(f"{k}=0x{v:X}" for k, v in regs.items()))
            # GenerateMaze blob header runtime dump (0xF000) - arena tasiyicisi icin
            try:
                hb = bytes(uc.mem_read(0x14000F000, 0x40))
                import struct as _s
                nn, mg = _s.unpack_from("<II", hb, 0)
                k2, = _s.unpack_from("<Q", hb, 8)
                asz, ns, so, isz = _s.unpack_from("<IIII", hb, 0x28)
                self.error += f" | RUNTIME-HDR: nRegions={nn} magic={mg:08X} arenaSize=0x{asz:X} nSites={ns} sitesOff=0x{so:X} imgSize=0x{isz:X}"
                # runtime site tablosu + arena'daki 0x954 bolgesi
                st = bytes(uc.mem_read(0x14000F000 + so, ns * 4))
                self.error += f" | SITES={[hex(x) for x in _s.unpack_from(f'<{ns}I', st)]}"
                ab = bytes(uc.mem_read(0x140410950, 16))
                self.error += f" | ARENA@950={ab.hex()}"
            except Exception as e:
                self.error += f" | hdr-dump-hata:{e}"
            # faulting komutu coz (hata ayiklama)
            try:
                rip = uc.reg_read(UC_X86_REG_RIP)
                code = bytes(uc.mem_read(rip, 16))
                from capstone import Cs, CS_ARCH_X86, CS_MODE_64
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                for i in md.disasm(code, rip):
                    self.error += f" | FAULT-INSN: {i.bytes.hex()} {i.mnemonic} {i.op_str}"
                    # FF 25 (jmp [rip+d]) ise slot degerini ve slot cevresini dok
                    if i.bytes[0] == 0xFF and i.bytes[1] == 0x25 and i.size == 6:
                        import struct as _s
                        disp = _s.unpack("<i", i.bytes[2:6])[0]
                        slot = rip + 6 + disp
                        q = bytes(uc.mem_read(slot, 8))
                        self.error += f" | SLOT@0x{slot:X} = 0x{_s.unpack('<Q', q)[0]:X} slotbytes={q.hex()}"
                        # slot'un oldugu blob'un header'i (slot-0x38 = blob basi)
                        bb = slot - 0x38
                        hb = bytes(uc.mem_read(bb, 0x40))
                        self.error += f" | BLOBHDR={hb[:16].hex()}|{hb[16:32].hex()}|{hb[32:40].hex()}|{hb[40:48].hex()}"
                    break
            except Exception:
                pass
        return False

    def _api_hook(self, uc, address, size, user_data):
        rip = uc.reg_read(UC_X86_REG_RIP)
        idx = (rip - API_BASE) // 8
        if not (0 <= idx < len(self.apis)):
            # V4.1: GetProcAddress sentinel slotlari (no-op ret C3) — gec
            return
        name = self.apis[idx][0]
        self.api_calls[name] = self.api_calls.get(name, 0) + 1
        a = lambda r: uc.reg_read(r)
        W = UC_X86_REG_RAX
        if name == "GetStdHandle":          uc.reg_write(W, 0x100)
        elif name == "GetCommandLineA":     uc.reg_write(W, CMDL_ADDR)
        elif name == "GetTickCount":
            self.tick += 16; uc.reg_write(W, self.tick)
            self.frames = getattr(self, "frames", 0) + 1
            if os.environ.get("MP_DEBUG") and self.frames % 50 == 0:
                import time as _t
                print(f"[DBG] frame {self.frames} t={_t.strftime('%H:%M:%S')}", file=sys.stderr)
        elif name == "WriteFile":
            buf, ln = a(UC_X86_REG_RDX), a(UC_X86_REG_R8)
            if ln: self.out += bytes(uc.mem_read(buf, ln))
            wrp = a(UC_X86_REG_R9)
            if wrp: uc.mem_write(wrp, struct.pack("<I", ln))
            uc.reg_write(W, 1)
        elif name == "VirtualAlloc":
            hint, sz = a(UC_X86_REG_RCX), a(UC_X86_REG_RDX)
            sz = (sz + 0xFFF) & ~0xFFF
            if os.environ.get("MP_DEBUG"):
                print(f"[DBG] VirtualAlloc(hint=0x{hint:X}, size=0x{sz:X})", file=sys.stderr)
            if hint == 0:
                # klasik havuz (DecoyAlloc vb.)
                p = self.free_pages.pop() if self.free_pages else self.heap_next
                if not self.free_pages: self.heap_next += 0x1000
                uc.reg_write(W, p)
            elif hint in self.arena_live:
                # Windows gercegi: canli bolge -> NULL (stub +4MB zincire duser)
                uc.reg_write(W, 0)
            elif self.fail_alloc_left > 0:
                self.fail_alloc_left -= 1
                uc.reg_write(W, 0)
            elif hint in self.arena_free and self.arena_free[hint] >= sz:
                # serbest bolge yeterli -> yeniden kullan (unmap YOK: TB cache korunur)
                self.arena_live[hint] = self.arena_free.pop(hint)
                uc.reg_write(W, hint)
            else:
                try:
                    old = self.arena_free.pop(hint, None)
                    if old is not None and old < sz:
                        try: uc.mem_unmap(hint, old)
                        except UcError: pass
                    uc.mem_map(hint, sz, UC_PROT_ALL)
                    self.arena_live[hint] = sz
                    uc.reg_write(W, hint)
                except UcError:
                    uc.reg_write(W, 0)   # stub +4MB hint ile tekrar dener -> 8'de fallback
        elif name == "VirtualFree":
            fp, typ = a(UC_X86_REG_RCX), a(UC_X86_REG_R8)
            if fp in self.arena_live:
                # MEM_RELEASE: live -> free havuzu (map'li kalir - TB cache; icerigi
                # bir sonraki ayni-hint arena kopyasi ezer; real Windows'ta gercek free)
                if typ & 0x8000:
                    self.arena_free[fp] = self.arena_live.pop(fp)
                else:
                    self.arena_live.pop(fp, None)
            elif fp:
                self.free_pages.append(fp)
            uc.reg_write(W, 1)
        elif name == "SetConsoleCursorPosition": uc.reg_write(W, 1)
        elif name == "SetConsoleTextAttribute":  uc.reg_write(W, 1)
        elif name == "GetAsyncKeyState":    uc.reg_write(W, 0)
        elif name == "Sleep":               pass
        elif name == "LoadLibraryA" or name == "LoadLibraryW":
            # V4.1: yabanci PE'ler icin fake modul handle (dosya islemez)
            self.loadlib_n = getattr(self, "loadlib_n", 0) + 1
            uc.reg_write(W, 0x72000000 + self.loadlib_n * 0x10000)
        elif name == "GetProcAddress":
            self.getproc_n = getattr(self, "getproc_n", 0) + 1
            uc.reg_write(W, API_BASE + 0xFF00 + self.getproc_n * 8)
            # sentinel API bolgesine kaydet: cagrilirsa no-op ret
            try: uc.mem_write(API_BASE + 0xFF00 + (self.getproc_n - 1) * 8, b"\xC3" * 8)
            except UcError: pass
        elif name == "GetModuleHandleA" or name == "GetModuleHandleW":
            uc.reg_write(W, 0x72100000)
        elif name == "GetConsoleCursorInfo" or name == "SetConsoleCursorInfo": uc.reg_write(W, 1)
        elif name == "ReadConsoleInput" or name == "PeekConsoleInputA" or name == "PeekConsoleInputW":
            n = a(UC_X86_REG_R9)
            if n: uc.mem_write(a(UC_X86_REG_R8), b"\x00" * (n * 20))
            uc.reg_write(W, 0)
        elif name in ("_kbhit", "kbhit"): uc.reg_write(W, 0)
        elif name in ("_getch", "getch", "_getche", "getchx"): uc.reg_write(W, 0)
        elif name in ("srand", "rand", "_rand"):
            # V4.1: deterministik rand — LCG (seed=uc ve sabit)
            if not hasattr(self, "rt_seed"): self.rt_seed = 0x1234ABCD
            if name == "srand": self.rt_seed = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF; uc.reg_write(W, 0)
            else:
                self.rt_seed = (self.rt_seed * 1103515245 + 12345) & 0x7FFFFFFF
                uc.reg_write(W, self.rt_seed)
        elif name in ("_time64", "time", "_time32"):
            # V4.1: deterministik zaman (0) — yabanci oyun seed'i icin
            self.tick += 16
            uc.reg_write(W, self.tick)
            if uc.reg_read(UC_X86_REG_RDX):  # 2. arg: time_t* dst
                try: uc.mem_write(uc.reg_read(UC_X86_REG_RDX), struct.pack("<Q", self.tick))
                except UcError: pass
        elif name == "GetConsoleScreenBufferInfo":
            # V4.1: 80x25 konsol — CONSOLE_SCREEN_BUFFER_INFO doldur
            p = a(UC_X86_REG_RDX)
            if p:
                uc.mem_write(p, struct.pack("<HHHHHHHHHH", 80, 25, 0, 0, 0x07, 0, 0, 79, 24, 0) + struct.pack("<HH", 80, 25))
            uc.reg_write(W, 1)
        elif name in ("GetConsoleMode", "GetFileType", "SetConsoleWindowInfo", "GetConsoleWindowInfo", "SetConsoleScreenBufferSize", "SetConsoleInfo", "FlushConsoleInputBuffer"): uc.reg_write(W, 1)
        elif name in ("SetConsoleMode", "SetConsoleTitleA", "SetConsoleTitleW", "SetConsoleOutputCP", "SetConsoleCP"): uc.reg_write(W, 1)
        elif name in ("GetModuleFileNameA", "GetModuleFileNameW"): uc.reg_write(W, 0)
        elif name in ("EncodePointer", "DecodePointer"): uc.reg_write(W, a(UC_X86_REG_RCX))
        elif name in ("memset", "memcpy", "memmove"):
            # V4.1: TCC CRT memset/memcpy — uc direkt kopya
            dst = a(UC_X86_REG_RCX)
            srcp = a(UC_X86_REG_RDX)
            ln = a(UC_X86_REG_R8)
            if name == "memset":
                val = uc.reg_read(UC_X86_REG_RDX) & 0xFF
                ln = uc.reg_read(UC_X86_REG_R8)
                if ln: uc.mem_write(dst, bytes([val]) * ln)
            else:
                ln = uc.reg_read(UC_X86_REG_R8)
                if ln: uc.mem_write(dst, bytes(uc.mem_read(srcp, ln)))
            uc.reg_write(W, dst)
        elif name in ("printf", "_printf_p", "puts"):
            # V4.1: printf/puts = mini C format + WriteFile(stdout)
            fp = a(UC_X86_REG_RCX)          # fmt (puts: str)
            PBUF = getattr(self, "printf_buf", None) or 0x72300000
            self.printf_buf = PBUF
            if not getattr(self, "pbuf_mapped", False):
                try: uc.mem_map(PBUF, 0x10000, UC_PROT_ALL)
                except UcError: pass
                self.pbuf_mapped = True
            def pcstr(p):
                out = bytearray()
                try:
                    while True:
                        bb = uc.mem_read(p + len(out), 1)
                        if not bb[0]: break
                        out += bytes(bb)
                        if len(out) > 8192: break
                except UcError:
                    pass
                return bytes(out)
            fm = pcstr(fp) if name != "puts" else pcstr(fp) + b"\n"
            def pnextarg(i):
                return struct.unpack("<Q", bytes(uc.mem_read(a(UC_X86_REG_RSP) + 8 + i * 8, 8)))[0]
            outb = bytearray(); ai = 0; j = 0
            while j < len(fm):
                c = fm[j]
                if c != 0x25: outb += bytes([c]); j += 1; continue
                k = j + 1; spec = bytearray()
                while k < len(fm) and fm[k:k+1] in (b'-', b'+', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b' ', b'.'):
                    spec += fm[k:k+1]; k += 1
                conv = chr(fm[k]) if k < len(fm) else 'd'
                if conv in 'diu':
                    v = pnextarg(ai) & 0xFFFFFFFF; ai += 1
                    s = str(v if conv == 'u' else (v if v < 0x80000000 else v - 0x100000000)).encode()
                elif conv in 'xX':
                    v = pnextarg(ai) & 0xFFFFFFFF; ai += 1
                    s = (("%x" % v) if conv == 'x' else ("%X" % v)).encode()
                elif conv == 'c':
                    s = bytes([pnextarg(ai) & 0xFF]); ai += 1
                elif conv == 's':
                    s = pcstr(pnextarg(ai)); ai += 1
                elif conv == '%':
                    outb += b'%'; j = k + 1; continue
                else:
                    outb += fm[j:k+1]; j = k + 1; continue
                pd = bytes(spec).decode() if spec else ''
                w = int(pd) if pd.lstrip('-0').isdigit() else (int(pd.lstrip('-0')) if pd.lstrip('-0') else 0)
                if '0' in pd and '-' not in pd and len(s) < w: s = s.rjust(w, b'0')
                elif '-' in pd: s = s.ljust(w, b' ')
                elif w and len(s) < w: s = s.rjust(w, b' ')
                outb += s; j = k + 1
            uc.mem_write(PBUF, bytes(outb))
            h = uc.reg_read(UC_X86_REG_RCX)  # eski rcx (fmt) — stdout handle 0x100
            try:
                wh = struct.unpack("<Q", bytes(uc.mem_read(a(UC_X86_REG_RSP) + 8, 8)))[0]
            except UcError:
                wh = 0
            self.out += bytes(outb)
            uc.reg_write(W, len(outb))
        elif name in ("sprintf", "_snprintf", "snprintf", "vsprintf", "_vsnprintf", "wsprintfA"):
            # V4.1: mini C format — uc argümanlarını stack/x64 konvansiyonundan oku
            if name.startswith("wsprintf"):
                dst, fmt = a(UC_X86_REG_RCX), a(UC_X86_REG_RDX)
                argbase = None
            else:
                dst, fmt = a(UC_X86_REG_RCX), a(UC_X86_REG_RDX)
                argbase = a(UC_X86_REG_RSP) + 8  # stack args (x64 shadow sonrası)
            def cstr(p):
                out = bytearray()
                try:
                    while True:
                        b = uc.mem_read(p + len(out), 1)
                        if not b[0]: break
                        out += bytes(b)
                        if len(out) > 4096: break
                except UcError:
                    pass
                return bytes(out)
            def nextarg(i):
                regs = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
                # dst, fmt = ilk 2 arg → format arg'ları 3. slot'tan (stack'e taşar)
                if i < 4 - 2:
                    if name.startswith("vs"):
                        # vs* : rcx=dst, rdx=fmt, r8=va_list ptr → oku
                        va = a(UC_X86_REG_R8)
                        return struct.unpack("<Q", bytes(uc.mem_read(va + i * 8, 8)))[0]
                    return None
                off = a(UC_X86_REG_RSP) + 8 + (i - 2) * 8 if not name.startswith("vs") else None
                if off is None:
                    va = a(UC_X86_REG_R8)
                    return struct.unpack("<Q", bytes(uc.mem_read(va + i * 8, 8)))[0]
                return struct.unpack("<Q", bytes(uc.mem_read(off, 8)))[0]
            fm = cstr(fmt)
            outb = bytearray(); ai = 0; j = 0
            try:
                while j < len(fm):
                    c = fm[j]
                    if c != 0x25:  # %
                        outb += bytes([c]); j += 1; continue
                    k = j + 1
                    spec = bytearray()
                    while k < len(fm) and fm[k:k+1] in (b'-', b'+', b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b' ', b'.'):
                        spec += fm[k:k+1]; k += 1
                    conv = chr(fm[k]) if k < len(fm) else 'd'
                    if conv in 'diu':
                        v = nextarg(2 + ai); ai += 1
                        v = v & 0xFFFFFFFF
                        s = str(v if conv == 'u' else (v if v < 0x80000000 else v - 0x100000000)).encode()
                    elif conv in 'xX':
                        v = nextarg(2 + ai); ai += 1
                        s = (("%x" % (v & 0xFFFFFFFF)) if conv == 'x' else ("%X" % (v & 0xFFFFFFFF))).encode()
                    elif conv == 'c':
                        v = nextarg(2 + ai); ai += 1
                        s = bytes([v & 0xFF])
                    elif conv == 's':
                        p = nextarg(2 + ai); ai += 1
                        s = cstr(p)
                    elif conv == '%':
                        outb += b'%'; j = k + 1; continue
                    else:
                        outb += fm[j:k+1]; j = k + 1; continue
                    w = int(bytes(spec).decode() or '0') if spec else 0
                    pad = bytes(spec).decode()
                    if '0' in pad and '-' not in pad and len(s) < abs(w):
                        s = s.rjust(abs(w), b'0')
                    elif '-' in pad:
                        s = s.ljust(abs(w), b' ')
                    elif w and len(s) < w:
                        s = s.rjust(w, b' ')
                    outb += s; j = k + 1
            except Exception as ex:
                if os.environ.get("MP_DEBUG"): print("[DBG] sprintf hata:", ex, file=sys.stderr)
            if outb:
                uc.mem_write(dst, bytes(outb))
            uc.reg_write(W, len(outb))
        elif name == "VirtualProtect":
            # V4.1: yabanci PE CRT'leri VirtualProtect kullanir -> hep basarili
            op = a(UC_X86_REG_R9)
            if op: uc.mem_write(op, struct.pack("<I", a(UC_X86_REG_R8)))
            uc.reg_write(W, 1)
        elif name == "ExitProcess":
            self.exit_code = a(UC_X86_REG_RCX) & 0xFFFFFFFF
            uc.emu_stop(); return
        else:
            self.error = f"BILINMEYEN API: {name} rip=0x{rip:X}"
            uc.emu_stop(); return
        # standart dönüş: ret
        rsp = a(UC_X86_REG_RSP)
        ret = struct.unpack("<Q", bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret)

    def run(self, max_insns=600_000_000):
        entry = self.img_base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        try:
            mi = os.environ.get("MP_MAXINSN")
            if mi: max_insns = int(mi)
            self.uc.emu_start(entry, 0, 0, max_insns)
            if self.exit_code is None:
                self.error = self.error or f"emu bitti ama ExitProcess yok (rip=0x{self.uc.reg_read(UC_X86_REG_RIP):X})"
        except UcError as e:
            if not self.error:
                self.error = f"UC-ERROR: {e} rip=0x{self.uc.reg_read(UC_X86_REG_RIP):X}"
        return self

if __name__ == "__main__":
    exe = sys.argv[1]
    args = sys.argv[2] if len(sys.argv) > 2 else ""
    e = Emu(exe, args).run()
    out = bytes(e.out).decode("utf-8", "replace")
    print("=== OUTPUT ===")
    print(out if out.strip() else "(bos)")
    print("=== API CAGRILARI ===")
    print(", ".join(f"{k}x{v}" for k, v in sorted(e.api_calls.items())))
    print(f"=== SONUC: exit={e.exit_code if e.exit_code is not None else '?'} error={e.error or 'yok'} ===")
    if getattr(e, "rvafreq", None):
        print("=== RVAFREQ (top 24 kova, 64B) ===")
        for b, cnt in sorted(e.rvafreq.items(), key=lambda kv: -kv[1])[:24]:
            print(f"  RVA {(b << 6):#08x} hits={cnt}")
    if e.error or os.environ.get('MP_TRACE_N'):
        print("=== TRACE (son 40) ===")
        print(" ".join(f"{a & 0xFFFFF:X}" for a in e.trace[-int(os.environ.get('MP_TRACE_N','40')):]))
    sys.exit(0 if (e.exit_code == 0 and not e.error) else 1)
