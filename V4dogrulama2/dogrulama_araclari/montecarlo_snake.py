#!/usr/bin/env python3
# Monte-Carlo: rdtsc rastgele + tus enjeksiyonu ile korumali exe'yi N kez kostur
# Amac: real-Windows "bazen coku" davranisini emulasyonda yakalamak
import sys, os, struct, random, pefile
from unicorn import *
from unicorn.x86_const import *
import capstone

sys.path.insert(0, "/home/z/my-project/download/V4Dogrulama")
API_BASE   = 0x70000000
STACK_BASE = 0x00200000
STACK_SIZE = 0x200000
HEAP_BASE  = 0x00400000
GS_BASE    = 0x00090000

KEYS = [ord('d'), ord('s'), ord('a'), ord('w')]

class MonteCarlo:
    def __init__(self, path, seed):
        self.pe = pefile.PE(path)
        self.img_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.img_size = (self.pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF
        self.out = bytearray()
        self.rng = random.Random(seed)
        self.seed = seed
        self.exit_code = None
        self.error = None
        self.api_calls = {}
        self.apis = []
        self.frames = 0
        self.kb_n = 0
        self.getch_n = 0
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.uc = uc
        uc.mem_map(self.img_base, self.img_size, UC_PROT_ALL)
        uc.mem_write(self.img_base, self.pe.header)
        for s in self.pe.sections:
            d = s.get_data()
            if d: uc.mem_write(self.img_base + s.VirtualAddress, bytes(d))
        idx = 0
        for d in self.pe.DIRECTORY_ENTRY_IMPORT:
            for imp in d.imports:
                sent = API_BASE + idx * 8
                self.apis.append((imp.name.decode(), sent, imp.address))
                uc.mem_write(imp.address, struct.pack("<Q", sent))
                idx += 1
        uc.mem_map(API_BASE, 0x10000, UC_PROT_ALL)
        uc.mem_write(API_BASE, b"\xC3" * 0x10000)
        hb = ((self.img_base + self.img_size + 0xFFFFFF) & ~0xFFFFFF)
        uc.mem_map(hb, 0x800000, UC_PROT_ALL)
        self.heap_next = hb
        uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
        uc.mem_map(GS_BASE & ~0xFFF, 0x1000, UC_PROT_ALL)
        uc.reg_write(UC_X86_REG_GS_BASE, GS_BASE)
        gs_page = GS_BASE & ~0xFFF
        peb = gs_page + 0x80
        uc.mem_write(gs_page + 0x60, struct.pack("<Q", peb))
        uc.mem_write(peb + 0x10, struct.pack("<Q", self.img_base))
        self.arena_live = {}
        self.arena_free = {}
        uc.reg_write(UC_X86_REG_RSP, (STACK_BASE + STACK_SIZE - 0x1000) & ~0xF)
        uc.hook_add(UC_HOOK_BLOCK, self._api_hook, begin=API_BASE, end=API_BASE + 0xFFFF)
        uc.hook_add(UC_HOOK_MEM_INVALID, self._mem_fault)
        uc.hook_add(UC_HOOK_CODE, self._code_hook, begin=0x400000, end=0x470000)
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    def _code_hook(self, uc, address, size, user_data):
        if size == 2:
            try:
                if bytes(uc.mem_read(address, 2)) == b"\x0f\x31":
                    self._rdtsc(uc, None)
            except UcError:
                pass

    def _rdtsc(self, uc, user_data):
        # rastgele 64-bit TSC (real Windows davranisi)
        v = self.rng.getrandbits(64)
        uc.reg_write(UC_X86_REG_RAX, v & 0xFFFFFFFF)
        uc.reg_write(UC_X86_REG_RDX, (v >> 32) & 0xFFFFFFFF)
        return True  # emulate edildi say

    def _mem_fault(self, uc, access, address, size, value, user_data):
        if not self.error:
            regs = {r: uc.reg_read(globals()['UC_X86_REG_' + r]) for r in
                    ('RAX','RCX','RDX','RBX','RSP','RBP','RSI','RDI','R8','R9','R10','R11','R12','R13','R14','R15')}
            rip = uc.reg_read(UC_X86_REG_RIP)
            self.error = (f"MEM-FAULT tip={access} addr=0x{address:X} size={size} rip=0x{rip:X} seed={self.seed} frame={self.frames} " +
                          " ".join(f"{k}=0x{v:X}" for k, v in regs.items()))
            try:
                code = bytes(uc.mem_read(rip, 16))
                for i in self.md.disasm(code, rip):
                    self.error += f" | FAULT: {i.bytes.hex()} {i.mnemonic} {i.op_str}"
                    break
                # konum analizi
                rb = rip - self.img_base
                loc = f"RVA=0x{rb:X}" if 0 <= rb < self.img_size else f"ARENA-off=0x{rip-0x450000:X}" if 0x450000 <= rip < 0x460000 else "?"
                self.error += f" | loc={loc}"
            except Exception: pass
        return False

    def _api_hook(self, uc, address, size, user_data):
        rip = uc.reg_read(UC_X86_REG_RIP)
        idx = (rip - API_BASE) // 8
        if not (0 <= idx < len(self.apis)): return
        name = self.apis[idx][0]
        self.api_calls[name] = self.api_calls.get(name, 0) + 1
        a = lambda r: uc.reg_read(r)
        W = UC_X86_REG_RAX
        if name == "GetStdHandle": uc.reg_write(W, 0x100)
        elif name == "WriteFile":
            buf, ln = a(UC_X86_REG_RDX), a(UC_X86_REG_R8)
            if ln: self.out += bytes(uc.mem_read(buf, ln))
            wrp = a(UC_X86_REG_R9)
            if wrp: uc.mem_write(wrp, struct.pack("<I", ln))
            uc.reg_write(W, 1)
        elif name == "VirtualAlloc":
            hint, sz = a(UC_X86_REG_RCX), a(UC_X86_REG_RDX)
            sz = (sz + 0xFFF) & ~0xFFF
            if hint == 0:
                p = self.heap_next; self.heap_next += 0x1000; uc.reg_write(W, p)
            elif hint in self.arena_live:
                uc.reg_write(W, 0)
            elif hint in self.arena_free and self.arena_free[hint] >= sz:
                self.arena_live[hint] = self.arena_free.pop(hint); uc.reg_write(W, hint)
            else:
                try:
                    uc.mem_map(hint, sz, UC_PROT_ALL); self.arena_live[hint] = sz; uc.reg_write(W, hint)
                except UcError: uc.reg_write(W, 0)
        elif name == "VirtualFree":
            fp, typ = a(UC_X86_REG_RCX), a(UC_X86_REG_R8)
            if fp in self.arena_live:
                if typ & 0x8000: self.arena_free[fp] = self.arena_live.pop(fp)
                else: self.arena_live.pop(fp, None)
            uc.reg_write(W, 1)
        elif name in ("_kbhit", "kbhit"):
            # frame 3'ten sonra tus gonder (gercek oyuncu simulasyonu)
            self.kb_n += 1
            uc.reg_write(W, 1 if self.kb_n > 3 else 0)
        elif name in ("_getch", "getch", "_getche"):
            self.getch_n += 1
            uc.reg_write(W, KEYS[self.getch_n % len(KEYS)])
        elif name == "Sleep": pass
        elif name in ("srand", "rand"):
            if not hasattr(self, "rt_seed"): self.rt_seed = 0x1234ABCD
            if name == "srand": self.rt_seed = uc.reg_read(UC_X86_REG_RCX) & 0xFFFFFFFF; uc.reg_write(W, 0)
            else:
                self.rt_seed = (self.rt_seed * 1103515245 + 12345) & 0x7FFFFFFF
                uc.reg_write(W, self.rt_seed)
        elif name in ("_time64", "time"):
            self.frames += 1
            uc.reg_write(W, self.frames)
            if uc.reg_read(UC_X86_REG_RDX):
                uc.mem_write(uc.reg_read(UC_X86_REG_RDX), struct.pack("<Q", self.frames))
        elif name == "GetConsoleScreenBufferInfo":
            p = a(UC_X86_REG_RDX)
            if p: uc.mem_write(p, struct.pack("<HHHHHHHHHH", 80, 25, 0, 0, 7, 0, 0, 79, 24, 0) + struct.pack("<HH", 80, 25))
            uc.reg_write(W, 1)
        elif name in ("SetConsoleCursorPosition","SetConsoleTextAttribute","GetConsoleCursorInfo","SetConsoleCursorInfo",
                      "GetConsoleMode","SetConsoleMode","SetConsoleTitleA","GetFileType","FlushConsoleInputBuffer",
                      "SetConsoleWindowInfo","GetConsoleWindowInfo","SetConsoleScreenBufferSize","SetConsoleOutputCP","SetConsoleCP"):
            uc.reg_write(W, 1)
        elif name in ("memset", "memcpy", "memmove"):
            dst, srcp = a(UC_X86_REG_RCX), a(UC_X86_REG_RDX)
            if name == "memset":
                val = uc.reg_read(UC_X86_REG_RDX) & 0xFF; ln = uc.reg_read(UC_X86_REG_R8)
                if ln: uc.mem_write(dst, bytes([val]) * ln)
            else:
                ln = uc.reg_read(UC_X86_REG_R8)
                if ln: uc.mem_write(dst, bytes(uc.mem_read(srcp, ln)))
            uc.reg_write(W, dst)
        elif name in ("printf", "puts"):
            fp = a(UC_X86_REG_RCX)
            PBUF = 0x72300000
            if not getattr(self, "pbuf_mapped", False):
                try: uc.mem_map(PBUF, 0x10000, UC_PROT_ALL); self.pbuf_mapped = True
                except UcError: pass
            outb = bytearray()
            try:
                while True:
                    bb = uc.mem_read(fp + len(outb), 1)
                    if not bb[0]: break
                    outb += bytes(bb)
                    if len(outb) > 8192: break
            except UcError: pass
            self.out += bytes(outb)
            uc.reg_write(W, len(outb))
        elif name in ("sprintf",):
            dst = a(UC_X86_REG_RCX); uc.reg_write(W, 0)
        elif name == "ExitProcess":
            self.exit_code = a(UC_X86_REG_RCX) & 0xFFFFFFFF
            uc.emu_stop(); return
        else:
            uc.reg_write(W, 0)
        rsp = a(UC_X86_REG_RSP)
        ret = struct.unpack("<Q", bytes(uc.mem_read(rsp, 8)))[0]
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret)

    def run(self, max_insns=120_000_000):
        entry = self.img_base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        try:
            self.uc.emu_start(entry, 0, 0, max_insns)
            if self.exit_code is None:
                rip = self.uc.reg_read(UC_X86_REG_RIP)
                rb = rip - self.img_base
                loc = f"RVA=0x{rb:X}" if 0 <= rb < self.img_size else (f"ARENA+0x{rip-0x450000:X}" if 0x450000 <= rip < 0x460000 else f"0x{rip:X}")
                self.error = self.error or f"insn-limit (rip={loc} frame={self.frames})"
        except UcError as e:
            if not self.error:
                self.error = f"UC-ERROR: {e} rip=0x{self.uc.reg_read(UC_X86_REG_RIP):X} seed={self.seed}"
        return self

if __name__ == "__main__":
    exe = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    budget = int(sys.argv[3]) if len(sys.argv) > 3 else 120_000_000
    for seed in range(1000, 1000 + n):
        mc = MonteCarlo(exe, seed).run(budget)
        status = f"exit={mc.exit_code}" if mc.exit_code is not None else f"frames={mc.frames}"
        if mc.error and "insn-limit" not in mc.error:
            print(f"seed={seed}: CRASH! {mc.error[:600]}")
        else:
            print(f"seed={seed}: OK {status} kb={mc.kb_n} getch={mc.getch_n} alloc={mc.api_calls.get('VirtualAlloc',0)}")
        if mc.error and "insn-limit" not in mc.error:
            break
