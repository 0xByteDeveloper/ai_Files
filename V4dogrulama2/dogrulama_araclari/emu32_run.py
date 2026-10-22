#!/usr/bin/env python3
# x86 (PE32) unicorn hakemli calistirma - korumali exe hata ayiklama
import sys, struct, pefile
from unicorn import *
from unicorn.x86_const import *
import capstone

API_BASE   = 0x70000000
STACK_BASE = 0x00200000
STACK_SIZE = 0x200000
GS_BASE    = 0x00090000

class Emu32:
    def __init__(self, path):
        self.pe = pefile.PE(path)
        self.img_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.img_size = (self.pe.OPTIONAL_HEADER.SizeOfImage + 0xFFF) & ~0xFFF
        self.out = bytearray()
        self.exit_code = None
        self.error = None
        self.api_calls = {}
        self.apis = []
        uc = Uc(UC_ARCH_X86, UC_MODE_32)
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
                self.apis.append((imp.name.decode(), sent))
                uc.mem_write(imp.address, struct.pack("<I", sent))
                idx += 1
        uc.mem_map(API_BASE, 0x10000, UC_PROT_ALL)
        uc.mem_write(API_BASE, b"\xC3" * 0x10000)
        uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
        uc.mem_map(GS_BASE & ~0xFFF, 0x1000, UC_PROT_ALL)
        uc.reg_write(UC_X86_REG_GS_BASE, GS_BASE)
        gs_page = GS_BASE & ~0xFFF
        # x86 TEB: gs:[0x18]=TEB self, gs:[0x30]=PEB
        teb = gs_page + 0x40
        peb = gs_page + 0x80
        uc.mem_write(gs_page + 0x18, struct.pack("<I", teb))
        uc.mem_write(teb + 0x30, struct.pack("<I", peb))
        uc.mem_write(peb + 0x10, struct.pack("<I", self.img_base))  # ImageBaseAddress? x86 PEB+8
        uc.mem_write(peb + 0x08, struct.pack("<I", self.img_base))
        self.arena_live = {}
        uc.reg_write(UC_X86_REG_ESP, (STACK_BASE + STACK_SIZE - 0x1000) & ~0xF)
        uc.hook_add(UC_HOOK_BLOCK, self._api_hook, begin=API_BASE, end=API_BASE + 0xFFFF)
        uc.hook_add(UC_HOOK_MEM_INVALID, self._mem_fault)
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.trace = []

    def _mem_fault(self, uc, access, address, size, value, user_data):
        if not self.error:
            regs = {r: uc.reg_read(globals()['UC_X86_REG_' + r]) for r in
                    ('EAX','ECX','EDX','EBX','ESP','EBP','ESI','EDI')}
            rip = uc.reg_read(UC_X86_REG_RIP)
            self.error = (f"FAULT tip={access} addr=0x{address:X} rip=0x{rip:X} " +
                          " ".join(f"{k}=0x{v:X}" for k, v in regs.items()))
            try:
                code = bytes(uc.mem_read(rip, 16))
                for i in self.md.disasm(code, rip):
                    self.error += f" | INS: {i.bytes.hex()} {i.mnemonic} {i.op_str}"
                    break
            except Exception: pass
            self.error += " | TRACE: " + " ".join(f"{a & 0xFFFFF:X}" for a in self.trace[-24:])
        return False

    def _api_hook(self, uc, address, size, user_data):
        rip = uc.reg_read(UC_X86_REG_RIP)
        idx = (rip - API_BASE) // 8
        if not (0 <= idx < len(self.apis)): return
        name = self.apis[idx][0]
        self.api_calls[name] = self.api_calls.get(name, 0) + 1
        a = lambda r: uc.reg_read(r)
        W = UC_X86_REG_EAX
        rsp = a(UC_X86_REG_ESP)
        def argi(n):  # stdcall args on stack (0-based, ret at [rsp])
            return struct.unpack("<I", bytes(uc.mem_read(rsp + 4 + n * 4, 4)))[0]
        if name == "GetStdHandle": uc.reg_write(W, 0x100)
        elif name == "WriteFile":
            buf, ln = argi(1), argi(2)
            if ln: self.out += bytes(uc.mem_read(buf, ln))
            wrp = argi(3)
            if wrp: uc.mem_write(wrp, struct.pack("<I", ln))
            uc.reg_write(W, 1)
        elif name == "VirtualAlloc":
            hint, sz = argi(0), argi(1)
            sz = (sz + 0xFFF) & ~0xFFF
            if hint == 0:
                uc.reg_write(W, 0)  # x86 yolunda hint hep verilir
            elif hint in self.arena_live:
                uc.reg_write(W, 0)
            else:
                try:
                    uc.mem_map(hint, sz, UC_PROT_ALL); self.arena_live[hint] = sz; uc.reg_write(W, hint)
                except UcError:
                    uc.reg_write(W, 0)
        elif name == "VirtualFree":
            uc.reg_write(W, 1)
        elif name == "ExitProcess":
            self.exit_code = argi(0); uc.emu_stop(); return
        else:
            uc.reg_write(W, 0)
        ret = struct.unpack("<I", bytes(uc.mem_read(rsp, 4)))[0]
        uc.reg_write(UC_X86_REG_ESP, rsp + 4)
        uc.reg_write(UC_X86_REG_EIP, ret)

    def run(self, max_insns=60_000_000, trace_n=2000):
        entry = self.img_base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        lo, hi = self.img_base + 0x1000, self.img_base + self.img_size
        def tr(uc, address, size, ud):
            self.trace.append(address)
            if len(self.trace) > trace_n: self.trace.pop(0)
        self.uc.hook_add(UC_HOOK_CODE, tr, begin=lo, end=hi)
        try:
            self.uc.emu_start(entry, 0, 0, max_insns)
            if self.exit_code is None:
                rip = self.uc.reg_read(UC_X86_REG_RIP)
                self.error = self.error or f"limit rip=0x{rip:X}"
        except UcError as e:
            if not self.error:
                self.error = f"UC-ERR {e} rip=0x{self.uc.reg_read(UC_X86_REG_RIP):X}"
        return self

if __name__ == "__main__":
    e = Emu32(sys.argv[1]).run()
    out = bytes(e.out).decode("utf-8", "replace")
    print("=== OUTPUT ==="); print(out[:600])
    print("=== API ===", ", ".join(f"{k}x{v}" for k, v in sorted(e.api_calls.items())))
    print("=== SONUC: exit=", e.exit_code, " error=", e.error)
