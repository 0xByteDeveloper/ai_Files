#!/usr/bin/env python3
# uni_maze86.py - mb86 benzeri x86 PE'de SendBattle'i unicorn'da cagir
# Kullanim: python3 uni_maze86.py <pe> [trace]
import struct, sys
from unicorn import *
from unicorn.x86_const import *
from capstone import *

PATH = sys.argv[1]
TRACE = len(sys.argv) > 2 and sys.argv[2] == 'trace'
BASE = 0x400000
STACK = 0x1FF00000      # 512MB alti
HEAP  = 0x01000000      # VirtualAlloc havuzu (RWX)
RET_MAGIC = 0x00DEAD00
IAT_MAGIC = 0x00D1C000  # her import icin ayri 16B slot

d = open(PATH,'rb').read()
elf = struct.unpack_from('<I', d, 0x3C)[0]
nsec = struct.unpack_from('<H', d, elf+6)[0]
opt = elf+24
is64 = struct.unpack_from('<H', d, opt)[0] == 0x20B
ddoff = opt + (112 if is64 else 96)
secoff = opt + (240 if is64 else 224)
sizeimg = struct.unpack_from('<I', d, opt+56)[0]
imgbase = struct.unpack_from('<Q' if is64 else '<I', d, opt+28 if is64 else opt+28)[0]
secs=[]
for i in range(nsec):
    o=secoff+i*40
    name=d[o:o+8].rstrip(b'\0').decode(errors='replace')
    vsz,va,rsz,rraw=struct.unpack_from('<IIII',d,o+8)
    secs.append((name,va,vsz,rraw,rsz))

# --- importlari topla (IAT adresleri) ---
imp_rva, imp_sz = struct.unpack_from('<II', d, ddoff+8)
imports = []  # (iatRva, dll, func)
if imp_rva and imp_sz:
    off = imp_rva
    def rva2raw(rva):
        for n,va,vsz,rraw,rsz in secs:
            if va<=rva<va+max(vsz,rsz) and rraw:
                return rraw+(rva-va)
        return None
    def cstr(rva):
        p = rva2raw(rva)
        if p is None: return ''
        s=d[p:p+256].split(b'\0')[0]
        return s.decode(errors='replace')
    end = imp_rva + imp_sz
    while off + 20 <= end:
        po = rva2raw(off)
        if po is None: break
        ilt, ts, fc, nameRva, iatRva = struct.unpack_from('<IIIII', d, po)
        if not nameRva or not (ilt or iatRva): break
        dll = cstr(nameRva)
        t = ilt or iatRva
        idx=0
        while True:
            p = rva2raw(t+idx*4)
            if p is None: break
            v = struct.unpack_from('<I', d, p)[0]
            if not v: break
            if not (v & 0x80000000):
                fn = cstr(v+2)
                if iatRva: imports.append((iatRva+idx*4, dll, fn))
            idx+=1
            if idx > 4096: break
        off+=20

mu = Uc(UC_ARCH_X86, UC_MODE_32)
img_sz = (sizeimg + 0xFFF) & ~0xFFF
mu.mem_map(BASE, img_sz)
mu.mem_map(STACK - 0x100000, 0x200000)
mu.mem_map(HEAP, 0x1000000)         # 16MB havuz
mu.mem_map(RET_MAGIC & ~0xFFF, 0x1000)
mu.mem_map(IAT_MAGIC & ~0xFFF, 0x1000)
for name,va,vsz,rraw,rsz in secs:
    if rsz: mu.mem_write(BASE+va, d[rraw:rraw+rsz])

heap_ptr = HEAP + 0x1000
print(f"image {hex(imgbase)} size={hex(img_sz)} imports={len(imports)}")

# --- IAT yonlendir ---
iat_map = {}   # magic -> (dll,func)
for i,(iatRva,dll,fn) in enumerate(imports):
    magic = IAT_MAGIC + i*16
    mu.mem_write(BASE+iatRva, struct.pack('<I', magic))
    iat_map[magic] = (dll, fn)

heap_pool = []
def do_valloc(size):
    global heap_ptr
    base = heap_ptr
    sz = (size + 0xFFF) & ~0xFFF
    heap_ptr += sz + 0x1000
    if heap_ptr > HEAP + 0x1000000:
        raise RuntimeError("havuz tasma")
    heap_pool.append((base, sz))
    return base

out = []
stage_entry = []
dbg3 = []
def hook_code(uc, address, size, ud):
    if TRACE and address != RET_MAGIC:
        out.append(address)
    if address == 0x100100d:
        print(f"[dbg] stage-dispatch cmp edx,7 -> edx={hex(uc.reg_read(UC_X86_REG_EDX))} esp={hex(uc.reg_read(UC_X86_REG_ESP))}")
    if address == 0x1001000 and len(stage_entry) < 2:
        stage_entry.append(uc.reg_read(UC_X86_REG_EDX))
    if address in (0x1001123, 0x1001125, 0x1001136) and len(dbg3) < 9:
        dbg3.append((address, uc.reg_read(UC_X86_REG_EAX), uc.reg_read(UC_X86_REG_ESP)))
        print(f"[dbg] @ {hex(address)} eax={hex(uc.reg_read(UC_X86_REG_EAX))} esp={hex(uc.reg_read(UC_X86_REG_ESP))}")

def hook_mem_invalid(uc, access, address, size, value, user_data):
    rip = uc.reg_read(UC_X86_REG_EIP)
    kind = {UC_MEM_READ_UNMAPPED:'READ', UC_MEM_WRITE_UNMAPPED:'WRITE', UC_MEM_FETCH_UNMAPPED:'FETCH'}[access]
    print(f"!! INVALID {kind} addr={hex(address)} size={size} RIP={hex(rip)}")
    return False

def hook_intr(uc, intno, user_data):
    print(f"!! INTERRUPT {intno} RIP={hex(uc.reg_read(UC_X86_REG_EIP))}")

mu.hook_add(UC_HOOK_CODE, hook_code)
mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
mu.hook_add(UC_HOOK_INTR, hook_intr)

stopped = []
allocs = []
calls = []
def hook_iat(uc, address, size, ud):
    if address not in iat_map: return
    dll, fn = iat_map[address]
    calls.append((address, dll, fn))
    if len(calls) <= 12:
        print(f"  IAT cagri #{len(calls)}: {dll}!{fn} @ {hex(address)} RIP={hex(uc.reg_read(UC_X86_REG_EIP))}")
    esp = uc.reg_read(UC_X86_REG_ESP)
    ret = struct.unpack('<I', uc.mem_read(esp,4))[0]
    def arg(n): return struct.unpack('<I', uc.mem_read(esp+4+4*n,4))[0]
    if fn == 'VirtualAlloc':
        sz = arg(1)
        base = do_valloc(sz)
        allocs.append((arg(0), sz, base))
        if len(allocs) <= 8 or len(allocs) % 64 == 0:
            print(f"  VirtualAlloc(req={hex(arg(0))}, sz={hex(sz)}) = {hex(base)}  [#alloc={len(allocs)}] esp={hex(esp)}")
        uc.reg_write(UC_X86_REG_EAX, base)
    elif fn == 'VirtualFree':
        uc.reg_write(UC_X86_REG_EAX, 1)
    elif fn in ('ExitProcess','_exit'):
        stopped.append('ExitProcess')
        uc.emu_stop(); return
    elif fn in ('printf','_printf','puts','_puts','__mingw_printf'):
        # minimal: sadece formatlari yut
        fmtaddr = arg(0)
        try: fmt = uc.mem_read(fmtaddr, 64).split(b'\0')[0].decode(errors='replace')
        except: fmt='?'
        out_txt = f"[printf] {fmt!r}"
        print(out_txt)
        uc.reg_write(UC_X86_REG_EAX, 1)
    else:
        if TRACE: print(f"  [IAT {dll}!{fn}] paramsiz devam (eax=0)")
        uc.reg_write(UC_X86_REG_EAX, 0)
    # stdcall temizligi: ret n
    # arg sayisini fonksiyon adina gore bilmiyoruz; VirtualAlloc/Free=4, printf>=1
    nargs = {'VirtualAlloc':4,'VirtualFree':3,'ExitProcess':1}.get(fn, 1)
    uc.reg_write(UC_X86_REG_ESP, esp + 4 + 4*nargs)
    if not stopped:
        uc.reg_write(UC_X86_REG_EIP, ret)

mu.hook_add(UC_HOOK_CODE, hook_iat)

# --- cagri kurulumu: stdcall SendBattle(0x1111, 0x2222) ---
FN = 0x401535
sp = STACK
sp -= 4; mu.mem_write(sp, struct.pack('<I', 0x2222))
sp -= 4; mu.mem_write(sp, struct.pack('<I', 0x1111))
sp -= 4; mu.mem_write(sp, struct.pack('<I', RET_MAGIC))
mu.reg_write(UC_X86_REG_ESP, sp)
mu.reg_write(UC_X86_REG_EBP, STACK - 0x1000)

try:
    mu.emu_start(FN, RET_MAGIC, count=20_000_000)
except UcError as e:
    print(f"UC HATA: {e} RIP={hex(mu.reg_read(UC_X86_REG_EIP))}")

eax = mu.reg_read(UC_X86_REG_EAX)
print(f"EAX = {hex(eax)} (beklenen 0xBBB8) {'TAM' if eax==0xBBB8 else 'YANLIS'}")
if stopped: print("durus:", stopped)
if TRACE and out:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    print("--- son 80 komut ---")
    for a in out[-80:]:
        for i in md.disasm(mu.mem_read(a, 12), a, 1):
            print(f"  {hex(a)}: {i.mnemonic} {i.op_str}")
            break
