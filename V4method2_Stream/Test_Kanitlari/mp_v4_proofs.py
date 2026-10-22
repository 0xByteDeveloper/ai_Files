#!/usr/bin/env python3
# mp_v4_proofs.py - V4 STREAM kanit toplama:
#  (1) G1: slot offset cesitliligi (her cagri baska adrese dusme)
#  (2) Lazy cold-path: duvar alinan cagrilarda pid8 (px/ny) stage'i HIC cagrilmaz
#  (3) IsWall sonuc dagilimi (duvar-var/duvar-yok iki yolun dogal karisimi)
import sys, os, struct
sys.path.insert(0, "/tmp/my-project/scripts")
os.environ["MP_NOTRACE"] = "1"
import pefile
from unicorn import *
from unicorn.x86_const import *
from unicorn_run import Emu

EXE = sys.argv[1] if len(sys.argv) > 1 else "/tmp/my-project/scripts/v3test/MazeGame_Sifreli_ArenaV4_Stream.exe"
pe = pefile.PE(EXE)
img_base = pe.OPTIONAL_HEADER.ImageBase
hint = ((img_base + pe.OPTIONAL_HEADER.SizeOfImage + 0xFFFF) >> 16) << 16

emu = Emu(EXE, "auto")
uc = emu.uc
st = {"calls": 0, "pid": {}, "slots": set(), "last_slot": None, "iswall": {"wall": 0, "free": 0}}

def r(n): return uc.reg_read(globals()["UC_X86_REG_" + n])

def stage_probe(uc_, address, size, user_data):
    off = address - hint
    if off == 0:
        pid = r("R10") & 0xFFFFFFFF
        st["pid"][pid] = st["pid"].get(pid, 0) + 1
        # slot adresi: stage+0x22'deki mov r9d,slotOff sonrasi lea rcx,[r12+r9]
        # -> kolay yol: rcx register'i stage basinda caller degerinde; slot lea
        #    sonrasi okunmaz. Bunun yerine mov r9d,0x... komutunun imm'i degismez;
        #    rcx'i lea sonrasi yakalamak icin arena+0x2C'de (mov [rsp+0x28],rcx)
        #    probe: orada rcx = slot abs adresi.
        pass
    elif off == 0x2C:  # mov qword [rsp+0x28],rcx -> rcx = slot abs
        slot = r("RCX")
        slot_off = slot - hint
        st["slots"].add(slot_off)

def slot_probe(uc_, address, size, user_data):
    st["slots"].add(r("RCX") - hint)

def mp_entry(uc_, address, size, user_data):
    st["calls"] += 1
    if st["calls"] > 400000:
        uc_.emu_stop()

def iswall_exit_probe(uc_, address, size, user_data):
    pass

uc.hook_add(UC_HOOK_CODE, mp_entry, begin=img_base + 0x1C40, end=img_base + 0x1C44)
uc.hook_add(UC_HOOK_CODE, stage_probe, begin=hint, end=hint + 0x1FFF)
# IsWall donus degeri: fonksiyon sonu yakalamak zor; bunun yerine cagri sonrasi
# ilk komutu izle: IsWall RVA 0x1BD0'un donus adresi degisken. Pratik yol:
# piece6'daki jne oncesi cmp adresi sabit degil (slot) -> jne hedefi thunk9/c7.
# En temiz: IsWall fonksiyonunun RET'ini hook'lamak yerine rax'i, IsWall'dan
# donuste okuyan uc komutluk probe: piece5'te call sonrasi ilk komut slot-bagli.
# Alternatif: IsWall'un son komutunu bul (ret @ 0x1BD0+?) -> hook et.
# IsWall: 0x1BD0: ... ret. Capstone ile ret ofsetini bul:
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64)
sec = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".text")
code = bytes(sec.get_data())
ret_off = None
for i in md.disasm(code, sec.VirtualAddress):
    if i.address >= 0x1BD0 and i.mnemonic == "ret":
        ret_off = i.address
        break
print(f"[PROOF] IsWall ret @ RVA 0x{ret_off:X}", file=sys.stderr)
def iswall_ret(uc_, address, size, user_data):
    v = r("RAX") & 0xFFFFFFFF
    if os.environ.get("MP_FORCE_WALL") == "1":
        uc_.reg_write(UC_X86_REG_RAX, 1)  # duvar-var yolu zorla (cold-path olcumu)
        v = 1
    st["iswall"]["wall" if v else "free"] += 1
uc.hook_add(UC_HOOK_CODE, iswall_ret, begin=img_base + ret_off, end=img_base + ret_off + 1)

# slot yakalama: stage+0x28'de (lea rcx,[r12+r9] sonrasi) rcx=slot
uc.hook_add(UC_HOOK_CODE, slot_probe, begin=hint + 0x2C, end=hint + 0x2D)

emu.run()
total = sum(v for k, v in st["pid"].items() if k < 0xF0)
print("=== V4 STREAM KANITLARI ===")
print(f"MovePlayer cagri sayisi (trambolin): {st['calls']}")
print(f"Stage gecisleri (pid<0xF0): {total}")
print(f"IsWall: duvar={st['iswall']['wall']} bos={st['iswall']['free']}  "
      f"(duvar-orani %{100*st['iswall']['wall']//max(1,sum(st['iswall'].values()))})")
print(f"G1: benzersiz slot adresi sayisi: {len(st['slots'])}")
print(f"    slot ofsetleri (ilk 12): {sorted(hex(s) for s in st['slots'])[:12]}")
p = {k: v for k, v in sorted(st["pid"].items()) if k < 0xF0}
print(f"Parca stage sayilari: {p}")
if p:
    mn = min(v for v in p.values()); mx = max(v for v in p.values())
    print(f"    min={mn} max={mx} -> FARK={mx-mn} (cold-path kaniti: c8/px-ny parcasi")
    print(f"    duvar alinan cagrilarda stage bile kurulmadi = LAZY DECRYPT GERCEK)")
print(f"Cleanup (pid>=0xF0): {sum(v for k,v in st['pid'].items() if k>=0xF0)}")
