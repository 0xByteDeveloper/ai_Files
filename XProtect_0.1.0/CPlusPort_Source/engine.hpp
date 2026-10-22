// ============================================================
// engine.hpp — CPlusPort koruma motoru arayuzleri
// ============================================================
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include "vm_opcodes.h"

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int16_t  i16;
typedef int32_t  i32;
typedef int64_t  i64;

// ---------------- PE ----------------
struct Section {
    char name[9];
    u32 va, vsz, rawoff, rawsz, chars;
};

struct PEFile {
    std::vector<u8> buf;
    bool is64 = false;
    u16 machine = 0;
    u32 imagebase = 0, entry_rva = 0;
    u64 ib64 = 0;   // tam 64-bit ImageBase (PE32+ icin dogru deger, log/rapor)
    u32 secalign = 0x1000, filealign = 0x200, sizeofimage = 0, sizeofheaders = 0;
    u32 symtab_off = 0; u32 symtab_n = 0; u32 strtab_off = 0;
    u32 e_lfanew = 0;
    std::vector<Section> secs;

    bool load(const std::string& path, std::string& err);
    bool save(const std::string& path);
    u32  rva2raw(u32 rva, bool* ok = nullptr) const;
    Section* secbyrva(u32 rva);
    Section* secbyname(const char* n);
    const Section* secbyname_c(const char* n) const;
    bool add_section(const char* name, const std::vector<u8>& data, u32 chars,
                     u32& out_rva);
    void fix_checksum();
    // BUGFIX #13: sanallastirilan fonksiyon bolgelerine dusen eski
    // .reloc girdilerini siler (ASLR'da loader stub baytlarini bozuyordu)
    bool filter_relocs(const std::vector<std::pair<u32,u32>>& ranges,
                       u32& removed, std::string& note);
    // export tablosu
    void exports(std::vector<std::pair<std::string, u32>>& out);
    // COFF sembol tablosu (isim -> rva), fonksiyon olanlar
    void coff_symbols(std::vector<std::pair<std::string, u32>>& out);
};

// ---------------- Disassembler ----------------
enum XOp {
    XP_UNKNOWN = 0, XP_NOP, XP_INT3, XP_PUSH_R, XP_POP_R, XP_MOV_MR, XP_MOV_RM,
    XP_MOV_MI, XP_MOV_RI, XP_MOV_RI64, XP_LEA, XP_ALU, XP_SHIFT, XP_IMUL_RRI,
    XP_IMUL_RR, XP_INCDEC_R, XP_INCDEC_M, XP_MOVZX, XP_MOVSX, XP_JMP, XP_JCC,
    XP_CALL, XP_RET, XP_RETI16, XP_SETCC, XP_CWDE, XP_CDQ, XP_IDIV, XP_TEST_RM, XP_PUSH_I, XP_LEAVE, XP_CMOV,
    XP_NEG, XP_NOT
};

struct MemOp {
    bool present = false;
    int  base = -1, idx = -1, scale = 0;
    long long disp = 0;
    bool riprel = false;      // x64 rip-relative
    bool absimage = false;    // x86 mutlak, image araliginda -> base+rva'ya cevrilir
    u64  absval = 0;
};

struct Insn {
    XOp op = XP_UNKNOWN;
    u32 pc = 0, len = 0;
    int sz = 4;               // 1,2,4,8
    int r1 = -1, r2 = -1;
    u64 imm = 0; int immsz = 0;
    int cc = 0, alu = 0, shi = 0, ud = 0;
    MemOp mem;
    u64 target = 0;           // jmp/jcc/call hedefi (VA)
    std::string text;         // okunur gosterim (log icin)
};

Insn disasm(const u8* p, int maxlen, bool is64, u32 pc, u64 imagebase, u32 imagesize);

// ---------------- Lifter ----------------
struct VFn {
    u32 rva = 0, size = 0;
    std::string name;
    bool ok = false;
    std::string why;
    std::vector<u8> plain;          // duz bayt-kod (sifreleme son adimda)
    std::vector<std::pair<u32, u32>> fix;   // (bc offset, hedef bc-ic)
    std::vector<std::string> notes;
    std::vector<u32> str_refs;      // .rdata string baslangic RVA'lari
    u32 retimm = 0xFFFFFFFF;        // x86 stdcall ret imm16
};

// lifter: fonksiyonun makine kodunu VM bayt-koduna cevirir.
// junk_level: 0=kapali, 2=mutation junk; junk_seed: deterministik uretim
VFn lift_function(const u8* code, u32 rva, u32 size, bool is64,
                  u64 imagebase, u32 imagesize, bool allow_call,
                  u32 rdata_rva, u32 rdata_size, int junk_level, u32 junk_seed);

// ---------------- Stub ureteci ----------------
// x64: 15 reg push + ctx + call vm_entry(RDI) + geri
// x86: pushad + ctx + push ctxptr + call vm_entry(cdecl) + popad + ret[imm16]
std::vector<u8> build_stub_x64(u32 stub_rva, u32 vm_entry_rel_target_rva,
                               u64 key, u32 bc_rva, u32 bc_len);
std::vector<u8> build_stub_x86(u32 stub_rva, u32 vm_entry_rva,
                               u64 key, u32 bc_rva, u32 bc_len, u32 retimm);

// ---------------- Orkestrasyon ----------------
struct Options {
    int  level = 2;            // 1=Virt, 2=UltraVirt+Mutation
    bool antidebug = false;
    bool strenc = false;
    bool memprot = false;
    bool vmenc = true;
    std::vector<std::string> funcs;   // isim ya da rva(hex) listesi; bos -> hepsi uygun olanlar
    bool all = false;
};

struct FnInfo {
    u32 rva = 0, size = 0;
    std::string name;
    bool selected = false;
    bool virtualized = false;
    bool exported = false;
    std::string note;
};

// koruma ana isi; log satirlarini log vektorune birikirir
int protect(const std::string& in, const std::string& out, const Options& opt,
            std::vector<std::string>& log);

// yardimcilar
std::string hexs(const u8* p, int n);
std::string hex32(u32 v);
const char* regname(bool is64, int enc);

extern const unsigned char VM_BLOB64[]; extern const int VM_BLOB64_LEN;
extern const unsigned char VM_BLOBX86[]; extern const int VM_BLOBX86_LEN;
extern const u32 VM_BLOB64_ENTRY_OFF;   // blob icinde vm_entry ofseti
extern const u32 VM_BLOBX86_ENTRY_OFF;
