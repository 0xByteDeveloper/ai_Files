#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>
#include <string>
#include <map>
#include <unordered_map>
#include <set>
#include <algorithm>
#include <mutex>
#include <functional>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <deque>
#include <cstdint>
#pragma comment(lib,"psapi.lib")
#include <capstone/capstone.h>
#pragma comment(lib,"capstone.lib")

using u8 = uint8_t; using u16 = uint16_t; using u32 = uint32_t; using u64 = uint64_t;
using i8 = int8_t; using i16 = int16_t; using i32 = int32_t; using i64 = int64_t;

struct SecInfo { char name[9]{}; u32 va = 0, vSz = 0, raw = 0, rawSz = 0, chars = 0; };
struct ImpFunc { std::string name; u16 ord = 0; u64 iatAddr = 0; };
struct ImpDll { std::string name; std::vector<ImpFunc> funcs; };
struct DisLine { u64 addr = 0; u8 bytes[16]{}; u8 len = 0; std::string mn, op, sym; bool isCall = 0, isJmp = 0, isRet = 0, isCond = 0; u64 target = 0; bool hasMemTarget = 0; u64 memTarget = 0; };
struct RefInfo { u64 src = 0, dst = 0; enum Type :u8 { CALL = 0, JMP, JCC, PUSH }type = CALL; static const char* TypeStr(Type t) { static const char* s[] = { "call","jmp","jcc","push" }; return s[t]; } };
struct EditEntry { u64 addr = 0; std::vector<u8>oldData, newData; };

class PEFile {
public:
    std::vector<u8>raw; std::vector<SecInfo>secs; std::vector<ImpDll>imps;
    struct RelocEntry { u32 rva; u16 type; }; std::vector<RelocEntry>relocs;
    bool valid = 0, is64 = 0, hasRelocs = 0; u64 imgBase = 0; u32 imgSz = 0, hdrSz = 0, ep = 0; u16 numSec = 0, dllCharacteristics = 0;

    bool Load(const wchar_t* path) {
        Clear();
        HANDLE hF = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
        if (hF == INVALID_HANDLE_VALUE)return 0;
        DWORD sz = GetFileSize(hF, 0);
        if (sz < 64) { CloseHandle(hF); return 0; }
        raw.resize(sz); DWORD rd = 0;
        ReadFile(hF, raw.data(), sz, &rd, 0); CloseHandle(hF);
        if (rd != sz) { raw.clear(); return 0; }
        return Parse();
    }
    bool DisableASLR() {
        if (raw.empty())return 0;
        auto dos = (PIMAGE_DOS_HEADER)raw.data();
        auto nt = (PIMAGE_NT_HEADERS)(raw.data() + dos->e_lfanew);
        if (is64) { auto n = (PIMAGE_NT_HEADERS64)nt; n->OptionalHeader.DllCharacteristics &= ~0x60; dllCharacteristics = n->OptionalHeader.DllCharacteristics; }
        else { auto n = (PIMAGE_NT_HEADERS32)nt; n->OptionalHeader.DllCharacteristics &= ~0x40; dllCharacteristics = n->OptionalHeader.DllCharacteristics; }
        return 1;
    }
    static u32 AlignUp(u32 v, u32 a) { return a ? ((v + a - 1) / a) * a : v; }
    u64 AddSection(const char* name, size_t size, u32 characteristics) {
        if (raw.empty() || !valid)return 0;
        auto dos = (PIMAGE_DOS_HEADER)raw.data(); auto nt = (PIMAGE_NT_HEADERS)(raw.data() + dos->e_lfanew);
        u32 secAlign, fileAlign;
        if (is64) { auto n = (PIMAGE_NT_HEADERS64)nt; secAlign = n->OptionalHeader.SectionAlignment; fileAlign = n->OptionalHeader.FileAlignment; }
        else { auto n = (PIMAGE_NT_HEADERS32)nt; secAlign = n->OptionalHeader.SectionAlignment; fileAlign = n->OptionalHeader.FileAlignment; }
        auto firstSec = IMAGE_FIRST_SECTION(nt); auto lastSec = &firstSec[numSec - 1];
        u8* newPos = (u8*)(lastSec + 1);
        if (newPos + sizeof(IMAGE_SECTION_HEADER) > raw.data() + hdrSz)return 0;
        u32 lastEnd = lastSec->VirtualAddress + lastSec->Misc.VirtualSize;
        u32 newVA = AlignUp(lastEnd, secAlign), newRaw = AlignUp(lastSec->PointerToRawData + lastSec->SizeOfRawData, fileAlign);
        u32 alignVSz = AlignUp((u32)size, secAlign), rawSz = AlignUp((u32)size, fileAlign);
        IMAGE_SECTION_HEADER h = {}; size_t nl = strlen(name); memcpy(h.Name, name, nl > 8 ? 8 : nl);
        h.Misc.VirtualSize = (u32)size; h.VirtualAddress = newVA; h.SizeOfRawData = rawSz; h.PointerToRawData = newRaw; h.Characteristics = characteristics;
        size_t newFSz = newRaw + rawSz; if (newFSz > raw.size())raw.resize(newFSz, 0xCC);
        memcpy(newPos, &h, sizeof(h)); nt->FileHeader.NumberOfSections = numSec + 1;
        if (is64)((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.SizeOfImage = newVA + alignVSz;
        else((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.SizeOfImage = newVA + alignVSz;
        SecInfo si; memcpy(si.name, h.Name, 8); si.va = newVA; si.vSz = (u32)size; si.raw = newRaw; si.rawSz = rawSz; si.chars = characteristics;
        secs.push_back(si); numSec++; imgSz = newVA + alignVSz;
        return imgBase + newVA;
    }
    bool AddRelocation(u32 rva, u16 type = 3) { if (!hasRelocs)return 0; relocs.push_back({ rva,type }); return 1; }
    bool Save(const wchar_t* path, const u8* mem, u64 memBase, size_t memSz) {
        if (raw.empty())return 0; std::vector<u8>out = raw;
        for (auto& s : secs) { if (!s.rawSz || !s.raw)continue; size_t cl = (std::min)((size_t)s.rawSz, (size_t)s.vSz); if (s.va + cl > memSz || s.raw + cl > out.size())continue; memcpy(out.data() + s.raw, mem + s.va, cl); }
        if (!relocs.empty())RebuildRelocations(out);
        HANDLE hF = CreateFileW(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0); if (hF == INVALID_HANDLE_VALUE)return 0;
        DWORD wr = 0; WriteFile(hF, out.data(), (DWORD)out.size(), &wr, 0); CloseHandle(hF); return wr == out.size();
    }
    void Clear() { raw.clear(); secs.clear(); imps.clear(); relocs.clear(); valid = is64 = hasRelocs = 0; imgBase = imgSz = hdrSz = ep = numSec = dllCharacteristics = 0; }
    u32 RvaToRaw(u32 rva)const { for (auto& s : secs)if (rva >= s.va && rva < s.va + (std::max)(s.vSz, s.rawSz))return s.raw + (rva - s.va); return rva < hdrSz ? rva : 0; }
private:
    bool Parse() {
        if (raw.size() < sizeof(IMAGE_DOS_HEADER))return 0;
        auto dos = (PIMAGE_DOS_HEADER)raw.data(); if (dos->e_magic != IMAGE_DOS_SIGNATURE)return 0;
        if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > raw.size())return 0;
        auto nt = (PIMAGE_NT_HEADERS)(raw.data() + dos->e_lfanew); if (nt->Signature != IMAGE_NT_SIGNATURE)return 0;
        is64 = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        if (is64) { auto n = (PIMAGE_NT_HEADERS64)nt; imgBase = n->OptionalHeader.ImageBase; imgSz = n->OptionalHeader.SizeOfImage; hdrSz = n->OptionalHeader.SizeOfHeaders; ep = n->OptionalHeader.AddressOfEntryPoint; dllCharacteristics = n->OptionalHeader.DllCharacteristics; }
        else { auto n = (PIMAGE_NT_HEADERS32)nt; imgBase = n->OptionalHeader.ImageBase; imgSz = n->OptionalHeader.SizeOfImage; hdrSz = n->OptionalHeader.SizeOfHeaders; ep = n->OptionalHeader.AddressOfEntryPoint; dllCharacteristics = n->OptionalHeader.DllCharacteristics; }
        numSec = nt->FileHeader.NumberOfSections; auto sh = IMAGE_FIRST_SECTION(nt); secs.resize(numSec);
        for (u16 i = 0; i < numSec; i++) { memcpy(secs[i].name, sh[i].Name, 8); secs[i].va = sh[i].VirtualAddress; secs[i].vSz = sh[i].Misc.VirtualSize; secs[i].raw = sh[i].PointerToRawData; secs[i].rawSz = sh[i].SizeOfRawData; secs[i].chars = sh[i].Characteristics; }
        ParseImports(); ParseRelocations(); valid = 1; return 1;
    }
    void ParseRelocations() {
        if (raw.empty())return; auto dos = (PIMAGE_DOS_HEADER)raw.data(); auto nt = (PIMAGE_NT_HEADERS)(raw.data() + dos->e_lfanew);
        PIMAGE_DATA_DIRECTORY rd = is64 ? &((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] : &((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!rd->VirtualAddress || !rd->Size)return; u32 off = RvaToRaw(rd->VirtualAddress); if (!off || off >= raw.size())return;
        hasRelocs = 1; relocs.clear(); u32 proc = 0;
        while (proc < rd->Size) {
            auto blk = (PIMAGE_BASE_RELOCATION)(raw.data() + off + proc); if (!blk->SizeOfBlock)break;
            u32 n = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2; u16* e = (u16*)((u8*)blk + sizeof(IMAGE_BASE_RELOCATION));
            for (u32 i = 0; i < n; i++) { u16 t = e[i] >> 12, o = e[i] & 0xFFF; if (t)relocs.push_back({ blk->VirtualAddress + o,t }); }proc += blk->SizeOfBlock;
        }
    }
    void RebuildRelocations(std::vector<u8>& out) {
        auto dos = (PIMAGE_DOS_HEADER)out.data(); auto nt = (PIMAGE_NT_HEADERS)(out.data() + dos->e_lfanew);
        PIMAGE_DATA_DIRECTORY rd = is64 ? &((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] : &((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (!rd->VirtualAddress)return; std::sort(relocs.begin(), relocs.end(), [](auto& a, auto& b) {return a.rva < b.rva; });
    }
    void ParseImports() {
        if (raw.empty())return; auto dos = (PIMAGE_DOS_HEADER)raw.data(); auto nt = (PIMAGE_NT_HEADERS)(raw.data() + dos->e_lfanew);
        PIMAGE_DATA_DIRECTORY id = is64 ? &((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] : &((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (!id->VirtualAddress || !id->Size)return; u32 off = RvaToRaw(id->VirtualAddress); if (!off || off >= raw.size())return;
        auto desc = (PIMAGE_IMPORT_DESCRIPTOR)(raw.data() + off);
        while (desc->Name) {
            u32 nOff = RvaToRaw(desc->Name); if (!nOff || nOff >= raw.size())break;
            ImpDll dll; dll.name = (char*)(raw.data() + nOff);
            u32 thRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk, thOff = RvaToRaw(thRva), iatRva = desc->FirstThunk;
            if (thOff && thOff < raw.size()) {
                if (is64) {
                    auto th = (PIMAGE_THUNK_DATA64)(raw.data() + thOff); u64 ia = imgBase + iatRva;
                    while (th->u1.AddressOfData) {
                        ImpFunc f; f.iatAddr = ia;
                        if (IMAGE_SNAP_BY_ORDINAL64(th->u1.Ordinal)) { f.ord = (u16)IMAGE_ORDINAL64(th->u1.Ordinal); f.name = "Ord_" + std::to_string(f.ord); }
                        else { u32 ho = RvaToRaw((u32)th->u1.AddressOfData); if (ho && ho < raw.size())f.name = (char*)(raw.data() + ho + 2); }
                        dll.funcs.push_back(f); th++; ia += 8;
                    }
                }
                else {
                    auto th = (PIMAGE_THUNK_DATA32)(raw.data() + thOff); u64 ia = imgBase + iatRva;
                    while (th->u1.AddressOfData) {
                        ImpFunc f; f.iatAddr = ia;
                        if (IMAGE_SNAP_BY_ORDINAL32(th->u1.Ordinal)) { f.ord = (u16)IMAGE_ORDINAL32(th->u1.Ordinal); f.name = "Ord_" + std::to_string(f.ord); }
                        else { u32 ho = RvaToRaw(th->u1.AddressOfData); if (ho && ho < raw.size())f.name = (char*)(raw.data() + ho + 2); }
                        dll.funcs.push_back(f); th++; ia += 4;
                    }
                }
            }
            imps.push_back(dll); desc++;
        }
    }
};

class MemImage {
public:
    std::vector<u8>data; u64 base = 0; bool is64 = 0;
    bool Expand(size_t n) { if (!n)return 1; try { data.resize(data.size() + n, 0xCC); return 1; } catch (...) { return 0; } }
    bool ExpandTo(u64 a) { if (a < base)return 0; size_t r = (size_t)(a - base + 1); return r <= data.size() ? 1 : Expand(r - data.size()); }
    bool Resize(size_t n) { try { size_t o = data.size(); data.resize(n); if (n > o)memset(data.data() + o, 0xCC, n - o); return 1; } catch (...) { return 0; } }
    bool Create(PEFile& pe) {
        data.clear(); data.resize(pe.imgSz, 0); base = pe.imgBase; is64 = pe.is64; memcpy(data.data(), pe.raw.data(), pe.hdrSz);
        for (auto& s : pe.secs) { if (!s.rawSz || !s.raw)continue; size_t cl = (std::min)((size_t)s.rawSz, (size_t)s.vSz); if (s.raw + cl > pe.raw.size() || s.va + cl > data.size())continue; memcpy(data.data() + s.va, pe.raw.data() + s.raw, cl); }
        ResolveImports(pe); return 1;
    }
    bool InRange(u64 a)const { return a >= base && a < base + data.size(); }
    u8 Read8(u64 a)const { return InRange(a) ? data[a - base] : 0; }
    u16 Read16(u64 a)const { return InRange(a + 1) ? *(u16*)&data[a - base] : 0; }
    u32 Read32(u64 a)const { return InRange(a + 3) ? *(u32*)&data[a - base] : 0; }
    u64 Read64(u64 a)const { return InRange(a + 7) ? *(u64*)&data[a - base] : 0; }
    bool Write8(u64 a, u8 v) { if (!InRange(a))return 0; data[a - base] = v; return 1; }
    bool WriteBytes(u64 a, const u8* b, size_t l) { if (!InRange(a) || !InRange(a + l - 1))return 0; memcpy(&data[a - base], b, l); return 1; }
    bool ReadBytes(u64 a, u8* b, size_t l)const { if (!InRange(a) || !InRange(a + l - 1))return 0; memcpy(b, &data[a - base], l); return 1; }
private:
    void ResolveImports(PEFile& pe) {
        for (auto& d : pe.imps) {
            HMODULE h = LoadLibraryA(d.name.c_str()); if (!h)continue;
            for (auto& f : d.funcs) {
                FARPROC p = f.ord ? GetProcAddress(h, MAKEINTRESOURCEA(f.ord)) : GetProcAddress(h, f.name.c_str());
                if (p && InRange(f.iatAddr)) { if (is64)*(u64*)&data[f.iatAddr - base] = (u64)p; else*(u32*)&data[f.iatAddr - base] = (u32)(uintptr_t)p; }
            }
        }
    }
};

class Disasm {
public:
    csh handle = 0; bool init = 0, is64 = 0;
    bool Init(bool x64) { if (init)cs_close(&handle); is64 = x64; if (cs_open(CS_ARCH_X86, x64 ? CS_MODE_64 : CS_MODE_32, &handle) != CS_ERR_OK)return 0; cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL); init = 1; return 1; }
    ~Disasm() { if (init)cs_close(&handle); }
    std::vector<DisLine>DisasmRange(const MemImage& mem, u64 start, u64 end) {
        std::vector<DisLine>r; if (!init || !mem.InRange(start))return r; u64 a = start;
        while (a < end && a < mem.base + mem.data.size()) {
            DisLine l; l.addr = a;
            if (!mem.InRange(a)) { l.len = 1; l.mn = "??"; r.push_back(l); a++; continue; }
            const u8* c = &mem.data[a - mem.base]; size_t rm = mem.data.size() - (a - mem.base); cs_insn* ins = 0; size_t n = cs_disasm(handle, c, (std::min)(rm, (size_t)16), a, 1, &ins);
            if (n > 0) {
                l.len = (u8)ins[0].size; memcpy(l.bytes, ins[0].bytes, l.len); l.mn = ins[0].mnemonic; l.op = ins[0].op_str; l.sym = l.op;
                cs_detail* d = ins[0].detail; if (d) {
                    for (u8 g = 0; g < d->groups_count; g++) { if (d->groups[g] == CS_GRP_CALL)l.isCall = 1; if (d->groups[g] == CS_GRP_JUMP)l.isJmp = 1; if (d->groups[g] == CS_GRP_RET)l.isRet = 1; }
                    if (l.isJmp && l.mn.substr(0, 3) != "jmp")l.isCond = 1;
                    for (int i = 0; i < d->x86.op_count; i++) { auto& o = d->x86.operands[i]; if (o.type == X86_OP_IMM)l.target = o.imm; else if (o.type == X86_OP_MEM) { l.hasMemTarget = 1; if (o.mem.base == X86_REG_INVALID && o.mem.index == X86_REG_INVALID)l.memTarget = (u64)o.mem.disp; } }
                }
                cs_free(ins, 1); a += l.len;
            }
            else { l.len = 1; l.bytes[0] = c[0]; l.mn = "db"; char b[8]; sprintf(b, "0x%02X", c[0]); l.op = b; a++; }
            r.push_back(l);
        }return r;
    }
    bool DisasmOne(const u8* c, size_t l, u64 a, DisLine& o) { if (!init || !c || !l)return 0; cs_insn* ins = 0; size_t n = cs_disasm(handle, c, l, a, 1, &ins); if (!n)return 0; o.addr = a; o.len = (u8)ins[0].size; memcpy(o.bytes, ins[0].bytes, o.len); o.mn = ins[0].mnemonic; o.op = ins[0].op_str; cs_free(ins, 1); return 1; }
};

class Assembler {
public:
    bool is64 = 0;
    std::function<u64(const std::string&)>symbolLookup, iatLookup, allocateString;
    std::function<u64(u64)>readMemory;
    std::function<void(u64, u16)>addRelocation;

    std::vector<u8>Asm(const std::string& text, u64 addr) {
        std::vector<u8>out; std::string s = text; Trim(s); std::string lw = s; Lower(lw);
        std::string mn, op1, op2; size_t sp = lw.find(' ');
        if (sp == std::string::npos)mn = lw; else { mn = lw.substr(0, sp); std::string ops = s.substr(sp + 1); Trim(ops); size_t cm = ops.find(','); if (cm == std::string::npos)op1 = ops; else { op1 = ops.substr(0, cm); op2 = ops.substr(cm + 1); RTrim(op1); LTrim(op2); } }
        std::string op1L = op1, op2L = op2; Lower(op1L); Lower(op2L);
        if (mn == "nop")return{ 0x90 }; if (mn == "ret" || mn == "retn")return{ 0xC3 }; if (mn == "int3")return{ 0xCC }; if (mn == "leave")return{ 0xC9 };
        if (mn == "pushad" && !is64)return{ 0x60 }; if (mn == "popad" && !is64)return{ 0x61 }; if (mn == "pushfd" && !is64)return{ 0x9C }; if (mn == "popfd" && !is64)return{ 0x9D };
        if (mn == "cdq")return{ 0x99 }; if (mn == "cwde")return{ 0x98 };
        if (mn == "push") {
            if (op1.length() > 5 && op1.substr(0, 5) == "@STR:") { std::string sc = op1.substr(5); if (sc.length() >= 2 && sc[0] == '"' && sc.back() == '"')sc = sc.substr(1, sc.length() - 2); if (allocateString) { u64 sa = allocateString(sc); if (sa) { out = { 0x68 }; PushImm32(out, sa); return out; } }return out; }
            int rc = Reg32(op1L); if (rc >= 0)return{ (u8)(0x50 + rc) }; u64 im = ParseImm(op1); if (!im && op1 != "0" && op1 != "0x0" && symbolLookup) { u64 sa = symbolLookup(op1); if (sa)im = sa; }
            if ((i64)im >= -128 && (i64)im <= 127)return{ 0x6A,(u8)(im & 0xFF) }; out = { 0x68 }; PushImm32(out, im); return out;
        }
        if (mn == "pop") { int rc = Reg32(op1L); if (rc >= 0)return{ (u8)(0x58 + rc) }; }
        if (mn == "mov") { int dr = Reg32(op1L), sr = Reg32(op2L); if (dr >= 0 && sr >= 0)return{ 0x8B,(u8)(0xC0 | (dr << 3) | sr) }; if (dr >= 0 && !op2.empty()) { u64 im = ResolveOp(op2); out = { (u8)(0xB8 + dr) }; PushImm32(out, im); return out; } }
        if (mn == "cmp") { int r1 = Reg32(op1L), r2 = Reg32(op2L); if (r1 >= 0 && r2 >= 0)return{ 0x3B,(u8)(0xC0 | (r1 << 3) | r2) }; if (r1 >= 0 && !op2.empty()) { u64 im = ParseImm(op2); if ((i64)im >= -128 && (i64)im <= 127)return{ 0x83,(u8)(0xF8 | r1),(u8)(im & 0xFF) }; } }
        if (mn == "test") { int r1 = Reg32(op1L), r2 = Reg32(op2L); if (r1 >= 0 && r2 >= 0)return{ 0x85,(u8)(0xC0 | (r2 << 3) | r1) }; }
        if (mn == "xor") { int r1 = Reg32(op1L), r2 = Reg32(op2L); if (r1 >= 0 && r2 >= 0)return{ 0x31,(u8)(0xC0 | (r2 << 3) | r1) }; }
        if (mn == "and") { int r1 = Reg32(op1L); if (r1 == 0 && !op2.empty()) { u64 im = ParseImm(op2); out = { 0x25 }; PushImm32(out, im); return out; } }
        if (mn == "or" && op1L == "al" && !op2.empty()) { u64 im = ParseImm(op2); return{ 0x0C,(u8)(im & 0xFF) }; }
        if (mn == "sub" && (op1L == "esp" || op1L == "rsp")) { u64 im = ParseImm(op2); if (im <= 127)return is64 ? std::vector<u8>{0x48, 0x83, 0xEC, (u8)im} : std::vector<u8>{ 0x83,0xEC,(u8)im }; }
        if (mn == "add" && (op1L == "esp" || op1L == "rsp")) { u64 im = ParseImm(op2); if (im <= 127)return is64 ? std::vector<u8>{0x48, 0x83, 0xC4, (u8)im} : std::vector<u8>{ 0x83,0xC4,(u8)im }; }
        if (mn == "call")return AsmCall(op1, addr);
        if (mn == "jmp")return AsmJmp(op1, addr);
        if (IsCondJmp(mn))return AsmCondJmp(mn, op1, addr);
        return out;
    }
    std::vector<u8>ParseBytes(const std::string& t) { std::vector<u8>o; std::string s = t; LTrim(s); size_t p = 0; while (p < s.size()) { while (p < s.size() && (s[p] == ' ' || s[p] == '\t'))p++; if (p >= s.size())break; if (p + 1 < s.size() && isxdigit(s[p]) && isxdigit(s[p + 1])) { char h[3] = { s[p],s[p + 1],0 }; o.push_back((u8)strtoul(h, 0, 16)); p += 2; } else if (isxdigit(s[p])) { char h[2] = { s[p],0 }; o.push_back((u8)strtoul(h, 0, 16)); p++; } else break; }return o; }
private:
    void Trim(std::string& s) { LTrim(s); RTrim(s); }
    void LTrim(std::string& s) { while (!s.empty() && (s[0] == ' ' || s[0] == '\t'))s.erase(0, 1); }
    void RTrim(std::string& s) { while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))s.pop_back(); }
    void Lower(std::string& s) { for (auto& c : s)c = tolower(c); }
    int Reg32(const std::string& r) { if (r == "eax" || r == "rax")return 0; if (r == "ecx" || r == "rcx")return 1; if (r == "edx" || r == "rdx")return 2; if (r == "ebx" || r == "rbx")return 3; if (r == "esp" || r == "rsp")return 4; if (r == "ebp" || r == "rbp")return 5; if (r == "esi" || r == "rsi")return 6; if (r == "edi" || r == "rdi")return 7; return-1; }
    void PushImm32(std::vector<u8>& o, u64 v) { o.push_back(v & 0xFF); o.push_back((v >> 8) & 0xFF); o.push_back((v >> 16) & 0xFF); o.push_back((v >> 24) & 0xFF); }
    bool IsReg(const std::string& s) { std::string l = s; Lower(l); static const std::set<std::string>regs = { "eax","ebx","ecx","edx","esi","edi","ebp","esp","rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15","ax","bx","cx","dx","si","di","bp","sp","al","bl","cl","dl","ah","bh","ch","dh","cs","ds","es","fs","gs","ss" }; return regs.count(l) > 0; }
    u64 ParseImm(const std::string& s) { if (s.empty())return 0; std::string v = s; Trim(v); if (v.size() >= 2 && v[0] == '0' && (v[1] == 'x' || v[1] == 'X'))return strtoull(v.c_str() + 2, 0, 16); if (!v.empty() && (v.back() == 'h' || v.back() == 'H'))return strtoull(v.c_str(), 0, 16); bool hx = 0; for (char c : v)if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) { hx = 1; break; }return hx ? strtoull(v.c_str(), 0, 16) : strtoull(v.c_str(), 0, 0); }
    u64 ResolveOp(const std::string& op) { if (op.empty())return 0; std::string o = op; Trim(o); u64 im = ParseImm(o); if (im || o == "0" || o == "0x0")return im; if (symbolLookup) { u64 a = symbolLookup(o); if (a)return a; }if (iatLookup && readMemory) { u64 ia = iatLookup(o); if (ia)return readMemory(ia); }return 0; }
    std::vector<u8>AsmCall(const std::string& op, u64 addr) {
        std::vector<u8>o; if (op.empty())return o; std::string s = op; Trim(s); bool ind = 0; std::string inner = s; std::string lw = s; Lower(lw);
        if (lw.find("dword ptr") == 0 || lw.find("qword ptr") == 0) { inner = s.substr(9); LTrim(inner); }
        if (!inner.empty() && inner[0] == '[' && inner.back() == ']') { ind = 1; inner = inner.substr(1, inner.length() - 2); Trim(inner); }
        bool isSym = !inner.empty() && !isdigit(inner[0]) && !IsReg(inner);
        if (isSym) { u64 iat = iatLookup ? iatLookup(inner) : 0, dir = symbolLookup ? symbolLookup(inner) : 0; if (iat)return AsmIndCall(iat, addr); if (dir)return ind ? AsmIndCall(dir, addr) : AsmDirCall(dir, addr); return o; }
        u64 t = ParseImm(inner); if (t || inner == "0" || inner == "0x0")return ind ? AsmIndCall(t, addr) : AsmDirCall(t, addr); return o;
    }
    std::vector<u8>AsmDirCall(u64 t, u64 a) { std::vector<u8>o; i64 r = (i64)t - (i64)(a + 5); if (r >= -2147483648LL && r <= 2147483647LL) { o = { 0xE8 }; PushImm32(o, (u32)r); }return o; }
    std::vector<u8>AsmIndCall(u64 m, u64 a) { std::vector<u8>o; if (is64) { i64 r = (i64)m - (i64)(a + 6); if (r >= -2147483648LL && r <= 2147483647LL) { o = { 0xFF,0x15 }; PushImm32(o, (u32)r); } } else { o = { 0xFF,0x15 }; PushImm32(o, m); if (addRelocation)addRelocation(a + 2, 3); }return o; }
    std::vector<u8>AsmJmp(const std::string& op, u64 addr) {
        std::vector<u8>o; if (op.empty())return o; std::string s = op; Trim(s); bool ind = 0; std::string inner = s; std::string lw = s; Lower(lw);
        if (lw.find("dword ptr") == 0 || lw.find("qword ptr") == 0) { inner = s.substr(9); LTrim(inner); }
        if (!inner.empty() && inner[0] == '[' && inner.back() == ']') { ind = 1; inner = inner.substr(1, inner.length() - 2); Trim(inner); }
        if (IsReg(inner))return o; bool isSym = !inner.empty() && !isdigit(inner[0]);
        if (isSym && !ind) { u64 iat = iatLookup ? iatLookup(inner) : 0, dir = symbolLookup ? symbolLookup(inner) : 0; if (iat)return AsmIndJmp(iat, addr); if (dir)return AsmDirJmp(dir, addr); return o; }
        u64 t = ParseImm(inner); if (t || inner == "0" || inner == "0x0")return ind ? AsmIndJmp(t, addr) : AsmDirJmp(t, addr); return o;
    }
    std::vector<u8>AsmDirJmp(u64 t, u64 a) { std::vector<u8>o; i64 rs = (i64)t - (i64)(a + 2); if (rs >= -128 && rs <= 127)return{ 0xEB,(u8)(i8)rs }; i64 r = (i64)t - (i64)(a + 5); if (r >= -2147483648LL && r <= 2147483647LL) { o = { 0xE9 }; PushImm32(o, (u32)r); }return o; }
    std::vector<u8>AsmIndJmp(u64 m, u64 a) { std::vector<u8>o; if (is64) { i64 r = (i64)m - (i64)(a + 6); if (r >= -2147483648LL && r <= 2147483647LL) { o = { 0xFF,0x25 }; PushImm32(o, (u32)r); } } else { o = { 0xFF,0x25 }; PushImm32(o, m); if (addRelocation)addRelocation(a + 2, 3); }return o; }
    bool IsCondJmp(const std::string& mn) { static const std::set<std::string>cj = { "ja","jae","jb","jbe","jc","jcxz","jecxz","jrcxz","je","jg","jge","jl","jle","jna","jnae","jnb","jnbe","jnc","jne","jng","jnge","jnl","jnle","jno","jnp","jns","jnz","jo","jp","jpe","jpo","js","jz" }; return cj.count(mn) > 0; }
    u8 CondJmpOp(const std::string& mn) { static const std::map<std::string, u8>op = { {"jo",0x80},{"jno",0x81},{"jb",0x82},{"jc",0x82},{"jnae",0x82},{"jae",0x83},{"jnb",0x83},{"jnc",0x83},{"je",0x84},{"jz",0x84},{"jne",0x85},{"jnz",0x85},{"jbe",0x86},{"jna",0x86},{"ja",0x87},{"jnbe",0x87},{"js",0x88},{"jns",0x89},{"jp",0x8A},{"jpe",0x8A},{"jnp",0x8B},{"jpo",0x8B},{"jl",0x8C},{"jnge",0x8C},{"jge",0x8D},{"jnl",0x8D},{"jle",0x8E},{"jng",0x8E},{"jg",0x8F},{"jnle",0x8F} }; auto it = op.find(mn); return it != op.end() ? it->second : 0; }
    std::vector<u8>AsmCondJmp(const std::string& mn, const std::string& op, u64 addr) {
        std::vector<u8>o; if (op.empty())return o; u64 t = ResolveOp(op); if (!t && op != "0" && op != "0x0")return o;
        i64 r = (i64)t - (i64)(addr + 2); if (r >= -128 && r <= 127) { u8 so = CondJmpOp(mn); if (so >= 0x80) { o.push_back(0x70 + (so - 0x80)); o.push_back((u8)r); return o; } }
        r = (i64)t - (i64)(addr + 6); if (r >= -2147483648LL && r <= 2147483647LL) { u8 op2 = CondJmpOp(mn); if (op2) { o = { 0x0F,op2 }; PushImm32(o, (u32)r); } }return o;
    }
};

class RefEngine {
public:
    std::vector<RefInfo>refs; std::multimap<u64, size_t>toMap, fromMap; bool built = 0;
    void Build(const MemImage& mem, Disasm& dis, std::function<void(int)>prog = nullptr) {
        refs.clear(); toMap.clear(); fromMap.clear(); built = 0; if (mem.data.empty() || !dis.init)return;
        u64 a = mem.base, end = mem.base + mem.data.size(); size_t tot = mem.data.size(), done = 0; int lastPct = -1;
        while (a < end) {
            const u8* c = &mem.data[a - mem.base]; size_t rm = end - a; cs_insn* ins = 0; size_t n = cs_disasm(dis.handle, c, (std::min)(rm, (size_t)16), a, 1, &ins);
            if (n > 0) {
                cs_detail* d = ins[0].detail; if (d) {
                    RefInfo::Type ty = RefInfo::CALL; bool found = 0;
                    for (u8 g = 0; g < d->groups_count; g++) { if (d->groups[g] == CS_GRP_CALL) { ty = RefInfo::CALL; found = 1; break; }if (d->groups[g] == CS_GRP_JUMP) { ty = (strncmp(ins[0].mnemonic, "jmp", 3) == 0) ? RefInfo::JMP : RefInfo::JCC; found = 1; break; } }
                    if (!found && strcmp(ins[0].mnemonic, "push") == 0 && d->x86.op_count > 0 && d->x86.operands[0].type == X86_OP_IMM) { u64 im = d->x86.operands[0].imm; if (im >= mem.base && im < mem.base + mem.data.size()) { ty = RefInfo::PUSH; found = 1; } }
                    if (found) {
                        u64 t = 0; for (int i = 0; i < d->x86.op_count; i++)if (d->x86.operands[i].type == X86_OP_IMM) { t = d->x86.operands[i].imm; break; }
                        if (t) { size_t idx = refs.size(); refs.push_back({ a,t,ty }); toMap.insert({ t,idx }); fromMap.insert({ a,idx }); }
                    }
                }
                done += ins[0].size; a += ins[0].size; cs_free(ins, 1);
            }
            else { done++; a++; }
            if (prog && tot > 0) { int pct = (int)(done * 100 / tot); if (pct != lastPct) { lastPct = pct; prog(pct); } }
        }built = 1;
    }
    std::vector<RefInfo>FindTo(u64 a)const { std::vector<RefInfo>o; auto rg = toMap.equal_range(a); for (auto it = rg.first; it != rg.second; ++it)if (it->second < refs.size())o.push_back(refs[it->second]); return o; }
    bool HasRefsTo(u64 a)const { return toMap.find(a) != toMap.end(); }
};

class UndoSys {
public:
    std::deque<EditEntry>hist; size_t pos = 0;
    void Record(u64 a, const u8* od, const u8* nd, size_t l) { while (hist.size() > pos)hist.pop_back(); EditEntry e; e.addr = a; e.oldData.assign(od, od + l); e.newData.assign(nd, nd + l); hist.push_back(e); pos = hist.size(); if (hist.size() > 500) { hist.pop_front(); pos--; } }
    bool Undo(MemImage& m) { if (!pos)return 0; pos--; auto& e = hist[pos]; return m.WriteBytes(e.addr, e.oldData.data(), e.oldData.size()); }
    bool Redo(MemImage& m) { if (pos >= hist.size())return 0; auto& e = hist[pos]; pos++; return m.WriteBytes(e.addr, e.newData.data(), e.newData.size()); }
    void Clear() { hist.clear(); pos = 0; }
};

class SymTable {
public:
    std::unordered_map<u64, std::string>addr2name; std::unordered_map<std::string, u64>name2addr;
    void Build(const std::vector<ImpDll>& imps, u64 base) { addr2name.clear(); name2addr.clear(); for (auto& d : imps)for (auto& f : d.funcs) { std::string full = d.name + "." + f.name; addr2name[f.iatAddr] = full; name2addr[full] = f.iatAddr; name2addr[f.name] = f.iatAddr; } }
    std::string Resolve(u64 a)const { auto it = addr2name.find(a); return it != addr2name.end() ? it->second : ""; }
    u64 Lookup(const std::string& n)const { auto it = name2addr.find(n); return it != name2addr.end() ? it->second : 0; }
    std::vector<std::pair<std::string, u64>>Search(const std::string& pat)const { std::vector<std::pair<std::string, u64>>o; std::string lp = pat; for (auto& c : lp)c = tolower(c); for (auto& p : name2addr) { std::string ln = p.first; for (auto& c : ln)c = tolower(c); if (ln.find(lp) != std::string::npos)o.push_back({ p.first,p.second }); }return o; }
};

class StringStorage {
public:
    enum class StorageMode { HookSection = 0, TextSection = 1 };
    struct StringEntry { u64 addr = 0; std::string content; size_t size = 0; StorageMode mode = StorageMode::HookSection; bool valid = 0, wasExisting = 0; };
    std::vector<StringEntry>entries; StorageMode currentMode = StorageMode::HookSection;
    u64 hookSectionStart = 0, hookSectionEnd = 0, hookStringAreaStart = 0, textStringBase = 0, textSectionEnd = 0;
    u64 textStringOffset = 0; bool hookScanned = 0, textExpanded = 0, textScanned = 0;
    void Clear() { entries.clear(); hookSectionStart = hookSectionEnd = hookStringAreaStart = textStringBase = textStringOffset = textSectionEnd = 0; hookScanned = textExpanded = textScanned = 0; }
    void ScanExistingStrings(PEFile& pe, MemImage& mem) { Clear(); ScanHookSection(pe, mem); ScanTextSection(pe, mem); }
    StringEntry* FindExisting(const std::string& c) { for (auto& e : entries)if (e.valid && e.content == c && e.mode == currentMode)return&e; return 0; }
    u64 AllocateString(PEFile& pe, MemImage& mem, const std::string& c) { StringEntry* ex = FindExisting(c); if (ex)return ex->addr; size_t sz = c.length() + 1; return currentMode == StorageMode::HookSection ? AllocInHook(pe, mem, c, sz) : AllocInText(pe, mem, c, sz); }
private:
    bool IsPrintable(u8 c) { return(c >= 32 && c < 127) || c >= 128 || c == '\t' || c == '\n' || c == '\r'; }
    void ScanHookSection(PEFile& pe, MemImage& mem) {
        SecInfo* hs = 0; for (auto& s : pe.secs)if (strncmp(s.name, ".hook", 5) == 0) { hs = &s; break; }if (!hs) { hookScanned = 1; return; }
        hookSectionStart = mem.base + hs->va; hookSectionEnd = hookSectionStart + hs->vSz; hookStringAreaStart = hookSectionEnd;
        u64 sa = hookSectionEnd - 1; while (sa > hookSectionStart + 0x200) {
            if (!mem.InRange(sa))break; u8 b = mem.Read8(sa); if (b == 0 || b == 0xCC || b == 0x90) { sa--; continue; }
            u64 se = sa + 1, ss = sa; while (ss > hookSectionStart) { u8 c = mem.Read8(ss - 1); if (c == 0 || c == 0xCC || c == 0x90 || !IsPrintable(c))break; ss--; }
            size_t sl = se - ss; if (sl >= 2 && sl <= 260) {
                std::string ct; bool vs = 1; for (u64 a = ss; a < se; a++) { u8 c = mem.Read8(a); if (!IsPrintable(c)) { vs = 0; break; }ct += (char)c; }
                if (vs && ct.length() >= 2) { entries.push_back({ ss,ct,sl + 1,StorageMode::HookSection,1,1 }); if (ss < hookStringAreaStart)hookStringAreaStart = ss; }
            }
            sa = ss - 1; while (sa > hookSectionStart && mem.Read8(sa) == 0)sa--;
        }hookScanned = 1;
    }
    void ScanTextSection(PEFile& pe, MemImage& mem) {
        SecInfo* ts = 0; for (auto& s : pe.secs)if (strncmp(s.name, ".text", 5) == 0 || strncmp(s.name, ".code", 5) == 0) { ts = &s; break; }if (!ts) { textScanned = 1; return; }
        u64 tst = mem.base + ts->va, tend = tst + ts->vSz, sa = tend - 1, fne = tend;
        while (sa > tst + ts->vSz / 2) { if (!mem.InRange(sa))break; u8 b = mem.Read8(sa); if (b != 0 && b != 0xCC && b != 0x90) { fne = sa; break; }sa--; }
        textSectionEnd = fne; textStringBase = fne; textStringOffset = 0; textScanned = 1;
    }
    u64 AllocInHook(PEFile& pe, MemImage& mem, const std::string& c, size_t sz) {
        SecInfo* hs = 0; for (auto& s : pe.secs)if (strncmp(s.name, ".hook", 5) == 0) { hs = &s; break; }
        if (!hs) { if (!CreateHookSection(pe, mem))return 0; for (auto& s : pe.secs)if (strncmp(s.name, ".hook", 5) == 0) { hs = &s; break; }hookSectionStart = mem.base + hs->va; hookSectionEnd = hookSectionStart + hs->vSz; hookStringAreaStart = hookSectionEnd; }
        if (!hs)return 0; if (!hookScanned)ScanHookSection(pe, mem);
        u64 aa = hookStringAreaStart - sz, minA = hookSectionStart + 0x100; if (aa < minA)return 0; aa &= ~3ULL;
        for (size_t i = 0; i < c.length(); i++)mem.Write8(aa + i, (u8)c[i]); mem.Write8(aa + c.length(), 0);
        u32 rva = (u32)(aa - mem.base), ro = pe.RvaToRaw(rva); if (ro && ro + sz <= pe.raw.size())memcpy(pe.raw.data() + ro, c.c_str(), sz);
        entries.push_back({ aa,c,sz,StorageMode::HookSection,1,0 }); hookStringAreaStart = aa; return aa;
    }
    u64 AllocInText(PEFile& pe, MemImage& mem, const std::string& c, size_t sz) {
        if (!textScanned)ScanTextSection(pe, mem); SecInfo* ts = 0; for (auto& s : pe.secs)if (strncmp(s.name, ".text", 5) == 0 || strncmp(s.name, ".code", 5) == 0) { ts = &s; break; }if (!ts)return 0;
        if (!textExpanded) { if (!ExpandTextSection(pe, mem, ts, 0x1000)) { currentMode = StorageMode::HookSection; return AllocInHook(pe, mem, c, sz); }textExpanded = 1; }
        u64 aa = textStringBase + textStringOffset, se = mem.base + ts->va + ts->vSz; if (aa + sz > se)return 0;
        for (size_t i = 0; i < c.length(); i++)mem.Write8(aa + i, (u8)c[i]); mem.Write8(aa + c.length(), 0);
        u32 rva = (u32)(aa - mem.base), ro = pe.RvaToRaw(rva); if (ro && ro + sz <= pe.raw.size())memcpy(pe.raw.data() + ro, c.c_str(), sz);
        entries.push_back({ aa,c,sz,StorageMode::TextSection,1,0 }); textStringOffset += sz; while (textStringOffset % 4)textStringOffset++; return aa;
    }
    bool CreateHookSection(PEFile& pe, MemImage& mem) {
        if (pe.raw.empty())return 0; auto dos = (PIMAGE_DOS_HEADER)pe.raw.data(); auto nt = (PIMAGE_NT_HEADERS)(pe.raw.data() + dos->e_lfanew); auto sh = IMAGE_FIRST_SECTION(nt);
        size_t he = (u8*)(sh + nt->FileHeader.NumberOfSections + 1) - pe.raw.data(); if (he > pe.hdrSz)return 0;
        u32 sa, fa; if (pe.is64) { sa = ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.SectionAlignment; fa = ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.FileAlignment; }
        else { sa = ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.SectionAlignment; fa = ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.FileAlignment; }
        auto& ls = pe.secs.back(); u32 lve = ls.va + ((ls.vSz + sa - 1) / sa) * sa, lre = ls.raw + ls.rawSz, nva = lve, nraw = ((lre + fa - 1) / fa) * fa, sz = 0x1000, avs = ((sz + sa - 1) / sa) * sa, rsz = ((sz + fa - 1) / fa) * fa;
        IMAGE_SECTION_HEADER nh = {}; strncpy((char*)nh.Name, ".hook", 8); nh.Misc.VirtualSize = sz; nh.VirtualAddress = nva; nh.SizeOfRawData = rsz; nh.PointerToRawData = nraw; nh.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE;
        memcpy(&sh[nt->FileHeader.NumberOfSections], &nh, sizeof(nh)); nt->FileHeader.NumberOfSections++;
        u32 nis = nva + avs; if (pe.is64)((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.SizeOfImage = nis; else((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.SizeOfImage = nis;
        pe.raw.resize(nraw + rsz, 0); SecInfo si; strncpy(si.name, ".hook", 8); si.va = nva; si.vSz = sz; si.raw = nraw; si.rawSz = rsz; si.chars = nh.Characteristics; pe.secs.push_back(si); pe.numSec++; pe.imgSz = nis;
        mem.data.resize(nis, 0); if (pe.hdrSz <= mem.data.size())memcpy(mem.data.data(), pe.raw.data(), pe.hdrSz);
        hookSectionStart = mem.base + nva; hookSectionEnd = hookSectionStart + sz; hookStringAreaStart = hookSectionEnd; hookScanned = 1; return 1;
    }
    bool ExpandTextSection(PEFile& pe, MemImage& mem, SecInfo* ts, u32 extra) {
        if (!ts)return 0; u64 ce = mem.base + ts->va + ts->vSz, nss = mem.base + mem.data.size();
        for (auto& s : pe.secs)if (s.va > ts->va) { u64 ss = mem.base + s.va; if (ss < nss)nss = ss; }if (ce + extra > nss)return 0;
        auto dos = (PIMAGE_DOS_HEADER)pe.raw.data(); auto nt = (PIMAGE_NT_HEADERS)(pe.raw.data() + dos->e_lfanew); auto sh = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)if (strncmp((char*)sh[i].Name, ts->name, 8) == 0) {
            sh[i].Misc.VirtualSize += extra; sh[i].SizeOfRawData += extra; ts->vSz += extra; ts->rawSz += extra;
            size_t ip = ts->raw + ts->rawSz - extra; pe.raw.insert(pe.raw.begin() + ip, extra, 0);
            for (int j = i + 1; j < nt->FileHeader.NumberOfSections; j++)sh[j].PointerToRawData += extra; for (auto& s : pe.secs)if (s.va > ts->va)s.raw += extra; break;
        }
        textSectionEnd = ce; textStringBase = ce; textStringOffset = 0; return 1;
    }
};
static StringStorage g_stringStorage;

class Core {
public:
    PEFile pe; MemImage mem; Disasm dis; Assembler asmb; RefEngine refs; SymTable syms; UndoSys undo; std::wstring filePath; bool loaded = 0;
    static Core& I() { static Core c; return c; }
    void SetupAssemblerCallbacks() {
        asmb.symbolLookup = [this](const std::string& n)->u64 {return syms.Lookup(n); };
        asmb.iatLookup = [this](const std::string& n)->u64 {std::string ln = n; for (auto& c : ln)c = tolower(c); for (auto& d : pe.imps) { std::string dl = d.name; for (auto& c : dl)c = tolower(c); std::string dn = dl; if (dn.size() > 4 && dn.substr(dn.size() - 4) == ".dll")dn = dn.substr(0, dn.size() - 4); for (auto& f : d.funcs) { std::string fl = f.name; for (auto& c : fl)c = tolower(c); if (fl == ln || dn + "." + fl == ln || dl + "." + fl == ln)return f.iatAddr; } }return 0; };
        asmb.readMemory = [this](u64 a)->u64 {return mem.InRange(a) ? (pe.is64 ? mem.Read64(a) : mem.Read32(a)) : 0; };
        asmb.addRelocation = [this](u64 a, u16 t) {if (a >= mem.base && a < mem.base + mem.data.size())pe.AddRelocation((u32)(a - mem.base), t); };
        asmb.allocateString = [this](const std::string& c)->u64 {return g_stringStorage.AllocateString(pe, mem, c); };
    }
    bool LoadFile(const wchar_t* path) { Close(); if (!pe.Load(path) || !mem.Create(pe) || !dis.Init(pe.is64))return 0; asmb.is64 = pe.is64; syms.Build(pe.imps, pe.imgBase); SetupAssemblerCallbacks(); if (pe.dllCharacteristics & 0x40)pe.DisableASLR(); filePath = path; loaded = 1; return 1; }
    bool DisableASLR() { return loaded ? pe.DisableASLR() : 0; }
    bool IsASLREnabled()const { return loaded ? (pe.dllCharacteristics & 0x40) != 0 : 0; }
    bool Edit(u64 addr, const std::string& text) { if (!loaded || !mem.InRange(addr))return 0; if (!asmb.symbolLookup)SetupAssemblerCallbacks(); auto bytes = asmb.Asm(text, addr); if (bytes.empty())bytes = asmb.ParseBytes(text); if (bytes.empty())return 0; std::vector<u8>old(bytes.size()); mem.ReadBytes(addr, old.data(), old.size()); if (!mem.WriteBytes(addr, bytes.data(), bytes.size()))return 0; undo.Record(addr, old.data(), bytes.data(), bytes.size()); return 1; }
    bool SaveFile(const wchar_t* path) { return loaded ? pe.Save(path, mem.data.data(), mem.base, mem.data.size()) : 0; }
    void Close() { pe.Clear(); mem.data.clear(); refs.refs.clear(); refs.toMap.clear(); refs.fromMap.clear(); refs.built = 0; undo.Clear(); filePath.clear(); loaded = 0; }
    u64 EP()const { return loaded ? pe.imgBase + pe.ep : 0; }u64 Base()const { return mem.base; }u64 Size()const { return mem.data.size(); }
    std::vector<DisLine>Dis(u64 addr, int lines) { if (!loaded)return{}; u64 s = addr, e = addr + lines * 8; if (e > mem.base + mem.data.size())e = mem.base + mem.data.size(); auto r = dis.DisasmRange(mem, s, e); if (r.size() > (size_t)lines)r.resize(lines); for (auto& l : r) { if (l.target) { std::string sy = syms.Resolve(l.target); if (!sy.empty())l.sym = sy; }if (l.hasMemTarget && l.memTarget) { std::string sy = syms.Resolve(l.memTarget); if (!sy.empty())l.sym = "[" + sy + "]"; } }return r; }
    bool Undo() { return undo.Undo(mem); }bool Redo() { return undo.Redo(mem); }
    void BuildRefs(std::function<void(int)>prog = nullptr) { if (loaded)refs.Build(mem, dis, prog); }
};

class ByteInjector {
public:
    enum class SmartMode { Consuming = 0, Shift = 1 };
    struct Result { bool ok = 0; u64 addr = 0; size_t size = 0; u64 hookAddr = 0, retAddr = 0, shiftStart = 0, shiftEnd = 0; int int3sConsumed = 0, int3sRemaining = 0, refsFixed = 0; std::string err, log; };
    struct CollectedInstr { u64 origAddr = 0, newAddr = 0; std::vector<u8>bytes; int size = 0; std::string mnemonic, operands; bool isRelBranch = 0, hasMemDisp = 0, isInt3OrNop = 0; u64 branchTarget = 0, memDisp = 0; };
    struct Region { u64 start = 0, end = 0; int int3Count = 0, usableInt3s = 0, codeBytes = 0; bool isInt3Block = 0, isCodeBlock = 0; std::string description; };
    struct ShiftPlan { u64 injectAt = 0, funcStart = 0, shiftStart = 0, shiftEnd = 0; int totalCodeBytes = 0, totalInt3Bytes = 0, usableInt3Bytes = 0, int3sNeeded = 0, boundaryInt3sKept = 0; bool valid = 0; std::string invalidReason; std::vector<CollectedInstr>codeInstructions, allInstructions; std::vector<Region>regions; std::map<u64, u64>addrMap; };
    SmartMode smartMode = SmartMode::Consuming; bool keepBoundaryInt3 = 1; std::string lastLog;
    Result SmartInject(PEFile& pe, MemImage& mem, Disasm& dis, RefEngine& refs, u64 injectAt, const std::vector<u8>& code);
    Result CreateHook(PEFile& pe, MemImage& mem, Disasm& dis, Assembler& asmb, u64 hookAt, const std::string& hookCode);
    Result CreateHookAt(PEFile& pe, MemImage& mem, Disasm& dis, Assembler& asmb, u64 hookAt, const std::string& hookCode, u64 targetAddr);
    ShiftPlan CreateConsumingPlan(MemImage& mem, Disasm& dis, u64 injectAt, size_t neededBytes);
    ShiftPlan CreateShiftPlan(MemImage& mem, Disasm& dis, u64 injectAt, size_t neededBytes);
    bool AddSection(PEFile& pe, MemImage& mem, const char* name, u32 size, u32 chars);
    u64 FindFreeSpace(PEFile& pe, MemImage& mem, size_t need);
private:
    void Log(const char* fmt, ...) { char buf[1024]; va_list a; va_start(a, fmt); vsnprintf(buf, sizeof(buf), fmt, a); va_end(a); lastLog += buf; lastLog += "\n"; }
    u64 FindFunctionStart(MemImage& mem, Disasm& dis, u64 addr);
    u64 FindFunctionEnd(MemImage& mem, Disasm& dis, u64 addr);
    Region ScanRegion(MemImage& mem, Disasm& dis, u64 startAddr);
    void CollectAllInstructions(MemImage& mem, Disasm& dis, u64 start, u64 end, std::vector<CollectedInstr>& all, std::vector<CollectedInstr>& code, std::vector<Region>& regs);
    bool PatchRelative(MemImage& mem, u64 instrAddr, u64 newTarget, u8 opcode, int instrSize);
    bool PatchImmediate32(MemImage& mem, u64 instrAddr, int instrSize, u64 oldVal, u64 newVal);
    int FixCollectedInstructions(MemImage& mem, Disasm& dis, std::vector<CollectedInstr>& instrs, std::map<u64, u64>& addrMap, u64 shiftStart, u64 shiftEnd);
    int FixExternalReferences(MemImage& mem, Disasm& dis, RefEngine& refs, std::map<u64, u64>& addrMap, u64 shiftStart, u64 shiftEnd);
    int FixShiftedInstructions(MemImage& mem, Disasm& dis, u64 funcStart, u64 shiftStart, u64 shiftEnd, i64 shift);
    int FixExternalRefsShiftMode(MemImage& mem, Disasm& dis, RefEngine& refs, u64 shiftStart, u64 shiftEnd, i64 shift);
    int FixMemoryOperands(MemImage& mem, Disasm& dis, std::map<u64, u64>& addrMap);
    int FixMemoryOperandsShiftMode(MemImage& mem, Disasm& dis, RefEngine& refs, u64 shiftStart, u64 shiftEnd, i64 shift);
};

inline u64 ByteInjector::FindFunctionStart(MemImage& mem, Disasm& dis, u64 addr) { u64 s = addr; int i3c = 0; for (int i = 0; i<0x2000 && s>mem.base; i++) { u64 ca = s - 1; if (!mem.InRange(ca))break; u8 b = mem.Read8(ca); if (b == 0xCC) { i3c++; if (i3c >= 2)break; } else i3c = 0; if (i > 5 && b == 0x55 && ca > mem.base && mem.Read8(ca - 1) == 0xCC) { s = ca; break; }s = ca; }return s; }
inline u64 ByteInjector::FindFunctionEnd(MemImage& mem, Disasm& dis, u64 addr) { u64 e = addr; bool fr = 0; for (int i = 0; i < 0x4000 && e < mem.base + mem.data.size();) { if (!mem.InRange(e))break; const u8* c = &mem.data[e - mem.base]; size_t rm = mem.data.size() - (e - mem.base); cs_insn* ins = 0; size_t n = cs_disasm(dis.handle, c, std::min(rm, (size_t)16), e, 1, &ins); if (n > 0) { cs_detail* d = ins[0].detail; if (d)for (u8 g = 0; g < d->groups_count; g++)if (d->groups[g] == CS_GRP_RET) { fr = 1; break; }e += ins[0].size; i += ins[0].size; cs_free(ins, 1); if (fr && mem.InRange(e) && mem.Read8(e) == 0xCC)break; } else { e++; i++; } }return e; }

inline ByteInjector::Region ByteInjector::ScanRegion(MemImage& mem, Disasm& dis, u64 sa) {
    Region r; r.start = sa; r.end = sa; if (!mem.InRange(sa))return r; u8 fb = mem.Read8(sa);
    if (fb == 0xCC || fb == 0x90) { r.isInt3Block = 1; u64 a = sa; while (mem.InRange(a) && (mem.Read8(a) == 0xCC || mem.Read8(a) == 0x90)) { r.int3Count++; a++; }r.end = a; r.usableInt3s = keepBoundaryInt3 ? (r.int3Count > 1 ? r.int3Count - 1 : 0) : r.int3Count; char b[64]; sprintf(b, "INT3(%d/%d)", r.int3Count, r.usableInt3s); r.description = b; return r; }
    r.isCodeBlock = 1; u64 a = sa; std::string fi; while (mem.InRange(a)) { u8 b = mem.Read8(a); if (b == 0xCC || b == 0x90) { r.end = a; break; }const u8* c = &mem.data[a - mem.base]; size_t rm = mem.data.size() - (a - mem.base); cs_insn* ins = 0; size_t n = cs_disasm(dis.handle, c, std::min(rm, (size_t)16), a, 1, &ins); if (n > 0) { if (fi.empty())fi = std::string(ins[0].mnemonic) + " " + ins[0].op_str; r.codeBytes += ins[0].size; a += ins[0].size; cs_free(ins, 1); } else { r.codeBytes++; a++; }if (a - sa > 0x10000)break; }r.end = a; if (fi.length() > 40)fi = fi.substr(0, 40) + "..."; char b[128]; sprintf(b, "Code(%d):%s", r.codeBytes, fi.c_str()); r.description = b; return r;
}

inline void ByteInjector::CollectAllInstructions(MemImage& mem, Disasm& dis, u64 start, u64 end, std::vector<CollectedInstr>& all, std::vector<CollectedInstr>& code, std::vector<Region>& regs) {
    all.clear(); code.clear(); regs.clear(); u64 a = start; Region* cr = 0;
    while (a < end && mem.InRange(a)) {
        u8 b = mem.Read8(a); bool isI3 = (b == 0xCC || b == 0x90); if (regs.empty() || (cr->isInt3Block != isI3)) { Region r; r.start = a; r.isInt3Block = isI3; r.isCodeBlock = !isI3; regs.push_back(r); cr = &regs.back(); }
        CollectedInstr ci; ci.origAddr = a; if (isI3) { ci.size = 1; ci.bytes.push_back(b); ci.mnemonic = (b == 0xCC) ? "int3" : "nop"; ci.isInt3OrNop = 1; cr->int3Count++; all.push_back(ci); a++; continue; }
        const u8* c = &mem.data[a - mem.base]; size_t rm = mem.data.size() - (a - mem.base); cs_insn* ins = 0; size_t n = cs_disasm(dis.handle, c, std::min(rm, (size_t)16), a, 1, &ins);
        if (!n) { ci.size = 1; ci.bytes.push_back(b); ci.mnemonic = "db"; all.push_back(ci); code.push_back(ci); cr->codeBytes++; a++; continue; }
        ci.size = ins[0].size; ci.mnemonic = ins[0].mnemonic; ci.operands = ins[0].op_str; for (int i = 0; i < ins[0].size; i++)ci.bytes.push_back(mem.Read8(a + i));
        cs_detail* d = ins[0].detail; u8 op = ins[0].bytes[0]; if (d) {
            for (u8 g = 0; g < d->groups_count; g++) { if (d->groups[g] == CS_GRP_CALL && op == 0xE8)ci.isRelBranch = 1; if (d->groups[g] == CS_GRP_JUMP && (op == 0xE9 || op == 0xEB || (op >= 0x70 && op <= 0x7F) || op == 0x0F))ci.isRelBranch = 1; }
            for (int i = 0; i < d->x86.op_count; i++) { if (d->x86.operands[i].type == X86_OP_IMM && ci.isRelBranch)ci.branchTarget = d->x86.operands[i].imm; if (d->x86.operands[i].type == X86_OP_MEM && d->x86.operands[i].mem.base == X86_REG_INVALID && d->x86.operands[i].mem.index == X86_REG_INVALID && d->x86.operands[i].mem.disp) { ci.hasMemDisp = 1; ci.memDisp = (u64)d->x86.operands[i].mem.disp; } }
        }
        all.push_back(ci); code.push_back(ci); cr->codeBytes += ci.size; a += ins[0].size; cs_free(ins, 1);
    }
    for (size_t i = 0; i < regs.size(); i++) { regs[i].end = (i + 1 < regs.size()) ? regs[i + 1].start : end; if (regs[i].isInt3Block && keepBoundaryInt3)regs[i].usableInt3s = (regs[i].int3Count > 1) ? regs[i].int3Count - 1 : 0; else regs[i].usableInt3s = regs[i].int3Count; }
}

inline ByteInjector::ShiftPlan ByteInjector::CreateConsumingPlan(MemImage& mem, Disasm& dis, u64 injectAt, size_t nb) {
    ShiftPlan p; p.injectAt = injectAt; p.int3sNeeded = (int)nb; p.valid = 0; if (!mem.InRange(injectAt)) { p.invalidReason = "Out of range"; return p; }
    p.funcStart = FindFunctionStart(mem, dis, injectAt); p.shiftStart = injectAt; u64 sa = injectAt; const u64 MAX_SCAN = 0x100000, lim = std::min(mem.base + mem.data.size(), injectAt + MAX_SCAN);
    int tui3 = 0, tcb = 0, ti3b = 0, bi3k = 0; while (sa < lim) { Region r = ScanRegion(mem, dis, sa); if (r.end <= r.start)break; p.regions.push_back(r); if (r.isInt3Block) { ti3b += r.int3Count; tui3 += r.usableInt3s; if (keepBoundaryInt3 && r.int3Count > 0)bi3k++; } else tcb += r.codeBytes; sa = r.end; if (tui3 >= (int)nb) { p.shiftEnd = r.end; break; } }
    p.totalCodeBytes = tcb; p.totalInt3Bytes = ti3b; p.usableInt3Bytes = tui3; p.boundaryInt3sKept = bi3k;
    if (tui3 < (int)nb) { char b[256]; sprintf(b, "Not enough INT3. Need:%d Found:%d", (int)nb, tui3); p.invalidReason = b; return p; }
    int ts = tcb + ti3b, sn = (int)nb + tcb + bi3k; if (sn > ts) { char b[256]; sprintf(b, "Overflow. Space:%d Need:%d", ts, sn); p.invalidReason = b; return p; }
    CollectAllInstructions(mem, dis, p.shiftStart, p.shiftEnd, p.allInstructions, p.codeInstructions, p.regions);
    u64 wa = p.injectAt + nb; for (auto& ci : p.codeInstructions) { ci.newAddr = wa; p.addrMap[ci.origAddr] = wa; wa += ci.size; }
    if (wa + bi3k > p.shiftEnd) { char b[256]; sprintf(b, "Final overflow. End:%llX Limit:%llX", wa + bi3k, p.shiftEnd); p.invalidReason = b; return p; }
    p.valid = 1; return p;
}

inline ByteInjector::ShiftPlan ByteInjector::CreateShiftPlan(MemImage& mem, Disasm& dis, u64 injectAt, size_t nb) {
    ShiftPlan p; p.injectAt = injectAt; p.int3sNeeded = (int)nb; p.valid = 0; if (!mem.InRange(injectAt)) { p.invalidReason = "Out of range"; return p; }
    p.funcStart = FindFunctionStart(mem, dis, injectAt); u64 fe = FindFunctionEnd(mem, dis, injectAt); p.shiftStart = injectAt;
    u64 sa = fe; const u64 MAX_SCAN = 0x100000; int tui3 = 0, ti3b = 0; while (sa < mem.base + mem.data.size() && sa < fe + MAX_SCAN && tui3 < (int)nb) { Region r = ScanRegion(mem, dis, sa); if (r.end <= r.start)break; p.regions.push_back(r); if (r.isInt3Block) { ti3b += r.int3Count; tui3 += r.usableInt3s; }sa = r.end; }
    p.totalInt3Bytes = ti3b; p.usableInt3Bytes = tui3; if (tui3 < (int)nb) { char b[256]; sprintf(b, "Not enough INT3. Need:%d Found:%d", (int)nb, tui3); p.invalidReason = b; return p; }
    int rm = (int)nb; u64 ae = fe; for (auto& r : p.regions) { if (rm <= 0)break; if (r.isInt3Block) { if (r.usableInt3s <= rm) { rm -= r.usableInt3s; ae = r.end; } else { int bd = keepBoundaryInt3 ? 1 : 0; ae = r.start + rm + bd; rm = 0; } } }
    p.shiftEnd = ae; p.totalCodeBytes = (int)(fe - injectAt); p.valid = 1; return p;
}

inline bool ByteInjector::PatchRelative(MemImage& mem, u64 ia, u64 nt, u8 op, int sz) {
    if (!mem.InRange(ia))return 0;
    if ((op == 0xE8 || op == 0xE9) && sz == 5) { i64 r = (i64)nt - (i64)(ia + 5); if (r < -2147483648LL || r>2147483647LL)return 0; i32 r32 = (i32)r; mem.Write8(ia + 1, r32 & 0xFF); mem.Write8(ia + 2, (r32 >> 8) & 0xFF); mem.Write8(ia + 3, (r32 >> 16) & 0xFF); mem.Write8(ia + 4, (r32 >> 24) & 0xFF); return 1; }
    if (op == 0xEB && sz == 2) { i64 r = (i64)nt - (i64)(ia + 2); if (r >= -128 && r <= 127) { mem.Write8(ia + 1, (u8)(i8)r); return 1; }return 0; }
    if (op >= 0x70 && op <= 0x7F && sz == 2) { i64 r = (i64)nt - (i64)(ia + 2); if (r >= -128 && r <= 127) { mem.Write8(ia + 1, (u8)(i8)r); return 1; }return 0; }
    if (op == 0x0F && sz == 6) { i64 r = (i64)nt - (i64)(ia + 6); if (r < -2147483648LL || r>2147483647LL)return 0; i32 r32 = (i32)r; mem.Write8(ia + 2, r32 & 0xFF); mem.Write8(ia + 3, (r32 >> 8) & 0xFF); mem.Write8(ia + 4, (r32 >> 16) & 0xFF); mem.Write8(ia + 5, (r32 >> 24) & 0xFF); return 1; }
    return 0;
}

inline bool ByteInjector::PatchImmediate32(MemImage& mem, u64 ia, int sz, u64 ov, u64 nv) {
    if (!mem.InRange(ia))return 0; u8 ob[4] = { (u8)(ov & 0xFF),(u8)((ov >> 8) & 0xFF),(u8)((ov >> 16) & 0xFF),(u8)((ov >> 24) & 0xFF) };
    for (int i = 0; i <= sz - 4; i++) { bool m = 1; for (int j = 0; j < 4 && m; j++)if (mem.Read8(ia + i + j) != ob[j])m = 0; if (m) { mem.Write8(ia + i, nv & 0xFF); mem.Write8(ia + i + 1, (nv >> 8) & 0xFF); mem.Write8(ia + i + 2, (nv >> 16) & 0xFF); mem.Write8(ia + i + 3, (nv >> 24) & 0xFF); return 1; } }return 0;
}

inline int ByteInjector::FixCollectedInstructions(MemImage& mem, Disasm& dis, std::vector<CollectedInstr>& instrs, std::map<u64, u64>& am, u64 ss, u64 se) {
    int fx = 0; for (auto& ci : instrs) { if (ci.isInt3OrNop || !ci.isRelBranch || !ci.branchTarget)continue; u64 nia = ci.newAddr, ot = ci.branchTarget, nt = ot; auto it = am.find(ot); if (it != am.end())nt = it->second; u8 op = ci.bytes[0]; if (PatchRelative(mem, nia, nt, op, ci.size))if (nt != ot || ci.newAddr != ci.origAddr)fx++; }return fx;
}

inline int ByteInjector::FixExternalReferences(MemImage& mem, Disasm& dis, RefEngine& refs, std::map<u64, u64>& am, u64 ss, u64 se) {
    int fx = 0; for (auto& r : refs.refs) {
        if (r.src >= ss && r.src < se)continue; auto it = am.find(r.dst); if (it == am.end())continue; u64 nt = it->second; if (!mem.InRange(r.src))continue;
        const u8* c = &mem.data[r.src - mem.base]; size_t rm = mem.data.size() - (r.src - mem.base); cs_insn* ins = 0; size_t n = cs_disasm(dis.handle, c, std::min(rm, (size_t)16), r.src, 1, &ins); if (!n)continue; u8 op = ins[0].bytes[0]; int sz = ins[0].size; cs_free(ins, 1);
        bool p = 0; if (r.type == RefInfo::CALL && op == 0xE8)p = PatchRelative(mem, r.src, nt, op, sz); else if ((r.type == RefInfo::JMP || r.type == RefInfo::JCC) && (op == 0xE9 || op == 0xEB || (op >= 0x70 && op <= 0x7F) || op == 0x0F))p = PatchRelative(mem, r.src, nt, op, sz); else if (r.type == RefInfo::PUSH && op == 0x68 && sz == 5)p = PatchImmediate32(mem, r.src, sz, r.dst, nt); if (p)fx++;
    }return fx;
}

inline int ByteInjector::FixShiftedInstructions(MemImage& mem, Disasm& dis, u64 fs, u64 ss, u64 se, i64 sh) {
    int fx = 0; u64 nse = se + sh, a = ss + sh; while (a < nse) {
        if (!mem.InRange(a))break; const u8* c = &mem.data[a - mem.base]; size_t rm = mem.data.size() - (a - mem.base); cs_insn* ins = 0; size_t n = cs_disasm(dis.handle, c, std::min(rm, (size_t)16), a, 1, &ins); if (!n) { a++; continue; }
        cs_detail* d = ins[0].detail; int sz = ins[0].size; u8 op = ins[0].bytes[0]; bool isRel = 0; if (d)for (u8 g = 0; g < d->groups_count; g++) { if (d->groups[g] == CS_GRP_CALL && op == 0xE8)isRel = 1; if (d->groups[g] == CS_GRP_JUMP && (op == 0xE9 || op == 0xEB || (op >= 0x70 && op <= 0x7F) || op == 0x0F))isRel = 1; }
        if (isRel && d) {
            i32 rv = 0; if (op == 0xE8 || op == 0xE9)rv = (i32)mem.Read32(a + 1); else if (op == 0xEB || (op >= 0x70 && op <= 0x7F))rv = (i8)mem.Read8(a + 1); else if (op == 0x0F)rv = (i32)mem.Read32(a + 2);
            u64 oia = a - sh, ot; if (op == 0xE8 || op == 0xE9)ot = oia + 5 + rv; else if (op == 0xEB || (op >= 0x70 && op <= 0x7F))ot = oia + 2 + rv; else if (op == 0x0F)ot = oia + 6 + rv; else ot = 0;
            if (ot && !(ot >= ss && ot < se))if (PatchRelative(mem, a, ot, op, sz))fx++;
        }
        a += sz; cs_free(ins, 1);
    }return fx;
}

inline int ByteInjector::FixExternalRefsShiftMode(MemImage& mem, Disasm& dis, RefEngine& refs, u64 ss, u64 se, i64 sh) {
    int fx = 0; for (auto& r : refs.refs) {
        if (r.src >= ss && r.src < se)continue; if (r.dst < ss || r.dst >= se)continue; u64 nt = r.dst + sh; if (!mem.InRange(r.src))continue;
        const u8* c = &mem.data[r.src - mem.base]; size_t rm = mem.data.size() - (r.src - mem.base); cs_insn* ins = 0; size_t n = cs_disasm(dis.handle, c, std::min(rm, (size_t)16), r.src, 1, &ins); if (!n)continue; u8 op = ins[0].bytes[0]; int sz = ins[0].size; cs_free(ins, 1);
        bool p = 0; if (r.type == RefInfo::CALL && op == 0xE8)p = PatchRelative(mem, r.src, nt, op, sz); else if ((r.type == RefInfo::JMP || r.type == RefInfo::JCC) && (op == 0xE9 || op == 0xEB || (op >= 0x70 && op <= 0x7F) || op == 0x0F))p = PatchRelative(mem, r.src, nt, op, sz); else if (r.type == RefInfo::PUSH && op == 0x68 && sz == 5)p = PatchImmediate32(mem, r.src, sz, r.dst, nt); if (p)fx++;
    }return fx;
}

inline int ByteInjector::FixMemoryOperands(MemImage& mem, Disasm& dis, std::map<u64, u64>& am) {
    int fx = 0; u64 a = mem.base; while (a < mem.base + mem.data.size()) {
        if (!mem.InRange(a)) { a++; continue; }const u8* c = &mem.data[a - mem.base]; size_t rm = mem.data.size() - (a - mem.base); cs_insn* ins = 0; size_t n = cs_disasm(dis.handle, c, std::min(rm, (size_t)16), a, 1, &ins); if (!n) { a++; continue; }
        cs_detail* d = ins[0].detail; int sz = ins[0].size; if (d)for (int i = 0; i < d->x86.op_count; i++) { auto& o = d->x86.operands[i]; if (o.type == X86_OP_MEM && o.mem.base == X86_REG_INVALID && o.mem.index == X86_REG_INVALID && o.mem.disp) { u64 dp = (u64)o.mem.disp; auto it = am.find(dp); if (it != am.end())if (PatchImmediate32(mem, a, sz, dp, it->second))fx++; } }
        a += sz; cs_free(ins, 1);
    }return fx;
}

inline int ByteInjector::FixMemoryOperandsShiftMode(MemImage& mem, Disasm& dis, RefEngine& refs, u64 ss, u64 se, i64 sh) {
    int fx = 0; u64 a = mem.base, ea = mem.base + mem.data.size(); while (a < ea) {
        if (!mem.InRange(a)) { a++; continue; }const u8* c = &mem.data[a - mem.base]; size_t rm = mem.data.size() - (a - mem.base); cs_insn* ins = 0; size_t n = cs_disasm(dis.handle, c, std::min(rm, (size_t)16), a, 1, &ins); if (!n) { a++; continue; }
        cs_detail* d = ins[0].detail; int sz = ins[0].size; if (d)for (int i = 0; i < d->x86.op_count; i++) { auto& o = d->x86.operands[i]; if (o.type == X86_OP_MEM && o.mem.base == X86_REG_INVALID && o.mem.index == X86_REG_INVALID && o.mem.disp) { u64 dp = (u64)o.mem.disp; if (dp >= ss && dp < se)if (PatchImmediate32(mem, a, sz, dp, dp + sh))fx++; } }
        a += sz; cs_free(ins, 1);
    }return fx;
}

inline ByteInjector::Result ByteInjector::SmartInject(PEFile& pe, MemImage& mem, Disasm& dis, RefEngine& refs, u64 injectAt, const std::vector<u8>& code) {
    Result r; lastLog.clear(); if (code.empty()) { r.err = "Empty code"; return r; }if (!mem.InRange(injectAt)) { r.err = "Out of range"; return r; }
    size_t isz = code.size(); Log("[SmartInject] Addr:%llX Size:%zu Mode:%s", injectAt, isz, smartMode == SmartMode::Consuming ? "Consuming" : "Shift");
    refs.refs.clear(); refs.toMap.clear(); refs.fromMap.clear(); refs.built = 0; refs.Build(mem, dis, nullptr); Log("[Refs] %zu", refs.refs.size());
    if (smartMode == SmartMode::Consuming) {
        ShiftPlan p = CreateConsumingPlan(mem, dis, injectAt, isz); Log("[Plan] Range:%llX-%llX Code:%d INT3:%d/%d", p.shiftStart, p.shiftEnd, p.totalCodeBytes, p.usableInt3Bytes, p.totalInt3Bytes);
        if (!p.valid) { r.err = p.invalidReason; r.log = lastLog; return r; }
        for (size_t i = 0; i < isz; i++)mem.Write8(injectAt + i, code[i]); for (auto& ci : p.codeInstructions)for (size_t i = 0; i < ci.bytes.size(); i++)mem.Write8(ci.newAddr + i, ci.bytes[i]);
        u64 ce = p.codeInstructions.empty() ? injectAt + isz : p.codeInstructions.back().newAddr + p.codeInstructions.back().size; int i3f = 0; for (u64 fa = ce; fa < p.shiftEnd; fa++) { mem.Write8(fa, 0xCC); i3f++; }
        int ifx = FixCollectedInstructions(mem, dis, p.codeInstructions, p.addrMap, p.shiftStart, p.shiftEnd); int efx = FixExternalReferences(mem, dis, refs, p.addrMap, p.shiftStart, p.shiftEnd); int mfx = FixMemoryOperands(mem, dis, p.addrMap);
        r.int3sConsumed = p.usableInt3Bytes; r.int3sRemaining = i3f; r.refsFixed = ifx + efx + mfx; r.shiftStart = p.shiftStart; r.shiftEnd = p.shiftEnd;
    }
    else {
        ShiftPlan p = CreateShiftPlan(mem, dis, injectAt, isz); if (!p.valid) { r.err = p.invalidReason; r.log = lastLog; return r; }
        size_t ssz = p.shiftEnd - p.shiftStart; std::vector<u8>ex(ssz); for (size_t i = 0; i < ssz; i++)ex[i] = mem.Read8(p.shiftStart + i);
        for (size_t i = 0; i < isz; i++)mem.Write8(injectAt + i, code[i]); for (size_t i = 0; i < ssz; i++)mem.Write8(injectAt + isz + i, ex[i]);
        int ifx = FixShiftedInstructions(mem, dis, p.funcStart, p.shiftStart, p.shiftEnd, (i64)isz); int efx = FixExternalRefsShiftMode(mem, dis, refs, p.shiftStart, p.shiftEnd, (i64)isz); int mfx = FixMemoryOperandsShiftMode(mem, dis, refs, p.shiftStart, p.shiftEnd, (i64)isz);
        r.int3sConsumed = (int)isz; r.int3sRemaining = p.usableInt3Bytes - (int)isz; r.refsFixed = ifx + efx + mfx; r.shiftStart = p.shiftStart; r.shiftEnd = p.shiftEnd + isz;
    }
    refs.refs.clear(); refs.toMap.clear(); refs.fromMap.clear(); refs.built = 0; Log("[Done] Injected:%zu Refs:%d", isz, r.refsFixed); r.ok = 1; r.addr = injectAt; r.size = isz; r.log = lastLog; return r;
}

inline bool ByteInjector::AddSection(PEFile& pe, MemImage& mem, const char* name, u32 size, u32 chars) {
    if (pe.raw.empty())return 0; auto dos = (PIMAGE_DOS_HEADER)pe.raw.data(); auto nt = (PIMAGE_NT_HEADERS)(pe.raw.data() + dos->e_lfanew); auto sh = IMAGE_FIRST_SECTION(nt);
    size_t he = (u8*)(sh + nt->FileHeader.NumberOfSections + 1) - pe.raw.data(); if (he > pe.hdrSz)return 0;
    u32 sa, fa; if (pe.is64) { sa = ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.SectionAlignment; fa = ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.FileAlignment; }
    else { sa = ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.SectionAlignment; fa = ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.FileAlignment; }
    auto& ls = pe.secs.back(); u32 lve = ls.va + ((ls.vSz + sa - 1) / sa) * sa, lre = ls.raw + ls.rawSz, nva = lve, nraw = ((lre + fa - 1) / fa) * fa, avs = ((size + sa - 1) / sa) * sa, rsz = ((size + fa - 1) / fa) * fa;
    IMAGE_SECTION_HEADER nh = {}; strncpy((char*)nh.Name, name, 8); nh.Misc.VirtualSize = size; nh.VirtualAddress = nva; nh.SizeOfRawData = rsz; nh.PointerToRawData = nraw; nh.Characteristics = chars;
    memcpy(&sh[nt->FileHeader.NumberOfSections], &nh, sizeof(nh)); nt->FileHeader.NumberOfSections++;
    u32 nis = nva + avs; if (pe.is64)((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.SizeOfImage = nis; else((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.SizeOfImage = nis;
    pe.raw.resize(nraw + rsz, 0); SecInfo si; strncpy(si.name, name, 8); si.va = nva; si.vSz = size; si.raw = nraw; si.rawSz = rsz; si.chars = chars; pe.secs.push_back(si); pe.numSec++; pe.imgSz = nis;
    mem.data.resize(nis, 0); if (pe.hdrSz <= mem.data.size())memcpy(mem.data.data(), pe.raw.data(), pe.hdrSz); return 1;
}

inline u64 ByteInjector::FindFreeSpace(PEFile& pe, MemImage& mem, size_t need) {
    for (auto& s : pe.secs)if (strncmp(s.name, ".hook", 5) == 0) { u64 ss = mem.base + s.va, se = ss + s.vSz; for (u64 a = ss; a < se - need; a++) { bool f = 1; for (size_t i = 0; i < need && f; i++) { u8 b = mem.Read8(a + i); if (b && b != 0xCC)f = 0; }if (f)return a; } }
    if (AddSection(pe, mem, ".hook", 0x1000, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE))return mem.base + pe.secs.back().va; return 0;
}

inline ByteInjector::Result ByteInjector::CreateHook(PEFile& pe, MemImage& mem, Disasm& dis, Assembler& asmb, u64 hookAt, const std::string& hookCode) {
    Result r; lastLog.clear(); Log("[Hook] At:%llX", hookAt); if (!mem.InRange(hookAt)) { r.err = "Out of range"; r.log = lastLog; return r; }
    const int JMPSZ = 5; struct OI { u64 addr = 0; std::vector<u8>bytes; int size = 0; std::string mn, op; bool isRelBranch = 0, isCall = 0, isJmp = 0, isCondJmp = 0, isRet = 0; u8 opcode = 0; u64 branchTarget = 0; };
    std::vector<OI>ois; size_t osz = 0; u64 a = hookAt;
    while (osz < JMPSZ && mem.InRange(a)) {
        const u8* c = &mem.data[a - mem.base]; size_t rm = mem.data.size() - (a - mem.base); cs_insn* ins = 0; size_t n = cs_disasm(dis.handle, c, std::min(rm, (size_t)16), a, 1, &ins); if (!n) { r.err = "Disasm fail"; r.log = lastLog; return r; }
        OI oi; oi.addr = a; oi.size = ins[0].size; oi.mn = ins[0].mnemonic; oi.op = ins[0].op_str; oi.opcode = ins[0].bytes[0]; for (int i = 0; i < ins[0].size; i++)oi.bytes.push_back(mem.Read8(a + i));
        cs_detail* d = ins[0].detail; if (d) {
            for (u8 g = 0; g < d->groups_count; g++) { if (d->groups[g] == CS_GRP_CALL) { oi.isCall = 1; if (oi.opcode == 0xE8)oi.isRelBranch = 1; }if (d->groups[g] == CS_GRP_JUMP) { oi.isJmp = strncmp(ins[0].mnemonic, "jmp", 3) == 0; oi.isCondJmp = !oi.isJmp; if (oi.opcode == 0xE9 || oi.opcode == 0xEB || (oi.opcode >= 0x70 && oi.opcode <= 0x7F) || oi.opcode == 0x0F)oi.isRelBranch = 1; }if (d->groups[g] == CS_GRP_RET)oi.isRet = 1; }
            for (int i = 0; i < d->x86.op_count; i++)if (d->x86.operands[i].type == X86_OP_IMM) { oi.branchTarget = d->x86.operands[i].imm; break; }
        }
        ois.push_back(oi); osz += ins[0].size; a += ins[0].size; cs_free(ins, 1);
    }
    u64 retAddr = hookAt + osz; bool needRet = 1; u64 finalJt = 0; if (!ois.empty()) { auto& l = ois.back(); if (l.isJmp && !l.isCondJmp && l.branchTarget) { needRet = 0; finalJt = l.branchTarget; }if (l.isRet)needRet = 0; }
    u64 hs = FindFreeSpace(pe, mem, 256); if (!hs) { r.err = "No hook space"; r.log = lastLog; return r; }Log("[HookSpace] %llX", hs);
    std::vector<u8>hb; u64 ca = hs; std::istringstream iss(hookCode); std::string line;
    while (std::getline(iss, line)) { while (!line.empty() && (line[0] == ' ' || line[0] == '\t'))line.erase(0, 1); while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r'))line.pop_back(); if (line.empty())continue; auto lb = asmb.Asm(line, ca); if (lb.empty()) { r.err = "Asm fail: " + line; r.log = lastLog; return r; }hb.insert(hb.end(), lb.begin(), lb.end()); ca += lb.size(); }
    for (size_t i = 0; i < ois.size(); i++) {
        auto& oi = ois[i]; u64 nia = ca; bool isLUJ = (i == ois.size() - 1) && oi.isJmp && !oi.isCondJmp;
        if (oi.isRelBranch && oi.branchTarget) {
            u64 ot = oi.branchTarget;
            if (isLUJ || oi.isCall || (oi.isJmp && oi.opcode == 0xE9)) { i64 rl = (i64)ot - (i64)(nia + 5); if (rl < -2147483648LL || rl>2147483647LL) { r.err = "Target too far"; r.log = lastLog; return r; }hb.push_back(isLUJ || oi.opcode == 0xE9 ? 0xE9 : 0xE8); hb.push_back(rl & 0xFF); hb.push_back((rl >> 8) & 0xFF); hb.push_back((rl >> 16) & 0xFF); hb.push_back((rl >> 24) & 0xFF); ca += 5; }
            else if (oi.opcode == 0xEB) { i64 rl = (i64)ot - (i64)(nia + 5); if (rl < -2147483648LL || rl>2147483647LL) { r.err = "Target too far"; r.log = lastLog; return r; }hb.push_back(0xE9); hb.push_back(rl & 0xFF); hb.push_back((rl >> 8) & 0xFF); hb.push_back((rl >> 16) & 0xFF); hb.push_back((rl >> 24) & 0xFF); ca += 5; }
            else if (oi.isCondJmp) { i64 rl = (i64)ot - (i64)(nia + 6); if (rl < -2147483648LL || rl>2147483647LL) { r.err = "Target too far"; r.log = lastLog; return r; }u8 cc; if (oi.opcode >= 0x70 && oi.opcode <= 0x7F)cc = oi.opcode - 0x70 + 0x80; else if (oi.opcode == 0x0F && oi.bytes.size() >= 2)cc = oi.bytes[1]; else { hb.insert(hb.end(), oi.bytes.begin(), oi.bytes.end()); ca += oi.size; continue; }hb.push_back(0x0F); hb.push_back(cc); hb.push_back(rl & 0xFF); hb.push_back((rl >> 8) & 0xFF); hb.push_back((rl >> 16) & 0xFF); hb.push_back((rl >> 24) & 0xFF); ca += 6; }
            else { hb.insert(hb.end(), oi.bytes.begin(), oi.bytes.end()); ca += oi.size; }
        }
        else { hb.insert(hb.end(), oi.bytes.begin(), oi.bytes.end()); ca += oi.size; }
    }
    if (needRet) { i64 jr = (i64)retAddr - (i64)(ca + 5); if (jr < -2147483648LL || jr>2147483647LL) { r.err = "Ret too far"; r.log = lastLog; return r; }hb.push_back(0xE9); hb.push_back(jr & 0xFF); hb.push_back((jr >> 8) & 0xFF); hb.push_back((jr >> 16) & 0xFF); hb.push_back((jr >> 24) & 0xFF); ca += 5; }
    for (size_t i = 0; i < hb.size(); i++)mem.Write8(hs + i, hb[i]); for (auto& s : pe.secs)if (strncmp(s.name, ".hook", 5) == 0) { u64 sv = mem.base + s.va; if (hs >= sv && hs < sv + s.vSz) { u32 o = (u32)(hs - sv), ro = s.raw + o; if (ro + hb.size() <= pe.raw.size())memcpy(pe.raw.data() + ro, hb.data(), hb.size()); }break; }
    i64 hjr = (i64)hs - (i64)(hookAt + 5); if (hjr < -2147483648LL || hjr>2147483647LL) { r.err = "Hook jmp too far"; r.log = lastLog; return r; }
    mem.Write8(hookAt, 0xE9); mem.Write8(hookAt + 1, hjr & 0xFF); mem.Write8(hookAt + 2, (hjr >> 8) & 0xFF); mem.Write8(hookAt + 3, (hjr >> 16) & 0xFF); mem.Write8(hookAt + 4, (hjr >> 24) & 0xFF); for (size_t i = 5; i < osz; i++)mem.Write8(hookAt + i, 0x90);
    Log("[Done] Hook:%llX Code:%llX(%zu)", hookAt, hs, hb.size()); r.ok = 1; r.addr = hookAt; r.size = hb.size(); r.hookAddr = hs; r.retAddr = needRet ? retAddr : finalJt; r.log = lastLog; return r;
}

inline ByteInjector::Result ByteInjector::CreateHookAt(PEFile& pe, MemImage& mem, Disasm& dis, Assembler& asmb, u64 hookAt, const std::string& hookCode, u64 targetAddr) {
    Result r; lastLog.clear(); Log("[HookAt] Hook:%llX Target:%llX", hookAt, targetAddr); if (!mem.InRange(hookAt) || !mem.InRange(targetAddr)) { r.err = "Out of range"; r.log = lastLog; return r; }
    const int JMPSZ = 5; struct OI { u64 addr = 0; std::vector<u8>bytes; int size = 0; std::string mn, op; bool isRelBranch = 0, isCall = 0, isJmp = 0, isCondJmp = 0, isRet = 0; u8 opcode = 0; u64 branchTarget = 0; };
    std::vector<OI>ois; size_t osz = 0; u64 a = hookAt;
    while (osz < JMPSZ && mem.InRange(a)) {
        const u8* c = &mem.data[a - mem.base]; size_t rm = mem.data.size() - (a - mem.base); cs_insn* ins = 0; size_t n = cs_disasm(dis.handle, c, std::min(rm, (size_t)16), a, 1, &ins); if (!n) { r.err = "Disasm fail"; r.log = lastLog; return r; }
        OI oi; oi.addr = a; oi.size = ins[0].size; oi.mn = ins[0].mnemonic; oi.op = ins[0].op_str; oi.opcode = ins[0].bytes[0]; for (int i = 0; i < ins[0].size; i++)oi.bytes.push_back(mem.Read8(a + i));
        cs_detail* d = ins[0].detail; if (d) {
            for (u8 g = 0; g < d->groups_count; g++) { if (d->groups[g] == CS_GRP_CALL) { oi.isCall = 1; if (oi.opcode == 0xE8)oi.isRelBranch = 1; }if (d->groups[g] == CS_GRP_JUMP) { oi.isJmp = strncmp(ins[0].mnemonic, "jmp", 3) == 0; oi.isCondJmp = !oi.isJmp; if (oi.opcode == 0xE9 || oi.opcode == 0xEB || (oi.opcode >= 0x70 && oi.opcode <= 0x7F) || oi.opcode == 0x0F)oi.isRelBranch = 1; }if (d->groups[g] == CS_GRP_RET)oi.isRet = 1; }
            for (int i = 0; i < d->x86.op_count; i++)if (d->x86.operands[i].type == X86_OP_IMM) { oi.branchTarget = d->x86.operands[i].imm; break; }
        }
        ois.push_back(oi); osz += ins[0].size; a += ins[0].size; cs_free(ins, 1);
    }
    u64 retAddr = hookAt + osz; bool needRet = 1; u64 finalJt = 0; if (!ois.empty()) { auto& l = ois.back(); if (l.isJmp && !l.isCondJmp && l.branchTarget) { needRet = 0; finalJt = l.branchTarget; }if (l.isRet)needRet = 0; }
    u64 hs = targetAddr; std::vector<u8>hb; u64 ca = hs; std::istringstream iss(hookCode); std::string line;
    while (std::getline(iss, line)) { while (!line.empty() && (line[0] == ' ' || line[0] == '\t'))line.erase(0, 1); while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r'))line.pop_back(); if (line.empty())continue; auto lb = asmb.Asm(line, ca); if (lb.empty()) { r.err = "Asm fail: " + line; r.log = lastLog; return r; }hb.insert(hb.end(), lb.begin(), lb.end()); ca += lb.size(); }
    for (size_t i = 0; i < ois.size(); i++) {
        auto& oi = ois[i]; u64 nia = ca; bool isLUJ = (i == ois.size() - 1) && oi.isJmp && !oi.isCondJmp;
        if (oi.isRelBranch && oi.branchTarget) {
            u64 ot = oi.branchTarget;
            if (isLUJ || oi.isCall || (oi.isJmp && oi.opcode == 0xE9)) { i64 rl = (i64)ot - (i64)(nia + 5); if (rl < -2147483648LL || rl>2147483647LL) { r.err = "Target too far"; r.log = lastLog; return r; }hb.push_back(isLUJ || oi.opcode == 0xE9 ? 0xE9 : 0xE8); hb.push_back(rl & 0xFF); hb.push_back((rl >> 8) & 0xFF); hb.push_back((rl >> 16) & 0xFF); hb.push_back((rl >> 24) & 0xFF); ca += 5; }
            else if (oi.opcode == 0xEB) { i64 rl = (i64)ot - (i64)(nia + 5); if (rl < -2147483648LL || rl>2147483647LL) { r.err = "Target too far"; r.log = lastLog; return r; }hb.push_back(0xE9); hb.push_back(rl & 0xFF); hb.push_back((rl >> 8) & 0xFF); hb.push_back((rl >> 16) & 0xFF); hb.push_back((rl >> 24) & 0xFF); ca += 5; }
            else if (oi.isCondJmp) { i64 rl = (i64)ot - (i64)(nia + 6); if (rl < -2147483648LL || rl>2147483647LL) { r.err = "Target too far"; r.log = lastLog; return r; }u8 cc; if (oi.opcode >= 0x70 && oi.opcode <= 0x7F)cc = oi.opcode - 0x70 + 0x80; else if (oi.opcode == 0x0F && oi.bytes.size() >= 2)cc = oi.bytes[1]; else { hb.insert(hb.end(), oi.bytes.begin(), oi.bytes.end()); ca += oi.size; continue; }hb.push_back(0x0F); hb.push_back(cc); hb.push_back(rl & 0xFF); hb.push_back((rl >> 8) & 0xFF); hb.push_back((rl >> 16) & 0xFF); hb.push_back((rl >> 24) & 0xFF); ca += 6; }
            else { hb.insert(hb.end(), oi.bytes.begin(), oi.bytes.end()); ca += oi.size; }
        }
        else { hb.insert(hb.end(), oi.bytes.begin(), oi.bytes.end()); ca += oi.size; }
    }
    if (needRet) { i64 jr = (i64)retAddr - (i64)(ca + 5); if (jr < -2147483648LL || jr>2147483647LL) { r.err = "Ret too far"; r.log = lastLog; return r; }hb.push_back(0xE9); hb.push_back(jr & 0xFF); hb.push_back((jr >> 8) & 0xFF); hb.push_back((jr >> 16) & 0xFF); hb.push_back((jr >> 24) & 0xFF); ca += 5; }
    for (size_t i = 0; i < hb.size(); i++)mem.Write8(hs + i, hb[i]); for (auto& s : pe.secs) { u64 sv = mem.base + s.va; if (hs >= sv && hs < sv + s.vSz) { u32 o = (u32)(hs - sv), ro = s.raw + o; if (ro + hb.size() <= pe.raw.size())memcpy(pe.raw.data() + ro, hb.data(), hb.size()); break; } }
    i64 hjr = (i64)hs - (i64)(hookAt + 5); if (hjr < -2147483648LL || hjr>2147483647LL) { r.err = "Hook jmp too far"; r.log = lastLog; return r; }
    mem.Write8(hookAt, 0xE9); mem.Write8(hookAt + 1, hjr & 0xFF); mem.Write8(hookAt + 2, (hjr >> 8) & 0xFF); mem.Write8(hookAt + 3, (hjr >> 16) & 0xFF); mem.Write8(hookAt + 4, (hjr >> 24) & 0xFF); for (size_t i = 5; i < osz; i++)mem.Write8(hookAt + i, 0x90);
    Log("[Done] Hook:%llX Code:%llX(%zu)", hookAt, hs, hb.size()); r.ok = 1; r.addr = hookAt; r.size = hb.size(); r.hookAddr = hs; r.retAddr = needRet ? retAddr : finalJt; r.log = lastLog; return r;
}