// ============================================================================
//  Motor_V4.3_IP.h - MazeProtector IN-PLACE motoru (V4M1-IP / V4M2-IP)
//  ----------------------------------------------------------------------------
//  MODEL: HICBIR KOMUT TASINMAZ.
//    - Fonksiyon govdesi .text'te YERINDE sifreli bekler
//    - Cagri: E9 trambolin -> handler govdeyi YERINDE cozer (orijinal adres,
//      orijinal baytlar) -> proxy (giris komutlari) -> govde calisir
//    - Donus (ret-stub): govde YERINDE yeniden sifrelenir
//      M1 (TekTek-IP)   : sabit anahtar
//      M2 (Stream-IP)   : her cagrida YENI rastgele anahtar
//    - Giris komutlari proxy'de; rip-rel/rel8/rel32 disp build-time duzeltme
//    - ABI-TAM: return-slot YERINDE degistirilir (side[] havuzu ile) -> arguman
//      bolgesi HIC kaymaz; callee-saved regs (x86: ebx/esi) geri verilir
//    - RELOC-GUVENLI: loader sifreli govdeye += delta uygularsa ilk decrypt'te
//      -delta ile geri alinir (relocApplied bayragi)
//    - recursion/multi-thread: depth + spinlock + LIFO side havuzu
//    - tail-jmp/longjmp/exit: state bayragi -> guvenli bozulma (cokme YOK)
//    - IAT degisikligi YOK, VirtualAlloc YOK, TLS/EP hook YOK, reloc EKLEME YOK
//  ============================================================================

#pragma once
#include <capstone/capstone.h>

namespace MazeIP {

struct Options {
    u32  fnRva  = 0;
    u32  fnSize = 0;
    int  method = 1;      // 1 = TekTek-IP, 2 = Stream-IP (donen anahtar)
    u32  seed   = 0;      // 0 = rastgele
};

struct Report {
    bool   ok = false;
    std::string err;
    std::vector<std::string> warnings;
    u32 fnRva = 0, fnSize = 0, headLen = 0, bodyLen = 0;
    u32 cbRva = 0, proxyRva = 0, handlerRva = 0, retsRva = 0;
    u32 mazeRva = 0, blobRva = 0, blobSize = 0;
    u32 seed = 0; int method = 1;
    int headInsns = 0, proxyExpands = 0, proxyRipFix = 0, proxyRelFix = 0;
    u32 bodyCrc = 0, relocCount = 0;
};

// ---- anahtar akisi: xorshift32, bayt = (st>>16)&0xFF ----------------------
inline u32 KsNext(u32& st) {
    st ^= st << 13; st ^= st >> 17; st ^= st << 5;
    return (st >> 16) & 0xFFu;
}
inline u32 Crc32(const u8* p, size_t n) {
    u32 c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1)));
    }
    return ~c;
}
inline u32 Rnd32() {
    static u32 s = 0;
    if (!s) { s = (u32)(uintptr_t)&s ^ (u32)time(nullptr) ^ 0x9E3779B9u; if (!s) s = 1; }
    s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s;
}

// ---- mini assembler --------------------------------------------------------
struct Asm {
    std::vector<u8> b;
    std::map<std::string, u32> lab;
    struct Fix { u32 pos; std::string to; int kind; };   // 1=rel8, 4=rel32, 0=absRVA
    std::vector<Fix> fixes;
    void hx(const char* s) {
        u8 v = 0; bool hi = false;
        for (const char* p = s; ; p++) {
            char c = *p;
            if (c == ' ' || c == 0) { if (hi) { b.push_back(v); v = 0; hi = false; } if (!c) break; continue; }
            u8 d = (c >= '0' && c <= '9') ? u8(c - '0') : u8((c | 0x20) - 'a' + 10);
            if (!hi) { v = u8(d << 4); hi = true; } else { v |= d; b.push_back(v); v = 0; hi = false; }
        }
    }
    void imm32(u32 v) { b.push_back(u8(v)); b.push_back(u8(v >> 8)); b.push_back(u8(v >> 16)); b.push_back(u8(v >> 24)); }
    void zeros(u32 n) { b.insert(b.end(), n, 0); }
    void rawBytes(const std::vector<u8>& v) { b.insert(b.end(), v.begin(), v.end()); }
    void L(const char* n) { lab[n] = (u32)b.size(); }
    void call(const char* t) { hx("E8"); fixes.push_back({ (u32)b.size(), t, 4 }); imm32(0); }
    void rel32(const char* t, const char* pre) { hx(pre); fixes.push_back({ (u32)b.size(), t, 4 }); imm32(0); }
    void j8(u8 opc, const char* t) { b.push_back(opc); fixes.push_back({ (u32)b.size(), t, 1 }); b.push_back(0); }
    void j32(u8 opc0f, const char* t) { hx("0F"); b.push_back(opc0f); fixes.push_back({ (u32)b.size(), t, 4 }); imm32(0); }
    void picBase64(u32 rvaBase) { hx("E8 00 00 00 00"); u32 p = (u32)b.size(); hx("58"); hx("48 2D"); imm32(rvaBase + p); }
    void picBase32(u32 rvaBase) { hx("E8 00 00 00 00"); u32 p = (u32)b.size(); hx("58"); hx("2D");     imm32(rvaBase + p); }
    bool Finish(std::string& err) {
        for (auto& f : fixes) {
            if (f.kind == 0) continue;
            auto it = lab.find(f.to);
            if (it == lab.end()) { err = std::string("etiket yok: ") + f.to; return false; }
            i64 disp = (i64)it->second - (i64)(f.pos + f.kind);
            if (f.kind == 1) {
                if (disp < -128 || disp > 127) { err = "rel8 tasma: " + f.to; return false; }
                b[f.pos] = (u8)(i8)disp;
            } else {
                if (disp < -(1LL << 31) || disp > (1LL << 31) - 1) { err = "rel32 tasma: " + f.to; return false; }
                i32 v = (i32)disp; memcpy(&b[f.pos], &v, 4);
            }
        }
        return true;
    }
};

// ---- giris komutlarini ayir ------------------------------------------------
struct HeadInsn {
    u32 rva = 0; u8 size = 0; u8 raw[16] = {};
    bool isRip = false; i32 ripDisp = 0; u32 ripOff = 0;
    bool isRel = false; i32 relDisp = 0; u32 relOff = 0; int relKind = 0;
    std::string mn;
};

static bool SplitHead(Core& c, u32 fnRva, u32 maxLen, std::vector<HeadInsn>& out,
                      u32& headLen, std::string& err) {
    auto& mem = c.mem;
    u64 a = mem.base + fnRva; u32 acc = 0;
    while (acc < 5) {
        const u8* p = &mem.data[(size_t)(a - mem.base)];
        size_t rm = mem.data.size() - (size_t)(a - mem.base);
        cs_insn* ins = nullptr;
        size_t n = cs_disasm(c.dis.handle, p, (std::min)(rm, (size_t)16), a, 1, &ins);
        if (!n) { err = "Giris komutu cozunemedi (RVA 0x" + std::to_string(fnRva + acc) + ")"; return false; }
        HeadInsn h;
        h.rva = fnRva + acc; h.size = (u8)ins[0].size;
        memcpy(h.raw, ins[0].bytes, h.size);
        h.mn = ins[0].mnemonic;
        u8 op0 = h.raw[0];
        if (op0 >= 0xE0 && op0 <= 0xE3) { cs_free(ins, 1); err = "Giris komutunda loop/jcxz (desteklenmiyor)"; return false; }
        if (op0 == 0xE8 || op0 == 0xE9) { h.isRel = true; h.relKind = 4; h.relOff = 1; }
        else if (op0 == 0xEB || (op0 >= 0x70 && op0 <= 0x7F)) { h.isRel = true; h.relKind = 1; h.relOff = 1; }
        else if (op0 == 0x0F && h.size >= 6 && h.raw[1] >= 0x80 && h.raw[1] <= 0x8F) { h.isRel = true; h.relKind = 4; h.relOff = (u32)h.size - 4; }
        if (h.isRel) {
            if (h.relKind == 1) h.relDisp = (i8)h.raw[h.relOff];
            else memcpy(&h.relDisp, &h.raw[h.relOff], 4);
        }
        cs_detail* d = ins[0].detail;
        if (d) {
            for (int i = 0; i < d->x86.op_count && !h.isRip; i++) {
                auto& o = d->x86.operands[i];
                if (o.type == X86_OP_MEM && o.mem.base == X86_REG_RIP) {
                    h.isRip = true; h.ripDisp = (i32)o.mem.disp;
                    h.ripOff = (u32)MazeProtect::CalcRipDispOff(h.raw, h.size, &d->x86);
                }
            }
        }
        out.push_back(h);
        acc += h.size; a += h.size;
        cs_free(ins, 1);
        if (acc > maxLen) { err = "Giris komutlari 32 bayti asti"; return false; }
    }
    headLen = acc;
    return true;
}

// ---- proxy uretimi ---------------------------------------------------------
static void BuildProxy(const std::vector<HeadInsn>& head, u32 fnRva, u32 headLen,
                       u32 proxyRva, std::vector<u8>& px, Report& rep) {
    px.clear(); px.reserve(headLen + 8 * head.size() + 16);
    for (auto& h : head) {
        u32 cur = proxyRva + (u32)px.size();
        i64 delta = (i64)cur - (i64)h.rva;
        if (h.isRip) {
            px.insert(px.end(), h.raw, h.raw + h.size);
            i32 nd = (i32)((i64)h.ripDisp - delta);
            memcpy(&px[px.size() - h.size + h.ripOff], &nd, 4);
            rep.proxyRipFix++;
        } else if (h.isRel && h.relKind == 4) {
            px.insert(px.end(), h.raw, h.raw + h.size);
            i32 nd = (i32)((i64)h.relDisp - delta);
            memcpy(&px[px.size() - h.size + h.relOff], &nd, 4);
            rep.proxyRelFix++;
        } else if (h.isRel && h.relKind == 1) {
            i64 nd = (i64)h.relDisp - delta;
            if (nd >= -128 && nd <= 127) {
                px.insert(px.end(), h.raw, h.raw + h.size);
                px[px.size() - 1] = (u8)(i8)nd;
                rep.proxyRelFix++;
            } else if (h.raw[0] == 0xEB) {
                px.push_back(0xE9);
                i32 v = (i32)((i64)h.rva + 2 + h.relDisp - (i64)cur - 5);
                px.resize(px.size() + 4);
                memcpy(&px[px.size() - 4], &v, 4);
                rep.proxyExpands++;
            } else {
                px.push_back(0x0F); px.push_back(u8(0x10 + h.raw[0]));
                i32 v = (i32)((i64)h.rva + 2 + h.relDisp - (i64)cur - 6);
                px.resize(px.size() + 4);
                memcpy(&px[px.size() - 4], &v, 4);
                rep.proxyExpands++;
            }
        } else {
            px.insert(px.end(), h.raw, h.raw + h.size);
        }
    }
    u32 cur = proxyRva + (u32)px.size();
    i32 d = (i32)((i64)(fnRva + headLen) - (i64)cur - 5);
    px.push_back(0xE9); px.resize(px.size() + 4);
    memcpy(&px[px.size() - 4], &d, 4);
}

// ---- CB (0xD0) -------------------------------------------------------------
// 0x00 magic | 0x04 depth | 0x08 lock | 0x0C state | 0x10 fnRva | 0x14 fnSize
// 0x18 headLen | 0x1C seed | 0x20 bodyLen | 0x24 method | 0x28 sideCount
// 0x2C sideMax | 0x30..0xB0 side[16] (stride 8) | 0xB0 bodyCrc | 0xB8 prefBase
// 0xC0 relocListRva | 0xC4 relocCount | 0xC8 relocApplied
static const u32 CB_SIZE  = 0xD0;
static const u32 CB_MAGIC = 0x35495A4Du; // 'MZI5'

// ---- x64 handler -----------------------------------------------------------
static void EmitHandlerX64(Asm& a, u32 blobRva) {
    a.L("handler");
    a.rel32("cb", "4C 8D 1D");               // lea r11, [rip+cb]      r11 = &CB
    a.L("spin");
    a.hx("F0 41 0F BA 6B 08 00");            // lock bts dword [r11+8], 0
    a.j8(0x72, "spin");
    a.hx("41 FF 43 04");                     // inc dword [r11+4]       (depth++)
    a.hx("41 83 7B 04 01");                  // cmp dword [r11+4], 1
    a.j32(0x85, "skipdec");                  // jne skipdec (nested: zaten plain)
    a.hx("41 83 7B 0C 01");                  // cmp dword [r11+0x0C], 1 (state==plain?)
    a.j32(0x85, "dodec");                    // jne dodec
    // --- recovery: plain govdeyi CB.seed ile geri sifrele ---
    a.hx("51 52 41 50 41 51 56 57");         // push rcx,rdx,r8,r9,rax,rsi,rdi
    a.picBase64(blobRva);                    // rax = imgBase
    a.hx("41 8B 7B 10");                     // mov edi, [r11+0x10]  (fnRva)
    a.hx("48 01 C7");                        // add rdi, rax
    a.hx("41 8B 53 18");                     // mov edx, [r11+0x18]  (headLen)
    a.hx("48 01 D7");                        // add rdi, rdx
    a.hx("41 8B 4B 20");                     // mov ecx, [r11+0x20]  (bodyLen)
    a.hx("45 8B 43 1C");                     // mov r8d, [r11+0x1C]  (seed)
    a.call("xorloop");
    a.hx("41 C7 43 0C 00 00 00 00");         // state = enc
    a.hx("5F 5E 58 41 59 41 58 5A 59");      // pop rdi,rsi,rax,r9,r8,rdx,rcx
    a.L("dodec");
    // --- decrypt: ÖNCE reloc delta geri al (loader 'enc+delta' yazmistir),
    //     SONRA yerinde coz (XOR ve ADD dagilmaz - sira kritik!) ---
    a.hx("51 52 41 50 41 51 56 57");         // push rcx,rdx,r8,r9,rax,rsi,rdi
    a.picBase64(blobRva);                    // rax = imgBase
    a.hx("48 89 C6");                        // mov rsi, rax  (imgBase)
    a.hx("41 83 7B 2C 00");                  // cmp dword [r11+0x2C], 0 (relocApplied)
    a.j8(0x74, "skipadj");                   // je skipadj
    a.hx("41 C7 43 2C 00 00 00 00");         // relocApplied = 0
    a.hx("48 89 F2");                        // mov rdx, rsi
    a.hx("49 2B 53 70");                     // sub rdx, [r11+0x70]  (delta = imgBase - prefBase)
    a.hx("45 8B 4B 7C");                     // mov r9d, [r11+0x7C]  (count)
    a.hx("45 85 C9");                        // test r9d, r9d
    a.j8(0x74, "skipadj");                   // je skipadj (count=0 -> donguye girme!)
    a.hx("49 8B 7B 78");                     // mov rdi, [r11+0x78]  (listRva)
    a.hx("48 01 F7");                        // add rdi, rsi         (listVA)
    a.L("adjloop");
    a.hx("44 8B 07");                        // mov r8d, [rdi]       (rva)
    a.hx("49 01 F0");                        // add r8, rsi          (addr)
    a.hx("49 29 10");                        // sub qword [r8], rdx  (-= delta)
    a.hx("48 83 C7 04");                     // add rdi, 4
    a.hx("41 FF C9");                        // dec r9d
    a.j8(0x75, "adjloop");
    a.L("skipadj");
    a.hx("41 8B 7B 10");                     // mov edi, [r11+0x10]
    a.hx("48 01 F7");                        // add rdi, rsi
    a.hx("41 8B 53 18");                     // mov edx, [r11+0x18]
    a.hx("48 01 D7");                        // add rdi, rdx
    a.hx("41 8B 4B 20");                     // mov ecx, [r11+0x20]
    a.hx("45 8B 43 1C");                     // mov r8d, [r11+0x1C]
    a.call("xorloop");                       // govde ^= keystream -> TAM orijinal
    a.hx("41 C7 43 0C 01 00 00 00");         // state = plain
    a.hx("5F 5E 58 41 59 41 58 5A 59");      // pop rdi,rsi,rax,r9,r8,rdx,rcx
    a.L("skipdec");
    // --- realRet -> side[] ; return-slot YERINDE degistir (ABI-TAM) ---
    a.hx("51 52 50");                        // push rcx, rdx, rax
    a.hx("41 8B 4B 28");                     // mov ecx, [r11+0x28]  (sideCount)
    a.hx("48 83 F9 08");                     // cmp rcx, 8  (side[8])
    a.j8(0x73, "nostash");                   // jae nostash
    a.hx("48 8B 44 24 18");                  // mov rax, [rsp+24]    (realRet peek)
    a.hx("4F 8D 53 30");                     // lea r10, [r11+0x30]  (side[])  REX=W+R+B
    a.hx("49 89 04 CA");                     // mov [r10+rcx*8], rax
    a.hx("41 FF 43 28");                     // inc dword [r11+0x28]
    a.rel32("rets", "4C 8D 15");             // lea r10, [rip+rets]
    a.hx("4C 89 54 24 18");                  // mov [rsp+24], r10    (return-slot swap)
    a.L("nostash");
    a.hx("58 5A 59");                        // pop rax, rdx, rcx
    a.hx("41 C7 43 08 00 00 00 00");         // unlock
    a.rel32("proxy", "4C 8D 15");            // lea r10, [rip+proxy]
    a.hx("41 FF E2");                        // jmp r10
    // ---- xor dongusu: rdi=ptr, ecx=cnt, r8d=st ----
    a.L("xorloop");
    a.hx("44 89 C0 C1 E0 0D 41 31 C0");      // st ^= st<<13
    a.hx("44 89 C0 C1 E8 11 41 31 C0");      // st ^= st>>17
    a.hx("44 89 C0 C1 E0 05 41 31 C0");      // st ^= st<<5
    a.hx("44 89 C0 C1 E8 10");               // eax = st>>16
    a.hx("30 07");                           // xor [rdi], al
    a.hx("48 FF C7");                        // inc rdi
    a.hx("FF C9");                           // dec ecx
    a.j8(0x75, "xorloop");
    a.hx("C3");
    // ---- RET-STUB: giris [rsp]=arg1, rax=retval ----
    a.L("rets");
    a.rel32("cb", "4C 8D 1D");               // lea r11, [rip+cb]
    a.hx("50");                              // push rax (retval)
    a.hx("57");                              // push rdi
    a.L("spin2");
    a.hx("F0 41 0F BA 6B 08 00");
    a.j8(0x72, "spin2");
    a.hx("41 8B 4B 28");                     // mov ecx, [r11+0x28]
    a.hx("41 FF 4B 28");                     // dec dword [r11+0x28]
    a.hx("4F 8D 53 30");                     // lea r10, [r11+0x30]  REX=W+R+B
    a.hx("4B 8B 54 CA F8");                  // mov r10, [r10+rcx*8-8]  (realRet)  REX=W+R+B
    a.hx("41 52");                           // push r10 (realRet en dibe)
    a.hx("41 FF 4B 04");                     // dec dword [r11+4]
    a.hx("41 83 7B 04 00");                  // cmp dword [r11+4], 0
    a.j8(0x75, "rel2");
    a.hx("41 83 7B 0C 01");                  // cmp dword [r11+0x0C], 1
    a.j8(0x75, "rel2");
    a.picBase64(blobRva);                    // rax = imgBase
    a.hx("41 8B 7B 10");                     // mov edi, [r11+0x10]
    a.hx("48 01 C7");
    a.hx("41 8B 53 18"); a.hx("48 01 D7");
    a.hx("41 8B 4B 20");
    a.hx("41 83 7B 24 02");                  // method==2?
    a.j8(0x75, "same2");
    a.hx("0F 31");                           // rdtsc
    a.hx("31 D0");                           // xor eax, edx
    a.hx("31 E0");                           // xor eax, esp
    a.hx("69 C0"); a.imm32(0x9E3779B9u);     // imul eax, eax, golden
    a.hx("41 89 C0");                        // mov r8d, eax
    a.hx("45 89 43 1C");                     // mov [r11+0x1C], r8d (YENI seed)
    a.j8(0xEB, "go2");
    a.L("same2");
    a.hx("45 8B 43 1C");                     // mov r8d, [r11+0x1C]
    a.L("go2");
    a.call("xorloop");
    a.hx("41 C7 43 0C 00 00 00 00");         // state = enc
    a.L("rel2");
    a.hx("41 C7 43 08 00 00 00 00");         // unlock
    a.hx("5A");                              // pop rdx (realRet)
    a.hx("5F");                              // pop rdi
    a.hx("58");                              // pop rax (retval)
    a.hx("52");                              // push rdx -> [rsp]=realRet
    a.hx("C3");                              // ret -> realRet
}

// ---- x86 handler -----------------------------------------------------------
static void EmitHandlerX86(Asm& a, u32 blobRva) {
    a.L("handler");
    a.hx("53");                              // push ebx (cagiranin)
    a.hx("56");                              // push esi (cagiranin)
    a.picBase32(blobRva);                    // eax = imgBase
    a.hx("89 C6");                           // mov esi, eax
    a.hx("05"); a.imm32(0xDEAD0000); a.fixes.push_back({ (u32)a.b.size() - 4, "cbRva", 0 });
    a.hx("89 C3");                           // mov ebx, eax (&CB)
    a.L("spin");
    a.hx("F0 0F BA 6B 08 00");               // lock bts dword [ebx+8], 0
    a.j8(0x72, "spin");
    a.hx("FF 43 04");                        // inc dword [ebx+4]
    a.hx("83 7B 04 01");                     // cmp dword [ebx+4], 1
    a.j32(0x85, "skipdec");
    a.hx("83 7B 0C 01");                     // cmp dword [ebx+0x0C], 1
    a.j32(0x85, "dodec");
    // recovery
    a.hx("60 9C");                           // pushal; pushfd
    a.hx("89 F7");                           // mov edi, esi
    a.hx("81 C7"); a.imm32(0xDEAD0001); a.fixes.push_back({ (u32)a.b.size() - 4, "bodyOff", 0 });
    a.hx("8B 4B 20");                        // mov ecx, [ebx+0x20]
    a.hx("8B 43 1C");                        // mov eax, [ebx+0x1C]
    a.call("xorloop");
    a.hx("C7 43 0C 00 00 00 00");            // state = enc
    a.hx("9D 61");                           // popfd; popal
    a.L("dodec");
    // decrypt: ÖNCE reloc delta geri al, SONRA yerinde coz
    a.hx("60 9C");                           // pushal; pushfd
    a.hx("89 F7");                           // mov edi, esi (imgBase)
    a.hx("83 7B 2C 00");                     // cmp dword [ebx+0x2C], 0 (relocApplied)
    a.j8(0x74, "skipadj");
    a.hx("C7 43 2C 00 00 00 00");            // relocApplied = 0
    a.hx("89 F0");                           // mov eax, esi
    a.hx("2B 43 70");                        // sub eax, [ebx+0x70]  (delta, prefBase low32)
    a.hx("8B 4B 7C");                        // mov ecx, [ebx+0x7C]  (count)
    a.hx("85 C9");                           // test ecx, ecx
    a.j8(0x74, "skipadj");                   // je skipadj (count=0!)
    a.hx("8B 7B 78");                        // mov edi, [ebx+0x78]  (listRva)
    a.hx("01 F7");                           // add edi, esi         (listVA)
    a.L("adjloop");
    a.hx("8B 2F");                           // mov ebp, [edi]
    a.hx("01 F5");                           // add ebp, esi
    a.hx("29 45 00");                        // sub dword [ebp+0], eax
    a.hx("83 C7 04");                        // add edi, 4
    a.hx("49");                              // dec ecx
    a.j8(0x75, "adjloop");
    a.L("skipadj");
    a.hx("89 F7");                           // mov edi, esi (imgBase)
    a.hx("81 C7"); a.imm32(0xDEAD0002); a.fixes.push_back({ (u32)a.b.size() - 4, "bodyOff", 0 });
    a.hx("8B 4B 20");                        // mov ecx, [ebx+0x20]
    a.hx("8B 43 1C");                        // mov eax, [ebx+0x1C]
    a.call("xorloop");                       // sifre coz -> TAM orijinal
    a.hx("C7 43 0C 01 00 00 00");            // state = plain
    a.hx("9D 61");                           // popfd; popal
    a.L("skipdec");
    // realRet -> side[] ; return-slot yerinde degistir
    a.hx("8B 43 28");                        // mov eax, [ebx+0x28]  (sideCount)
    a.hx("83 F8 08");                        // cmp eax, 8  (side[8])
    a.j8(0x73, "nostash");
    a.hx("8B 4C 24 08");                     // mov ecx, [esp+8]     (realRet peek)
    a.hx("8D 53 30");                        // lea edx, [ebx+0x30]  (side[])
    a.hx("89 0C C2");                        // mov [edx+eax*8], ecx (stride 8)
    a.hx("FF 43 28");                        // inc dword [ebx+0x28]
    a.hx("89 F2");                           // mov edx, esi
    a.hx("81 C2"); a.imm32(0xDEAD0009); a.fixes.push_back({ (u32)a.b.size() - 4, "retsRva", 0 });
    a.hx("89 54 24 08");                     // mov [esp+8], edx     (return-slot swap)
    a.L("nostash");
    a.hx("C7 43 08 00 00 00 00");            // unlock (ebx=&CB)
    a.hx("89 F0");                           // mov eax, esi
    a.hx("05"); a.imm32(0xDEAD0003); a.fixes.push_back({ (u32)a.b.size() - 4, "proxyRva", 0 });
    a.hx("5E");                              // pop esi  (cagiranin)
    a.hx("5B");                              // pop ebx  (cagiranin)
    a.hx("FF E0");                           // jmp eax
    // xor dongusu: eax=st, edi=ptr, ecx=cnt, edx=tmp
    a.L("xorloop");
    a.hx("89 C2 C1 E2 0D 31 D0");            // st ^= st<<13
    a.hx("89 C2 C1 EA 11 31 D0");            // st ^= st>>17
    a.hx("89 C2 C1 E2 05 31 D0");            // st ^= st<<5
    a.hx("89 C2 C1 EA 10");                  // edx = st>>16
    a.hx("30 17");                           // xor [edi], dl
    a.hx("47");
    a.hx("49");
    a.j8(0x75, "xorloop");
    a.hx("C3");
    // ---- RET-STUB: [esp]=arg1, eax=retval ----
    a.L("rets");
    a.hx("50");                              // push eax (retval)
    a.hx("53");                              // push ebx
    a.hx("57");                              // push edi
    a.picBase32(blobRva);                    // eax = imgBase
    a.hx("89 C3");                           // mov ebx, eax
    a.hx("81 C3"); a.imm32(0xDEAD0004); a.fixes.push_back({ (u32)a.b.size() - 4, "cbRva", 0 });
    a.L("spin2");
    a.hx("F0 0F BA 6B 08 00");
    a.j8(0x72, "spin2");
    a.hx("8B 4B 28");                        // mov ecx, [ebx+0x28]
    a.hx("FF 4B 28");                        // dec dword [ebx+0x28]
    a.hx("8D 53 30");                        // lea edx, [ebx+0x30]
    a.hx("8B 44 CA F8");                     // mov eax, [edx+ecx*8-8]  (realRet)
    a.hx("50");                              // push eax (realRet)
    a.hx("FF 4B 04");                        // dec dword [ebx+4]
    a.hx("83 7B 04 00");                     // cmp dword [ebx+4], 0
    a.j8(0x75, "rel2");
    a.hx("83 7B 0C 01");                     // cmp dword [ebx+0x0C], 1
    a.j8(0x75, "rel2");
    a.picBase32(blobRva);                    // eax = imgBase
    a.hx("89 C7");                           // mov edi, eax
    a.hx("81 C7"); a.imm32(0xDEAD0005); a.fixes.push_back({ (u32)a.b.size() - 4, "bodyOff", 0 });
    a.hx("8B 4B 20");                        // mov ecx, [ebx+0x20]
    a.hx("83 7B 24 02");                     // cmp dword [ebx+0x24], 2
    a.j8(0x75, "same2");
    a.hx("0F 31");                           // rdtsc
    a.hx("31 D0");                           // xor eax, edx
    a.hx("31 E0");                           // xor eax, esp
    a.hx("69 C0"); a.imm32(0x9E3779B9u);
    a.hx("89 43 1C");                        // mov [ebx+0x1C], eax (YENI seed)
    a.j8(0xEB, "go2");
    a.L("same2");
    a.hx("8B 43 1C");                        // mov eax, [ebx+0x1C]
    a.L("go2");
    a.call("xorloop");
    a.hx("C7 43 0C 00 00 00 00");            // state = enc
    a.L("rel2");
    a.hx("C7 43 08 00 00 00 00");            // unlock
    a.hx("5A");                              // pop edx (realRet)
    a.hx("5F");                              // pop edi
    a.hx("5B");                              // pop ebx
    a.hx("58");                              // pop eax (retval)
    a.hx("52");                              // push edx -> [esp]=realRet
    a.hx("C3");                              // ret -> realRet
}

// x86 build-const yamalari
static bool ApplyAbsFixes(Asm& a, const Report& rep, std::string& err) {
    for (auto& f : a.fixes) {
        if (f.kind != 0) continue;
        u32 rva;
        if      (f.to == "cbRva")   rva = rep.cbRva;
        else if (f.to == "retsRva") rva = rep.retsRva;
        else if (f.to == "proxyRva")rva = rep.proxyRva;
        else if (f.to == "bodyOff") rva = rep.fnRva + rep.headLen;
        else { err = "bilinmeyen abs fix: " + f.to; return false; }
        i32 v = (i32)rva; memcpy(&a.b[f.pos], &v, 4);
    }
    return true;
}

// ---- TAM BLOB: CB + relocList + proxy + handler ----------------------------
static void EmitBlob(bool is64, u32 blobRva, const std::vector<u8>& proxy,
                     const std::vector<u8>& relocList, Asm& a) {
    a.L("cb");
    a.zeros(CB_SIZE);
    a.L("reloc");
    a.rawBytes(relocList);
    a.L("proxy");
    a.rawBytes(proxy);
    a.L("handler");
    if (is64) EmitHandlerX64(a, blobRva); else EmitHandlerX86(a, blobRva);
}

// ---- ANA GIRIS --------------------------------------------------------------
inline bool Build(Core& c, const Options& optIn, Report& rep) {
    auto& pe = c.pe; auto& mem = c.mem;
    rep.fnRva = optIn.fnRva; rep.fnSize = optIn.fnSize; rep.method = optIn.method;

    if (!pe.valid || mem.data.empty())          { rep.err = "PE yuklu degil"; return false; }
    if (optIn.method != 1 && optIn.method != 2) { rep.err = "method 1|2 olmali"; return false; }
    if (optIn.fnSize < 16)                      { rep.err = "Fonksiyon cok kucuk (<16)"; return false; }
    if (optIn.fnRva == 0 || optIn.fnRva >= pe.imgSz) { rep.err = "RVA goruntu disinda"; return false; }
    if (optIn.fnRva + optIn.fnSize > pe.imgSz)  { rep.err = "Aralik SizeOfImage'i asiyor"; return false; }

    u32 secEnd = 0; bool inExec = false;
    for (auto& s : pe.secs) {
        u32 e = s.va + (std::max)(s.vSz, s.rawSz);
        if (optIn.fnRva >= s.va && optIn.fnRva < e) {
            inExec = (s.chars & IMAGE_SCN_MEM_EXECUTE) != 0;
            secEnd = s.va + s.vSz; break;
        }
    }
    if (!inExec) { rep.err = "Fonksiyon calistirilabilir (X) section'da degil"; return false; }
    if (rep.fnSize > secEnd - rep.fnRva) {
        rep.warnings.push_back("fnSize section sonunu asiyordu -> kirpildi");
        rep.fnSize = secEnd - rep.fnRva;
        if (rep.fnSize < 16) { rep.err = "Kirpma sonrasi boyut cok kucuk"; return false; }
    }

    // govde tamamen cozulebilir olmali
    {
        u64 a = mem.base + rep.fnRva;
        while (a < mem.base + rep.fnRva + rep.fnSize) {
            const u8* p = &mem.data[(size_t)(a - mem.base)];
            cs_insn* ins = nullptr;
            size_t n = cs_disasm(c.dis.handle, p, (std::min)(mem.data.size() - (size_t)(a - mem.base), (size_t)16), a, 1, &ins);
            if (!n) { rep.err = "Govde icinde cozunemeyen bayt (RVA 0x" + std::to_string(a - mem.base) + ")"; return false; }
            a += ins[0].size; cs_free(ins, 1);
        }
    }

    std::vector<HeadInsn> head;
    if (!SplitHead(c, rep.fnRva, 32, head, rep.headLen, rep.err)) return false;
    rep.headInsns = (int)head.size();
    rep.bodyLen = rep.fnSize - rep.headLen;

    rep.seed = optIn.seed ? optIn.seed : Rnd32();
    rep.bodyCrc = Crc32(&mem.data[rep.fnRva + rep.headLen], rep.bodyLen);

    // ---- govde icindeki RELOC'lari topla (reloc-guvenli koruma) ----
    std::vector<u8> relocList;
    {
        std::map<u32, u8> rel;   // rva -> size
        u32 b0 = rep.fnRva + rep.headLen, b1 = rep.fnRva + rep.fnSize;
        for (auto& r : pe.relocs) {
            if (r.rva < b0) continue;
            u32 sz = (r.type == 10) ? 8 : 4;   // DIR64 : HIGHLOW/diger
            if (r.rva + sz > b1) continue;
            rel[r.rva] = (u8)sz;
        }
        rep.relocCount = (u32)rel.size();
        for (auto& kv : rel) {
            u32 rva = kv.first;                     // LISTEYE RVA DEGERI YAZILIR
            relocList.push_back(u8(rva)); relocList.push_back(u8(rva >> 8));
            relocList.push_back(u8(rva >> 16)); relocList.push_back(u8(rva >> 24));
        }
        // bas bolgesindeki reloc'lari PE'den CIKAR (trambolin kismen +delta
        // almasin); proxy disp'leri RVA-tabanli oldugu icin relocation'dan
        // bagimsizdir, bas bolgesinde deger yok (tramp+CC)
        pe.relocs.erase(std::remove_if(pe.relocs.begin(), pe.relocs.end(),
            [&](const PEFile::RelocEntry& r) { return r.rva >= rep.fnRva && r.rva < rep.fnRva + rep.headLen; }),
            pe.relocs.end());
        if (rep.relocCount)
            rep.warnings.push_back("Govdede " + std::to_string(rep.relocCount) + " reloc -> ilk decrypt'te delta geri alinacak (reloc-guvenli)");
    }

    std::vector<u8> proxy;
    BuildProxy(head, rep.fnRva, rep.headLen, 0, proxy, rep);   // 1. pas: boyut

    u32 mazeChars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    Asm probe;
    EmitBlob(pe.is64, 0, proxy, relocList, probe);
    std::string perr;
    if (!probe.Finish(perr)) { rep.err = "handler uretim hatasi: " + perr; return false; }
    u32 blobSize = (u32)probe.b.size();

    u32 mazeRva = 0;
    if (!MazeProtect::GrowAppendSection(pe, mem, ".maze", blobSize, mazeChars, mazeRva)) {
        rep.err = ".maze section eklenemedi (header dolu)"; return false;
    }
    rep.mazeRva = mazeRva; rep.blobRva = mazeRva; rep.blobSize = blobSize;
    rep.cbRva      = mazeRva;
    rep.proxyRva   = mazeRva + CB_SIZE + (u32)relocList.size();
    rep.handlerRva = rep.proxyRva + (u32)proxy.size();
    rep.retsRva    = rep.blobRva + probe.lab["rets"];

    // proxy 2. pas: gercek RVA ile
    rep.proxyExpands = 0; rep.proxyRipFix = 0; rep.proxyRelFix = 0;
    BuildProxy(head, rep.fnRva, rep.headLen, rep.proxyRva, proxy, rep);

    Asm a;
    EmitBlob(pe.is64, rep.blobRva, proxy, relocList, a);
    if (!a.Finish(perr)) { rep.err = "handler uretim hatasi: " + perr; return false; }
    if (!pe.is64) { if (!ApplyAbsFixes(a, rep, perr)) { rep.err = perr; return false; } }

    // ---- blob yaz + CB ----
    std::vector<u8> blob = a.b;
    u8* cb = &blob[0];
    memcpy(cb, "MZI5", 4);
    auto P = [&](u32 off, u32 v) { memcpy(cb + off, &v, 4); };
    P(0x04, 0); P(0x08, 0); P(0x0C, 0);
    P(0x10, rep.fnRva); P(0x14, rep.fnSize); P(0x18, rep.headLen);
    P(0x1C, rep.seed);  P(0x20, rep.bodyLen); P(0x24, (u32)rep.method);
    P(0x28, 0); P(0x2C, 1);                               // sideCount=0, relocApplied=1
    { u64 pb = pe.imgBase; memcpy(cb + 0x70, &pb, 8); }   // prefBase u64
    P(0x78, rep.blobRva + CB_SIZE);                       // relocListRva
    P(0x7C, rep.relocCount);                              // relocCount u32
    P(0x80, rep.bodyCrc);
    P(0x88, rep.retsRva); P(0x8C, rep.proxyRva); P(0x90, (u32)head.size());
    memcpy(&mem.data[rep.blobRva], blob.data(), blob.size());

    // ---- govdeyi yerinde sifrele ----
    u32 st = rep.seed;
    for (u32 i = 0; i < rep.bodyLen; i++)
        mem.data[rep.fnRva + rep.headLen + i] ^= (u8)KsNext(st);

    // ---- trambolin ----
    i32 tramp = (i32)((i64)rep.handlerRva - (i64)(rep.fnRva + 5));
    mem.data[rep.fnRva] = 0xE9;
    memcpy(&mem.data[rep.fnRva + 1], &tramp, 4);
    for (u32 i = 5; i < rep.headLen; i++) mem.data[rep.fnRva + i] = 0xCC;

    // ---- govde section yazilabilir ----
    for (auto& s : pe.secs) {
        if (rep.fnRva >= s.va && rep.fnRva < s.va + (std::max)(s.vSz, s.rawSz)) {
            if (!(s.chars & IMAGE_SCN_MEM_WRITE)) {
                s.chars |= IMAGE_SCN_MEM_WRITE;
                auto dos = (PIMAGE_DOS_HEADER)pe.raw.data();
                auto nt = (PIMAGE_NT_HEADERS)(pe.raw.data() + dos->e_lfanew);
                auto sh = IMAGE_FIRST_SECTION(nt);
                for (u16 i = 0; i < nt->FileHeader.NumberOfSections; i++)
                    if (!strncmp((const char*)sh[i].Name, s.name, 8)) sh[i].Characteristics |= IMAGE_SCN_MEM_WRITE;
                rep.warnings.push_back("Govde section'i yazilabilir yapildi (in-place decrypt)");
            }
            break;
        }
    }

    if (rep.proxyExpands) rep.warnings.push_back("Proxy: " + std::to_string(rep.proxyExpands) + " rel8->rel32 genisletme");
    if (rep.proxyRipFix)  rep.warnings.push_back("Proxy: " + std::to_string(rep.proxyRipFix) + " rip-rel disp duzeltme");
    rep.ok = true;
    return true;
}

} // namespace MazeIP
