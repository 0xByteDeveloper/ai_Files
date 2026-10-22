// ============================================================================
//  mp_driver43.cpp - MazeProtector V4.3 IP (in-place) Linux calistirma driveri
//  Kullanim:
//    mp_driver43 <giris.exe> <cikis.exe> <MazeMap.txt> ip1|ip2
//    ip1 = TekTek-IP  (sabit anahtar, donuste yeniden sifrele)
//    ip2 = Stream-IP  (her cagrida yeni rastgele anahtar)
//  Fonksiyon secimi:
//    .gfn section (isim+adres) / MP_ONLY=isim1,isim2
//    MP_FN=Ad MP_RVA=0x1234 [MP_SIZE=nnn]  -> manuel (PDB'siz programlar)
//    MP_START=0x1234 MP_END=0x1400         -> ARALIK modu (instruction-snapped)
//       * MP_END yoksa son, BFS ile BULUNUR (instruction ayraci = end-address
//         bulucu); MP_END verildiyse GERIYE dogru son komut sinirina SNAP edilir
//         (komut ortasindan sifreleme YAPILMAZ).
// ============================================================================
#define _CRT_SECURE_NO_WARNINGS
#include "../../download/i4MConsoleLoader/i4MConsoleLoader/globals.h"
#include "../../download/i4MConsoleLoader/i4MConsoleLoader/MazeProtector.h"
#include "Motor_V4.3_IP.h"
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <vector>
#include <set>

// ---- CFG-tabanli fonksiyon boyutu (BFS; end-address bulucu) ----------------
static u32 ComputeFnSizeCFG(const Core& c, u32 fnRva, u32* endOut = nullptr) {
    auto& mem = c.mem;
    std::vector<u64> work; std::set<u64> seen;
    u64 start = mem.base + fnRva;
    work.push_back(start); seen.insert(start);
    u64 maxEnd = 0;
    int steps = 0;
    while (!work.empty()) {
        if (++steps > 4096) break;
        u64 a = work.back(); work.pop_back();
        u64 guard = 0;
        while (true) {
            if (++guard > 4096) break;
            if (a < mem.base || a >= mem.base + mem.data.size()) return 0;
            const u8* p = &mem.data[(size_t)(a - mem.base)];
            cs_insn* ins = nullptr;
            size_t n = cs_disasm(c.dis.handle, p, 16, a, 1, &ins);
            if (!n) return 0;
            u64 nxt = a + ins->size;
            if (nxt - mem.base > maxEnd) maxEnd = nxt - mem.base;
            std::string mn(ins->mnemonic);
            bool stop = false;
            if (mn == "ret" || mn == "retf" || mn == "retq") stop = true;
            else if (mn.rfind("j", 0) == 0 && mn != "jmp") {
                if (ins->detail && ins->detail->x86.op_count == 1 && ins->detail->x86.operands[0].type == X86_OP_IMM) {
                    u64 tgt = (u64)ins->detail->x86.operands[0].imm;
                    if (tgt >= start && tgt - start < 8192) {
                        if (seen.insert(tgt).second) work.push_back(tgt);
                    }
                }
            } else if (mn == "jmp") {
                if (ins->detail && ins->detail->x86.op_count == 1 && ins->detail->x86.operands[0].type == X86_OP_IMM) {
                    u64 tgt = (u64)ins->detail->x86.operands[0].imm;
                    if (tgt >= start && tgt - start < 8192) {
                        if (seen.insert(tgt).second) work.push_back(tgt);
                        cs_free(ins, 1);
                        break;
                    } else stop = true;
                } else stop = true;
            } else if (mn == "ud2" || mn == "int3") stop = true;
            cs_free(ins, 1);
            if (stop) break;
            a = nxt;
        }
    }
    if (endOut) *endOut = (u32)maxEnd;
    return maxEnd ? (u32)(maxEnd - fnRva) : 0;
}

// ---- ARALIK modu: start/end'i KOMUT SINIRINA snap et (instruction ayraci) --
struct Snapped { u32 startRva, endRva; bool startAligned, endSnapped; std::string note; };
static bool SnapRange(Core& c, u32 start, u32 end, Snapped& out) {
    auto& mem = c.mem;
    u64 a = mem.base + start;
    // start hizasi: start'in kendisi bir komut baslangici olmali (kullaniciye
    // bildiririz; gosterge: buradan capstone ile yurunur)
    u32 lastBoundary = start;
    u32 lastRetEnd = 0;
    bool startAligned = true;
    {
        // start'tan ilk komut cozunmuyor ise start hizasizdir
        const u8* p = &mem.data[(size_t)(a - mem.base)];
        cs_insn* ins = nullptr;
        if (!cs_disasm(c.dis.handle, p, 16, a, 1, &ins)) startAligned = false;
        else cs_free(ins, 1);
    }
    u32 cur = start;
    while (cur < end) {
        u64 va = mem.base + cur;
        const u8* p = &mem.data[(size_t)(va - mem.base)];
        cs_insn* ins = nullptr;
        size_t n = cs_disasm(c.dis.handle, p, (std::min)(mem.data.size() - (size_t)(va - mem.base), (size_t)16), va, 1, &ins);
        if (!n) break;
        u32 nxt = cur + ins[0].size;
        std::string mn(ins[0].mnemonic);
        bool isRet = (mn == "ret" || mn == "retf" || mn == "retq");
        cs_free(ins, 1);
        if (nxt > end) { break; }                 // son komut end'i asar -> dur
        lastBoundary = nxt;
        if (isRet) lastRetEnd = nxt;
        cur = nxt;
    }
    bool endSnapped = (lastBoundary != end);
    u32 chosen = end;
    if (end > lastBoundary) {
        chosen = lastBoundary;                    // komut ortasindan kirpma YAPMA
    }
    char nb[256];
    snprintf(nb, sizeof(nb), "start=0x%X aligned=%s end=0x%X -> snapped=0x%X (son ret siniri=0x%X, fark=%u bayt)",
             start, startAligned ? "EVET" : "HAYIR", end, chosen, lastRetEnd, end - chosen);
    out = { start, chosen, startAligned, endSnapped, nb };
    return chosen > start;
}

int main(int argc, char** argv) {
    if (argc < 4) { fprintf(stderr, "Kullanim: mp_driver43 <giris.exe> <cikis.exe> <MazeMap.txt> ip1|ip2\n"); return 2; }
    bool ip2 = (argc > 4 && strstr(argv[4], "ip2")) || (getenv("MP_IP2") && *getenv("MP_IP2") == '1');
    int ipMethod = ip2 ? 2 : 1;

    std::wstring inW, outW;
    for (const char* p = argv[1]; *p; p++) inW.push_back((wchar_t)*p);
    for (const char* p = argv[2]; *p; p++) outW.push_back((wchar_t)*p);

    Core c;
    if (!c.LoadFile(inW.c_str())) { fprintf(stderr, "PE yuklenemedi: %s\n", argv[1]); return 2; }
    // DLL cakisma onlemi: korumali DLL'e serbest bir ImageBase ver (Build'lerden
    // ONCE -> CB.prefBase = son ImageBase -> delta tutarli; gercek cakismada
    // reloc-adjust yolu devreye girer)
    if (c.pe.raw.size() > 0x200) {
        auto dos = (PIMAGE_DOS_HEADER)c.pe.raw.data();
        auto nt = (PIMAGE_NT_HEADERS)(c.pe.raw.data() + dos->e_lfanew);
        bool isDll = (nt->FileHeader.Characteristics & 0x2000) != 0 /* IMAGE_FILE_DLL */;
        const char* eNB = getenv("MP_NEWBASE");
        if (eNB && *eNB == '0') isDll = false;
        if (isDll) {
            u64 oldBase = c.pe.imgBase;
            u64 newBase = c.pe.is64 ? 0x680000000ull : 0x62000000ull;
            u64 dB = newBase - oldBase;
            if (c.pe.is64) {
                ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.ImageBase = newBase;
                c.pe.imgBase = newBase; c.mem.base = newBase;
            } else {
                ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.ImageBase = (u32)newBase;
                c.pe.imgBase = newBase; c.mem.base = newBase;
            }
            // --- REBASE-TAM (V4.3.1): TUM mutlak VA'lari yeni base'e tasi ---
            // Tercih edilen base'de yuklemede loader relocation UYGULAMAZ.
            // ImageBase'i degistirirsek TLS dizini + kod/veri icindeki mutlak
            // degerler ESKI base'de kalicak -> ntdll TLS init garbage pointer
            // -> c000001d illegal-instruction (wine32'de kanitlandi).
            // (a) .reloc hedeflerindeki degerler (kod imm32/imm64 + TLS + veri)
            {
                int patched = 0;
                for (auto& r : c.pe.relocs) {
                    u32 sz = (r.type == 10) ? 8 : 4;
                    if (r.rva + sz > c.pe.imgSz) continue;
                    u64 v = 0;
                    memcpy(&v, &c.mem.data[r.rva], sz);
                    if (v >= oldBase && v < oldBase + c.pe.imgSz) {
                        v += dB;
                        memcpy(&c.mem.data[r.rva], &v, sz);
                        patched++;
                    }
                }
                // (b) TLS dizini (dd[9]): Start/End/Index/Callbacks mutlak VA
                // NOT: linuxshim'de PIMAGE_NT_HEADERS = 64-bit variant! Acik cast ZORUNLU.
                auto& tls = c.pe.is64 ? ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
                                      : ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
                if (tls.VirtualAddress && tls.Size >= 0x18) {
                    u32 o = tls.VirtualAddress;
                    for (int i = 0; i < 4; i++) {
                        u32 v; memcpy(&v, &c.mem.data[o + i * 4], 4);
                        if (v >= oldBase && v < oldBase + c.pe.imgSz) {
                            v += (u32)dB; memcpy(&c.mem.data[o + i * 4], &v, 4); patched++;
                        }
                    }
                }
                // (c) LoadConfig (dd[10], varsa): SEHandlerTable/GuardCF VA'lari
                auto& lcfg = c.pe.is64 ? ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
                                       : ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
                if (lcfg.VirtualAddress && lcfg.Size >= 0x40) {
                    u32 o = lcfg.VirtualAddress;
                    const u32 offs[3] = { 0x20, 0x28, 0x30 }; // SEHandlerTable, GuardCFCheckFnPtr, GuardCFFunctionTable
                    for (int i = 0; i < 3; i++) {
                        u32 v; memcpy(&v, &c.mem.data[o + offs[i]], 4);
                        if (v >= oldBase && v < oldBase + c.pe.imgSz) {
                            v += (u32)dB; memcpy(&c.mem.data[o + offs[i]], &v, 4); patched++;
                        }
                    }
                }
                printf("DLL rebase-TAM: %d mutlak VA yeni base'e tasindi (reloc+TLS+LoadConfig)\n", patched);
            }
            // .gfn icindeki mutlak VA'ları (isim+fnc) yeni base'e tasi
            for (auto& gs : c.pe.secs) {
                if (strcmp(gs.name, ".gfn")) continue;
                u32 step = c.pe.is64 ? 16 : 8;
                for (u32 o = 0; o + step <= gs.vSz; o += step) {
                    if (c.pe.is64) {
                        u64 a, b;
                        memcpy(&a, &c.mem.data[gs.va + o], 8);
                        memcpy(&b, &c.mem.data[gs.va + o + 8], 8);
                        if (a >= oldBase && a < oldBase + c.pe.imgSz) { a += dB; memcpy(&c.mem.data[gs.va + o], &a, 8); }
                        if (b >= oldBase && b < oldBase + c.pe.imgSz) { b += dB; memcpy(&c.mem.data[gs.va + o + 8], &b, 8); }
                    } else {
                        u32 a, b;
                        memcpy(&a, &c.mem.data[gs.va + o], 4);
                        memcpy(&b, &c.mem.data[gs.va + o + 4], 4);
                        if (a >= oldBase && a < oldBase + c.pe.imgSz) { a += (u32)dB; memcpy(&c.mem.data[gs.va + o], &a, 4); }
                        if (b >= oldBase && b < oldBase + c.pe.imgSz) { b += (u32)dB; memcpy(&c.mem.data[gs.va + o + 4], &b, 4); }
                    }
                }
            }
            printf("DLL ImageBase yenilendi: 0x%llX (cakisma onlemi, .gfn VA'lari tasinandi)\n", (unsigned long long)newBase);
        }
    }
    printf("PE yuklendi: imgBase=0x%llX imgSz=0x%X arch=%s section=%d\n",
           (unsigned long long)c.pe.imgBase, c.pe.imgSz, c.pe.is64 ? "x64" : "x86", (int)c.pe.numSec);

    // ---- .pdata: fonksiyon araliklari ----
    std::map<u32, u32> fnSizes;
    {
        const SecInfo* pd = nullptr;
        for (auto& s : c.pe.secs) if (!strcmp(s.name, ".pdata")) { pd = &s; break; }
        if (pd && pd->rawSz >= 12) {
            size_t base = pd->va;
            for (u32 off = 0; off + 12 <= pd->vSz; off += 12) {
                u32 beg, end;
                memcpy(&beg, &c.mem.data[base + off], 4);
                memcpy(&end, &c.mem.data[base + off + 4], 4);
                if (end > beg && end < c.pe.imgSz) fnSizes[beg] = end - beg;
            }
        }
        printf(".pdata: %d fonksiyon araligi\n", (int)fnSizes.size());
    }

    // ---- hedef listesi ----
    struct Target { std::string name; u32 rva; u32 size; };
    std::vector<Target> targets;
    {
        const SecInfo* gf = nullptr;
        for (auto& s : c.pe.secs) if (!strcmp(s.name, ".gfn")) { gf = &s; break; }
        if (gf) {
            u32 step = c.pe.is64 ? 16 : 8;
            for (u32 off = 0; off + step <= gf->rawSz; off += step) {
                u64 nameVA, fnVA;
                if (c.pe.is64) {
                    memcpy(&nameVA, &c.mem.data[gf->va + off], 8);
                    memcpy(&fnVA,  &c.mem.data[gf->va + off + 8], 8);
                } else {
                    u32 n32, f32;
                    memcpy(&n32, &c.mem.data[gf->va + off], 4);
                    memcpy(&f32, &c.mem.data[gf->va + off + 4], 4);
                    nameVA = n32; fnVA = f32;
                }
                if (!nameVA || !fnVA) break;
                std::string name;
                for (u64 a = nameVA - c.pe.imgBase; a < c.mem.data.size() && c.mem.data[a]; a++)
                    name.push_back((char)c.mem.data[a]);
                u32 rva = (u32)(fnVA - c.pe.imgBase);
                u32 sz = 0;
                auto it = fnSizes.find(rva);
                if (it != fnSizes.end()) sz = it->second;
                u32 csz = ComputeFnSizeCFG(c, rva);
                printf("  [CSZ] %-16s rva=0x%05X csz=%u pdata_sz=%u\n", name.c_str(), rva, csz, sz);
                if (csz >= 16) sz = csz;
                targets.push_back({ name, rva, sz });
            }
            printf(".gfn: %d fonksiyon kaydi\n", (int)targets.size());
        } else {
            printf(".gfn yok (manuel mod: MP_RVA / MP_START)\n");
        }
    }

    // ---- MP_ONLY ----
    std::vector<std::string> onlyNames;
    {
        const char* e = getenv("MP_ONLY");
        if (e && *e) {
            const char* p = e;
            while (*p) {
                const char* q = strchr(p, ',');
                if (!q) q = p + strlen(p);
                std::string n(p, (size_t)(q - p));
                size_t b = n.find_first_not_of(" \t");
                size_t t2 = n.find_last_not_of(" \t");
                if (b != std::string::npos) onlyNames.push_back(n.substr(b, t2 - b + 1));
                if (!*q) break;
                p = q + 1;
            }
        }
    }
    auto wanted = [&](const std::string& n) {
        if (onlyNames.empty()) return true;
        for (auto& x : onlyNames) if (x == n) return true;
        return false;
    };

    // ---- MP_FN / MP_RVA manuel mod ----
    {
        const char* eFn = getenv("MP_FN");
        const char* eRva = getenv("MP_RVA");
        if (eFn && eRva && *eRva) {
            u32 mrva = (u32)strtoul(eRva, nullptr, 0);
            u32 msz = 0;
            const char* eSz = getenv("MP_SIZE");
            if (eSz && *eSz) msz = (u32)strtoul(eSz, nullptr, 0);
            else msz = ComputeFnSizeCFG(c, mrva);
            targets.push_back({ eFn, mrva, msz });
            printf("MANUEL HEDEF: %s rva=0x%X size=%u (BFS hesapli)\n", eFn, mrva, msz);
        }
        // ---- MP_START / MP_END aralik modu (instruction-snapped) ----
        const char* eS = getenv("MP_START");
        if (eS && *eS) {
            u32 st = (u32)strtoul(eS, nullptr, 0);
            u32 en = 0;
            const char* eE = getenv("MP_END");
            if (eE && *eE) en = (u32)strtoul(eE, nullptr, 0);
            else { u32 e2 = 0; ComputeFnSizeCFG(c, st, &e2); en = e2; printf("MP_END verilmedi -> end-address bulucu (BFS): 0x%X\n", en); }
            Snapped sn;
            if (!SnapRange(c, st, en, sn)) fprintf(stderr, "ARALIK snap basarisiz\n");
            else {
                printf("INSTRUCTION-AYRACI: %s\n", sn.note.c_str());
                char nm[64]; snprintf(nm, sizeof(nm), "Aralik_0x%X", st);
                targets.push_back({ nm, sn.startRva, sn.endRva - sn.startRva });
            }
        }
    }
    if (!onlyNames.empty()) {
        printf("MP_ONLY: sadece su fonksiyonlar korunacak:");
        for (auto& x : onlyNames) printf(" %s", x.c_str());
        printf("\n");
    }

    // ---- MazeMap ac ----
    FILE* map = fopen(argv[3], "w");
    if (!map) { fprintf(stderr, "MazeMap.txt acilamadi\n"); return 2; }
    fprintf(map, "# MazeMap - i4M MazeProtector V4.3-IP (in-place sifreleme)\n");
    fprintf(map, "# MODE: %s\n", ipMethod == 2
        ? "IP2 Stream-IP: govde YERINDE sifreli; her cagrida yerinde cozulur, donuste YENI rastgele anahtarla yeniden sifrelenir"
        : "IP1 TekTek-IP: govde YERINDE sifreli; her cagrida yerinde cozulur, donuste ayni anahtarla yeniden sifrelenir");
    fprintf(map, "# Format: FUNC <isim> <fnRva> <fnSize> <cbRva> <proxyRva> <handlerRva> <seedHex> <method>\n");
    fprintf(map, "# RVA'lar ImageBase'e gore. Cheat Engine: modulBase + RVA\n");

    int okCount = 0, skipCount = 0;
    for (auto& t : targets) {
        if (!wanted(t.name)) { skipCount++; continue; }
        if (t.size < 16) {
            printf("  [ATLA] %-16s RVA 0x%X (boyut yok/cok kucuk)\n", t.name.c_str(), t.rva);
            skipCount++; continue;
        }
        MazeIP::Options opt;
        opt.fnRva = t.rva; opt.fnSize = t.size; opt.method = ipMethod;
        MazeIP::Report rep;
        if (!MazeIP::Build(c, opt, rep)) {
            printf("  [HATA] %-16s RVA 0x%X: %s\n", t.name.c_str(), t.rva, rep.err.c_str());
            skipCount++; continue;
        }
        okCount++;
        printf("  [OK-IP%d] %-16s RVA 0x%05X +%3d bayt (bas=%u, govde=%u) -> .maze 0x%05X blob=%uB CB=0x%05X proxy=0x%05X handler=0x%05X seed=%08X\n",
               ipMethod, t.name.c_str(), rep.fnRva, rep.fnSize, rep.headLen, rep.bodyLen,
               rep.mazeRva, rep.blobSize, rep.cbRva, rep.proxyRva, rep.handlerRva, rep.seed);
        for (auto& w : rep.warnings) printf("         ! %s\n", w.c_str());
        fprintf(map, "FUNC %s %u %u %u %u %u %08X %d\n",
                t.name.c_str(), rep.fnRva, rep.fnSize, rep.cbRva, rep.proxyRva, rep.handlerRva, rep.seed, ipMethod);
        fprintf(map, "IPINFO headLen=%u bodyLen=%u blobRva=0x%X blobSize=%u retsRva=0x%X crc=%08X state=depth0/lock0/enc\n",
                rep.headLen, rep.bodyLen, rep.blobRva, rep.blobSize, rep.retsRva, rep.bodyCrc);
        for (auto& w : rep.warnings) fprintf(map, "WARN %s\n", w.c_str());
    }
    fprintf(map, "# TOPLAM: %d fonksiyon korundu (IP%d), %d atlandi\n", okCount, ipMethod, skipCount);
    fclose(map);

    // ---- V4.3.1: .reloc KAPASITE KONTROLU ----
    // Head-reloc'lar proxy sayfalarina tasininca .reloc'ta YENI page-blok'lar
    // gerekir. RebuildRelocations() yalnizca mevcut .reloc raw alanina (cap =
    // eski DataDirectory Size) yazar; tasmayan bloklari SESSIZCE DUSURUR ->
    // loader proxy'deki mutlak VA'lari relocate etmez -> cakisan base'de cokes.
    // Cozum: kapasite yetmiyorsa yeni ".rloc" section ac + reloc dizinini ora tasi.
    {
        auto rels = c.pe.relocs;
        std::sort(rels.begin(), rels.end(), [](auto& a, auto& b) { return a.rva < b.rva; });
        u32 need = 0, page = 0xFFFFFFFF, cnt = 0;
        for (auto& r : rels) {
            if (r.type == 0) continue;
            u32 pg = r.rva & ~0xFFFu;
            if (pg != page) { if (cnt) need += 8 + 2 * cnt + (cnt & 1); page = pg; cnt = 0; }
            cnt++;
        }
        if (cnt) need += 8 + 2 * cnt + (cnt & 1);
        auto dos = (PIMAGE_DOS_HEADER)c.pe.raw.data();
        auto nt = (PIMAGE_NT_HEADERS)(c.pe.raw.data() + dos->e_lfanew);
        // NOT: linuxshim'de PIMAGE_NT_HEADERS = 64-bit variant -> acik cast ZORUNLU
        auto& rd = c.pe.is64 ? ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                             : ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        printf("RELOC kapasite kontrolu: need=%u rdSize=%u rdRva=0x%X relocs=%d\n",
               need, rd.Size, rd.VirtualAddress, (int)c.pe.relocs.size());
        printf("[DBG] e_lfanew=0x%X sig=0x%08X nsec=%d nRvaAndSizes=%d raw=%d dd0={0x%X,0x%X} dd1={0x%X,0x%X}\n",
               dos->e_lfanew, nt->Signature, (int)nt->FileHeader.NumberOfSections,
               (int)(c.pe.is64 ? ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.NumberOfRvaAndSizes
                               : ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.NumberOfRvaAndSizes), (int)c.pe.raw.size(),
               nt->OptionalHeader.DataDirectory[0].VirtualAddress, nt->OptionalHeader.DataDirectory[0].Size,
               nt->OptionalHeader.DataDirectory[1].VirtualAddress, nt->OptionalHeader.DataDirectory[1].Size);
        if (rd.VirtualAddress && need > rd.Size) {
            u32 rlocRva = 0, oldSz = rd.Size;
            u32 chars = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
            u32 allocSz = need + 256;   // guvenli pay
            if (MazeProtect::GrowAppendSection(c.pe, c.mem, ".rloc", allocSz, chars, rlocRva)) {
                rd.VirtualAddress = rlocRva;
                rd.Size = allocSz;
                printf("RELOC kapasitesi: gereken=%u > eski=%u -> yeni .rloc section (rva=0x%X, %uB)\n",
                       need, oldSz, rlocRva, allocSz);
            } else {
                fprintf(stderr, "UYARI: .rloc section eklenemedi -> head-reloc'lar dusme riski!\n");
            }
        } else if (rd.VirtualAddress) {
            printf("RELOC kapasitesi: gereken=%u <= mevcut=%u (ek section gerekmedi)\n", need, rd.Size);
        }
    }


    {   // DEBUG: reloc vektor durumu
        int headCnt = 0;
        for (auto& r : c.pe.relocs)
            if ((r.rva >= 0x14D0 && r.rva < 0x14D7) || (r.rva >= 0x1630 && r.rva < 0x163A)) headCnt++;
        printf("DEBUG: pe.relocs=%d adet, head-bolgesi=%d\n", (int)c.pe.relocs.size(), headCnt);
    }
    std::string saveErr;
    if (!c.pe.Save(outW.c_str(), c.mem.data.data(), c.mem.base, c.mem.data.size())) {
        fprintf(stderr, "PE kaydedilemedi\n"); return 2;
    }
    {   // checksum duzelt
        FILE* f = fopen(argv[2], "r+b");
        if (!f) { fprintf(stderr, "cikis dosyasi acilamadi\n"); return 2; }
        fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
        std::vector<u8> img((size_t)sz);
        fread(img.data(), 1, (size_t)sz, f);
        auto dos = (PIMAGE_DOS_HEADER)img.data();
        auto nt = (PIMAGE_NT_HEADERS)(img.data() + dos->e_lfanew);
        auto& sec = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        if (sec.VirtualAddress) { sec.VirtualAddress = 0; sec.Size = 0; }
        u32* pSum = &nt->OptionalHeader.CheckSum;
        u64 sumOff = (u64)((u8*)pSum - img.data());
        u32 sum = 0; size_t n = img.size();
        for (size_t i = 0; i + 1 < n; i += 2) {
            u32 v = 0;
            if (!(i == sumOff || i + 1 == sumOff)) v = img[i] | ((u32)img[i + 1] << 8);
            sum += v; sum = (sum & 0xFFFF) + (sum >> 16);
        }
        if (n & 1) { sum += img[n - 1]; sum = (sum & 0xFFFF) + (sum >> 16); }
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum += (u32)n;
        sum = (sum & 0xFFFF) + (sum >> 16);
        *pSum = sum;
        fseek(f, 0, SEEK_SET);
        fwrite(img.data(), 1, (size_t)sz, f);
        fclose(f);
    }
    printf("\n=== SONUC (IP%d): %d fonksiyon korundu, %d atlandi ===\n", ipMethod, okCount, skipCount);
    printf("Cikis: %s\nHarita: %s\n", argv[2], argv[3]);
    return okCount ? 0 : 2;
}
