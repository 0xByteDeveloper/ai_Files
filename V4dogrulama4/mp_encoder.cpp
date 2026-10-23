// ============================================================================
//  mp_encoder.cpp - i4M MazeProtector EVRENSEL SIFRELEYICI (komut satiri)
//  ----------------------------------------------------------------------------
//  KULLANIM:
//    mp_encoder.exe <giris.exe> <cikis.exe> <m1|m2|ip1|ip2> <start> <end|auto> [start2 end2 ...]
//
//    <start>/<end> : 0xHEX veya decimal. imgBase ile imgBase+imgSz arasinda ise
//                    VA kabul edilir (RVA'ya cevrilir), aksi halde RVA sayilir.
//                    end=auto -> BFS end-address bulucu (fonksiyon sonunu bulur,
//                    talimat sinirina snap eder).
//    m1  = V4method1 TekTek (stream, sabit slot, wipe-behind)
//    m2  = V4method2 Stream god-tier (G1 rastgele slot + G2 CRC + G3 decoy)
//    ip1 = V4.3-IP yerinde (sabit anahtar, govde .text'te sifreli)
//    ip2 = V4.3-IP yerinde + her cagrida yeni rastgele anahtar
//
//  ORNEK (Cheat Engine'den buldugun adresler):
//    mp_encoder.exe oyun.exe oyun_koruma.exe m2 0x140001158 0x140001410
//    mp_encoder.exe oyun.exe oyun_koruma.exe m1 0x1158 auto
//
//  Cikis: korumali exe + <cikis>_MazeMap.txt (RVA haritasi)
//  Not: Bu surum EXE hedefler. Ayni dosyaya ikinci kez koruma UYGULAMA.
//  ============================================================================
#include "../../i4MConsoleLoader/i4MConsoleLoader/globals.h"
#include "Motor_V4.2_MazeProtector.h"   // V4M1/V4M2 (MazeProtect::Build, GrowAppendSection)
#include "Motor_V4.3_IP.h"              // IP1/IP2 (MazeIP::Build)
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <set>
#include <map>

// ---- CFG-tabanli fonksiyon sonu bulucu (BFS; end-address) ------------------
static u32 ComputeFnSizeCFG(const Core& c, u32 fnRva, u32* endOut = nullptr) {
    auto& mem = c.mem;
    std::vector<u64> work; std::set<u64> seen;
    u64 start = mem.base + fnRva;
    work.push_back(start); seen.insert(start);
    u64 maxEnd = 0;
    int steps = 0;
    while (!work.empty()) {
        if (++steps > 8192) break;
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
                    if (tgt >= start && tgt - start < 65536) {
                        if (seen.insert(tgt).second) work.push_back(tgt);
                    }
                }
            } else if (mn == "jmp") {
                if (ins->detail && ins->detail->x86.op_count == 1 && ins->detail->x86.operands[0].type == X86_OP_IMM) {
                    u64 tgt = (u64)ins->detail->x86.operands[0].imm;
                    if (tgt >= start && tgt - start < 65536) { work.push_back(tgt); seen.insert(tgt); }
                    else stop = true;   // disari jmp (tail-jmp) -> fonksiyon sonu
                }
            }
            cs_free(ins, 1);
            if (stop) break;
            a = nxt;
        }
    }
    if (endOut) *endOut = (u32)(maxEnd - mem.base);
    return maxEnd ? (u32)(maxEnd - mem.base - fnRva) : 0;
}

// ---- araligi talimat sinirina snap et (end-address dogrusal yuruyus) --------
struct Snapped { u32 startRva, endRva; bool startAligned, endSnapped; std::string note; };
static u32 mem_lim_guard(Core& c) { return (u32)c.mem.data.size(); }
// start'tan ileri yuruyus: tum aralik talimat sinirlariyla kaplanir mi?
static bool ForwardWalk(Core& c, u32 start, u32 end, u32& lastBoundaryOut, u32& lastRetOut) {
    u32 cur = start, lastBoundary = start, lastRet = 0;
    while (cur < end) {
        cs_insn* i2 = nullptr;
        size_t n = cs_disasm(c.dis.handle, &c.mem.data[cur], 16, c.mem.base + cur, 1, &i2);
        if (!n) return false;
        u32 nxt = cur + i2[0].size;
        std::string mn(i2[0].mnemonic);
        bool isRet = (mn == "ret" || mn == "retf" || mn == "retq");
        cs_free(i2, 1);
        if (nxt > end) { lastBoundaryOut = lastBoundary; lastRetOut = lastRet; return false; }
        lastBoundary = nxt;
        if (isRet) lastRet = nxt;
        cur = nxt;
        if (cur >= mem_lim_guard(c)) return false;
    }
    lastBoundaryOut = lastBoundary; lastRetOut = lastRet;
    return true;
}
// kismi yuruyus: son talimat end'i asarsa dur, son sinira kadar olan kismi kabul et
static bool ForwardWalkPartial(Core& c, u32 start, u32 end, u32& lastBoundaryOut, u32& lastRetOut) {
    u32 cur = start, lastBoundary = start, lastRet = 0;
    while (cur < end) {
        cs_insn* i2 = nullptr;
        size_t n = cs_disasm(c.dis.handle, &c.mem.data[cur], 16, c.mem.base + cur, 1, &i2);
        if (!n) { lastBoundaryOut = lastBoundary; lastRetOut = lastRet; return lastBoundary > start; }
        u32 nxt = cur + i2[0].size;
        std::string mn(i2[0].mnemonic);
        bool isRet = (mn == "ret" || mn == "retf" || mn == "retq");
        cs_free(i2, 1);
        if (nxt > end) break;
        lastBoundary = nxt;
        if (isRet) lastRet = nxt;
        cur = nxt;
        if (cur >= mem_lim_guard(c)) break;
    }
    lastBoundaryOut = lastBoundary; lastRetOut = lastRet;
    return lastBoundary > start;
}
static bool SnapRange(Core& c, u32 start, u32 end, Snapped& out) {
    // 1) ONCE verilen start'i dene (pdata/sembol-dogru baslangiclar boyle korunur;
    //    ESKi davranis geriye kaydiriyordu ve onceki fonksiyonun ret'ini yiyordu!)
    u32 lb = 0, lr = 0;
    char nb[300];
    if (ForwardWalk(c, start, end, lb, lr)) {
        snprintf(nb, sizeof(nb), "start=0x%X aligned=EVET (ileri yuruyus %s) end=0x%X -> snapped=0x%X (son ret=0x%X, fark=%u bayt)",
                 start, (lb == end) ? "TAM" : "kismi", end, lb, lr, end - lb);
        out = { start, lb, true, (lb != end), nb };
        return lb > start;
    }
    // 2) Verilen start'tan yurunemedi -> geriye dogru talimat-basi ara (en fazla 15 bayt)
    bool startAligned = false;
    u32 s2 = start;
    for (int back = 1; back <= 15 && !startAligned; back++) {
        if ((u32)back > start) break;
        u32 t = start - back;
        if (ForwardWalk(c, t, end, lb, lr)) { s2 = t; startAligned = true; break; }
    }
    if (!startAligned) {
        // ileri yuruyus kismi olabilir (son komut end'i asiyyordu) -> mevcut start'la kirp
        if (ForwardWalkPartial(c, start, end, lb, lr)) {
            snprintf(nb, sizeof(nb), "start=0x%X aligned=EVET end=0x%X -> snapped=0x%X (son ret=0x%X, fark=%u bayt; end talimat ortasiydi)",
                     start, end, lb, lr, end - lb);
            out = { start, lb, true, true, nb };
            return lb > start;
        }
        snprintf(nb, sizeof(nb), "start=0x%X yurunemedi, end=0x%X", start, end);
        out = { start, start, false, true, nb };
        return false;
    }
    snprintf(nb, sizeof(nb), "start=0x%X -> geri-snap=0x%X aligned=EVET end=0x%X -> snapped=0x%X (son ret=0x%X)",
             start, s2, end, lb, lr);
    out = { s2, lb, true, (lb != end), nb };
    return lb > s2;
}

// ---- VA/RVA cozumleyici -----------------------------------------------------
static bool ResolveAddr(const Core& c, u64 v, const char* label, u32& rvaOut) {
    if (v >= c.pe.imgBase && v < c.pe.imgBase + c.pe.imgSz) {
        rvaOut = (u32)(v - c.pe.imgBase);
        printf("  %s: 0x%llX = VA -> RVA 0x%X\n", label, (unsigned long long)v, rvaOut);
        return true;
    }
    if (v < c.pe.imgSz) {
        rvaOut = (u32)v;
        printf("  %s: 0x%llX = RVA\n", label, (unsigned long long)v, rvaOut);
        return true;
    }
    fprintf(stderr, "HATA: %s adresi 0x%llX ne VA ne RVA (imgBase=0x%llX imgSz=0x%X)\n",
            label, (unsigned long long)v, (unsigned long long)c.pe.imgBase, c.pe.imgSz);
    return false;
}

// ---- checksum duzelt (driver43 ile ayni) ------------------------------------
static void FixChecksum(const char* path) {
    FILE* f = fopen(path, "r+b");
    if (!f) return;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    std::vector<u8> img((size_t)sz);
    if (fread(img.data(), 1, (size_t)sz, f) != (size_t)sz) { fclose(f); return; }
    auto dos = (PIMAGE_DOS_HEADER)img.data();
    auto nt = (PIMAGE_NT_HEADERS)(img.data() + dos->e_lfanew);
    auto& sec = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    if (sec.VirtualAddress || sec.Size) { sec.VirtualAddress = 0; sec.Size = 0; }
    u32* pSum = (u32*)&nt->OptionalHeader.CheckSum;
    u64 sumOff = (u64)((u8*)pSum - img.data());
    u32 sum = 0; size_t n = img.size();
    for (size_t i = 0; i + 1 < n; i += 2) {
        u32 v = 0;
        if (!(i == sumOff || i + 1 == sumOff)) v = (u32)img[i] | ((u32)img[i + 1] << 8);
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

int main(int argc, char** argv) {
    if (argc < 6) {
        fprintf(stderr,
            "i4M MazeProtector EVRENSEL SIFRELEYICI\n"
            "Kullanim:\n"
            "  mp_encoder.exe <giris.exe> <cikis.exe> <m1|m2|ip1|ip2> <start> <end|auto> [start2 end2 ...]\n"
            "Ornek:\n"
            "  mp_encoder.exe oyun.exe oyun_koruma.exe m2 0x140001158 0x140001410\n"
            "  mp_encoder.exe oyun.exe oyun_koruma.exe m1 0x1158 auto\n");
        return 2;
    }
    const char* method = argv[3];
    int mazeMethod = 0, ipMethod = 0;
    if (!strcmp(method, "m1")) mazeMethod = 1;
    else if (!strcmp(method, "m2")) mazeMethod = 2;
    else if (!strcmp(method, "ip1")) ipMethod = 1;
    else if (!strcmp(method, "ip2")) ipMethod = 2;
    else { fprintf(stderr, "HATA: metod m1|m2|ip1|ip2 olmali (verilen: %s)\n", method); return 2; }
    int pairs = (argc - 4) / 2 + ((argc - 4) % 2 ? 0 : 0);
    if ((argc - 4) % 2 != 0) { fprintf(stderr, "HATA: start/end ciftleri eksik\n"); return 2; }
    pairs = (argc - 4) / 2;

    std::wstring inW, outW;
    for (const char* p = argv[1]; *p; p++) inW.push_back((wchar_t)*p);
    for (const char* p = argv[2]; *p; p++) outW.push_back((wchar_t)*p);

    {   // ilk dosya kontrolu + bilgi (Core probe — döngüde her bolge taze yuklenir)
        Core c0;
        if (!c0.LoadFile(inW.c_str())) { fprintf(stderr, "PE yuklenemedi: %s\n", argv[1]); return 2; }
        printf("PE yuklendi: imgBase=0x%llX imgSz=0x%X arch=%s section=%d\n",
               (unsigned long long)c0.pe.imgBase, c0.pe.imgSz, c0.pe.is64 ? "x64" : "x86", (int)c0.pe.numSec);
        if (!c0.pe.is64 && mazeMethod)
            printf("BILGI: m1/m2 x86 (PE32) hedefinde x86 emitter ile kurulur (Motor_V4.2_X86)\n");
    }

    // ---- hedef araliklarini coz ----
    struct Target { std::string name; u32 rva; u32 size; };
    std::vector<Target> targets;
    for (int i = 0; i < pairs; i++) {
        u64 sv = strtoull(argv[4 + i * 2], nullptr, 0);
        u32 start;
        {
            Core c0; if (!c0.LoadFile(inW.c_str())) return 2;
            if (!ResolveAddr(c0, sv, "start", start)) return 2;
        }
        u32 size = 0;
        if (!strcmp(argv[5 + i * 2], "auto")) {
            u32 endR = 0, sz = 0;
            {
                Core c0; if (!c0.LoadFile(inW.c_str())) return 2;
                sz = ComputeFnSizeCFG(c0, start, &endR);
            }
            if (!sz) { fprintf(stderr, "HATA: end=auto bulamadi (start=0x%X) — Manuel end ver\n", start); return 2; }
            printf("  end=auto -> fonksiyon sonu RVA 0x%X (boyut=%u)\n", endR, sz);
            size = sz;
        } else {
            u64 ev = strtoull(argv[5 + i * 2], nullptr, 0);
            u32 end;
            {
                Core c0; if (!c0.LoadFile(inW.c_str())) return 2;
                if (!ResolveAddr(c0, ev, "end", end)) return 2;
                if (end <= start) { fprintf(stderr, "HATA: end <= start (0x%X <= 0x%X)\n", end, start); return 2; }
                Snapped sn;
                if (!SnapRange(c0, start, end, sn)) { fprintf(stderr, "HATA: aralik snap basarisiz\n"); return 2; }
                printf("  INSTRUCTION-AYRACI: %s\n", sn.note.c_str());
                size = sn.endRva - sn.startRva;
                start = sn.startRva;
            }
        }
        char nm[64]; snprintf(nm, sizeof(nm), "Bolge_%d_0x%X", i + 1, start);
        targets.push_back({ nm, start, size });
    }

    // ---- map dosyasi ----
    std::string mapPath = std::string(argv[2]) + "_MazeMap.txt";
    FILE* map = fopen(mapPath.c_str(), "w");
    if (!map) { fprintf(stderr, "Map dosyasi acilamadi: %s\n", mapPath.c_str()); return 2; }
    if (mazeMethod)
        fprintf(map, "# MazeMap - i4M MazeProtector V4.2 %s\n# RVA'lar ImageBase'e gore. Cheat Engine: modulBase + RVA\n",
                mazeMethod == 2 ? "V4method2 Stream god-tier (G1+G2+G3)" : "V4method1 TekTek (sabit slot, wipe-behind)");
    else
        fprintf(map, "# MazeMap - i4M MazeProtector V4.3-IP %s\n# RVA'lar ImageBase'e gore. Cheat Engine: modulBase + RVA\n",
                ipMethod == 2 ? "IP2 (her cagrida yeni anahtar)" : "IP1 (sabit anahtar)");

    int okCount = 0, skipCount = 0;
    for (int pi = 0; pi < (int)targets.size(); pi++) {
        auto& t = targets[pi];
        // IZOLASYON: her bolge icin TAZE Core — onceki Build'in yama/memory durumu
        // bir sonrakine sizmasin (cift-bölge arena-hint bozulmasinin cozumu)
        Core c;
        if (pi == 0) {
            if (!c.LoadFile(inW.c_str())) { fprintf(stderr, "PE yuklenemedi: %s\n", argv[1]); return 2; }
        } else {
            FixChecksum(argv[2]);
            if (!c.LoadFile(outW.c_str())) { fprintf(stderr, "PE yeniden yuklenemedi\n"); return 2; }
            printf("[IZOLASYON] bolge %d icin imaj taze yuklendi (imgSz=0x%X)\n", pi + 1, c.pe.imgSz);
        }
        if (t.size < 16) { printf("  [ATLA] %s RVA 0x%X (cok kucuk)\n", t.name.c_str(), t.rva); skipCount++; continue; }
        if (mazeMethod) {
            MazeProtect::Options opt;
            opt.fnRva = t.rva; opt.fnSize = t.size;
            opt.stream = true;
            opt.streamHardened = (mazeMethod == 2);
            MazeProtect::Report rep;
            if (!MazeProtect::Build(c, opt, rep)) {
                printf("  [HATA] %s RVA 0x%X +%u: %s\n", t.name.c_str(), t.rva, t.size, rep.err.c_str());
                skipCount++; continue;
            }
            okCount++;
            printf("  [OK-M%d] %s RVA 0x%05X +%u bayt -> .maze 0x%05X blob=%uB parca=%u site=%u thunk=%u entry=0x%05X\n",
                   mazeMethod, t.name.c_str(), rep.fnRva, rep.fnSize, rep.mazeRva, rep.blobBytes,
                   rep.streamBlocks, rep.streamSites, rep.streamThunks, rep.entryRva);
            for (auto& w : rep.warnings) printf("         ! %s\n", w.c_str());
            fprintf(map, "FUNC %s %u %u %u %u %u %u\n", t.name.c_str(), rep.fnRva, rep.fnSize,
                    rep.entryRva, rep.streamBlocks, rep.streamSites, rep.streamThunks);
            for (auto& s : rep.streamMap) fprintf(map, "%s\n", s.c_str());
            for (auto& w : rep.warnings) fprintf(map, "WARN %s\n", w.c_str());
        } else {
            MazeIP::Options opt;
            opt.fnRva = t.rva; opt.fnSize = t.size; opt.method = ipMethod;
            MazeIP::Report rep;
            if (!MazeIP::Build(c, opt, rep)) {
                printf("  [HATA] %s RVA 0x%X +%u: %s\n", t.name.c_str(), t.rva, t.size, rep.err.c_str());
                skipCount++; continue;
            }
            okCount++;
            printf("  [OK-IP%d] %s RVA 0x%05X +%3d bayt (bas=%u, govde=%u) -> .maze 0x%05X blob=%uB CB=0x%05X proxy=0x%05X handler=0x%05X seed=%08X\n",
                   ipMethod, t.name.c_str(), rep.fnRva, rep.fnSize, rep.headLen, rep.bodyLen,
                   rep.mazeRva, rep.blobSize, rep.cbRva, rep.proxyRva, rep.handlerRva, rep.seed);
            for (auto& w : rep.warnings) printf("         ! %s\n", w.c_str());
            fprintf(map, "FUNC %s %u %u %u %u %u %08X %d\n",
                    t.name.c_str(), rep.fnRva, rep.fnSize, rep.cbRva, rep.proxyRva, rep.handlerRva, rep.seed, ipMethod);
            fprintf(map, "IPINFO headLen=%u bodyLen=%u blobRva=0x%X blobSize=%u retsRva=0x%X crc=%08X state=depth0/lock0/enc\n",
                    rep.headLen, rep.bodyLen, rep.blobRva, rep.blobSize, rep.retsRva, rep.bodyCrc);
            for (auto& w : rep.warnings) fprintf(map, "WARN %s\n", w.c_str());
            // IP modlari: .reloc kapasite kontrolu (driver43 ile ayni)
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
                auto& rd = c.pe.is64 ? ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                                     : ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
                if (rd.VirtualAddress && need > rd.Size) {
                    u32 rlocRva = 0;
                    u32 chars = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
                    u32 allocSz = need + 256;
                    if (MazeProtect::GrowAppendSection(c.pe, c.mem, ".rloc", allocSz, chars, rlocRva)) {
                        rd.VirtualAddress = rlocRva; rd.Size = allocSz;
                        printf("RELOC kapasitesi: gereken=%u > eski=%u -> yeni .rloc section (rva=0x%X)\n", need, rd.Size, rlocRva);
                    } else fprintf(stderr, "UYARI: .rloc eklenemedi\n");
                }
            }
        }
        // her bolgeden hemen sonra kaydet (sonraki bolge taze Core ile BU dosyadan okur)
        if (okCount > 0 || pi + 1 == (int)targets.size()) {
            if (!c.pe.Save(outW.c_str(), c.mem.data.data(), c.mem.base, c.mem.data.size())) {
                fprintf(stderr, "PE kaydedilemedi: %s\n", argv[2]); return 2;
            }
        }
    }

    fclose(map);
    FixChecksum(argv[2]);
    printf("\n=== SONUC (%s): %d bolge korundu, %d atlandi ===\n", method, okCount, skipCount);
    printf("Cikis: %s\nHarita: %s\n", argv[2], mapPath.c_str());
    return okCount ? 0 : 2;
}
