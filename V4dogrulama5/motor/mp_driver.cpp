// ============================================================================
//  mp_driver.cpp - MazeProtector Linux calistirma driveri
//  Gercek engine kullanir: globals.h (Core/PEFile/MemImage) + MazeProtector.h
//  Kullanim: mp_driver <giris.exe> <cikis.exe> <MazeMap.txt>
//  Fonksiyon listesi: .gfn section (isim + adres) + .pdata (boyut)
// ============================================================================
#define _CRT_SECURE_NO_WARNINGS
#include "../download/i4MConsoleLoader/i4MConsoleLoader/globals.h"
#include "../download/i4MConsoleLoader/i4MConsoleLoader/MazeProtector.h"
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <vector>
#include <set>

// ---- CFG-tabanli fonksiyon boyutu (V4.1: .pdata guvenilmez, mingw -O2 cold
// fragment'leri .pdata'ya birlestiriyor). Baslangictan BFS: jcc iki yolu da,
// jmp hedefini takip et; call devam; ret yol bitir. Extent = max reach end.
static u32 ComputeFnSizeCFG(const Core& c, u32 fnRva) {
    auto& mem = c.mem;
    auto& dis = c.dis;
    std::vector<u64> work; std::set<u64> seen;
    u64 start = mem.base + fnRva;
    work.push_back(start); seen.insert(start);
    u64 maxEnd = 0;
    int steps = 0;
    bool dbg = getenv("MP_CFG_DEBUG") != nullptr;
    while (!work.empty()) {
        if (++steps > 4096) break;
        u64 a = work.back(); work.pop_back();
        u64 guard = 0;
        while (true) {
            if (++guard > 4096) break;
            if (a < mem.base || a >= mem.base + mem.data.size()) return 0;
            const u8* p = &mem.data[(size_t)(a - mem.base)];
            cs_insn* ins = nullptr;
            size_t n = cs_disasm(dis.handle, p, 16, a, 1, &ins);
            if (!n) { if (dbg) fprintf(stderr, "[cfg] disasm fail @ RVA 0x%X\n", (u32)(a - mem.base)); return 0; }
            u64 nxt = a + ins->size;
            if (nxt - mem.base > maxEnd) maxEnd = nxt - mem.base;
            if (dbg && (a - mem.base) > start - mem.base + 0x1300)
                fprintf(stderr, "[cfg] PENCERE-ASIMI yol: RVA 0x%X %s %s\n", (u32)(a - mem.base), ins->mnemonic, ins->op_str);
            std::string mn(ins->mnemonic);
            bool stop = false;
            if (mn == "ret" || mn == "retf" || mn == "retq") stop = true;
            else if (mn.rfind("j", 0) == 0 && mn != "jmp") {        // jcc
                if (ins->detail && ins->detail->x86.op_count == 1 && ins->detail->x86.operands[0].type == X86_OP_IMM) {
                    u64 tgt = (u64)ins->detail->x86.operands[0].imm;
                    // V4.1 pencere: 8KB disindaki hedefler (mingw -O2 cold fragment)
                    // fonksiyon extent'ine SAYILMAZ - yol sonu (plaintext kalicak)
                    if (tgt >= start && tgt - start < 8192) {
                        if (seen.insert(tgt).second) work.push_back(tgt);
                    } else if (dbg) fprintf(stderr, "[cfg] jcc pencere-disi @0x%X -> 0x%llX (takip yok)\n", (u32)(a - mem.base), (unsigned long long)tgt);
                }
            } else if (mn == "jmp") {                                // koşulsuz: sadece hedef
                if (ins->detail && ins->detail->x86.op_count == 1 && ins->detail->x86.operands[0].type == X86_OP_IMM) {
                    u64 tgt = (u64)ins->detail->x86.operands[0].imm;
                    if (tgt >= start && tgt - start < 8192) {
                        if (seen.insert(tgt).second) work.push_back(tgt);
                        cs_free(ins, 1);
                        break;  // bu yolda devam yok
                    } else { if (dbg) fprintf(stderr, "[cfg] jmp pencere-disi @0x%X -> 0x%llX (stop)\n", (u32)(a - mem.base), (unsigned long long)tgt); stop = true; }
                } else { if (dbg) fprintf(stderr, "[cfg] jmp dolayli @0x%X (stop)\n", (u32)(a - mem.base)); stop = true; }
            } else if (mn == "ud2" || mn == "int3") stop = true;
            cs_free(ins, 1);
            if (stop) break;
            a = nxt;
        }
    }
    return maxEnd ? (u32)(maxEnd - fnRva) : 0;
}

int main(int argc, char** argv) {
    if (argc < 4) { fprintf(stderr, "Kullanim: mp_driver <giris.exe> <cikis.exe> <MazeMap.txt> [arena|stream|tektek]\n"); return 2; }
    bool arenaMode = (argc > 4 && strstr(argv[4], "arena"));
    bool streamMode = false, hardened = false;
    {
        const char* m = (argc > 4) ? argv[4] : "";
        if (m && strstr(m, "stream")) { streamMode = true; hardened = true; }
        if (m && strstr(m, "tektek")) { streamMode = true; hardened = false; }
        const char* eS = getenv("MP_STREAM"); if (eS && *eS == '1') { streamMode = true; hardened = true; }
        const char* eT = getenv("MP_TEKTEK"); if (eT && *eT == '1') { streamMode = true; hardened = false; }
    }
    std::wstring inW, outW;
    for (const char* p = argv[1]; *p; p++) inW.push_back((wchar_t)*p);
    for (const char* p = argv[2]; *p; p++) outW.push_back((wchar_t)*p);

    Core c;
    if (!c.LoadFile(inW.c_str())) { fprintf(stderr, "PE yuklenemedi: %s\n", argv[1]); return 2; }
    printf("PE yuklendi: imgBase=0x%llX imgSz=0x%X section=%d reloc=%d\n",
           (unsigned long long)c.pe.imgBase, c.pe.imgSz, (int)c.pe.numSec, (int)c.pe.relocs.size());

    // ---- .pdata: fonksiyon boyutlari (Begin -> End-Begin) ----
    std::map<u32, u32> fnSizes;
    {
        const SecInfo* pd = nullptr;
        for (auto& s : c.pe.secs) if (!strcmp(s.name, ".pdata")) { pd = &s; break; }
        if (pd && pd->rawSz >= 12) {
            size_t base = pd->raw;  // mem.data RVA-uzayinda mi? mem = image kopyasi (virtual)
            base = pd->va;
            for (u32 off = 0; off + 12 <= pd->vSz; off += 12) {
                u32 beg, end;
                memcpy(&beg, &c.mem.data[base + off], 4);
                memcpy(&end, &c.mem.data[base + off + 4], 4);
                if (end > beg && end < c.pe.imgSz) fnSizes[beg] = end - beg;
            }
        }
        printf(".pdata: %d fonksiyon araligi\n", (int)fnSizes.size());
    }

    // ---- .gfn: isim + adres tablosu (PE32: 4+4 byte kayit, PE32+: 8+8) ----
    struct Target { std::string name; u32 rva; u32 size; };
    std::vector<Target> targets;
    {
        const SecInfo* gf = nullptr;
        for (auto& s : c.pe.secs) if (!strcmp(s.name, ".gfn")) { gf = &s; break; }
        if (!gf) fprintf(stderr, "UYARI: .gfn section yok (MP_RVA manuel mod kullanilabilir)\n");
        else {
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
                // V4.1: .pdata guvenilmez (mingw -O2 cold-fragment birlesimi) ->
                // CFG tabanli boyut VARSA onu kullan (fonksiyon extent'i ret'te biter)
                u32 csz = ComputeFnSizeCFG(c, rva);
                printf("  [CSZ] %-16s rva=0x%05X csz=%u pdata_sz=%u\n", name.c_str(), rva, csz, sz);
                if (csz >= 16) {
                    if (sz != csz) printf("  [INFO] %s boyut: .pdata=%u -> CFG=%u\n", name.c_str(), sz, csz);
                    sz = csz;
                } else {
                    printf("  [INFO] %s CFG basarisiz (csz=%u) -> .pdata=%u kullanilir\n", name.c_str(), csz, sz);
                }
                targets.push_back({ name, rva, sz });
            }
            printf(".gfn: %d fonksiyon kaydi\n", (int)targets.size());
        }
    }

    // ---- MP_ONLY: sadece secili fonksiyon(lar)i koru (virgulle ayri) ----
    //  Orn: MP_ONLY=MovePlayer ./mp_driver ...
    //  Hedef: sicak yolu (cizim/girdi/dongu) hic sifrelemeden oyunu akici tutmak;
    //  koruma sadece hedef fonksiyonda (tus basiminda) calisir -> maliyet ~0.
    std::vector<std::string> onlyNames;
    {
        const char* e = getenv("MP_ONLY");
        if (e && *e) {
            const char* p = e;
            while (*p) {
                const char* q = strchr(p, ',');
                if (!q) q = p + strlen(p);
                std::string n(p, (size_t)(q - p));
                // bosluklari kirp
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
    // ---- V4.1: MANUEL HEDEF MODU (PDB'siz/yabanci programlar icin) ----
    // MP_FN=Ad MP_RVA=0x1234 [MP_SIZE=auto-CFG] -> .gfn istemez, manuel kayit
    const char* eFn = getenv("MP_FN");
    const char* eRva = getenv("MP_RVA");
    if (eFn && eRva && *eRva) {
        u32 mrva = (u32)strtoul(eRva, nullptr, 0);
        u32 msz = 0;
        const char* eSz = getenv("MP_SIZE");
        if (eSz && *eSz) msz = (u32)strtoul(eSz, nullptr, 0);
        else msz = ComputeFnSizeCFG(c, mrva);   // CFG kendisi hesaplar (ret/join-jmp)
        std::string name = eFn;
        targets.push_back({ name, mrva, msz });
        printf("MANUEL HEDEF: %s rva=0x%X size=%u (CFG hesapli)\n", name.c_str(), mrva, msz);
    }
    if (!onlyNames.empty()) {
        printf("MP_ONLY: sadece su fonksiyonlar korunacak:");
        for (auto& x : onlyNames) printf(" %s", x.c_str());
        printf("\n");
    }
    const char* eDecoy = getenv("MP_DECOYS");
    int decoyChance = eDecoy ? atoi(eDecoy) : 70;

    // ---- MazeProtector: fonksiyonlari labirentle + sifrele ----
    FILE* map = fopen(argv[3], "w");
    if (!map) { fprintf(stderr, "MazeMap.txt acilamadi\n"); return 2; }
    fprintf(map, "# MazeMap - i4M MazeProtector (Jump labirenti haritasi)\n");
    fprintf(map, "# Format: FUNC <isim> <fnRva> <fnSize> <entryRva> <chunk> <jmpSayisi> sonra JMP satirlari\n");
    fprintf(map, "# RVA'lar ImageBase'e gore. Cheat Engine: modulBase + RVA\n");
    if (!onlyNames.empty()) {
        fprintf(map, "# KAPSAM: MP_ONLY - sadece ");
        for (size_t i = 0; i < onlyNames.size(); i++)
            fprintf(map, "%s%s", onlyNames[i].c_str(), i + 1 < onlyNames.size() ? "," : "");
        fprintf(map, " korundu (sicak yol plaintext: cizim/girdi/dongu sifresiz)\n");
    }
    if (arenaMode) {
        fprintf(map, "# MODE ARENA-V3: sifreli parcalar her cagride VirtualAlloc ile acilan free-mem'de\n");
        fprintf(map, "#  cozulur, ret'te VirtualFree ile SILINIR. .maze'deki JMP/parca adresleri HIC cozulmez\n");
        fprintf(map, "#  (sifreli gorunur). Cozulmus opcode'lar sadece gecici arenada yasar - CE'de gormek\n");
        fprintf(map, "#  icin tramboline BP koy, stub'a adimla, VirtualAlloc sonrasi rax = arena base.\n");
    } else if (streamMode) {
        if (hardened) {
            fprintf(map, "# MODE ARENA-V4-STREAM (god-tier, MP_STREAM): parcalar TEK TEK tek bir 32B slot'a\n");
            fprintf(map, "#  cozulur, WIPE-BEHIND oncekini siler -> her an arenada max 1 parca plaintext;\n");
            fprintf(map, "#  tam fonksiyon HICBIR an bitisik var olmaz. G1: slot her cagride rastgele adrese\n");
            fprintf(map, "#  duser (dump-replay olur). G2: CRC-8 parca butunlugu (anti-patch). G3: %%25 decoy\n");
            fprintf(map, "#  enjeksiyonu. Kenarlar .maze'deki 9B thunk'lardan gecer; duvar varsa jne alinir\n");
            fprintf(map, "#  ve px/ny parcasi o cagride HIC cozulmez (lazy cold-path).\n");
        } else {
            fprintf(map, "# MODE ARENA-V4-TEKTEK (MP_TEKTEK): ayni slot + wipe-behind; G1/G2/G3 KAPALI\n");
            fprintf(map, "#  (slot sabit adresde, CRC/decoy yok) - kullanici fikrinin duz hali.\n");
        }
    } else {
        fprintf(map, "# MODE YERINDE-V2: ilk cagri sonrasi parcalar .maze icinde YERINDE cozulur (decrypt-once).\n");
    }

    int okCount = 0, skipCount = 0, unselCount = 0, totalJmp = 0, totalDecoy = 0;
    for (auto& t : targets) {
        if (!wanted(t.name)) { unselCount++; continue; }   // MP_ONLY kapsami disi
        if (t.size < 16) {
            printf("  [ATLA] %-16s RVA 0x%X (boyut yok/cok kucuk)\n", t.name.c_str(), t.rva);
            skipCount++; continue;
        }
        MazeProtect::Options opt;
        opt.fnRva = t.rva; opt.fnSize = t.size;
        opt.chunkMax = 12;          // yogun labirent (cok sayida JMP)
        opt.encrypt = true;
        opt.decoyChance = decoyChance;
        opt.arena = arenaMode && !streamMode;
        opt.stream = streamMode;
        opt.streamHardened = streamMode && hardened;
        MazeProtect::Report rep;
        if (!MazeProtect::Build(c, opt, rep)) {
            printf("  [HATA] %-16s RVA 0x%X: %s\n", t.name.c_str(), t.rva, rep.err.c_str());
            skipCount++; continue;
        }
        okCount++;
        totalJmp += (int)rep.jmpSites.size();
        totalDecoy += rep.decoyCount;
        if (rep.streamActive) {
            printf("  [OK]   %-16s RVA 0x%05X +%3d bayt -> maze 0x%05X, %2d parca, %3d site, %d thunk, slot %uB (max parca %uB)%s\n",
                   t.name.c_str(), t.rva, t.size, rep.mazeRva, rep.streamBlocks,
                   (int)rep.streamSites, (int)rep.streamThunks, rep.slotSize, rep.maxPieceLen,
                   rep.streamSites ? "" : "");
        } else if (rep.arenaActive) {
            printf("  [OK]   %-16s RVA 0x%05X +%3d bayt -> maze 0x%05X, %2d parca, %3d JMP, ARENA ~%uB (%d site, %d cleanup)%s\n",
                   t.name.c_str(), t.rva, t.size, rep.mazeRva, rep.chunkCount,
                   (int)rep.jmpSites.size(), rep.arenaSize, (int)rep.arenaSites, (int)rep.arenaCleanup,
                   rep.warnings.size() > 2 ? "" : "");
        } else {
            printf("  [OK]   %-16s RVA 0x%05X +%3d bayt -> maze 0x%05X, %2d parca, %2d komut, %3d JMP, %d yem\n",
                   t.name.c_str(), t.rva, t.size, rep.mazeRva, rep.chunkCount, rep.insnCount,
                   (int)rep.jmpSites.size(), rep.decoyCount);
        }
        for (auto& w : rep.warnings) printf("         ! %s\n", w.c_str());
        fprintf(map, "FUNC %s %u %u %u %u %u\n", t.name.c_str(), t.rva, rep.fnSize, rep.entryRva, rep.chunkCount, (unsigned)rep.jmpSites.size());
        for (u32 js : rep.jmpSites) fprintf(map, "JMP %u\n", js);
        if (rep.streamActive)
            for (auto& s : rep.streamMap) fprintf(map, "%s\n", s.c_str());
        if (!rep.warnings.empty())
            for (auto& w : rep.warnings) fprintf(map, "WARN %s\n", w.c_str());
    }
    fprintf(map, "# TOPLAM: %d fonksiyon korundu, %d atlandi, %d kapsam-disi (MP_ONLY), %d JMP, %d yem blok\n",
            okCount, skipCount, unselCount, totalJmp, totalDecoy);
    fclose(map);

    // ---- Kaydet + checksum ----
    std::string saveErr;
    if (!c.pe.Save(outW.c_str(), c.mem.data.data(), c.mem.base, c.mem.data.size())) {
        fprintf(stderr, "PE kaydedilemedi\n"); return 2;
    }
    {
        // checksum duzelt (engine'deki ayni algoritma)
        std::string csErr;
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
    printf("\n=== SONUC: %d fonksiyon korundu, %d atlandi, %d kapsam-disi, toplam %d JMP, %d yem ===\n",
           okCount, skipCount, unselCount, totalJmp, totalDecoy);
    printf("Cikis: %s\nHarita: %s\n", argv[2], argv[3]);
    return okCount ? 0 : 2;
}
