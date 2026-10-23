// ============================================================================
//  mp_encoder.cpp - i4M MazeProtector EVRENSEL SIFRELEYICI (komut satiri) V4.5
//  ----------------------------------------------------------------------------
//  KULLANIM:
//    mp_encoder.exe <giris.exe> <cikis.exe> <m1|m2|ip1|ip2> <start> <end|auto> [start2 end2 ...]
//    mp_encoder.exe <giris.exe> <cikis.exe> <m1|m2|ip1|ip2> FN <hint-adres>
//
//    <start>/<end> : 0x'li veya ciplak HEX (E7B9E gibi) ya da decimal.
//                    imgBase ile imgBase+imgSz arasinda ise VA kabul edilir
//                    (RVA'ya cevrilir), aksi halde RVA sayilir.
//                    end=auto -> BFS end-address bulucu (fonksiyon sonunu bulur,
//                    talimat sinirina snap eder).
//    FN <hint>     : adresin FONKSIYON ICINDE oldugunu biliyorsan ama basini
//                    bilmiyorsan: FN modu geriye dogru ret+dolgu (int3/nop)
//                    sinirini arar, butun fonksiyonu bastan sona korur.
//    m1  = V4method1 TekTek (stream, sabit slot, wipe-behind)
//    m2  = V4method2 Stream god-tier (G1 rastgele slot + G2 CRC + G3 decoy)
//    ip1 = V4.3-IP yerinde (sabit anahtar, govde .text'te sifreli)
//    ip2 = V4.3-IP yerinde + her cagrida yeni rastgele anahtar
//
//  V4.5 NOT (ASLR / reloc): govdede mutlak adres (reloc kayitli VA) varsa m1/m2
//  artik REDDETMEZ — cikis PE'sinde DYNAMICBASE temizlenir (ASLR kapali): image
//  tercih-edilen base'de yuklenir, mutlak adresler gecerli kalir, loader sifreli
//  bolgeye dokunmaz. (ASLR'li buyuk oyun client'lari icin: metin2 tarzi)
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
#include <cctype>
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
    // V4.4.1 FIX: maxEnd ZATEN relative (nxt - mem.base ile birikir).
    // Eski kod burada mem.base'i bir DAHA dusuyor -> (u32) sarmasiyla
    // 0xC000150B gibi cop end adresi donuyor, auto modu her seferinde
    // "bölge çok büyük" deyip atliyordu. Dogrusu: dogrudan maxEnd kullan.
    if (endOut) *endOut = (u32)maxEnd;
    return maxEnd ? (u32)(maxEnd - fnRva) : 0;
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
// V4.4.1 FIX: bare-hex girisi ("14A4" gibi, disassembler'dan yapistirilan)
// strtoull(,,0) ile SESSIZCE 14'e dusuyor ('A'de kesiyor) -> PE header'larinda
// gezen bos BFS. Once base-0 (0x onekli hex / decimal) TAM parse dene;
// kismi kaldysa HEX olarak tamamla; o da olmadiysa hatayi bildir.
static bool ParseAddr(const char* s, u64& out) {
    if (!s || !*s) return false;
    char* end = nullptr;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {          // 0x... -> hex
        u64 v = strtoull(s + 2, &end, 16);
        if (end && *end == '\0' && end != s + 2) { out = v; return true; }
        return false;
    }
    // V4.5: ciplak giris DAIMA HEX (Cheat Engine gelenegi): "E7B9E", "14A4",
    // "1523" hepsi hex; decimal gerekirse 0x... kullanimi yoksa "0d" oneki:
    if (s[0] == '0' && (s[1] == 'd' || s[1] == 'D')) {          // 0d... -> decimal
        u64 v = strtoull(s + 2, &end, 10);
        if (end && *end == '\0' && end != s + 2) { out = v; return true; }
        return false;
    }
    u64 v = strtoull(s, &end, 16);
    if (end && *end == '\0') { out = v; return true; }
    return false;
}

static bool EqNI(const char* a, const char* b) {
    while (*a && *b) {
        char x = (char)tolower((unsigned char)*a), y = (char)tolower((unsigned char)*b);
        if (x != y) return false;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

// ---- V4.5: FN modu - fonksiyon basi bulucu ---------------------------------
// [from, to) araligi tamamen dolgu mu (int3 / nop / genisletilmis nop)?
static bool AllPadding(Core& c, u32 from, u32 to) {
    u32 p = from;
    while (p < to) {
        size_t rm = (size_t)(c.mem.data.size() - p);
        if (!rm) return false;
        cs_insn* i0 = nullptr;
        size_t n = cs_disasm(c.dis.handle, &c.mem.data[p], (std::min)(rm, (size_t)16), c.mem.base + p, 1, &i0);
        if (!n) return false;
        bool pad = !strcmp(i0[0].mnemonic, "nop") || !strcmp(i0[0].mnemonic, "int3");
        u32 sz = (u32)i0[0].size;
        cs_free(i0, 1);
        if (!pad) return false;
        p += sz;
    }
    return p == to;
}

// hint (fonksiyonun icinde bilinen bir adres) -> fonksiyonun GERCEK basi.
// YONTEM-1 (MSVC / metin2 tarzi): hint'ten geriye SON int3 (0xCC) dolgu baytini
// bul; fonksiyon basi = son CC+1 (ardindan varsa hizalama-nop'larini atla).
// Gereklilik: [aday, hint) ileri yuruyusle komut sinirlarindan kapsanmali.
// YONTEM-2 (GCC): ret (C3/C2) + ardindan nop/int3 dolgu run'i + fonksiyon basi.
static bool FindFunctionStart(Core& c, u32 hint, u32& startOut, std::string& note) {
    if (hint == 0 || hint >= c.mem.data.size()) return false;
    u32 floorRva = hint > 0x40000 ? hint - 0x40000 : 0;
    auto isNopish = [&](u8 b) { return b == 0x90 || b == 0xCC; };
    // ---- YONTEM-1: son 0xCC ----
    for (u32 q = hint; q-- > floorRva; ) {
        if (c.mem.data[q] != 0xCC) continue;
        // hint ile bu CC arasinda BASKA CC olmamali (en yakin CC bu olmali)
        bool closer = false;
        for (u32 p = q + 1; p < hint; p++) if (c.mem.data[p] == 0xCC) { closer = true; break; }
        if (closer) continue;
        u32 cand = q + 1;
        while (cand < hint) {   // hizalama dolgusunu atla (90/CC + coklu-bayt nop'lar)
            cs_insn* np = nullptr;
            size_t nn = cs_disasm(c.dis.handle, &c.mem.data[cand], 16, c.mem.base + cand, 1, &np);
            if (!nn) break;
            bool isNop = !strcmp(np[0].mnemonic, "nop") || !strcmp(np[0].mnemonic, "int3");
            u32 nsz = (u32)np[0].size;
            cs_free(np, 1);
            if (!isNop || nsz == 0) break;
            cand += nsz;
        }
        if (cand >= hint) continue;
        u32 lb = 0, lr = 0;
        if (!ForwardWalk(c, cand, hint, lb, lr)) continue;
        cs_insn* t0 = nullptr;
        if (!cs_disasm(c.dis.handle, &c.mem.data[hint], 16, c.mem.base + hint, 1, &t0)) continue;
        cs_free(t0, 1);
        char nb[128];
        snprintf(nb, sizeof(nb), "FN: int3-dolgu sonu 0x%X -> fonksiyon basi 0x%X (MSVC duzeni)", q, cand);
        startOut = cand; note = nb; return true;
    }
    // ---- YONTEM-2: ret + dolgu ----
    for (u32 q = hint; q-- > floorRva; ) {
        u8 b = c.mem.data[q];
        u32 retLen = 0;
        if (b == 0xC3) retLen = 1;
        else if (b == 0xC2 && q + 3 <= c.mem.data.size()) retLen = 3;
        else continue;
        u32 padStart = q + retLen;
        u32 k = padStart;
        while (k < hint && isNopish(c.mem.data[k])) k++;
        if (k == padStart || k >= hint) continue;             // dolgu run'i bos/tek-gecer
        u32 cand = k;
        u32 lb = 0, lr = 0;
        if (!ForwardWalk(c, cand, hint, lb, lr)) continue;
        cs_insn* t0 = nullptr;
        if (!cs_disasm(c.dis.handle, &c.mem.data[hint], 16, c.mem.base + hint, 1, &t0)) continue;
        cs_free(t0, 1);
        char nb[128];
        snprintf(nb, sizeof(nb), "FN: ret@0x%X + dolgu -> fonksiyon basi 0x%X", q, cand);
        startOut = cand; note = nb; return true;
    }
    return false;
}

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
            "i4M MazeProtector EVRENSEL SIFRELEYICI V4.5\n"
            "Kullanim:\n"
            "  mp_encoder.exe <giris.exe> <cikis.exe> <m1|m2|ip1|ip2> <start> <end|auto> [start2 end2 ...]\n"
            "  mp_encoder.exe <giris.exe> <cikis.exe> <m1|m2|ip1|ip2> FN <fonksiyon-ici-adres>\n"
            "Ornek:\n"
            "  mp_encoder.exe oyun.exe oyun_koruma.exe m2 0x140001158 0x140001410\n"
            "  mp_encoder.exe oyun.exe oyun_koruma.exe m1 0x1158 auto\n"
            "  mp_encoder.exe oyun.exe oyun_koruma.exe m2 FN 0xE7B9E   (fonksiyonun ortasindan bile butun fonksiyonu korur)\n"
            "Not: adresler 0x'li veya ciplak hex (E7B9E) olabilir; VA/RVA otomatik anlasilir.\n");
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
        if (!c0.pe.is64 && mazeMethod) {
            // ---- V4.5: x86 hedefte m1/m2 -> kanitli V4.3-IP motoruna OTOMATIK YONLENDIRME ----
            // Gerekce: V4.2-X86 stream motorunun runtime yolu (parca-arasi register
            // tasiyici veda/clDispatch hatti) kararsiz — unicorn izinde EAX sonucu
            // bozuk + wine32'de m1 dhangi/m2 segfault; IP motoru ise T1_32 + MiniGameDll
            // uzerinde wine32'de 11/11 hash birebir kanitli. Kullanici istegi
            // "bolum korunsun, ASLA cokmesin" -> x86'da IP motoru kullan.
            printf("BILGI: x86 (PE32) hedefte %s istendi -> V4.5 bunu V4.3-IP motoru (ip%d) ile kurar\n",
                   mazeMethod == 2 ? "m2 (V4method2)" : "m1 (V4method1)", mazeMethod);
            printf("      (gerekce: x86 stream motoru runtime-kararsiz; IP motoru wine32'de birebir kanitli,\n");
            printf("       yerinde sifreleme + reloc-guvenli + VirtualAlloc ISTEMEZ)\n");
            ipMethod = mazeMethod;   // m1->ip1 (sabit), m2->ip2 (her cagrida yeni anahtar)
            mazeMethod = 0;
        }
    }

    // ---- hedef araliklarini coz ----
    struct Target { std::string name; u32 rva; u32 size; };
    std::vector<Target> targets;
    for (int i = 0; i < pairs; i++) {
        u32 size = 0;
        if (EqNI(argv[4 + i * 2], "FN") || EqNI(argv[5 + i * 2], "FN")) {
            // ---- V4.5 FN MODU: hint fonksiyonun ICINDE; basi ve sonu biz buluruz ----
            u32 start = 0;
            const char* hintTok = EqNI(argv[4 + i * 2], "FN") ? argv[5 + i * 2] : argv[4 + i * 2];
            u64 hv = 0;
            if (!ParseAddr(hintTok, hv)) {
                fprintf(stderr, "HATA: FN hint adresi cozulemedi: '%s' (ornek: FN 0xE7B9E veya FN E7B9E)\n", hintTok);
                return 2;
            }
            u32 hint = 0;
            {
                Core c0; if (!c0.LoadFile(inW.c_str())) return 2;
                if (!ResolveAddr(c0, hv, "FN-hint", hint)) return 2;
                u32 fs = 0; std::string fnNote;
                if (!FindFunctionStart(c0, hint, fs, fnNote)) {
                    fprintf(stderr, "HATA: FN fonksiyon basini bulamadi (hint=0x%X). Manuel start/end ver.\n", hint);
                    return 2;
                }
                printf("  %s\n", fnNote.c_str());
                u32 endR = 0, sz2 = 0;
                sz2 = ComputeFnSizeCFG(c0, fs, &endR);
                if (!sz2) {
                    fprintf(stderr, "HATA: FN sonrasi end=auto bulamadi (fonksiyon basi=0x%X). Manuel end ver.\n", fs);
                    return 2;
                }
                Snapped snA;
                if (!SnapRange(c0, fs, endR, snA)) {
                    fprintf(stderr, "HATA: FN araligi snap edilemedi (basi=0x%X end=0x%X)\n", fs, endR);
                    return 2;
                }
                printf("  FN -> fonksiyon RVA 0x%X .. 0x%X (boyut=%u bayt)\n", snA.startRva, snA.endRva, snA.endRva - snA.startRva);
                {   // GUVENLI-RED: bolge icinde fonksiyonlar-arasi dolgu siniri (2+ CC) varsa
                    // BFS iki fonksiyonu birlestirmis demektir -> cokme riski, reddet
                    bool span = false;
                    for (u32 p = snA.startRva; p + 1 < snA.endRva; p++)
                        if (c0.mem.data[p] == 0xCC && c0.mem.data[p + 1] == 0xCC) { span = true; break; }
                    if (span) {
                        fprintf(stderr, "HATA: FN bolgesi fonksiyonlar-arasi dolgu (int3) iceriyor - iki fonksiyon birlesti. Manuel start/end ver.\n");
                        return 2;
                    }
                }
                start = snA.startRva; size = snA.endRva - snA.startRva;
            }
            char nm[64]; snprintf(nm, sizeof(nm), "Bolge_%d_0x%X", i + 1, start);
            targets.push_back({ nm, start, size });
            continue;
        }
        u64 sv = 0;
        if (!ParseAddr(argv[4 + i * 2], sv)) {
            fprintf(stderr, "HATA: start adresi cozulemedi: '%s' (ornek: 0x14A4, 14A4 veya FN 14A4)\n", argv[4 + i * 2]);
            return 2;
        }
        u32 start;
        {
            Core c0; if (!c0.LoadFile(inW.c_str())) return 2;
            if (!ResolveAddr(c0, sv, "start", start)) return 2;
        }
        if (!strcmp(argv[5 + i * 2], "auto")) {
            u32 endR = 0, sz = 0;
            {
                Core c0; if (!c0.LoadFile(inW.c_str())) return 2;
                sz = ComputeFnSizeCFG(c0, start, &endR);
            }
            if (!sz) { fprintf(stderr, "HATA: end=auto bulamadi (start=0x%X) — Manuel end ver\n", start); return 2; }
            // V4.4.1: auto sonucu da instruction-sinirina snap et + start hizasini dogrula
            {
                Core c0; if (!c0.LoadFile(inW.c_str())) return 2;
                Snapped snA;
                if (!SnapRange(c0, start, endR, snA)) {
                    fprintf(stderr, "HATA: end=auto araligi snap edilemedi (start=0x%X end=0x%X)\n", start, endR);
                    return 2;
                }
                printf("  end=auto -> fonksiyon sonu RVA 0x%X (boyut=%u) %s\n", snA.endRva, snA.endRva - snA.startRva,
                       snA.startAligned ? "start-aligned=EVET" : "[start geriye snap edildi]");
                start = snA.startRva; size = snA.endRva - snA.startRva;
            }
        } else {
            u64 ev = 0;
            if (!ParseAddr(argv[5 + i * 2], ev)) {
                fprintf(stderr, "HATA: end adresi cozulemedi: '%s' (ornek: 0x150B, 150B veya auto)\n", argv[5 + i * 2]);
                return 2;
            }
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
    bool stripAslrUsed = false;
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
        if (t.size < 16) {
            printf("  [ATLA] %s RVA 0x%X (%u bayt < 16) - cok kucuk; FN modu ile BUTUN fonksiyonu korumayi dene\n",
                   t.name.c_str(), t.rva, t.size);
            skipCount++; continue;
        }
        if (mazeMethod) {
            MazeProtect::Options opt;
            opt.fnRva = t.rva; opt.fnSize = t.size;
            opt.stream = true;
            opt.streamHardened = (mazeMethod == 2);
            {   // V4.5: govdede reloc'lu mutlak adres varsa izin + cikista ASLR kapat
                for (auto& r : c.pe.relocs) {
                    if (r.rva + 8 > t.rva && r.rva < t.rva + t.size) {
                        opt.allowRelocBody = true;
                        stripAslrUsed = true;
                        printf("  BILGI: govdede mutlak adres (reloc RVA 0x%X) -> cikista ASLR kapatilacak (DYNAMICBASE temizlenir)\n", r.rva);
                        break;
                    }
                }
            }
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
            {   // V4.5: govdede E8 cagrisi varsa ip kullanicisini uyar (x64 IP+cagri kombinasyonu sinirli dogrulandi)
                bool hasCall = false;
                for (u32 p = t.rva; p + 5 <= t.rva + t.size; p++) {
                    if (c.mem.data[p] == 0xE8) {
                        i32 rel = (i32)((u32)c.mem.data[p+1] | ((u32)c.mem.data[p+2]<<8) | ((u32)c.mem.data[p+3]<<16) | ((u32)c.mem.data[p+4]<<24));
                        u64 tgt = (u64)p + 5 + rel;
                        if (tgt >= c.mem.base && tgt < c.mem.base + c.mem.data.size()) { hasCall = true; break; }
                    }
                }
                if (hasCall && c.pe.is64)
                    printf("  UYARI: govde E8 cagrisi iceriyor - x64 IP motorunda cagri kombinasyonu sinirli dogrulandi; ciktiyi baseline ile karsilastir (x86'da sorun yok)\n");
            }
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
    if (stripAslrUsed) {
        fprintf(map, "ASLR KAPALI: DYNAMICBASE temizlendi (govdelerinde mutlak adres olan fonksiyonlar tercih-edilen base'i bekler)\n");
        printf("ASLR: cikista DYNAMICBASE temizlendi (reloc'lu govde kurallari)\n");
    }
    if (!okCount) {
        remove(argv[2]);   // V4.4.1: 0 bolge korunduysa cikis dosyasi yazilma (yalanci "korumali" olmasin)
        remove(mapPath.c_str());
        fprintf(stderr, "HIC bolge korunamadi -> cikis dosyasi YAZILMADI. Girisi ve adresleri kontrol et.\n");
        return 2;
    }
    FixChecksum(argv[2]);
    printf("\n=== SONUC (%s): %d bolge korundu, %d atlandi ===\n", method, okCount, skipCount);
    printf("Cikis: %s\nHarita: %s\n", argv[2], mapPath.c_str());
    return 0;
}
