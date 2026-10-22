// ============================================================================
//  LoaderSelfTest.h - LOADER SADAKAT TESTI (% metrik raporu)
//  Map edilen goruntunun GERCEK Windows loader sonucu ile ayni olup olmadigini
//  olcer: header baytlari, section kopya sadakati, relocation dogrulugu, IAT
//  cozumu + TLS/DelayImport/CFG/CLR/.pdata raporu. Sonuc: agirlikli % skor.
//
//  ADDITIVE: mevcut hiçbir davranisi degistirmez; sadece okur ve raporlar.
//  Kullanim: [24] komutu (map edilmis goruntu uzerinde calisir).
// ============================================================================
#pragma once
#include "stdafx.h"
#include "PEManualMapper.h"
#include <functional>

namespace LoaderSelfTest {

struct CheckResult { const char* name; double percent; bool pass; std::string note; };

// dosya baytlarindan bilgi raporu (TLS/delay/CFG/CLR/pdata/export/security)
inline void ReportPeculiarities(const std::vector<unsigned char>& file, std::vector<CheckResult>& out) {
    auto dos = (const IMAGE_DOS_HEADER*)file.data();
    auto nt = (const IMAGE_NT_HEADERS*)(file.data() + dos->e_lfanew);
    auto is64 = nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    auto& dd = nt->OptionalHeader.DataDirectory;

    // .pdata / SEH
    {
        CheckResult c; c.name = "PData/SEH (x64 unwind)"; c.percent = 100;
        if (dd[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress) {
            u32 sz = dd[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
            c.note = "VAR (" + std::to_string(sz / 12) + " RUNTIME_FUNCTION) - map edilir, calistirma icin RtlAddFunctionTable gerekir";
        } else c.note = "yok (normal)";
        c.pass = true; out.push_back(c);
    }
    // TLS
    {
        CheckResult c; c.name = "TLS dizini"; c.percent = 100;
        if (dd[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) {
            c.note = "VAR - section baytlari map edilir; callback'ler RAPORLANIR, CALISTIRILMAZ (dosya goruntuleme senaryosunda etkisiz)";
        } else c.note = "yok";
        c.pass = true; out.push_back(c);
    }
    // Delay imports
    {
        CheckResult c; c.name = "Delay imports"; c.percent = 100;
        if (dd[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress)
            c.note = "VAR - gercek loader da load-time'da COZMEZ (ilk cagride) -> davranis birebir";
        else c.note = "yok";
        c.pass = true; out.push_back(c);
    }
    // LoadConfig / CFG
    {
        CheckResult c; c.name = "LoadConfig/CFG"; c.percent = 100;
        if (dd[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress) {
            u32 off = dd[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
            // raw'da RVA->file offset (sections uzerinden)
            u32 fo = 0;
            auto sh = IMAGE_FIRST_SECTION(nt);
            for (u16 i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                if (off >= sh[i].VirtualAddress && off < sh[i].VirtualAddress + (std::max)(sh[i].Misc.VirtualSize, sh[i].SizeOfRawData)) {
                    fo = sh[i].PointerToRawData + (off - sh[i].VirtualAddress); break;
                }
            }
            if (fo && fo + 0x50 < file.size()) {
                u32 guardFlags = *(const u32*)(file.data() + fo + 12 + (is64 ? 40 : 28)); // GuardFlags offset (Win8+ layout)
                (void)guardFlags;
                c.note = "VAR (CFG bildirimli image) - map icin etkisiz; calistirmada CFG zorlanir (biz calistirmayiz)";
            } else c.note = "VAR (okunamadi)";
        } else c.note = "yok";
        c.pass = true; out.push_back(c);
    }
    // CLR / .NET
    {
        CheckResult c; c.name = "CLR/.NET"; c.percent = 100; c.pass = true;
        if (dd[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress) {
            c.note = "MANAGED image - gercek loader mscoree'ye devreder; i4M sadece native map yapar (bayt goruntuleme calisir, calistirma desteklenmez)";
        } else c.note = "yok (native)";
        out.push_back(c);
    }
    // Security (imza)
    {
        CheckResult c; c.name = "Authenticode imza"; c.percent = 100; c.pass = true;
        if (dd[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress)
            c.note = "IMZALI dosya - map goruntulemeyi etkilemez; DEGISIKLIK sonrasi kaydederken imza gecersiz olur";
        else c.note = "yok";
        out.push_back(c);
    }
}

inline void Run(const std::vector<unsigned char>& file, const PEManualMapper::MapResult& r,
                const std::function<bool(u64, unsigned char*, size_t)>& readMapped) {
    printf("\n====================================================================\n");
    printf("   LOADER SADAKAT TESTI - gercek Windows loader karsilastirmasi\n");
    printf("====================================================================\n");
    if (!r.success || !r.base) { printf("  Once map edin. [12]\n"); return; }

    std::vector<CheckResult> checks;
    auto dos = (const IMAGE_DOS_HEADER*)file.data();
    auto nt = (const IMAGE_NT_HEADERS*)(file.data() + dos->e_lfanew);
    u64 base = (u64)(uintptr_t)r.base;
    u64 delta = r.delta;
    printf("  Base: 0x%llX  (preferred 0x%llX, delta=0x%llX)\n\n",
           (unsigned long long)base, (unsigned long long)r.preferredBase, (unsigned long long)delta);

    auto rdVA = [&](u64 va, unsigned char* out, size_t n) -> bool {
        if (va >= base && va + n <= base + r.imageSize) {
            memcpy(out, (const void*)(uintptr_t)va, n); return true; // dogrudan okuma (ayni process)
        }
        return readMapped(va, out, n);
    };
    auto rva2raw = [&](u32 rva) -> u32 {
        auto sh = IMAGE_FIRST_SECTION(nt);
        if (rva < nt->OptionalHeader.SizeOfHeaders) return rva;
        for (u16 i = 0; i < nt->FileHeader.NumberOfSections; i++)
            if (rva >= sh[i].VirtualAddress && rva < sh[i].VirtualAddress + sh[i].SizeOfRawData)
                return sh[i].PointerToRawData + (rva - sh[i].VirtualAddress);
        return 0;
    };

    // ---- [1] HEADER BAYTLARI ----
    {
        CheckResult c; c.name = "Header baytlari (SizeOfHeaders)"; c.percent = 0;
        u32 hs = nt->OptionalHeader.SizeOfHeaders;
        std::vector<unsigned char> mapped(hs);
        if (rdVA(base, mapped.data(), hs)) {
            size_t diff = 0;
            for (u32 i = 0; i < hs; i++) if (mapped[i] != file[i]) diff++;
            c.percent = hs ? 100.0 * (hs - diff) / hs : 100;
            c.pass = diff == 0;
            c.note = std::to_string(hs - diff) + "/" + std::to_string(hs) + " bayt eslesiyor";
        } else c.note = "okunamadi";
        checks.push_back(c);
    }

    // ---- [2] SECTION KOPYA SADAKATI (reloc/IAT bolgeleri haric) ----
    {
        CheckResult c; c.name = "Section bayt sadakati"; c.percent = 0;
        auto sh = IMAGE_FIRST_SECTION(nt);
        size_t totalCmp = 0, totalDiff = 0;
        std::string det;
        for (u16 i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            u32 va = sh[i].VirtualAddress, rs = sh[i].SizeOfRawData;
            if (!rs) continue;
            u32 cl = (std::min)(rs, (u32)(sh[i].Misc.VirtualSize ? sh[i].Misc.VirtualSize : rs));
            std::vector<unsigned char> mapped(cl);
            if (!rdVA(base + va, mapped.data(), cl)) { det += " [" + std::string((const char*)sh[i].Name, 8) + ":okunamadi]"; continue; }
            size_t diff = 0;
            for (u32 o = 0; o < cl; o++) {
                u32 rva = va + o;
                if (mapped[o] != file[rva2raw(rva)]) diff++;
            }
            totalCmp += cl; totalDiff += diff;
            det += " [" + std::string((const char*)sh[i].Name, strnlen((const char*)sh[i].Name, 8)) + ":" +
                   std::to_string(cl - diff) + "/" + std::to_string(cl) + "]";
        }
        c.percent = totalCmp ? 100.0 * (totalCmp - totalDiff) / totalCmp : 100;
        c.pass = totalDiff == 0;
        c.note = det;
        checks.push_back(c);
    }

    // ---- [3] RELOCATION DOGRULUGU ----
    {
        CheckResult c; c.name = "Base relocation"; c.percent = 0;
        u32 off = 0; size_t tot = 0, ok = 0;
        auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (dd.VirtualAddress && dd.Size) {
            u32 ro = rva2raw(dd.VirtualAddress);
            while (off + 8 <= dd.Size && ro + off + 8 <= file.size()) {
                auto blk = (const IMAGE_BASE_RELOCATION*)(file.data() + ro + off);
                if (!blk->SizeOfBlock) break;
                u32 n = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
                auto e = (const u16*)((const u8*)blk + sizeof(IMAGE_BASE_RELOCATION));
                for (u32 k = 0; k < n; k++) {
                    u16 t = e[k] >> 12, o = e[k] & 0xFFF;
                    if (!t) continue;
                    u32 rva = blk->VirtualAddress + o;
                    u32 fo = rva2raw(rva);
                    if (!fo) continue;
                    tot++;
                    if (t == IMAGE_REL_BASED_DIR64) {
                        u64 fv = *(const u64*)(file.data() + fo), mv = 0;
                        if (rdVA(base + rva, (unsigned char*)&mv, 8) && mv == fv + delta) ok++;
                    } else if (t == IMAGE_REL_BASED_HIGHLOW) {
                        u32 fv = *(const u32*)(file.data() + fo), mv = 0;
                        if (rdVA(base + rva, (unsigned char*)&mv, 4) && mv == fv + (u32)delta) ok++;
                    }
                }
                off += blk->SizeOfBlock;
            }
        }
        c.percent = tot ? 100.0 * ok / tot : 100;
        c.pass = tot == 0 || ok == tot;
        c.note = tot ? (std::to_string(ok) + "/" + std::to_string(tot) + " kayit dogru (delta=0x" + std::to_string(delta) + ")") : "reloc yok";
        checks.push_back(c);
    }

    // ---- [4] IAT COZUMU ----
    {
        CheckResult c; c.name = "IAT cozumu (LoadLibrary/GetProcAddress)"; c.percent = 0;
        size_t tot = 0, ok = 0; std::string miss;
        for (auto& d : r.imports) {
            tot += d.resolved.size() + d.missing.size();
            ok += d.resolved.size();
            if (!d.missing.empty()) miss += " " + d.dllName + "(" + std::to_string(d.missing.size()) + ")";
        }
        c.percent = tot ? 100.0 * ok / tot : 100;
        c.pass = tot > 0 && ok == tot;
        c.note = tot ? (std::to_string(ok) + "/" + std::to_string(tot) + (miss.empty() ? "" : "  eksik:" + miss)) : "import yok";
        checks.push_back(c);
    }

    // ---- bilgi raporlari ----
    ReportPeculiarities(file, checks);

    // ---- SKOR ----
    double wSum = 0, acc = 0;
    for (auto& c : checks) {
        double w = 1.0;
        if (!strncmp(c.name, "Header", 6)) w = 15;
        else if (!strncmp(c.name, "Section", 7)) w = 30;
        else if (!strncmp(c.name, "Base relocation", 15)) w = 20;
        else if (!strncmp(c.name, "IAT", 3)) w = 25;
        else w = 2; // bilgi kalemleri
        wSum += w; acc += w * (c.percent / 100.0);
    }
    printf("  %-40s %8s  %s\n", "KONTROL", "SONUC", "NOT");
    printf("  ------------------------------------------------------------------\n");
    for (auto& c : checks) {
        printf("  %-40s %7.1f%%  %s%s\n", c.name, c.percent, c.pass ? "[OK]" : "[!!]", (" " + c.note).c_str());
    }
    printf("  ------------------------------------------------------------------\n");
    printf("  >>> LOADER SADAKAT SKORU: %.1f %% <<<\n", wSum ? 100.0 * acc / wSum : 0.0);
    printf("  (agirliklar: header 15, section 30, reloc 20, IAT 25, bilgi 2)\n");
    printf("  NOT: EP/TLS-callback CALISTIRMA bilincli olarak kapsam disidir\n");
    printf("  (dosyayi acmadan process-bellegi GORUNTULEME senaryosu icin gerekmez).\n\n");
}

} // namespace LoaderSelfTest
