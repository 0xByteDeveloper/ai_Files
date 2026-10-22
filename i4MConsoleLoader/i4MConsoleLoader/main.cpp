// ============================================================================
//  i4M Console Loader - main.cpp
//  ImGui/D3D11 arayuzu tamamen kaldirildi; eski GUI projesinin TUM cekirdek
//  motoru (globals.h + InstanceManager.h) korunarak konsola tasinmistir.
//
//  Windows'un "dosyayi acmadan process bellegine cevirme" yontemi
//  ayri bir dosyada izole edildi: PEManualMapper.h
//  (main.cpp buradan kontrol eder: g_mapper.options + MapFile/MapMemory/Unmap)
// ============================================================================
#include "stdafx.h"
#include "globals.h"
#include "InstanceManager.h"
#include "PEManualMapper.h"
#include <conio.h>

// ---- GLOBAL DURUM ----------------------------------------------------------

static Core g_core;                          // dosya modu (PEFile+MemImage+Disasm+...)
static PEManualMapper g_mapper;              // Windows loader emulasyonu
static PEManualMapper::MapResult g_map;      // map edilmis goruntu
static std::string g_procId;                 // bagli process instance id
static ByteInjector g_injector;              // kod enjeksiyonu

// ---- KONSOL YARDIMCILARI ----------------------------------------------------

static void Color(WORD attr) { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), attr); }
static void Gray()  { Color(8); }
static void White() { Color(7); }
static void Green() { Color(10); }
static void Red()   { Color(12); }
static void Cyan()  { Color(11); }
static void Yellow(){ Color(14); }

static void Pause() {
    Gray(); printf("\n  Devam etmek icin bir tusa basin..."); White();
    _getch(); printf("\n");
}

static std::string ReadLine() {
    char buf[4096];
    if (!fgets(buf, sizeof(buf), stdin)) return "";
    std::string s = buf;
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
    return s;
}

// hex adres okuma: "0x140001000", "140001000", "rva:1000" (map base + rva)
static bool ParseAddr(const std::string& in, u64& out) {
    std::string s = in; for (auto& c : s) c = (char)tolower(c);
    if (s.empty()) return false;
    if (s.rfind("rva:", 0) == 0) {
        u64 r = strtoull(s.c_str() + 4, nullptr, 16);
        out = g_core.mem.base + r; return true;
    }
    if (s.rfind("0x", 0) == 0) s = s.substr(2);
    if (s.empty()) return false;
    char* e = nullptr;
    out = strtoull(s.c_str(), &e, 16);
    return e && *e == 0;
}

static u64 PromptAddr(const char* msg) {
    printf("  %s (hex, orn: 140001000): ", msg);
    std::string s = ReadLine();
    u64 a = 0;
    if (!ParseAddr(s, a)) { Red(); printf("  Gecersiz adres!\n"); White(); return 0; }
    return a;
}

static u64 PromptNum(const char* msg) {
    printf("  %s: ", msg);
    std::string s = ReadLine();
    char* e = nullptr;
    u64 v = strtoull(s.c_str(), &e, 0); // 0x veya ondalik
    return (e && *e == 0) ? v : 0;
}

static std::wstring PromptPath(const char* msg, bool forSave) {
    printf("  %s: ", msg);
    std::string s = ReadLine();
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') s = s.substr(1, s.size() - 2);
    if (s.empty()) return L"";
    if (forSave && s.find('.') == std::string::npos) s += ".bin";
    return std::wstring(s.begin(), s.end());
}

// ---- ORTAK CIKTI YARDIMCILARI -----------------------------------------------

static void HexDumpBuf(const u8* buf, u64 addr, size_t size, size_t maxRows) {
    size_t totalRows = (size + 15) / 16, shown = 0;
    for (size_t off = 0; off < size && shown < maxRows; off += 16, shown++) {
        printf("  %016llX  ", (unsigned long long)(addr + off));
        size_t n = (16 < size - off) ? 16 : (size - off);
        for (size_t i = 0; i < 16; i++) {
            if (i < n) printf("%02X ", buf[off + i]); else printf("   ");
            if (i == 7) printf(" ");
        }
        printf(" |");
        for (size_t i = 0; i < n; i++) {
            u8 c = buf[off + i];
            putchar(c >= 32 && c < 127 ? c : '.');
        }
        printf("|\n");
    }
    if (totalRows > maxRows) Gray();
    if (totalRows > maxRows) printf("  ... (%zu satir daha var)\n", totalRows - maxRows);
    if (totalRows > maxRows) White();
}

static void PrintDisLines(const std::vector<DisLine>& ls) {
    for (auto& l : ls) {
        printf("  %016llX  ", (unsigned long long)l.addr);
        char bb[64] = {}; int p = 0;
        for (int i = 0; i < l.len && i < 16; i++) p += sprintf(bb + p, "%02X", l.bytes[i]);
        printf("%-20s  %-8s %s", bb, l.mn.c_str(), l.op.c_str());
        if (!l.sym.empty() && l.sym != l.op) { Gray(); printf("   ; %s", l.sym.c_str()); White(); }
        printf("\n");
    }
}

// ---- MAPPED BELLEK GUVENLI OKUMA (NOACCESS sayfalar icin VirtualProtect) ----

static bool ReadMapped(u64 addr, u8* out, size_t sz) {
    if (!g_map.success || !g_map.base) return false;
    u64 base = (u64)(uintptr_t)g_map.base;
    if (addr < base || addr + sz > base + g_map.imageSize) return false;
    SYSTEM_INFO si; GetSystemInfo(&si);
    u64 p = addr, end = addr + sz;
    while (p < end) {
        u64 pageEnd = ((p / si.dwPageSize) + 1) * si.dwPageSize;
        size_t chunk = (size_t)((pageEnd < end) ? (pageEnd - p) : (end - p));
        DWORD old = 0;
        if (!VirtualProtect((LPVOID)(uintptr_t)p, chunk, PAGE_READWRITE, &old)) return false;
        memcpy(out + (p - addr), (void*)(uintptr_t)p, chunk);
        DWORD t; VirtualProtect((LPVOID)(uintptr_t)p, chunk, old, &t);
        p += chunk;
    }
    return true;
}

static bool WriteMapped(u64 addr, const u8* in, size_t sz) {
    if (!g_map.success || !g_map.base) return false;
    u64 base = (u64)(uintptr_t)g_map.base;
    if (addr < base || addr + sz > base + g_map.imageSize) return false;
    SYSTEM_INFO si; GetSystemInfo(&si);
    u64 p = addr, end = addr + sz;
    while (p < end) {
        u64 pageEnd = ((p / si.dwPageSize) + 1) * si.dwPageSize;
        size_t chunk = (size_t)((pageEnd < end) ? (pageEnd - p) : (end - p));
        DWORD old = 0;
        if (!VirtualProtect((LPVOID)(uintptr_t)p, chunk, PAGE_READWRITE, &old)) return false;
        memcpy((void*)(uintptr_t)p, in + (p - addr), chunk);
        FlushInstructionCache(GetCurrentProcess(), (LPCVOID)(uintptr_t)p, chunk);
        DWORD t; VirtualProtect((LPVOID)(uintptr_t)p, chunk, old, &t);
        p += chunk;
    }
    return true;
}

// ============================================================================
//  MENU: DOSYA MODU
// ============================================================================

static void CmdLoadFile() {
    auto path = PromptPath("PE dosya yolu (orn: C:\\test\\ornek.exe)", false);
    if (path.empty()) return;
    if (g_map.base) { PEManualMapper::Unmap(g_map); Yellow(); printf("  Onceki map kaldirildi.\n"); White(); }
    g_core.Close();
    if (g_core.LoadFile(path.c_str())) {
        Green();
        printf("\n  PE yuklendi: %s\n", g_core.pe.is64 ? "x64 (PE32+)" : "x86 (PE32)");
        printf("  ImageBase = 0x%llX | SizeOfImage = 0x%X | EP = 0x%llX | Section = %u | Import DLL = %zu\n",
               (unsigned long long)g_core.pe.imgBase, g_core.pe.imgSz,
               (unsigned long long)(g_core.pe.imgBase + g_core.pe.ep),
               g_core.pe.numSec, g_core.pe.imps.size());
        White();
    } else {
        Red(); printf("  PE yuklenemedi! Dosya gecerli bir PE degil veya okunamadi.\n"); White();
    }
}

static void CmdPeInfo() {
    if (!g_core.loaded) { Red(); printf("  Once PE yukleyin. [1]\n"); White(); return; }
    auto& pe = g_core.pe;
    Cyan(); printf("\n  ===================== PE BILGISI =====================\n"); White();
    printf("  Mimari        : %s\n", pe.is64 ? "x64 (PE32+)" : "x86 (PE32)");
    printf("  Tur           : %s\n", (pe.dllCharacteristics & 0x2000) ? "DLL" : "EXE");
    printf("  ImageBase     : 0x%llX\n", (unsigned long long)pe.imgBase);
    printf("  SizeOfImage   : 0x%X\n", pe.imgSz);
    printf("  SizeOfHeaders : 0x%X\n", pe.hdrSz);
    printf("  EntryPoint    : RVA 0x%X -> VA 0x%llX\n", pe.ep, (unsigned long long)(pe.imgBase + pe.ep));
    printf("  DllCharacteristics: 0x%04X %s%s%s\n", pe.dllCharacteristics,
           (pe.dllCharacteristics & 0x40) ? "[DYNAMIC_BASE/ASLR] " : "",
           (pe.dllCharacteristics & 0x100) ? "[NX/DEP] " : "",
           (pe.dllCharacteristics & 0x400) ? "[NO_SEH]" : "");
    printf("  Relocation    : %s (%zu kayit)\n", pe.hasRelocs ? "VAR" : "YOK", pe.relocs.size());

    Cyan(); printf("\n  -- SECTION'LAR --\n"); White();
    printf("  %-8.8s %-10s %-10s %-10s %-10s %s\n", "Ad", "RVA", "VirtSz", "RawOfs", "RawSz", "Bayraklar");
    for (auto& s : pe.secs) {
        std::string fl;
        if (s.chars & IMAGE_SCN_MEM_EXECUTE) fl += "X";
        if (s.chars & IMAGE_SCN_MEM_READ)    fl += "R";
        if (s.chars & IMAGE_SCN_MEM_WRITE)   fl += "W";
        if (s.chars & IMAGE_SCN_CNT_CODE)    fl += " C";
        printf("  %-8.8s 0x%08X 0x%08X 0x%08X 0x%08X %s\n", s.name, s.va, s.vSz, s.raw, s.rawSz, fl.c_str());
    }

    Cyan(); printf("\n  -- IMPORT'LAR --\n"); White();
    for (auto& d : pe.imps) {
        printf("  %s  (%zu fonksiyon)\n", d.name.c_str(), d.funcs.size());
        size_t shown = 0;
        for (auto& f : d.funcs) {
            if (shown++ >= 8) { Gray(); printf("      ... +%zu daha\n", d.funcs.size() - 8); White(); break; }
            printf("      IAT 0x%llX  %s\n", (unsigned long long)f.iatAddr, f.name.c_str());
        }
    }
    printf("\n");
}

static void CmdStrings() {
    if (!g_core.loaded) { Red(); printf("  Once PE yukleyin. [1]\n"); White(); return; }
    printf("  Minimum uzunluk (5): ");
    std::string s = ReadLine();
    int minLen = atoi(s.c_str()); if (minLen < 4) minLen = 4;
    auto& data = g_core.mem.data; u64 base = g_core.mem.base;
    int found = 0;
    Cyan(); printf("\n  -- STRINGLER (ilk 200) --\n"); White();
    size_t i = 0;
    while (i < data.size() && found < 200) {
        if (data[i] >= 32 && data[i] < 127) {
            size_t j = i;
            while (j < data.size() && data[j] >= 32 && data[j] < 127) j++;
            if ((int)(j - i) >= minLen) {
                std::string str((const char*)data.data() + i, j - i);
                printf("  0x%016llX  \"%s\"\n", (unsigned long long)(base + i), str.c_str());
                found++;
            }
            i = j;
        } else i++;
    }
    if (!found) printf("  String bulunamadi.\n");
    printf("\n");
}

static void CmdDisasm() {
    if (!g_core.loaded) { Red(); printf("  Once PE yukleyin. [1]\n"); White(); return; }
    u64 addr = PromptAddr("Disassembly baslangic adresi (bos = EP)");
    if (!addr) addr = g_core.EP();
    u64 n = PromptNum("Satir sayisi (20)");
    if (!n) n = 20;
    Cyan(); printf("\n  -- DISASSEMBLY: 0x%llX --\n", (unsigned long long)addr); White();
    PrintDisLines(g_core.Dis(addr, (int)n));
    printf("\n");
}

static void CmdHexDump() {
    if (!g_core.loaded) { Red(); printf("  Once PE yukleyin. [1]\n"); White(); return; }
    u64 addr = PromptAddr("Hexdump adresi (bos = ImageBase)");
    if (!addr) addr = g_core.Base();
    u64 size = PromptNum("Boyut (bayt, 256)");
    if (!size) size = 256;
    if (!g_core.mem.InRange(addr) || !g_core.mem.InRange(addr + size - 1)) {
        Red(); printf("  Adres dosya gorunumu disinda (0x%llX - 0x%llX).\n",
                      (unsigned long long)g_core.mem.base,
                      (unsigned long long)(g_core.mem.base + g_core.mem.data.size())); White();
        return;
    }
    printf("\n");
    HexDumpBuf(g_core.mem.data.data() + (addr - g_core.mem.base), addr, (size_t)size, 64);
    printf("\n");
}

static void CmdEdit() {
    if (!g_core.loaded) { Red(); printf("  Once PE yukleyin. [1]\n"); White(); return; }
    u64 addr = PromptAddr("Duzenlenecek adres");
    if (!addr) return;
    printf("  Yeni deger (asm: 'mov eax,1' | hex bayt: '90 90 CC'): ");
    std::string text = ReadLine();
    if (text.empty()) return;
    if (g_core.Edit(addr, text)) {
        Green(); printf("  Yazildi: 0x%llX <- \"%s\" (undo: [8])\n", (unsigned long long)addr, text.c_str()); White();
    } else {
        Red(); printf("  Yazilamadi: gecersiz komut/bayt ya da adres gorunum disinda.\n"); White();
    }
}

static void CmdUndoRedo() {
    if (!g_core.loaded) { Red(); printf("  Once PE yukleyin. [1]\n"); White(); return; }
    printf("  [1] Undo  [2] Redo: ");
    std::string c = ReadLine();
    if (c == "1") printf(g_core.Undo() ? "  Geri alindi.\n" : "  Geri alinacak islem yok.\n");
    if (c == "2") printf(g_core.Redo() ? "  Yeniden uygulandi.\n" : "  Yeniden uygulanacak islem yok.\n");
}

static void CmdInject() {
    if (!g_core.loaded) { Red(); printf("  Once PE yukleyin. [1]\n"); White(); return; }
    u64 addr = PromptAddr("Hook adresi (5 bayt JMP yazilacak)");
    if (!addr) return;
    printf("  Assembly kodu (tek satir, komutlar '; ' ile ayrilir):\n  > ");
    std::string code = ReadLine();
    if (code.empty()) return;
    auto res = g_injector.CreateHook(g_core.pe, g_core.mem, g_core.dis, g_core.asmb, addr, code);
    printf("\n");
    Gray(); printf("%s", res.log.c_str()); White();
    if (res.ok) {
        Green(); printf("  HOOK OK! Hook=0x%llX  Trampoline=0x%llX  Donus=0x%llX  Boyut=%zu\n",
                        (unsigned long long)res.addr, (unsigned long long)res.hookAddr,
                        (unsigned long long)res.retAddr, res.size); White();
    } else {
        Red(); printf("  HOOK BASARISIZ: %s\n", res.err.c_str()); White();
    }
}

static void CmdSections() {
    if (!g_core.loaded) { Red(); printf("  Once PE yukleyin. [1]\n"); White(); return; }
    printf("  [1] Bos alan bul (code cave)  [2] Yeni section ekle: ");
    std::string c = ReadLine();
    if (c == "1") {
        u64 need = PromptNum("Gerekli bayt (256)");
        u64 a = g_injector.FindFreeSpace(g_core.pe, g_core.mem, (size_t)need);
        if (a) { Green(); printf("  Bos alan: 0x%llX (%llu bayt)\n", (unsigned long long)a, (unsigned long long)need); White(); }
        else { Red(); printf("  Yeterli bos alan bulunamadi.\n"); White(); }
    } else if (c == "2") {
        printf("  Section adi (max 8, orn .hook): ");
        std::string name = ReadLine();
        u64 size = PromptNum("Boyut (bayt, 4096)");
        if (!size) size = 4096;
        printf("  Koruma [1]=RX  [2]=RW  [3]=RWX (1): ");
        std::string p = ReadLine();
        u32 chars = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
        if (p == "2") chars |= IMAGE_SCN_MEM_WRITE;
        else if (p == "3") { chars |= IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE; }
        else chars |= IMAGE_SCN_MEM_EXECUTE;
        u64 va = g_injector.AddSection(g_core.pe, g_core.mem, name.c_str(), (u32)size, chars);
        if (va) { Green(); printf("  Section eklendi: VA 0x%llX (boyut 0x%llX)\n", (unsigned long long)va, (unsigned long long)size); White(); }
        else { Red(); printf("  Section eklenemedi (header alani dolu olabilir).\n"); White(); }
    }
}

static void CmdSave() {
    if (!g_core.loaded) { Red(); printf("  Once PE yukleyin. [1]\n"); White(); return; }
    printf("  [1] Orijinal dosyanin uzerine yaz  [2] Farkli kaydet: ");
    std::string c = ReadLine();
    std::wstring path = g_core.filePath;
    if (c == "2") {
        path = PromptPath("Kaydetme yolu", false);
        if (path.empty()) return;
    }
    if (g_core.SaveFile(path.c_str())) { Green(); printf("  Kaydedildi.\n"); White(); }
    else { Red(); printf("  Kaydedilemedi!\n"); White(); }
}

static void CmdClosePe() {
    if (!g_core.loaded) return;
    if (g_map.base) { PEManualMapper::Unmap(g_map); }
    g_core.Close();
    Green(); printf("  PE kapatildi.\n"); White();
}

// ============================================================================
//  MENU: WINDOWS LOADER EMULASYONU  (PEManualMapper kontrolu)
// ============================================================================

static void CmdMap() {
    if (!g_core.loaded) { Red(); printf("  Once PE yukleyin. [1]\n"); White(); return; }
    if (g_map.base) { PEManualMapper::Unmap(g_map); printf("  Onceki map kaldirildi.\n"); }

    printf("  Dosya diskten tekrar okunsun mu? [1]=Evet (temiz kopya) [2]=Hayir (bellekteki guncel hali) (1): ");
    std::string c = ReadLine();
    if (c == "2") {
        g_map = g_mapper.MapMemory(g_core.pe.raw);   // dosyayi acmadan, mevcut icerikten
    } else {
        g_map = g_mapper.MapFile(g_core.filePath.c_str()); // diskten okuyarak
    }

    printf("\n");
    if (g_map.success) {
        Cyan(); printf("  ================= LOADER LOG =================\n"); White();
        g_map.PrintLog();
        Green();
        printf("\n  Base       : 0x%p\n", (void*)g_map.base);
        printf("  EntryPoint : 0x%llX  (CALISTIRILMADI - sadece map)\n", (unsigned long long)g_map.entryPointVA);
        printf("  Relocated  : %s\n", g_map.wasRelocated ? "EVET (base kaydi, reloc uygulandi)" : "HAYIR");
        White();
    } else {
        Red(); printf("  MAP BASARISIZ: %s\n", g_map.error.c_str()); White();
    }
}

static void CmdMapLog() {
    if (!g_map.base) { Red(); printf("  Once map edin. [12]\n"); White(); return; }
    Cyan(); printf("\n  ================= LOADER LOG / RAPOR =================\n"); White();
    g_map.PrintLog();
    printf("\n");
}

static void CmdDumpMapped() {
    if (!g_map.base) { Red(); printf("  Once map edin. [12]\n"); White(); return; }
    auto path = PromptPath("Dump dosya yolu (orn: C:\\dump\\mapped.bin)", true);
    if (path.empty()) return;
    std::vector<u8> buf((size_t)g_map.imageSize);
    if (!ReadMapped((u64)(uintptr_t)g_map.base, buf.data(), buf.size())) {
        Red(); printf("  Mapped bellek okunamadi!\n"); White(); return;
    }
    HANDLE hF = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (hF == INVALID_HANDLE_VALUE) { Red(); printf("  Dosya olusturulamadi (hata %lu)\n", GetLastError()); White(); return; }
    DWORD wr = 0;
    WriteFile(hF, buf.data(), (DWORD)buf.size(), &wr, nullptr);
    CloseHandle(hF);
    if (wr == buf.size()) { Green(); printf("  Dump alindi: %zu bayt -> dosya\n", (size_t)wr); White(); }
    else { Red(); printf("  Yazma eksik: %lu / %zu\n", (unsigned long)wr, buf.size()); White(); }
}

static void CmdInspectMapped() {
    if (!g_map.base) { Red(); printf("  Once map edin. [12]\n"); White(); return; }
    printf("  [1] Hexdump  [2] Disassembly: ");
    std::string c = ReadLine();
    u64 addr = PromptAddr(c == "2" ? "Disassembly adresi (bos = EP)" : "Hexdump adresi (bos = base)");
    if (!addr) addr = (c == "2") ? g_map.entryPointVA : (u64)(uintptr_t)g_map.base;
    u64 size = PromptNum(c == "2" ? "Satir sayisi (20)" : "Boyut (bayt, 256)");
    if (c == "2") { if (!size) size = 20; }
    else { if (!size) size = 256; }
    u64 extent = (c == "2") ? size * 8 : size; // disasm: satir*8, hexdump: bayt
    if (addr < (u64)(uintptr_t)g_map.base || addr + extent > (u64)(uintptr_t)g_map.base + g_map.imageSize) {
        Red(); printf("  Adres mapped goruntu disinda!\n"); White(); return;
    }
    if (c == "1") {
        std::vector<u8> buf((size_t)size);
        if (!ReadMapped(addr, buf.data(), buf.size())) { Red(); printf("  Okuma basarisiz!\n"); White(); return; }
        printf("\n");
        HexDumpBuf(buf.data(), addr, (size_t)size, 64);
        printf("\n");
    } else {
        // mapped goruntuyu gecici MemImage'a kopyala, mevcut capstone motoru ile coz
        MemImage mv;
        mv.base = (u64)(uintptr_t)g_map.base;
        mv.is64 = g_map.is64;
        mv.data.resize((size_t)g_map.imageSize);
        if (!ReadMapped(mv.base, mv.data.data(), mv.data.size())) { Red(); printf("  Okuma basarisiz!\n"); White(); return; }
        Disasm d;
        if (!d.Init(g_map.is64)) { Red(); printf("  Capstone baslatilamadi!\n"); White(); return; }
        Cyan(); printf("\n  -- MAPPED DISASSEMBLY: 0x%llX --\n", (unsigned long long)addr); White();
        u64 end = addr + size * 8;
        auto ls = d.DisasmRange(mv, addr, end);
        int n = 0;
        for (auto& l : ls) {
            if (n++ >= (int)size) break;
            printf("  %016llX  ", (unsigned long long)l.addr);
            char bb[64] = {}; int p = 0;
            for (int i = 0; i < l.len && i < 16; i++) p += sprintf(bb + p, "%02X", l.bytes[i]);
            printf("%-20s  %-8s %s\n", bb, l.mn.c_str(), l.op.c_str());
        }
        printf("\n");
    }
}

static void CmdProtectMapped() {
    if (!g_map.base) { Red(); printf("  Once map edin. [12]\n"); White(); return; }
    u64 addr = PromptAddr("Bolge adresi");
    u64 size = PromptNum("Boyut (bayt)");
    if (!addr || !size) return;
    printf("  Yeni koruma [1]=R  [2]=RW  [3]=RX  [4]=RWX  [5]=NOACCESS: ");
    std::string c = ReadLine();
    DWORD prot = PAGE_READONLY;
    if (c == "2") prot = PAGE_READWRITE;
    else if (c == "3") prot = PAGE_EXECUTE_READ;
    else if (c == "4") prot = PAGE_EXECUTE_READWRITE;
    else if (c == "5") prot = PAGE_NOACCESS;
    SYSTEM_INFO si; GetSystemInfo(&si);
    u64 p = addr, end = addr + size; bool allOk = true;
    while (p < end) {
        u64 pageEnd = ((p / si.dwPageSize) + 1) * si.dwPageSize;
        size_t chunk = (size_t)((pageEnd < end) ? (pageEnd - p) : (end - p));
        DWORD old = 0;
        if (!VirtualProtect((LPVOID)(uintptr_t)p, chunk, prot, &old)) allOk = false;
        p += chunk;
    }
    if (allOk) { Green(); printf("  Korumayi ayarlandi (0x%llX, %llu bayt).\n", (unsigned long long)addr, (unsigned long long)size); White(); }
    else { Red(); printf("  Bazi sayfalarda VirtualProtect basarisiz (hata %lu).\n", GetLastError()); White(); }
}

static void CmdUnmap() {
    if (!g_map.base) { Red(); printf("  Map edilmis goruntu yok.\n"); White(); return; }
    if (PEManualMapper::Unmap(g_map)) { Green(); printf("  Map kaldirildi (VirtualFree OK).\n"); White(); }
    else { Red(); printf("  VirtualFree basarisiz (hata %lu)\n", GetLastError()); White(); }
}

// ============================================================================
//  MENU: PROCESS MODU  (InstanceManager - eski cekirdek korunmus halde)
// ============================================================================

static void CmdAttachProcess() {
    if (!g_procId.empty()) { Yellow(); printf("  Zaten bagli (pid). Once ayirin. [22]\n"); White(); return; }
    DWORD pid = (DWORD)PromptNum("PID");
    if (!pid) return;
    g_procId = InstanceManager::I().CreateProcessInstance(pid);
    auto inst = InstanceManager::I().GetInstance(g_procId);
    if (inst && inst->loaded) {
        Green();
        printf("  Baglanildi: %s\n", inst->name.c_str());
        printf("  Ana modul base: 0x%llX  boyut: 0x%X\n", (unsigned long long)inst->processBaseAddr, inst->processImageSize);
        White();
    } else {
        Red(); printf("  Baglanilamadi: PID bulunamadi veya erisim reddedildi (yonetici olarak calistirin).\n"); White();
        InstanceManager::I().RemoveInstance(g_procId);
        g_procId.clear();
    }
}

static void CmdProcInfo() {
    if (g_procId.empty()) { Red(); printf("  Once process'e baglanin. [18]\n"); White(); return; }
    auto inst = InstanceManager::I().GetInstance(g_procId);
    if (!inst) { Red(); printf("  Process baglantisi koptu.\n"); White(); g_procId.clear(); return; }
    Cyan(); printf("\n  ================= PROCESS BILGISI =================\n"); White();
    printf("  PID  : %lu\n", (unsigned long)inst->pid);
    printf("  Base : 0x%llX\n", (unsigned long long)inst->processBaseAddr);
    printf("  Size : 0x%X\n", inst->processImageSize);
    Cyan(); printf("\n  -- MODULLER --\n"); White();
    for (auto& m : inst->processModules)
        printf("  0x%016llX  %-12s  0x%X  (%zu import)\n",
               (unsigned long long)m.baseAddr, m.moduleName.c_str(), m.moduleSize, m.imports.size());
    printf("\n");
}

static void CmdProcRead() {
    if (g_procId.empty()) { Red(); printf("  Once process'e baglanin. [18]\n"); White(); return; }
    u64 addr = PromptAddr("Okuma adresi");
    u64 size = PromptNum("Boyut (bayt, 256)");
    if (!size) size = 256;
    std::vector<u8> buf((size_t)size);
    if (InstanceManager::I().ReadProcessMemoryAt(g_procId, addr, buf.data(), (size_t)size)) {
        printf("\n");
        HexDumpBuf(buf.data(), addr, (size_t)size, 64);
        printf("\n");
    } else {
        Red(); printf("  Okuma basarisiz! (bolge commit edilmemis olabilir)\n"); White();
    }
}

static void CmdProcWrite() {
    if (g_procId.empty()) { Red(); printf("  Once process'e baglanin. [18]\n"); White(); return; }
    u64 addr = PromptAddr("Yazma adresi");
    printf("  Baytlar (hex, orn: 90 90 C3): ");
    std::string s = ReadLine();
    std::vector<u8> bytes;
    char* p = (char*)s.c_str(); char* e = nullptr;
    while (*p) {
        unsigned long v = strtoul(p, &e, 16);
        if (e == p) { p++; continue; }
        bytes.push_back((u8)v);
        p = e;
    }
    if (bytes.empty()) { Red(); printf("  Bayt yok.\n"); White(); return; }
    if (InstanceManager::I().WriteProcessMemoryAt(g_procId, addr, bytes.data(), bytes.size())) {
        Green(); printf("  %zu bayt yazildi: 0x%llX\n", bytes.size(), (unsigned long long)addr); White();
    } else {
        Red(); printf("  Yazma basarisiz!\n"); White();
    }
}

static void CmdDetachProcess() {
    if (g_procId.empty()) return;
    if (InstanceManager::I().RemoveInstance(g_procId)) { Green(); printf("  Ayrildi.\n"); White(); }
    g_procId.clear();
}

// ============================================================================
//  ANA MENU
// ============================================================================

static void Banner() {
    Cyan();
    printf("\n====================================================================\n");
    printf("   i4M Console Loader  -  PE Windows Loader Emulatoru (x64)\n");
    printf("   Dosyayi acmadan process bellegine cevirir (manual map)\n");
    printf("====================================================================\n");
    White();
}

static void Menu() {
    Gray();
    printf("\n  DOSYA\n");
    printf("   [1] PE Yukle                [2] PE Bilgisi (hdr/sec/imp)\n");
    printf("   [3] String Tara             [4] Disassembly (dosya)\n");
    printf("   [5] Hexdump (dosya)         [6] Adres Duzenle (asm/hex)\n");
    printf("   [7] Undo / Redo             [8] Kod Enjeksiyonu (Hook)\n");
    printf("   [9] Section Ekle / Bos Alan [10] Dosyaya Kaydet\n");
    printf("   [11] PE Kapat\n");
    printf("  WINDOWS LOADER EMULASYONU\n");
    printf("   [12] Bellege Map Et         [13] Loader Log / Rapor\n");
    printf("   [14] Dump Al (mapped)       [15] Incele (mapped)\n");
    printf("   [16] Korumayi Degistir      [17] Map Kaldir (Unmap)\n");
    printf("  PROCESS\n");
    printf("   [18] Process'e Baglan (PID) [19] Process Bilgisi\n");
    printf("   [20] Bellegi Oku (proc)     [21] Bellege Yaz (proc)\n");
    printf("   [22] Ayir                   [0] Cikis\n");
    White();
    printf("\n  Secim> ");
}

int main() {
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
    SetConsoleTitleA("i4M Console Loader - PE Manual Mapper");

    Banner();
    g_mapper.options.continueOnMissingImport = true;

    bool running = true;
    while (running) {
        Menu();
        std::string c = ReadLine();
        printf("\n");
        if      (c == "1")  CmdLoadFile();
        else if (c == "2")  CmdPeInfo();
        else if (c == "3")  CmdStrings();
        else if (c == "4")  CmdDisasm();
        else if (c == "5")  CmdHexDump();
        else if (c == "6")  CmdEdit();
        else if (c == "7")  CmdUndoRedo();
        else if (c == "8")  CmdInject();
        else if (c == "9")  CmdSections();
        else if (c == "10") CmdSave();
        else if (c == "11") CmdClosePe();
        else if (c == "12") CmdMap();
        else if (c == "13") CmdMapLog();
        else if (c == "14") CmdDumpMapped();
        else if (c == "15") CmdInspectMapped();
        else if (c == "16") CmdProtectMapped();
        else if (c == "17") CmdUnmap();
        else if (c == "18") CmdAttachProcess();
        else if (c == "19") CmdProcInfo();
        else if (c == "20") CmdProcRead();
        else if (c == "21") CmdProcWrite();
        else if (c == "22") CmdDetachProcess();
        else if (c == "0")  running = false;
        else if (!c.empty()) { Yellow(); printf("  Gecersiz secim.\n"); White(); }

        if (!c.empty() && c != "0") Pause();
    }

    // Temiz cikis
    if (g_map.base) PEManualMapper::Unmap(g_map);
    if (!g_procId.empty()) InstanceManager::I().RemoveInstance(g_procId);
    g_core.Close();
    return 0;
}
