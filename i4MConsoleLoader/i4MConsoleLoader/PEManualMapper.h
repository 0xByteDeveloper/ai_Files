#pragma once
// ============================================================================
//  PEManualMapper.h - Windows PE Loader Emulasyonu (In-Process Manual Map)
// ============================================================================
//
//  Windows bir dosyayi calistirdiginda (CreateProcess) dosyayi acmaz; dosyanin
//  icerigini process belleGINE "cevirir". Bu cevirme asamalari:
//
//    1) DOS/NT header dogrulama                (NtCreateUserProcess)
//    2) ImageBase'de bellek ayirma             (NtMapViewOfSection / VirtualAlloc)
//    3) Header'larin kopyalanmasi              (SizeOfHeaders kadar)
//    4) Section'larin raw->virtual map edilmesi (her section VirtualAddress'a)
//    5) Base relocation (base kayarsa)         (LdrRelocateImageWithBias)
//    6) Import tablosunun cozulmesi (IAT snap) (LdrpSnapIAT -> LoadLibrary/GetProcAddress)
//    7) ImageBase alaninin guncellenmesi
//    8) Section korumalarinin ayarlanmasi      (VirtualProtect, Characteristics'e gore)
//    9) TLS callback'leri + Entry Point        (BU ARACTA CALISTIRILMAZ, sadece rapor)
//
//  Bu sinif yukaridaki akisin birebir emulasyonudur. Kod main.cpp'den
//  kontrol edilir; buradaki mantik tamamen bagimsizdir (sadece Windows.h).
//
//  Kullanim:
//      PEManualMapper mapper;
//      auto res = mapper.MapFile(L"C:\\hedef.exe");
//      if (res.success) { res.PrintLog(); ... mapper.Unmap(res); }
// ============================================================================

#include <Windows.h>
#include <winnt.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>

class PEManualMapper {
public:
    using u8 = unsigned char;
    using u16 = unsigned short;
    using u32 = unsigned int;
    using u64 = unsigned long long;

    // ---- Secenekler (loader davranisini ayarlar) ----
    struct Options {
        bool tryPreferredBase = true;      // ImageBase'i dene, basarili olmazsa yeni yer ara
        bool applyRelocations = true;      // base kaydiysa relocation uygula (gercek loader yapar)
        bool resolveImports = true;        // IAT doldur (LoadLibraryA + GetProcAddress)
        bool setSectionProtections = true; // Characteristic'lere gore VirtualProtect
        bool continueOnMissingImport = true; // eksik DLL/fonksiyon'ta devam et (loader'da bu olum: STATUS_DLL_NOT_FOUND)
    };

    // ---- Map edilen section raporu ----
    struct SectionMapInfo {
        char        name[9] = {};
        u32         rva = 0;        // image icindeki offset
        u32         virtualSize = 0;
        u32         rawSize = 0;
        u64         va = 0;         // mutlak adres (base + rva)
        DWORD       protect = 0;    // uygulan PAGE_*
        u32         chars = 0;      // section characteristics
    };

    // ---- Import raporu ----
    struct ImportDllInfo {
        std::string dllName;
        HMODULE     module = nullptr;   // LoadLibrary sonucu
        std::vector<std::string> resolved;
        std::vector<std::string> missing;
        bool        byOrdinalOnly = false;
    };

    // ---- Map sonucu ----
    struct MapResult {
        bool        success = false;
        u8*         base = nullptr;         // goruntunun biz process'teki base'i
        u64         imageSize = 0;
        u64         entryPointVA = 0;       // base + AddressOfEntryPoint (CALISTIRILMAZ)
        bool        is64 = false;
        bool        isDLL = false;
        bool        wasRelocated = false;   // base kaydi mi?
        u64         preferredBase = 0;      // PE icindeki ImageBase
        u64         delta = 0;              // actual - preferred
        std::vector<SectionMapInfo>  sections;
        std::vector<ImportDllInfo>   imports;
        // TLS bilgisi (rapor amacli, callback'ler CALISTIRILMAZ)
        bool        hasTLS = false;
        u64         tlsCallbacksVA = 0;     // callback dizisinin VA'si (null ile biter)
        int         tlsCallbackCount = 0;
        std::vector<std::string> log;
        std::string error;

        void PrintLog() const {
            for (auto& l : log) printf("  %s\n", l.c_str());
        }
    };

    // ---- Secenek ayarini degistir (main.cpp'den kontrol icin) ----
    Options options;

    // =========================================================================
    //  DOSYADAN MAP ET
    // =========================================================================
    MapResult MapFile(const wchar_t* path) {
        MapResult r;
        HANDLE hF = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hF == INVALID_HANDLE_VALUE) {
            r.error = "Dosya acilamadi (CreateFileW hata: " + std::to_string(GetLastError()) + ")";
            return r;
        }
        LARGE_INTEGER fsz{};
        if (!GetFileSizeEx(hF, &fsz) || fsz.QuadPart < 64) {
            CloseHandle(hF); r.error = "Dosya cok kucuk / boyut alinamadi"; return r;
        }
        std::vector<u8> bytes((size_t)fsz.QuadPart);
        DWORD rd = 0;
        if (!ReadFile(hF, bytes.data(), (DWORD)bytes.size(), &rd, nullptr) || rd != bytes.size()) {
            CloseHandle(hF); r.error = "Dosya okunamadi"; return r;
        }
        CloseHandle(hF);
        return MapMemory(bytes);
    }

    // =========================================================================
    //  BELLEKTEKI DOSYA ICERIGINDEN MAP ET (dosya diskte acilmaz!)
    //  Windows'un "dosyayi process bellegine cevirme" akisinin tamami burada.
    // =========================================================================
    MapResult MapMemory(const std::vector<u8>& file) {
        MapResult r;
        r.log.clear();

        // ---- [1/8] HEADER DOGRULAMA ----------------------------------------
        Log(r, "[1/8] Header dogrulaniyor...");
        if (file.size() < sizeof(IMAGE_DOS_HEADER)) { r.error = "Dosya DOS header icin cok kucuk"; return r; }

        auto dos = (const IMAGE_DOS_HEADER*)file.data();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) { r.error = "MZ imzasi yok (PE dosyasi degil)"; return r; }
        Log(r, "      MZ imzasi OK (e_lfanew = 0x%X)", dos->e_lfanew);

        if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > file.size()) { r.error = "NT header dosya sinirlari disinda"; return r; }
        auto nt = (const IMAGE_NT_HEADERS*)(file.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) { r.error = "PE imzasi (PE\\0\\0) gecersiz"; return r; }

        bool is64 = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        bool is32 = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
        if (!is64 && !is32) { r.error = "Bilinmeyen OptionalHeader.Magic"; return r; }

        WORD machine = nt->FileHeader.Machine;
        if (is64 && machine != IMAGE_FILE_MACHINE_AMD64)
            Log(r, "      ! UYARI: x64 header ama Machine=0x%04X", machine);

        u32 secAlign = is64 ? ((const IMAGE_NT_HEADERS64*)nt)->OptionalHeader.SectionAlignment
                            : ((const IMAGE_NT_HEADERS32*)nt)->OptionalHeader.SectionAlignment;
        u32 fileAlign = is64 ? ((const IMAGE_NT_HEADERS64*)nt)->OptionalHeader.FileAlignment
                             : ((const IMAGE_NT_HEADERS32*)nt)->OptionalHeader.FileAlignment;
        u64 imgBase = is64 ? ((const IMAGE_NT_HEADERS64*)nt)->OptionalHeader.ImageBase
                           : ((const IMAGE_NT_HEADERS32*)nt)->OptionalHeader.ImageBase;
        u32 imgSize = is64 ? ((const IMAGE_NT_HEADERS64*)nt)->OptionalHeader.SizeOfImage
                           : ((const IMAGE_NT_HEADERS32*)nt)->OptionalHeader.SizeOfImage;
        u32 hdrSize = is64 ? ((const IMAGE_NT_HEADERS64*)nt)->OptionalHeader.SizeOfHeaders
                           : ((const IMAGE_NT_HEADERS32*)nt)->OptionalHeader.SizeOfHeaders;
        u32 epRva = is64 ? ((const IMAGE_NT_HEADERS64*)nt)->OptionalHeader.AddressOfEntryPoint
                         : ((const IMAGE_NT_HEADERS32*)nt)->OptionalHeader.AddressOfEntryPoint;
        WORD numSec = nt->FileHeader.NumberOfSections;
        WORD dllChars = is64 ? ((const IMAGE_NT_HEADERS64*)nt)->OptionalHeader.DllCharacteristics
                             : ((const IMAGE_NT_HEADERS32*)nt)->OptionalHeader.DllCharacteristics;

        r.is64 = is64;
        r.isDLL = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;
        (void)dllChars; (void)secAlign; (void)fileAlign; // raporlama icin ayrildi
        r.preferredBase = imgBase;
        r.imageSize = imgSize;
        r.entryPointVA = 0; // map sonrasi doldurulur

        if (imgSize == 0) { r.error = "SizeOfImage = 0"; return r; }
        if (hdrSize > imgSize) { r.error = "SizeOfHeaders > SizeOfImage"; return r; }
        if ((size_t)hdrSize > file.size()) { r.error = "SizeOfHeaders dosya boyutundan buyuk"; return r; }

        Log(r, "      NT header OK: %s | Machine=%s | %u section | EP RVA=0x%X",
                 is64 ? "PE32+" : "PE32", machine == IMAGE_FILE_MACHINE_AMD64 ? "x64" :
                 (machine == IMAGE_FILE_MACHINE_I386 ? "x86" : "diger"), numSec, epRva);
        Log(r, "      ImageBase=0x%llX  SizeOfImage=0x%X  %s",
                 imgBase, imgSize, r.isDLL ? "[DLL]" : "[EXE]");
        if (!is64)
            Log(r, "      ! 32-bit PE: x64 process icinde sadece VERI olarak map edilir (calistirilamaz)");

        // ---- [2/8] BELLEK AYIRMA -------------------------------------------
        Log(r, "[2/8] Bellek ayriliyor (SizeOfImage = 0x%X, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE)...", imgSize);
        u8* base = nullptr;
        bool usedPreferred = false;
        if (options.tryPreferredBase && imgBase != 0) {
            base = (u8*)VirtualAlloc((LPVOID)(uintptr_t)imgBase, imgSize,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            usedPreferred = (base != nullptr);
            if (base) Log(r, "      Tercih edilen ImageBase kullanildi: 0x%p", (void*)base);
            else      Log(r, "      ImageBase 0x%llX bos degil -> yeni adres aranacak (relocation gerekli)", imgBase);
        }
        if (!base) {
            if (!is64) {
                // 32-bit PE: 4GB altinda bir adres bulmaliyiz (32-bit isaretciler ulasabilsin)
                const u64 cand[] = { imgBase, 0x00400000, 0x00800000, 0x01000000,
                                     0x10000000, 0x20000000, 0x30000000, 0x40000000,
                                     0x50000000, 0x60000000, 0x70000000 };
                for (u64 ca : cand) {
                    if (ca == 0) continue;
                    base = (u8*)VirtualAlloc((LPVOID)(uintptr_t)ca, imgSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                    if (base) { Log(r, "      32-bit PE icin dusuk adres kullanildi: 0x%p", (void*)base); break; }
                }
            }
            if (!base) {
                base = (u8*)VirtualAlloc(nullptr, imgSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                if (!base) {
                    r.error = "VirtualAlloc basarisiz (hata: " + std::to_string(GetLastError()) + ")";
                    return r;
                }
                if (!is64 && (u64)(uintptr_t)base > 0xFFFFFFFFULL)
                    Log(r, "      ! Dikkat: 32-bit PE 4GB uzerine map edildi (0x%p) - 32-bit isaretciler ulasamaz", (void*)base);
            }
        }
        r.base = base;
        r.wasRelocated = !usedPreferred;
        r.delta = (u64)(uintptr_t)base - imgBase;
        Log(r, "      Bellek ayrildi: 0x%p - 0x%p  (delta = %s0x%llX)",
                 (void*)base, (void*)(base + imgSize),
                 ((long long)r.delta < 0) ? "-" : "",
                 (unsigned long long)((long long)r.delta < 0 ? -(long long)r.delta : (long long)r.delta));

        // ---- [3/8] HEADER'LARI KOPYALA --------------------------------------
        Log(r, "[3/8] Header'lar kopyalaniyor (SizeOfHeaders = 0x%X bayt)...", hdrSize);
        memcpy(base, file.data(), hdrSize);

        // ---- [4/8] SECTION'LARI MAP ET (raw -> virtual) ----------------------
        Log(r, "[4/8] Section'lar map ediliyor (raw offset -> VirtualAddress)...");
        auto secHdr = IMAGE_FIRST_SECTION((IMAGE_NT_HEADERS*)(base + dos->e_lfanew));
        for (WORD i = 0; i < numSec; i++) {
            const IMAGE_SECTION_HEADER& sh = secHdr[i];
            SectionMapInfo si;
            memcpy(si.name, sh.Name, 8); si.name[8] = 0;
            si.rva = sh.VirtualAddress;
            si.virtualSize = sh.Misc.VirtualSize;
            si.rawSize = sh.SizeOfRawData;
            si.chars = sh.Characteristics;
            si.va = (u64)(uintptr_t)base + sh.VirtualAddress;

            u32 copySz = 0;
            if (sh.SizeOfRawData > 0 && sh.PointerToRawData > 0) {
                // Loader kurali: min(SizeOfRawData, VirtualSize) kadar kopyalanir.
                copySz = (sh.Misc.VirtualSize && sh.Misc.VirtualSize < sh.SizeOfRawData)
                       ? sh.Misc.VirtualSize : sh.SizeOfRawData;
                if (sh.PointerToRawData >= file.size()) {
                    copySz = 0;
                    Log(r, "      ! %s: raw offset dosya siniri disinda, hicbir sey kopyalanmadi", si.name);
                } else if ((size_t)sh.PointerToRawData + copySz > file.size()) {
                    copySz = (u32)(file.size() - sh.PointerToRawData);
                    Log(r, "      ! %s: raw veri dosya sinirlarini asiyor, 0x%X bayt kopyalanacak", si.name, copySz);
                }
                if (copySz) memcpy(base + sh.VirtualAddress, file.data() + sh.PointerToRawData, copySz);
            }
            // VirtualSize > SizeOfRawData ise kalan kisim zaten 0 (VirtualAlloc zero-filled) - loader ayni sekilde.
            r.sections.push_back(si);
            Log(r, "      %-8.8s RVA 0x%06X -> VA 0x%llX  (raw 0x%X, virt 0x%X) kopyalanan=0x%X %s",
                     si.name, si.rva, (unsigned long long)si.va, si.rawSize, si.virtualSize, copySz,
                     (sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) ? "[X]" : "   ");
        }

        auto ntMap = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

        // ---- [5/8] BASE RELOCATION (base kaydiysa) ---------------------------
        if (r.wasRelocated && options.applyRelocations) {
            Log(r, "[5/8] Base relocation uygulaniyor (delta = 0x%llX)...", (unsigned long long)r.delta);
            IMAGE_DATA_DIRECTORY& relocDir = is64
                ? ((PIMAGE_NT_HEADERS64)ntMap)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
                : ((PIMAGE_NT_HEADERS32)ntMap)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            if (relocDir.VirtualAddress && relocDir.Size) {
                int patched = ApplyRelocations(base, imgSize, relocDir.VirtualAddress, relocDir.Size, r.delta, r);
                Log(r, "      %d relocation kaydi duzeltildi", patched);
                FlushInstructionCache(GetCurrentProcess(), base, imgSize);
            } else {
                Log(r, "      ! Relocation tablosu yok ama base kaydi! ASLR'siz derlenen dosyada cagrilarda bozulma olabilir.");
            }
        } else if (r.wasRelocated) {
            Log(r, "[5/8] Base kaydi ama relocation secenekte kapali -> atlandi");
        } else {
            Log(r, "[5/8] Relocation gerekmiyor (tercih edilen base kullanildi)");
        }

        // ---- [6/8] IMPORT'LARI COZ (IAT SNAP) --------------------------------
        if (options.resolveImports) {
            Log(r, "[6/8] Import tablosu cozuluyor (LoadLibraryA + GetProcAddress)...");
            IMAGE_DATA_DIRECTORY& impDir = is64
                ? ((PIMAGE_NT_HEADERS64)ntMap)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                : ((PIMAGE_NT_HEADERS32)ntMap)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
            if (impDir.VirtualAddress && impDir.Size) {
                ResolveImports(base, is64, impDir.VirtualAddress, imgSize, r);
            } else {
                Log(r, "      Import tablosu yok (statik linked)");
            }
            // Delay-load sadece raporlanir (gercek loader da yukleme aninda islemez)
            IMAGE_DATA_DIRECTORY& dImpDir = is64
                ? ((PIMAGE_NT_HEADERS64)ntMap)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]
                : ((PIMAGE_NT_HEADERS32)ntMap)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
            if (dImpDir.VirtualAddress)
                Log(r, "      Delay-load import tablosu VAR (ilk cagrida cozulur, loader'da da islenmez)");
        } else {
            Log(r, "[6/8] Import cozumu secenekte kapali -> IAT ham haliyle birakti");
        }

        // ---- [7/8] MAPPED HEADER'LARI GUNCELLE -------------------------------
        Log(r, "[7/8] Mapped header guncelleniyor (ImageBase = 0x%p)...", (void*)base);
        if (is64) ((PIMAGE_NT_HEADERS64)ntMap)->OptionalHeader.ImageBase = (ULONGLONG)(uintptr_t)base;
        else      ((PIMAGE_NT_HEADERS32)ntMap)->OptionalHeader.ImageBase = (DWORD)(uintptr_t)base;
        r.entryPointVA = (u64)(uintptr_t)base + epRva;

        // ---- TLS RAPORU (calistirilmaz!) --------------------------------------
        IMAGE_DATA_DIRECTORY& tlsDir = is64
            ? ((PIMAGE_NT_HEADERS64)ntMap)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
            : ((PIMAGE_NT_HEADERS32)ntMap)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tlsDir.VirtualAddress) {
            r.hasTLS = true;
            u64 tlsRangeBeg = (u64)(uintptr_t)base, tlsRangeEnd = tlsRangeBeg + imgSize;
            if (is64) {
                auto tls = (PIMAGE_TLS_DIRECTORY64)(base + tlsDir.VirtualAddress);
                r.tlsCallbacksVA = tls->AddressOfCallBacks;
                if (r.tlsCallbacksVA >= tlsRangeBeg && r.tlsCallbacksVA + 8 < tlsRangeEnd) {
                    u64* cb = (u64*)(uintptr_t)r.tlsCallbacksVA;
                    while (*cb) { r.tlsCallbackCount++; cb++; }
                } else r.tlsCallbacksVA = 0;
            } else {
                auto tls = (PIMAGE_TLS_DIRECTORY32)(base + tlsDir.VirtualAddress);
                r.tlsCallbacksVA = tls->AddressOfCallBacks;
                if (r.tlsCallbacksVA >= tlsRangeBeg && r.tlsCallbacksVA + 4 < tlsRangeEnd) {
                    u32* cb = (u32*)(uintptr_t)r.tlsCallbacksVA;
                    while (*cb) { r.tlsCallbackCount++; cb++; }
                } else r.tlsCallbacksVA = 0;
            }
            if (r.tlsCallbacksVA)
                Log(r, "      TLS dizini VAR: %d callback (VA 0x%llX) - CALISTIRILMADI (sadece map)",
                         r.tlsCallbackCount, (unsigned long long)r.tlsCallbacksVA);
            else
                Log(r, "      TLS dizini VAR ama callback dizisi erisilemez - atlandi");
        }

        // ---- [8/8] SECTION KORUMALARI -----------------------------------------
        if (options.setSectionProtections) {
            Log(r, "[8/8] Section korumalari ayarlaniyor (VirtualProtect)...");
            DWORD hdrOld = 0;
            VirtualProtect(base, hdrSize, PAGE_READONLY, &hdrOld); // header'lar: readonly (loader gibi)
            Log(r, "      Header'lar       -> PAGE_READONLY");
            for (auto& si : r.sections) {
                si.protect = ProtectFromCharacteristics(si.chars);
                DWORD oldp = 0;
                if (si.virtualSize > 0 && VirtualProtect((LPVOID)(uintptr_t)si.va, si.virtualSize, si.protect, &oldp)) {
                    char pbuf[32]; ProtectName(si.protect, pbuf);
                    Log(r, "      %-8.8s -> %s", si.name, pbuf);
                } else {
                    char pbuf[32]; ProtectName(si.protect, pbuf);
                    Log(r, "      %-8.8s -> %s (VirtualProtect basarisiz, hata %lu)", si.name, pbuf, GetLastError());
                }
            }
        } else {
            Log(r, "[8/8] Section korumalari atlandi (tum goruntu PAGE_READWRITE)");
        }

        r.success = true;
        Log(r, "");
        Log(r, ">>> MAP TAMAMLANDI: Base=0x%p  Size=0x%X  EntryPoint=0x%llX  (%s, CALISTIRILMADI)",
                 (void*)base, imgSize, (unsigned long long)r.entryPointVA, is64 ? "x64" : "x86");
        return r;
    }

    // =========================================================================
    //  UNMAP (bellek iadesi)
    // =========================================================================
    static bool Unmap(MapResult& r) {
        if (!r.base) return false;
        bool ok = VirtualFree(r.base, 0, MEM_RELEASE) != 0;
        r.base = nullptr;
        r.success = false;
        return ok;
    }

    // =========================================================================
    //  SECTION CHARATERISTICS -> PAGE_* (loader'in ayni mantigi)
    // =========================================================================
    static DWORD ProtectFromCharacteristics(u32 c) {
        bool exe = (c & IMAGE_SCN_MEM_EXECUTE) != 0;
        bool rd  = (c & IMAGE_SCN_MEM_READ) != 0;
        bool wr  = (c & IMAGE_SCN_MEM_WRITE) != 0;
        if (exe && wr) return PAGE_EXECUTE_READWRITE;
        if (exe && rd) return PAGE_EXECUTE_READ;
        if (exe)       return PAGE_EXECUTE;
        if (wr)        return PAGE_READWRITE;
        if (rd)        return PAGE_READONLY;
        return PAGE_NOACCESS;
    }

private:
    static void Log(MapResult& r, const char* fmt, ...) {
        char buf[1024];
        va_list a; va_start(a, fmt);
        vsnprintf(buf, sizeof(buf), fmt, a);
        va_end(a);
        r.log.push_back(buf);
    }

    static void ProtectName(DWORD p, char* out) {
        switch (p) {
        case PAGE_NOACCESS:          strcpy(out, "PAGE_NOACCESS"); break;
        case PAGE_READONLY:          strcpy(out, "PAGE_READONLY"); break;
        case PAGE_READWRITE:         strcpy(out, "PAGE_READWRITE"); break;
        case PAGE_EXECUTE:           strcpy(out, "PAGE_EXECUTE"); break;
        case PAGE_EXECUTE_READ:      strcpy(out, "PAGE_EXECUTE_READ"); break;
        case PAGE_EXECUTE_READWRITE: strcpy(out, "PAGE_EXECUTE_READWRITE"); break;
        default:                     sprintf(out, "0x%08lX", (unsigned long)p); break;
        }
    }

    // ---- BASE RELOCATION (LdrRelocateImageWithBias emulasyonu) -------------
    int ApplyRelocations(u8* base, u32 imgSize, u32 relocRva, u32 relocSize, u64 delta, MapResult& r) {
        int patched = 0;
        u8* relocBase = base + relocRva;
        u32 processed = 0;
        while (processed < relocSize) {
            if ((u64)relocRva + processed + sizeof(IMAGE_BASE_RELOCATION) > imgSize) {
                Log(r, "      ! Relocation bloku goruntu sinirlarini asti, durdu");
                break;
            }
            auto block = (PIMAGE_BASE_RELOCATION)(relocBase + processed);
            if (block->SizeOfBlock == 0) break;
            if ((u64)processed + block->SizeOfBlock > relocSize) break;
            u32 count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(u16);
            u16* entries = (u16*)((u8*)block + sizeof(IMAGE_BASE_RELOCATION));
            for (u32 i = 0; i < count; i++) {
                u16 type = entries[i] >> 12;
                u16 offs = entries[i] & 0xFFF;
                u64 patchVA = (u64)(uintptr_t)base + block->VirtualAddress + offs;
                if (block->VirtualAddress + offs >= imgSize) continue;
                u8* p = (u8*)(uintptr_t)patchVA;
                switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE: break; // padding, atla
                case IMAGE_REL_BASED_HIGH: {   // HIGH: hiword += HIWORD(delta)
                    u16 v; memcpy(&v, p, 2);
                    v += (u16)HIWORD(delta); memcpy(p, &v, 2); patched++; break;
                }
                case IMAGE_REL_BASED_LOW: {    // LOW: loword += LOWORD(delta)
                    u16 v; memcpy(&v, p, 2);
                    v += (u16)LOWORD(delta); memcpy(p, &v, 2); patched++; break;
                }
                case IMAGE_REL_BASED_HIGHLOW: { // 32-bit tam adres
                    u32 v; memcpy(&v, p, 4);
                    v += (u32)delta; memcpy(p, &v, 4); patched++; break;
                }
                case IMAGE_REL_BASED_HIGHADJ: { // HIGH + sonraki entry ile birlesir (+0x8000 yuvarlama, ntdll aynisi)
                    if (i + 1 >= count) break;
                    u16 addend = entries[++i];
                    u32 v = ((u32)(*(u16*)p) << 16) + (u32)addend + (u32)delta + 0x8000;
                    u16 hi = (u16)(v >> 16); memcpy(p, &hi, 2); patched++; break;
                }
                case IMAGE_REL_BASED_DIR64: {   // 64-bit tam adres
                    u64 v; memcpy(&v, p, 8);
                    v += delta; memcpy(p, &v, 8); patched++; break;
                }
                default:
                    Log(r, "      ! Bilinmeyen relocation tipi %u @ RVA 0x%X", type, block->VirtualAddress + offs);
                    break;
                }
            }
            processed += block->SizeOfBlock;
        }
        return patched;
    }

    // ---- IMPORT COZUMU (LdrpSnapIAT emulasyonu) ----------------------------
    void ResolveImports(u8* base, bool is64, u32 importRva, u32 imgSizeEnd, MapResult& r) {
        auto desc = (PIMAGE_IMPORT_DESCRIPTOR)(base + importRva);
        int dllIdx = 0;
        for (; desc->Name != 0; desc++, dllIdx++) {
            const char* dllName = (const char*)(base + desc->Name);
            ImportDllInfo info;
            info.dllName = dllName;

            HMODULE hMod = LoadLibraryA(dllName);
            if (!hMod) {
                char sysDll[MAX_PATH];
                if (GetSystemDirectoryA(sysDll, MAX_PATH)) {
                    std::string alt = std::string(sysDll) + "\\" + dllName;
                    hMod = LoadLibraryA(alt.c_str());
                }
            }
            info.module = hMod;
            if (!hMod) {
                Log(r, "      [%d] %-20s -> YUKLENEMEDI! (hata %lu)", dllIdx, dllName, GetLastError());
                info.missing.push_back("<DLL YUKLENEMEDI>");
                r.imports.push_back(info);
                if (!options.continueOnMissingImport) return;
                continue;
            }

            // Thunk dizileri: INT (isimler) + IAT (doldurulacak)
            u32 thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            u64 iatVA    = (u64)(uintptr_t)base + desc->FirstThunk;
            u64 nameVA   = (u64)(uintptr_t)base + thunkRva;
            int resolved = 0, failed = 0;

            for (;;) {
                if (nameVA + 8 > (u64)(uintptr_t)base + imgSizeEnd || iatVA + 8 > (u64)(uintptr_t)base + imgSizeEnd) {
                    Log(r, "      ! Thunk dizisi goruntu sinirlarini asti, kesildi");
                    break;
                }
                ULONGLONG thunkVal = is64 ? *(u64*)(uintptr_t)nameVA : (ULONGLONG)*(u32*)(uintptr_t)nameVA;
                if (thunkVal == 0) break; // dizi sonu

                FARPROC fn = nullptr;
                std::string fname;
                if (is64 ? IMAGE_SNAP_BY_ORDINAL64(thunkVal) : IMAGE_SNAP_BY_ORDINAL32(thunkVal)) {
                    u64 ord = is64 ? IMAGE_ORDINAL64(thunkVal) : IMAGE_ORDINAL32(thunkVal);
                    fname = "#" + std::to_string(ord);
                    fn = GetProcAddress(hMod, MAKEINTRESOURCEA((WORD)ord));
                    info.byOrdinalOnly = true;
                } else {
                    // IMAGE_IMPORT_BY_NAME: 2 bayt Hint + isim
                    u64 ibnVA = (u64)(uintptr_t)base + (u32)thunkVal;
                    if (ibnVA + 2 >= (u64)(uintptr_t)base + imgSizeEnd) { failed++; break; }
                    fname = (const char*)(uintptr_t)(ibnVA + 2);
                    fn = GetProcAddress(hMod, (LPCSTR)(uintptr_t)(ibnVA + 2));
                }

                if (fn) {
                    if (is64) *(u64*)(uintptr_t)iatVA = (u64)(uintptr_t)fn;
                    else      *(u32*)(uintptr_t)iatVA = (u32)(uintptr_t)fn;
                    info.resolved.push_back(fname);
                    resolved++;
                } else {
                    info.missing.push_back(fname);
                    failed++;
                }
                nameVA += is64 ? 8 : 4;
                iatVA  += is64 ? 8 : 4;
            }
            Log(r, "      [%d] %-20s -> 0x%p  (%d cozuldu, %d eksik)", dllIdx, dllName,
                     (void*)hMod, resolved, failed);
            r.imports.push_back(info);
        }
    }
};
