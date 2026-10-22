// ============================================================
// VMPHelper.c — CPlusPort sanallastirma dogrulama yardimcisi (v1.3)
// (Cheat Engine esliginde neyin nerede degistigini gosterir)
//
// v1.3 duzeltmeleri:
//  [BUGFIX #14] x86 CheckCollision manifest key'i bayatti:
//               0x4C80AE49A01823B1 -> 0x4C80AE497AD22F21
//               (kanit: motor logu 'key=0x4C80AE497AD22F21' + dosya baytlari)
//  [BUGFIX #15] 'Tercih edilen ImageBase' artik DISKTAKI dosyadan okunur.
//               Neden? Windows loader, bellege maplenen header'daki ImageBase
//               alanini gercek tabanla gunceller (dosyada 0x400000 iken
//               canlida 0x750000 gorundu) -> kayma hep 0 gorunuyordu.
//
// Derleme (x64, WOW64 x86 sureclerini de okuyabilir):
//   zig c++ -target x86_64-windows-gnu -O2 VMPHelper.c -o VMPHelper.exe
//
// Kullanim:
//   VMPHelper.exe                 -> Test_vmp.exe / Test32_vmp.exe ara
//   VMPHelper.exe <pid>           -> belirli surec
//   VMPHelper.exe Test32_vmp.exe  -> isimle
// ============================================================
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

// ------------------- DERLEME ZAMANI MANIFEST -------------------
// (cplport_debug.log son oturumdan; motor deterministik)
typedef struct { const char* name; DWORD funcRva; int tramp; DWORD stubRva; DWORD bcLen; unsigned long long key; } FN;
typedef struct { int is64; DWORD vmpRva; DWORD vmpSize; DWORD ventOff; DWORD blobLen; FN f[5]; int nf; const char* exe; } MAN;

static MAN g_man[] = {
    { 1, 0x03D000, 0x0038C9, 0x0730, 12344, {
        { "WrapPos",        0x1000, 1, 0x0405B0,  77, 0x15D289B9360A8F9FULL },
        { "MovePlayer",     0x1030, 0, 0x040650, 409, 0xC0395AE98CC3BBABULL },
        { "GhostStep",      0x10E0, 0, 0x0406F0, 568, 0x865D0499B336A1B9ULL },
        { "CheckCollision", 0x11B0, 1, 0x040790, 176, 0x136FE469A01823B1ULL },
        { "GameTick",       0x1200, 1, 0x040830, 145, 0x84C5EBB91C9F8623ULL },
      }, 5, "Test_vmp.exe" },
    { 0, 0x049000, 0x004E04, 0x0C10, 18257, {
        { "WrapPos",        0x1000, 1, 0x04DC50, 103, 0x15D289B9FF256659ULL },
        { "MovePlayer",     0x1030, 0, 0x04DCC0, 439, 0xC0395AE9EAF664A9ULL },
        { "GhostStep",      0x10D0, 0, 0x04DD30, 540, 0xA2E569899F8FE1DDULL },
        { "CheckCollision", 0x1190, 1, 0x04DDA0, 175, 0x4C80AE497AD22F21ULL }, /* v1.3: bayat key duzeltildi (BUGFIX #14) */
      }, 4, "Test32_vmp.exe" },
};

static void hexdump8(const unsigned char* b, int n) {
    for (int i = 0; i < n; i++) printf("%02X ", b[i]);
}

// stub baytlarindan bc_rva + key cikarimi (canli bellekten!)
// Yapısal çapa: x64: key = son "48 B8 imm64" (movabs) — stub basindaki,
//   store'u "48 89 44 24 10" olan; bc = "48 89 44 24 18" sonrasi "48 05 imm32"
// x86: keyhi = "89 44 24 14" store'undan onceki "B8 imm32";
//   keylo = "89 44 24 10" store'undan onceki "B8 imm32"; bc = "89 44 24 18"
//   sonrasi "05 imm32"
static int extract_stub_info(const unsigned char* st, int len, int is64,
                             DWORD* bcRva, unsigned long long* key) {
    if (is64) {
        int i, j, k;
        int base_off = -1, key_store = -1;
        for (i = 0; i + 5 <= len; i++)
            if (st[i]==0x48 && st[i+1]==0x89 && st[i+2]==0x44 && st[i+3]==0x24 && st[i+4]==0x18) { base_off = i; break; }
        for (i = 0; i + 5 <= len; i++)
            if (st[i]==0x48 && st[i+1]==0x89 && st[i+2]==0x44 && st[i+3]==0x24 && st[i+4]==0x10) { key_store = i; break; }
        if (base_off < 0 || key_store < 0) return 0;
        // bc: base_off sonrasi "48 05 imm32"
        *bcRva = 0;
        for (j = base_off + 5; j + 6 <= len; j++)
            if (st[j]==0x48 && st[j+1]==0x05) {
                *bcRva = st[j+2] | (st[j+3]<<8) | (st[j+4]<<16) | ((DWORD)st[j+5]<<24);
                break;
            }
        // key: key_store'dan GERIYE son "48 B8"
        *key = 0;
        for (k = key_store - 2; k - 2 >= 0; k--)
            if (st[k]==0x48 && st[k+1]==0xB8) {
                *key = 0;
                for (int b = 0; b < 8; b++) *key |= (unsigned long long)st[k+2+b] << (8*b);
                break;
            }
        return *bcRva && *key;
    } else {
        int i, j, k;
        int base_off = -1, lo_store = -1, hi_store = -1;
        for (i = 0; i + 4 <= len; i++)
            if (st[i]==0x89 && st[i+1]==0x44 && st[i+2]==0x24 && st[i+3]==0x18) { base_off = i; break; }
        for (i = 0; i + 4 <= len; i++)
            if (st[i]==0x89 && st[i+1]==0x44 && st[i+2]==0x24 && st[i+3]==0x10) { lo_store = i; break; }
        for (i = 0; i + 4 <= len; i++)
            if (st[i]==0x89 && st[i+1]==0x44 && st[i+2]==0x24 && st[i+3]==0x14) { hi_store = i; break; }
        if (base_off < 0 || lo_store < 0 || hi_store < 0) return 0;
        *bcRva = 0;
        for (j = base_off + 4; j + 5 <= len; j++)
            if (st[j]==0x05) {
                *bcRva = st[j+1] | (st[j+2]<<8) | (st[j+3]<<16) | ((DWORD)st[j+4]<<24);
                break;
            }
        // keylo: lo_store'dan onceki "B8 imm32"; keyhi: hi_store'dan onceki
        unsigned long long lo = 0, hi = 0;
        for (k = lo_store - 1; k - 4 >= 0; k--)
            if (st[k]==0xB8) { lo = st[k+1] | (st[k+2]<<8) | (st[k+3]<<16) | ((DWORD)st[k+4]<<24); break; }
        for (k = hi_store - 1; k - 4 >= 0; k--)
            if (st[k]==0xB8) { hi = st[k+1] | (st[k+2]<<8) | (st[k+3]<<16) | ((DWORD)st[k+4]<<24); break; }
        *key = lo | (hi << 32);
        return *bcRva && *key;
    }
}

// v1.3 (BUGFIX #15): tercih edilen ImageBase'i DISKTAKI dosyadan oku.
// Canli header'daki ImageBase alani loader tarafindan guncellendigi icin
// oradan okumak 'ASLR kaymasi 0' yanilsamasi uretiyordu.
static int read_file_pe_base(const char* name, unsigned long long* prefBase, WORD* dllChars) {
    FILE* f = fopen(name, "rb");
    if (!f) return 0;
    unsigned char hbuf[0x400];
    size_t n = fread(hbuf, 1, sizeof(hbuf), f);
    fclose(f);
    if (n < 0x200 || hbuf[0] != 'M' || hbuf[1] != 'Z') return 0;
    DWORD e = *(DWORD*)(hbuf + 0x3C);
    if (e + 0x48 > n) return 0;
    WORD magic = *(WORD*)(hbuf + e + 24);
    if (magic == 0x20B)      *prefBase = *(unsigned long long*)(hbuf + e + 24 + 0x18);
    else if (magic == 0x10B) *prefBase = (unsigned long long)*(DWORD*)(hbuf + e + 24 + 0x1C);
    else return 0;
    *dllChars = *(WORD*)(hbuf + e + 24 + 0x46);
    return 1;
}

static void dump_process(HANDLE h, DWORD pid, const char* procName) {
    HMODULE mod = NULL; DWORD modSize = 0;
    // modul tabani (x86 hedef icin TH32CS_SNAPMODULE32)
    HANDLE ms = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (ms != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me; me.dwSize = sizeof(me);
        if (Module32FirstW(ms, &me)) {
            do {
                wchar_t low[260]; lstrcpyW(low, me.szModule);
                for (wchar_t* p = low; *p; p++) if (*p >= L'A' && *p <= L'Z') *p += 32;
                if (wcsstr(low, L"test_vmp") || wcsstr(low, L"test32_vmp")) {
                    mod = (HMODULE)me.modBaseAddr; modSize = me.modBaseSize; break;
                }
            } while (Module32NextW(ms, &me));
        }
        CloseHandle(ms);
    }
    if (!mod) { printf("  modul tabani bulunamadi\n"); return; }

    BOOL wow = FALSE; IsWow64Process(h, &wow);
    MAN* m = NULL;
    for (int i = 0; i < 2; i++) if (g_man[i].is64 == !wow) m = &g_man[i];
    if (!m) { printf("  mimari tespit edilemedi\n"); return; }

    unsigned char hdr[0x400];
    SIZE_T rd = 0;
    printf("\n================ %s (PID %lu) ================\n", procName, (unsigned long)pid);
    printf("Hedef mimari : %s\n", wow ? "x86 (32-bit, WOW64)" : "x64");
    if (!ReadProcessMemory(h, mod, hdr, sizeof(hdr), &rd) || rd < 0x200) {
        printf("  PE basligi okunamadi (hata %lu)\n", GetLastError()); return;
    }
    DWORD e_lfanew = *(DWORD*)(hdr + 0x3C);
    unsigned long long prefBase = 0; WORD dch = 0;
    int fromDisk = read_file_pe_base(procName, &prefBase, &dch);
    if (!fromDisk) {
        /* dosya CWD'de yok -> eski yontem (canli header; loader guncelledigi
           icin kayma 0 gorunebilir — v1.2 davranisi) */
        prefBase = wow ? (unsigned long long)*(DWORD*)(hdr + e_lfanew + 0x34)
                       : *(unsigned long long*)(hdr + e_lfanew + 0x30);
    }
    unsigned long long modAddr = (unsigned long long)(DWORD_PTR)mod;
    printf("Modul tabani : 0x%llX   (Windows'un gercek yukleme adresi)\n", modAddr);
    printf("Tercih edilen ImageBase : 0x%llX  [%s]\n", prefBase,
           fromDisk ? "DISKTAKI dosyadan (gercek tercih)"
                    : "canli header'dan (loader guncellemis olabilir!)");
    printf("ASLR kaymasi : %s0x%llX  (CE'de adresler = modul tabani + RVA)\n",
           (modAddr - prefBase) ? "+" : "", modAddr - prefBase);
    if (fromDisk && (dch & 0x0040))
        printf("               [DYNAMIC_BASE ACIK: her calistirmada taban rastgele degisir]\n");

    // --- bolum tablosu ---
    WORD nsec = *(WORD*)(hdr + e_lfanew + 6);
    DWORD optsize = *(WORD*)(hdr + e_lfanew + 20);
    unsigned char* sh = hdr + e_lfanew + 24 + optsize;
    printf("\n--- Bolum tablosu (bellekteki PE) ---\n");
    printf("%-10s %-10s %-10s %s\n", "BOLUM", "RVA", "VSIZE", "CHARS");
    for (WORD i = 0; i < nsec && i < 16; i++) {
        unsigned char* s = sh + i * 40;
        char nm[9]; memcpy(nm, s, 8); nm[8] = 0;
        DWORD va = *(DWORD*)(s + 12), vsz = *(DWORD*)(s + 8), ch = *(DWORD*)(s + 36);
        printf("%-10s 0x%08lX 0x%08lX 0x%08lX %s\n", nm, (unsigned long)va, (unsigned long)vsz, (unsigned long)ch,
               strncmp(nm, ".vmp0", 5) == 0 ? "  <-- VM BOLUMU (kod+veri, RWX)" : "");
    }

    printf("\n--- Sanallastirilan fonksiyonlar (%s) ---\n", m->exe);
    printf("%-16s %-9s %-11s %-11s %s\n", "FONKSIYON", "RVA", "STUB TIPI", "BC BOYUT", "VM ANAHTARI");
    for (int i = 0; i < m->nf; i++) {
        FN* f = &m->f[i];
        printf("%-16s +0x%05lX  %-11s %-11llu 0x%016llX\n",
               f->name, (unsigned long)f->funcRva, f->tramp ? "trampoline" : "yerinde",
               (unsigned long long)f->bcLen, f->key);
    }
    printf("(GameTick x86'da native birakildi: yaprak-modu geregi)\n" );
    printf("vm_entry        : modul+%X  (VM yorumlayici girisi, .vmp0 basi)\n", m->vmpRva + m->ventOff);

    printf("\n--- Canli bellek dogrulama (ReadProcessMemory) ---\n");
    for (int i = 0; i < m->nf; i++) {
        FN* f = &m->f[i];
        unsigned char buf[0x90]; SIZE_T rr = 0;
        DWORD_PTR addr = (DWORD_PTR)mod + f->funcRva;
        if (!ReadProcessMemory(h, (LPCVOID)addr, buf, 0x90, &rr)) {
            printf("  (modul+0x%lX okunamadi hata=%lu)\n", (unsigned long)f->funcRva, GetLastError());
            continue;
        }
        printf("\n%s  [+0x%lX]\n", f->name, (unsigned long)f->funcRva);
        printf("  .text'teki ilk 32 bayt : "); hexdump8(buf, 32); printf("\n");
        if (f->tramp) {
            printf("  (E9 = trampoline jmp; gercek stub .vmp0 icinde +0x%lX)\n", (unsigned long)f->stubRva);
            DWORD_PTR sa = (DWORD_PTR)mod + f->stubRva;
            if (ReadProcessMemory(h, (LPCVOID)sa, buf, 0x90, &rr)) {
                printf("  stub @modul+0x%lX ilk 32 : ", (unsigned long)f->stubRva); hexdump8(buf, 32); printf("\n");
                DWORD bcrva = 0; unsigned long long key = 0;
                if (extract_stub_info(buf, (int)rr, m->is64, &bcrva, &key)) {
                    printf("  stub'dan cikarilan bc RVA=0x%lX  key=0x%016llX %s\n",
                           (unsigned long)bcrva, key, (key == f->key) ? "(manifest ile AYNI)" : "(FARK!?)");
                    unsigned char bc[16];
                    DWORD_PTR ba = (DWORD_PTR)mod + bcrva;
                    if (ReadProcessMemory(h, (LPCVOID)ba, bc, 16, &rr)) {
                        printf("  sifreli bytecode ilk 16 : "); hexdump8(bc, 16); printf("\n");
                        printf("  (XOR anahtari pozisyon-bazli; CE'de bu adreste anlamsiz\n"
                               "   bayt gorursunuz — bu NORMALDIR, VM cozumler)\n");
                    }
                }
            }
        } else {
            printf("  (yerinde stub: tum VM girisi .text'te; kopyasi .vmp0 +0x%lX)\n", (unsigned long)f->stubRva);
        }
    }

    // --- .vmp0 canli koruma + exec/free bellek taramasi ---
    printf("\n--- Bellek haritasi taramasi (VirtualQueryEx) ---\n");
    SIZE_T vmpStart = (SIZE_T)mod + m->vmpRva;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T addr = 0, top = wow ? 0x7FFF0000ULL : 0x7FFFFFFEFFFFULL;
    int privExec = 0; DWORD vmpProt = 0; int iter = 0;
    while (addr < top && iter++ < 200000) {
        if (!VirtualQueryEx(h, (LPCVOID)addr, &mbi, sizeof(mbi))) break;
        if (mbi.State == MEM_COMMIT && (mbi.Protect & 0xF0) != 0 &&
            !(mbi.Protect & PAGE_GUARD)) {
            int exec = (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE ||
                        mbi.Protect == PAGE_EXECUTE_WRITECOPY || mbi.Protect == PAGE_EXECUTE);
            if (exec && mbi.Type == MEM_PRIVATE) {
                privExec++;
                printf("  OZEL EXEC bolge: 0x%p boyut=0x%lX protect=0x%lX\n",
                       (void*)mbi.BaseAddress, (unsigned long)mbi.RegionSize, (unsigned long)mbi.Protect);
            }
            if ((SIZE_T)mbi.BaseAddress <= vmpStart &&
                vmpStart < (SIZE_T)mbi.BaseAddress + mbi.RegionSize) {
                vmpProt = mbi.Protect;
            }
        }
        addr = (SIZE_T)mbi.BaseAddress + mbi.RegionSize;
    }
    printf("  .vmp0 korumasi       : 0x%lX (%s)\n", (unsigned long)vmpProt,
           vmpProt == PAGE_EXECUTE_READWRITE ? "RWX — VM bytecode cozumlemesi icin yazilabilir" : "?");
    printf("  Modul disi ozel EXEC : %d bolge\n", privExec);
    printf("  (Bu port runtime'da kod URETMEZ/YAZMAZ — VMProtect'in aksine JIT yok;\n"
           "   tum VM kodu .vmp0'da statik. Ozel EXEC beklenmez.)\n");

    printf("\n--- Cheat Engine yol haritasi ---\n");
    printf("  1) CE ac -> bilgisayar ikonu -> bu sureci sec\n");
    printf("  2) Memory Viewer -> Address: \"%s\"+%lX (orijinalde burasi %s idi)\n",
           m->exe, (unsigned long)m->f[0].funcRva, m->f[0].name);
    printf("  3) Orijinalle karsilastirmak icin \"%s\" dosyasindan da bakabilirsin\n", m->exe);
    printf("     (orijinalde +0x%lX'de gercek opcode'lar: push rbp/mov...)\n", (unsigned long)m->f[0].funcRva);
    printf("  4) VM giris anini yakalamak: modul+%lX (vm_entry) 'e breakpoint koy;\n"
           "     her w/a/s/d+Enter'da buraya gelmeli\n", (unsigned long)(m->vmpRva + m->ventOff));
    printf("  5) VM calisma alani STACK'tedir (ctx ~0x268 bayt); key ctx+0x10'da\n");
}

static int try_process(DWORD pid, const char* pname) {
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { printf("OpenProcess basarisiz PID=%lu hata=%lu\n", (unsigned long)pid, GetLastError()); return 0; }
    dump_process(h, pid, pname);
    CloseHandle(h);
    return 1;
}

int main(int argc, char** argv) {
    printf("VMPHelper — CPlusPort sanallastirma dogrulama araci (v1.3)\n");
    printf("=====================================================\n");
    if (argc > 1) {
        // pid ya da isim
        DWORD pid = (DWORD)atoi(argv[1]);
        if (pid) { try_process(pid, argv[1]); return 0; }
        HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        wchar_t want[260]; mbstowcs(want, argv[1], 259);
        for (wchar_t* p = want; *p; p++) if (*p >= L'A' && *p <= L'Z') *p += 32;
        if (s != INVALID_HANDLE_VALUE) {
            if (Process32FirstW(s, &pe)) {
                do {
                    wchar_t low[260]; lstrcpyW(low, pe.szExeFile);
                    for (wchar_t* p = low; *p; p++) if (*p >= L'A' && *p <= L'Z') *p += 32;
                    if (lstrcmpW(low, want) == 0) try_process(pe.th32ProcessID, argv[1]);
                } while (Process32NextW(s, &pe));
            }
            CloseHandle(s);
        }
        return 0;
    }
    // varsayilan: bilinen iki exe'yi ara
    const char* targets[] = { "Test_vmp.exe", "Test32_vmp.exe" };
    int found = 0;
    for (int t = 0; t < 2; t++) {
        HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (s == INVALID_HANDLE_VALUE) continue;
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        wchar_t low[260]; mbstowcs(low, targets[t], 259);
        for (wchar_t* p = low; *p; p++) if (*p >= L'A' && *p <= L'Z') *p += 32;
        if (Process32FirstW(s, &pe)) {
            do {
                wchar_t lo2[260]; lstrcpyW(lo2, pe.szExeFile);
                for (wchar_t* p = lo2; *p; p++) if (*p >= L'A' && *p <= L'Z') *p += 32;
                if (lstrcmpW(lo2, low) == 0) { found += try_process(pe.th32ProcessID, targets[t]); }
            } while (Process32NextW(s, &pe));
        }
        CloseHandle(s);
    }
    if (!found) {
        printf("\nCalisan Test_vmp.exe / Test32_vmp.exe bulunamadi.\n"
               "Once korumali oyunu baslat, sonra bu araci ac.\n");
#ifdef DEBUG_LIST
        printf("[debug] surec listesi:\n");
        HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (s != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
            if (Process32FirstW(s, &pe)) {
                int n = 0;
                do {
                    char nm[260]; wcstombs(nm, pe.szExeFile, 259);
                    printf("  pid=%lu %s\n", (unsigned long)pe.th32ProcessID, nm);
                } while (++n < 25 && Process32NextW(s, &pe));
            } else printf("  Process32FirstW basarisiz hata=%lu\n", GetLastError());
            CloseHandle(s);
        } else printf("  snapshot basarisiz hata=%lu\n", GetLastError());
#endif
    }
    return 0;
}
