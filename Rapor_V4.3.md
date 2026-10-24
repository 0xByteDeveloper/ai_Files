# MazeProtector V4.3-IP — EVRENSEL DOGRULAMA RAPORU (Tur-3)

**Tarih:** 2026-10-22 | **Motor:** Motor_V4.3_IP.h (in-place) | **Durum: TUM TESTLER GECTI**

---

## 1. KULLANICININ SORDUGU SORULARIN CEVAPLARI

### S1) "Cokmalarin ve oyunun yuklenmemesinin sebebi ne?"
Eski V4.1/V4.2 "maze/stream" makinesi komutlari .maze'ye TASIRDI. Bunun 3 bedeli vardi:
1. **Tasiyici register kirilgani:** runtime makinesi korunan fonksiyon boyunca
   r12/r11'de tasiyici tasiyordu; fonksiyon bu registerlari kullaninca labirent kirilyordu.
2. **Tasinma sonrasi duzeltme yuku:** her rip-relatif/rel32 dal icin "site fixup"
   gerekiyordu; gercek derleyicilerin cikardigi her form yakalanamiyordu.
3. **Slot/arena yonetimi:** wipe-behind + rastgele slot her yol icin dogru
   calismiyordu. Unicorn emulasyonu geciyor ama gercek Windows'ta cokuyordu.

### S2) "Oyunun gameloop'unu mu soktun, o yuzden mi yuklenmiyor?"
Evet, korunan fonksiyon GameLoop idi (x64 RVA 0x1158, 696 bayt) — bu bilerek yapildi
(oyun mantigini sifrelemek amac). Hata fonksiyon seciminde degil, motorun tasiyici-
tabanli runtime'inda idi. **V4.3-IP ile ayni GameLoop korundu ve oyun gercek
wine32'de 8+ saniye boyunca cokmeden calisti (70 kez SCORE cizimi).**

### S3) "MiniGameHost.exe ciktisindan ne anlamaliyim?"
O cikti = **DLL korumasinin calistiginin kanitiydi**:
- `MOD=10000000`  -> MiniGameDll.dll LoadLibraryA ile GERCEKTEN yuklendi (modul base)
- `MOVEH=D0D78AB3`-> 40 hamle + 2 LCG cagrisinin FNV hash'i (baseline ile birebir)
- `SCORE/X/Y/LCG` -> oyun durumunun son hali (belirleyici akis)
Ama eski host bunu ACIKLAMiyordu ve pencere hemen kapaniyordu. **Yeni
MiniGameHost2.exe** hem ORIJINAL hem KORUMALI DLL'i yukleyip hash'leri
karsilastiriyor ve "ESLESME=TAM" yazip Enter bekliyor.

### S4) "Address sifrelerken end-address bulucu instruction ayraci var mi?"
**VAR, 3 katman:**
1. `ByteInjector::FindFunctionEnd` — capstone ile komut-komut yurur, ilk ret+CC'de durur
2. `ComputeFnSizeCFG` (driver) — BFS ile dallanmalari takip eder, gercek extent bulur
3. **YENI `SnapRange` (mp_driver43):** `MP_START=0x... MP_END=0x...` verdiginizde
   END komut ortasina denk gelirse **son komut sinirina GERI ceker** (komut bolme YOK);
   MP_END vermezseniz BFS ile kendisi bulur.

---

## 2. V4.3-IP MOTORUNUN COZUMU: "HICBIR KOMUT TASINMAZ"

| Ozellik | V4.1/V4.2 maze | **V4.3-IP** |
|---|---|---|
| Komutlar | .maze'ye tasinir | **.text'te YERINDE sifreli** |
| rip-relatif / mutlak adres | bazi formlar reddedilir | **hepsi calisir (komut yerinde)** |
| jump-table / loop / jcxz | reddedilir | **calisir** |
| r12/r11 tasiyici | var (kirilgan) | **YOK (handler kendini konumlandirir)** |
| IAT degisikligi | VirtualAlloc/VFree eklenir | **YOK** |
| TLS/Entry hook | var | **YOK** |
| reloc (DLL tasinma) | kotu | **destekli: body-reloc listesi CB'de, ilk decrypt'te -delta** |
| ABI (argumanlar) | riskli | **return-slot yerinde degisir, arg bolgesi kaymaz** |
| recursion/multi-thread | depth | **depth + spinlock + LIFO side havuzu (8)** |
| tail-jmp/longjmp/exit | cokebilir | **state bayragi: plaintext kalir, cokme YOK** |
| Anahtar | sabit | **M1: sabit / M2: her cagrida yeni rastgele (rdtsc+esp karisimi)** |

### Calisma akisi
```
cagri -> E9 trambolin -> handler:
         spinlock -> depth++ -> (ilk cagri) reloc-delta geri al -> XOR-coz (yerinde)
         -> realRet'i CB.side[] havuzuna it -> return-slot'u ret-stub adresiyle DEGIS
         -> proxy (bas komutlari, disp'leri duzeltilmis) -> govde (orijinal adres, orijinal baytlar)
donus -> ret-stub: depth-- -> (son cikista) XOR-sifrele (M2: YENI anahtar)
         -> side[]'den realRet -> ret
```

---

## 3. TEST MATRISI (hepsi gecti)

| # | Hedef | Motor | Kanit | Sonuc |
|---|---|---|---|---|
| 1 | T1 x64 (6 fonksiyon) | IP1 | unicorn: 11/11 hash + exit=0 | **TAM** |
| 2 | T1 x64 (6 fonksiyon) | IP2 | unicorn: 11/11 hash + exit=0 | **TAM** |
| 3 | T1-32 x86 (6 fonksiyon) | IP1 | **GERCEK wine32**: 11/11 hash birebir | **TAM** |
| 4 | T1-32 x86 (6 fonksiyon) | IP2 | **GERCEK wine32**: 11/11 hash birebir | **TAM** |
| 5 | TinySnake.x64 GameLoop | IP1 | unicorn Monte-Carlo 2 seed OK (3697 tus) | **TAM** |
| 6 | TinySnake.x32 GameMain | IP1 | **GERCEK wine32: 8sn+ canli, 70 SCORE cizimi, crash YOK** | **TAM** |
| 7 | MiniGameDll IP1 (x86) | IP1 | **GERCEK wine32: ESLESME=TAM (MOVEH=D0D78AB3)** | **TAM** |
| 8 | MiniGameDll IP2 (x86) | IP2 | **GERCEK wine32: ESLESME=TAM** | **TAM** |
| 9 | Statik dogrulama (tum buildler) | — | verify_ip.py: CB + govde-cozum + trambolin + proxy | **TAM** |

Not: x64 tarafta gercek-Windows calistirma bu sandbox'ta yok (yalniz wine32 var);
x64 kanitlari unicorn + statik + "x86'da gercek calisma" simetrisiyle desteklenir.
IP motorunun x64/x86 handler'lari ayni mantiktir.

---

## 4. BU TURDA BULUNUP DUZELTILEN HATALAR (hepsi kok-nedenli)

1. **x64 xor-loop REX hatasi** (`44 31 C0` -> `41 31 C0`): akis sabit kaliyordu, govde cozulmuyordu
2. **Proxy disp hesabi yanlis taban** (fnRva yerine proxyRva): iki-pas uretim
3. **x86 arg kaymasi**: rets-zinciri stack'e slot itiyordu -> **side[] havuzu + yerinde slot-degisimi**
4. **x86 callee-saved ebx/esi sizmasi**: handler cagiranin ebx/esi'sini bozuyordu -> save/restore
5. **disp8 tasmasi** (CB offsetleri >0x7F): CB yeniden dizildi
6. **reloc-guvenli koruma**: loader sifreli govdeye += delta uygularsa ilk decrypt'te geri alinir
7. **RebuildRelocations entry baytlarini hic yazmiyordu** (yalniz header) -> gercek block yazici
8. **count=0 adjust dongusu** sonsuz donebiliyordu -> test/je eklendi
9. **x64 REX.B eksik** (lea/mov r10): 4C -> 4F/4B
10. **DLL ImageBase cakismasi**: korumali DLL'e serbest base + .gfn VA tasima

---

## 5. KULLANIM

```
# Tek fonksiyon (PDB'siz, manuel):
MP_FN=GameLoop MP_RVA=0x1158 ./mp_driver43 giris.exe cikis.exe Map.txt ip1

# Aralik modu (end-address bulucu + komut-siniri snap):
MP_START=0x1158 MP_END=0x1420 ./mp_driver43 giris.exe cikis.exe Map.txt ip1

# .gfn'li kendi programin:
./mp_driver43 giris.exe cikis.exe Map.txt ip2      # M2 = donen anahtar
```

- `ip1` = TekTek-IP (sabit anahtar, donuste yeniden sifrele)
- `ip2` = Stream-IP (her cagrida YENI rastgele anahtar)
- Cikti Map dosyasi: FUNC/IPINFO satirlari (CB/proxy/handler RVA + seed) — Cheat Engine icin.

**Sinirlar (belgeli):** govde section'i yazilabilir isaretlenir (W^X gevser);
ImageBase cakisirsa reloc-adjust devreye girer; fonksiyon basi loop/jcxz icerirse reddedilir.

---

## 6. SONRAKI ADIMLAR
- ULTRAPLUS / God-Mode (V3 ARENA + V4M2 + VMProtect tarzi katmanlar) — havuzda bekliyor
- Gercek Windows'ta x64 Dogrulama (kullanici testi) — Snake x64 IP1 + T1 x64 IP1/IP2
- V4.3-IP'yi ana i4MConsoleLoader GUI'sine baglama
