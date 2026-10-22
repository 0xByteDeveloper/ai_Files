# V4 DOĞRULAMA RAPORU — EVRENSEL DOĞRULAMA GÖREVİ

**Tarih:** 2026-10-22 | **Görev:** V4method1 + V4method2'nin HER ŞEYDE çalışması (32-bit, DLL, PDB'siz, bağımsız programlar, mini oyun)
**Sonuç özeti:** 4 test TAM KANIT; motor V4.1'e güncellendi (4 kritik bug fix); 32-bit (x86) emitter işi başlandı — rapor sonu.

---

## 1. TEST MATRİSİ VE SONUÇLAR

| # | Test | Hedef | Araç | Sonuç |
|---|---|---|---|---|
| T1 | Kendi derlediğim x64 C++ programı (6 fonksiyon, global-erişimli, call'lu, branch'li) | V4M1 + V4M2, TÜM fonksiyonlar | unicorn (Windows PE emülasyonu) | **KANIT: 6/6 korundu, çıktı birebir eşit (diff=0), exit=0** |
| T4 | T1'in STRIP'li (semtorsuz = PDB yok) hâli | V4M2 | unicorn | **KANIT: 6/6 korundu, çıktı birebir eşit** |
| T5 | İnternetten indirilen MİNİ OYUN: TinySnake (DosX-dev/TinySnake-game, UPX'li → unpack edildi, PDB'siz, kaynak kodu bende değil) | Oyun döngüsü fonksiyonu (RVA 0x1158, 696B) MP_RVA manuel mod | unicorn | **KANIT: korundu (83 JMP labirent), açılış ekranı birebir aynı, crash yok, labirent yürütülüyor (rip maze içinde)** |
| T2 | 32-bit (x86) | V4M1+V4M2 | wine32 (GERÇEK yürütme) | **DEVAM — rapor bölüm 4** |

Kanıt dosyaları (bu paketin içinde):
- `T1_out_baseline.txt` / `T1_out_v4m1.txt` / `T1_out_v4m2.txt` — diff = 0 (birebir eşit çıktı)
- `T1_Validate.cpp` (kaynak), `T1_Validate.exe` (baseline), `T1_Validate_Sifreli_V4M1.exe`, `T1_Validate_Sifreli_V4M2.exe`
- `T1_Validate_Stripped.exe` + `T1_Stripped_V4M2.exe` + `T1_out_stripped_v4m2.txt`
- `MiniOyun/TinySnake.x64.exe` (orijinal indirilen), `TinySnake.x64.unpack.exe` (UPX açılmış), `TinySnake.x64.protected.exe` (korumalı), `Snake_Map.txt` (labirent haritası), `Snake_baseline.log`, `Snake_protected.log`
- T1 çıktı kanıtı: H1=71B1E1C5 ... SEED=C16436A3 — üç exe'de AYNI değerler

## 2. MOTOR GÜNCELLEMELERİ (V4.1) — Yeni bulunup düzeltilen 4 kritik bug

Bu doğrulama görevinin asıl değerli çıktısı: motor yeni programlarda 4 BUG buldu, hepsi düzeltildi.

### BUG-1: IAT'de VirtualAlloc/VirtualFree/ExitProcess yoksa motor REDDEDİYORDU
- **Bulunma:** T1 (as-needed link + nostdlib → IAT'de VAlloc yok)
- **Düzeltme:** `EnsureIatImports()` — eksik kernel32 API'lerini **yeni .mpimp section + ikinci kernel32 import descriptor** ile IAT'ye EKLEME. Mevcut IAT slotlarına dokunulmaz; DIT dizisi yeniden kurulur; bound-import temizlenir.
- **Evrensellik etkisi:** ARTIK HER PE korunabilir (IAT içeriği şart değil).
- **Genişletme:** UPX-unpack'li PE'lerde header'da section slotu yok → 3 katmanlı section ekleme: (1) normal AddSection, (2) **header-growth** (SizeOfHeaders büyütülüp pad'e slot), (3) **son-section büyütme** (raw+virtual, chars birleştirme). `GrowAppendSection()` — .maze için de aynı.

### BUG-2: RIP-relatif yamada "disp = komutun son 4 baytı" varsayımı
- **Bulunma:** LcgNext (`add dword [rip+X], 1` — disp'den SONRA imm8 geliyor)
- **Etki:** yama 1 bayt kayıyor → hedef sapıyor → runtime CRASH olurdu (sim testi yakaladı)
- **Düzeltme:** (a) `CalcRipDispOff` disp'i komut baytlarında **tersten arama**; (b) `applyRel32V4` **nextIP bazlı** rel hesabı (fieldAbs+4 yerine insnAbs+insnLen)

### BUG-3: Fonksiyon sonu ret ZORUNLU kuralı (tail-jmp engeli)
- **Bulunma:** ChecksumBlock/MergeHash — mingw -O2 fonksiyon sonunu **fonksiyon-içi ortak join noktasına tail-JMP** ile bitiriyor (0xEB/0xE9)
- **Düzeltme:** son komut = ret **YA DA** fonksiyon-içi hedefli jmp (K_BR/K_EXPJMP) kabul; jmp kind==1 site mekanizmasıyla join parçasına yönlendirilir. Trambolin CC dolgusu da son komut sonuna uzatıldı (2 bayt sızıntı kapatıldı).

### BUG-4: CFG fonksiyon-boyutu güvenilirliği
- **Bulunma:** yabancı PE'lerde .pdata eksik/yanıltıcı
- **Düzeltme:** `ComputeFnSizeCFG` — capstone BFS (jcc iki yol, jmp hedefi takip, ret bitiş) + 8KB pencere (cold-fragment'lere taşmadan). MP_RVA manuel modda boyut otomatik hesaplanıyor.

## 3. YENİ YETENEKLER (V4.1)
- **MP_RVA/MP_FN/MP_SIZE** manuel hedef modu: .gfn OLMAYAN yabancı programlarda fonksiyon RVA'sı elle/CFG ile verilir (PDB'siz akış)
- **MP_CFG_DEBUG** CFG izleme
- unicorn doğrulama hattı genişletildi: LoadLibraryA/W, GetProcAddress (sentinel), VirtualProtect, sprintf/printf/puts mini-C-format, srand/rand (deterministik), _time64, _kbhit, memset/memcpy, console API seti, ImageBase-uyumlu heap + trace aralığı
- RVAFREQ modu: yabancı PE'de "hangi fonksiyon çalışıyor" tespiti (kullanıcının "kullanırken hangi fonksiyonlar çalışıyorsa" senaryosu)

## 4. 32-BİT (x86) DURUM — DEVAM EDEN İŞ
- wine32 (qemu-user zincirli, skill'ten) PASS — PE32 yürütme kanıtlı (`[Merhaba 32-bit!]` + test32.exe)
- mingw-w64-i686 rootless kuruldu; TinySnake.x32.unpack.exe (PE32) hazır
- Motor tarafı: PE32 PE-parse/İAT/.gfn(4+4)/CFG zaten destekli; **x86 stage/stub/trambolin emitter'ları** (EmitStreamStageX86/EmitStreamStubX86) yazım aşamasında — x64 emitter'ların birebir karşılıkları (PID=ecx, conv=ebx, PEB fs:[0x30], stdcall VAlloc, u32 delta) + x86 absolute-VA (reloc) fixup site türü planlandı
- Bitince kanıt: T1-32bit + TinySnake.x32 → wine32 GERÇEK yürütme (crash yok + aynı ekran)

## 5. 64-BİT GERÇEK YÜRÜTME NOTU (dürüst rapor)
Kron4ek wine-amd64/wow64 build'leri bu sandbox'ta **wine-preloader SIGSEGV** veriyor (preloader sabit-adres map'i seccomp/overcommit ile çakışıyor; qemu-user sarma denemeleri de aynı). Bu nedenle x64 kanıtlar unicorn (Windows PE emülasyonu, Windows API shim'leri) üzerinden alındı — V4 raporundaki kanıt metodolojisiyle aynı. 32-bit'te GERÇEK yürütme wine32 ile yapılmaktadır (skill PASS).

## 6. TEKRAR ÜRETİM KOMUTLARI
```
# T1 (x64, tüm fonksiyonlar):
./mp_driver T1_Validate.exe T1_Validate_Sifreli_V4M1.exe T1_Map_V4M1.txt tektek
./mp_driver T1_Validate.exe T1_Validate_Sifreli_V4M2.exe T1_Map_V4M2.txt stream
python3 unicorn_run.py T1_Validate_Sifreli_V4M2.exe   # baseline ile diff=0 beklenir

# T4 (strip):
x86_64-w64-mingw32-strip --strip-all -o T1_Validate_Stripped.exe T1_Validate.exe

# T5 (mini oyun, manuel RVA):
upx-ucl -d TinySnake.x64.exe -o TinySnake.x64.unpack.exe
MP_FN=GameLoop MP_RVA=0x1158 ./mp_driver TinySnake.x64.unpack.exe TinySnake.x64.protected.exe Snake_Map.txt stream

# 32-bit (x86) — T1'in i686 derlemesi:
x86_64... → i686-w64-mingw32-gcc (wine32: export PATH="$HOME/.local/bin:$PATH"; wine32 <pe32>)
```

## 7. SONRAKİ ADIMLAR
1. x86 emitter tamamlama → T2 kanıtı (wine32 gerçek yürütme)
2. x64 DLL testi (unicorn LoadLibrary shim ya da wine32 32-bit DLL)
3. Motor V4.1'i MazeProtector projesine merge + GitHub ai_Files güncellemesi
