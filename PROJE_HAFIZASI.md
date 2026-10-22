# PROJE HAFIZASI — MazeProtector / i4MConsoleLoader / XProtect Portu

> **Bu dosyanın amacı:** Yapay zeka oturumu (GLM) herhangi bir nedenle çökerse, bu dosya + repo içeriğiyle projeyi KAYIPSIZ sürdürmek. Buradaki her bilgi 2026-10-22 itibarıyla doğrudur ve test kanıtlarıyla desteklidir.
> **Son güncelleme:** 2026-10-22 | **Durum:** V4method1 + V4method2 TAMAMLANDI (WON=1), VMProtect analizi TAMAMLANDI, C++ portu (XProtect) BAŞLADI

---

## 1. PROJE KİMLİĞİ VE AMAÇ

**Ana proje:** i4MConsoleLoader + içinde gömülü MazeProtector koruma modülü.

- **i4MConsoleLoader:** ImGui'siz, konsol, x64 PE **manuel-map loader** simülasyonu. Windows'un "dosya → process belleği" dönüşümünü 8 aşamada birebir taklit eder: (1) DOS/NT header doğrulama, (2) VirtualAlloc (ImageBase tercih edilir, doluysa relocation), (3) header kopya, (4) section raw→virtual map, (5) base relocation (HIGH/LOW/HIGHLOW/**HIGHADJ +0x8000**/DIR64), (6) import çözümü (LoadLibraryA+GetProcAddress→IAT), (7) PAGE_* korumalar, (8) entry point çağrısı. Kaynak: `i4MConsoleLoader/i4MConsoleLoader/PEManualMapper.h` (28.5K) + `main.cpp` (35.4K) + `globals.h` (76.5K, çekirdek motor) + `InstanceManager.h` + `LoaderSelfTest.h`. Eski adı i4MGUILoader (5938 satır ImGui sürümünden arındırılmış).
- **MazeProtector:** fonksiyon-RVA bazlı **JMP labirenti + XOR şifreleme** koruma modülü. Kaynak: `V4method2_Stream/i4MConsoleLoader_kaynak/i4MConsoleLoader/MazeProtector.h` (159.7 KB — **V3 VE V4 motorlarının ikisini de içerir**).

**Nihai hedef (kullanıcının büyük projesi):** VMProtect tarzı ticari kalitede, **tamamen C++ yazılmış** kendi kod koruyucumuzu yapmak. Yol: universalObfusPublicSrc (VMProtect 3.x kaynak kodu) analiz edilerek birebir C++ portu (XProtect) + üstüne bizim V4 runtime rastgelelik fikirleri.

---

## 2. YÖNTEM EVRİMİ (V1 → V4)

| Sürüm | Yöntem | Zayıflık |
|---|---|---|
| V3 (ARENA) | Fonksiyon TÜM BİR KERE plaintext RWX arenaya decrypt edilir: 8 push → VirtualAlloc → chunk kopya → **XOR 0xA14FC884A80CA3E1** → delta-fixup → JMP chunk1 → farewell → memset → VirtualFree ("free mem'e aç, iş bitince sil") | Her an TÜM fonksiyon plaintext → dump edilebilir |
| V4method1 (TekTek) | Per-piece decrypt + **wipe-behind**, SABİT slot. Her yeni parçadan önce önceki SIFIRLANIR (silmezsen op0+op1+...+op28 yine tam fonksiyon olur — birikim!) | Sabit adres → dump-replay mümkün |
| V4method2 (Stream) | Tek **24 baytlık slot** + wipe-behind + thunk geçişleri + G1/G2/G3. Arena 1113B → max 32B; 248B fonksiyon → max 24B plaintext | Şu anki en güçlü bizim yöntem |

**V4method2 (V4 STREAM) mimarisi — detay:**
- Tek 24B slot; kenarlar **kapıdan geçer**: connector/jne → `.maze` içindeki **10 baytlık thunk**'lara: `mov r10d, <parca_no>; jmp stage`
- **Per-call self-built stage:** her çağrı kendi stage'ini kurar (thread yarısı sorunu böyle çözüldü — jmpSlot paylaşımlı olduğu için çağrı yarısı bozuluyordu)
- **G1:** her çağrı başka adrese düşme (dump-replay ölür) — kanıt: 64 benzersiz slot adresi 0x3D0..0x7C0
- **G2:** CRC-8 anti-patch (parça-uğurlu)
- **G3:** decoy enjeksiyonu
- **Lazy cold path:** duvar (jne alınırsa) o çağrıda bazı parçalar FİZİKSEL olarak hiç decrypt edilmez — kanıt: MP_FORCE_WALL=1, 20000 çağrı → pid7=0 pid8=0 (px/ny parçaları hiç çözülmedi)
- Duvar-yok modda: 10 parça x 529 çağrı (min=max — deterministik dağılım)

**Header formatları:**
- `.gfn` section = fonksiyon kayıtları (RVA, boyut, parça sayısı)
- `.maze` section = MZE3 header: **nBlocks@0, magic@4** + şifreli parça blob'ları + thunk'lar
- Orijinal RVA'ya **5 baytlık E9 trambolin**
- XOR anahtarı: **0xA14FC884A80CA3E1** (V3'te sabit; V4'te parça başına)

**Sırada bekleyen fikirler (raporlandı, kodlanmadı):**
- **G5 (TF/VEH single-step):** EFLAGS.TF + AddVectoredExceptionHandler ile komut-komut decrypt (her an ≤1 komut ~15B). Maliyet: ~100-300x yavaş, ~300-500 satır, 2-4 gün. Bedava anti-debug bonus. Syscall TF silme ve CALL step-over zorlukları raporda.
- **G6 (mini-VM):** VMProtect benzeri kod sanallaştırma — 20-40 handler'lık el yapımı VM, VREG[], VLoop, .maze'de bytecode. Maliyet: ~10-50x yavaş, 1500-3000 satır, 1-3 hafta. L1 stack-VM → L2 register-VM → L3 mutation (opcode shuffle).
- **Anahtar zincirleme (VMProtect'ten ödünç):** parça N anahtarı parça N-1 plaintext'inden türesin — tek sabit XOR son zayıflık, bunu kapatır. (Rapor: universalObfusPublicSrc_Analiz.md bölüm 5.4)

---

## 3. V4M2 vs VMProtect KARŞILAŞTIRMASI (anti-debug hariç, kod koruma kategorisi)

| | V4method1 | V4method2 | VMProtect Ultra Virt+Mut |
|---|---|---|---|
| Koruma gücü | 5.5/10 | 8.5/10 | 9/10 |
| Performans (hot-path) | 9.5/10 | 9/10 | 3.5/10 |
| GENEL | 6/10 | **8.5/10** | 7/10 |

**Karar:** Move gibi sık çağrılan fonksiyonlar V4M2 ile korunmalı. VMProtect Virt 10-50x yavaşlatır. Hibrit öneri: V4M2 + kritik bloklara G6.

**VMProtect kaynak analizi sonucu (universalObfusPublicSrc = VMProtect 3.x tam kaynak, 1167 dosya, ~162K satır):**
- V4M çekirdek mekanizması (per-chunk decrypt + wipe + transient RWX + per-call rastgelelik) VMProtect'te **YOK** — birebir kanıt tablosu: `raporlar/universalObfusPublicSrc_Analiz.md` bölüm 5
- VMProtect runtime'da TOPLU LZMA unpack yapar (loader.cc:2285-2322), wipe yok, DecryptSection yok
- VMProtect'in güçlü yanı: her-BUILD rastgelelik (10 VM instance, opcode map shuffle, cryptor zincirleri) — bizim eksik yönümüz
- E9+RWX trampolin VMProtect'te VAR ama amacı API inline hook (hook_manager.cc:650-668)
- 7 taşınabilir fikir listelendi (analiz raporu 5.4): key chaining, OpcodeCryptor, ValueCryptor zinciri, offset-zincir handler, VM içi CRC, direct syscall, CryptoContainer

---

## 4. C++ PORTU — XProtect (DEVAM EDİYOR)

**Durum:** `XProtect_0.1.0/` içinde portun ilk sürümü var. Kullanıcı hedefi: **universalObfusPublicSrc'yi birebir aynı şekilde C++'a portlamak.**

**Sorun (neden port lazım):** VMProtect kaynak kodu ÇOKLU DİL kullanıyor (C++ core, C runtime, C# .NET runtime `runtime/VMProtect.Runtime/`, C# tools `utils/ipn_sqlclr`, Qt GUI, Lua gömülü, COM shellext) ve derlemesi hataya açık. Hedef: **tamamen C++ tek kod tabanı, hatasız derlenen.**

**Mevcut port içeriği (`XProtect_0.1.0/CPlusPort_Source/`):**
- `engine_main/disasm/lift/pe/stub/util.cpp` + `engine.hpp` — port motoru (disasm → lift → VM)
- `minipe.hpp` — minimal PE okuma
- `vm_core.c` + `vm64.bin` + `vmx86.bin` — VM çekirdeği (derlenmiş blob olarak gömülü)
- `build_all.sh` — derleme script'i; `gen_blob.py` — blob üretici
- Derlenmiş çıktılar: `CPlusPort.exe` (x64), `CPlusPort32.exe` (x86), `VMPHelper.exe` + kaynakları
- Test ikilileri: `Test.exe`, `Test32.exe`, `Test_vmp.exe`, `Test32_vmp.exe` + `Test_exe_Source`

**Porttaki bilinen eksikler (kullanıcı ifadesiyle):** "hâlâ portlanacak eksikler var". Detaylı eksik listesi için bir sonraki adım: VMProtect core dosyalarıyla (intel.cc 31K satır komut çevirici, processors.cc, files.cc) XProtect engine karşılaştırması yapılıp kapsam matrisi çıkarılmalı.

**Port işinin test altyapısı:**
- **i4MConsoleLoader** = protector'ın ürettiği korumalı exe'yi runtime'da **birebir açan** doğrulama aracı (manuel-map 8 aşama) — port doğru mu diye korumalı PE'yi loader'la açıp davranışı karşılaştırma imkânı
- **wine32** (aşağıda) = Linux'ta 32-bit port çıktılarını (CPlusPort32.exe, Test32.exe) test etme

---

## 5. WINE 32-BİT ÇÖZÜMÜ (ÇÖZÜLDÜ — BU OTURUMDA DOĞRULANDI)

**Geçmiş:** GLM 64-bit Wine'ı açıp test edebiliyordu ama 32-bit PE'leri test edemiyordu. `wine32-metot-ve-skill.zip` ile çözüm skill'i oluşturuldu. **2026-10-22 bu oturumda zip yeniden test edildi ve PASS:**

- Kurulum: `wine32-skill/skill/scripts/setup-wine32.sh` (root'suz, ~8 dk, idempotent)
- **Mimari zincir:** `bash launcher → wrapper script → qemu-i386-static (AMD64 syscall'ları) → 32-bit Wine (Kron4ek wine-11.20-x86) → PE32 exe`. Hiçbir şey native i386 çalışmaz (sandbox seccomp i386 ABI'yi kill ediyor).
- **Kritik tuzaklar (yeniden yükselen hatalar için):**
  1. amd64-wow64 build KULLANILMAZ — tüm 32-bit adres alanını tek mmap olarak rezerve eder → overcommit ENOMEM SIGSEGV. Sadece **x86 (pure 32-bit) build**.
  2. PT_INTERP yolu ≤18 karakter olmalı (`$HOME/l/ld.so` veya `/tmp/l/ld.so`) — patchelf bunu yapar.
  3. Guest i386 exec'ler yakalanmalı: `bin/wine`, `bin/wineserver`, `wine-preloader` → `*.real` + bash wrapper'ları (`exec qemu-i386-static -0 "$0" <real> "$@"`).
- **Kullanım:** `export PATH="$HOME/.local/bin:$PATH"` sonra `wine32 program.exe`
- **Kanıt (bu oturum):** mingw i686 derleme OK (PE32) + `wine32 test32.exe` → `[Merhaba 32-bit!]` exit=0 + `wine32 cmd /c echo` → OK. Kanıt logları: `wine32-skill/proof/`.
- FreeType font uyarısı kozmetiktir, çalışmayı etkilemez.

---

## 6. TESLİMAT DOSYALARI (yerel)

| Dosya | Yer |
|---|---|
| V4method1 paketi (28 dosya: src + kanıt + araç) | `/home/z/my-project/download/V4method1_TekTek.zip` |
| V4method2 paketi (34 dosya: src + kanıt + araç) | `/home/z/my-project/download/V4method2_Stream.zip` |
| V4 güvenlik raporu (10 bug kaydı dahil) | `/home/z/my-project/download/V4_Guvenlik_Raporu.txt` |
| V4method2 blueprint | `/home/z/my-project/download/V4_TekTek_Blueprint.txt` |
| VMProtect analiz raporu (5 bölüm, satır referanslı) | `/home/z/my-project/download/universalObfusPublicSrc_Analiz.md` |
| MovePlayer analizi (V3 kaynak analizleri) | `/home/z/my-project/download/MovePlayer_Analiz_V3.txt`, `MovePlayer_Opcode_Struct.txt` |
| Demo oyun (Move/Attack fonksiyonlu) | `/home/z/my-project/scripts/MazeGame.cpp` |

**V4 paketlerinin içeriği (her ikisinde benzer):**
- `i4MConsoleLoader_kaynak/i4MConsoleLoader/` → PEManualMapper.h, MazeProtector.h (159.7K!), main.cpp, globals.h, InstanceManager.h, LoaderSelfTest.h, stdafx.h, .vcxproj
- `MazeGame_kaynak.cpp` → demo (Move/Attack)
- `Test_Kanitlari/` → baseline/TekTek/Stream çıktıları, KANITLAR.txt, mp_v4_proofs.py, mp_v4_dump.py, mp_antipatch_test.py
- `Linux_Dogrulama_Araclari/` → mp_driver.cpp, mp_driver (derli), shims.cpp
- `MazeMap_ArenaV4_TekTek.txt` → arena haritası

---

## 7. SIRADAKİ ADIMLAR (öncelik sırası)

1. **XProtect eksik analizi:** VMProtect `core/` ile XProtect `CPlusPort_Source/` kapsam matrisi (hangi intel.cc özellikleri port edildi, hangileri eksik) → kullanıcı "birebir port" hedefine göre yol haritası
2. **Anahtar zincirleme V4M2'ye eklensin** (analiz raporu 5.4.1) — tek XOR kapanır
3. **G5 prototipi** (istek olursa) — V4M2 slot mantığı + VEH iskeleti
4. **G6 L1 stack-VM pilotu** (istek olursa) — Move'un tek basic block'u
5. **XProtect + VMPHelper + Test ikililerini wine32 ile Linux'ta doğrulama döngüsü** (artık mümkün!)

## 8. ÖNEMLİ KOMUTLAR / ORTAM

- Wine32: `export PATH="$HOME/.local/bin:$PATH"; wine32 <pe32.exe>`
- mingw i686: `$HOME/mingw/bin/i686-w64-mingw32-gcc`
- 32-bit prefix: `WINEPREFIX=$HOME/.wine32 WINEARCH=win32`
- V4 kanıt scriptleri: `python3 Test_Kanitlari/mp_v4_proofs.py` (MP_FORCE_WALL=1 ile duvar modu)
- VMProtect kaynak: `/home/z/my-project/work/universalObfus/vmp/` (zip'ten açılı)
- GitHub: `0xByteDeveloper/ai_Files` (bu repo — her şeyin kalıcı kopyası)
