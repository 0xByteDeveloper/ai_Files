# universalObfusPublicSrc.zip — Satır Satır Analiz Raporu

**Analiz kapsamı:** Zip'in tamamı açıldı: **1167 dosya**, ana kaynak kodda **~162.000 satır**. Kritik dosyalar (runtime/loader.cc, runtime/core.cc, runtime/crypto.cc, runtime/hook_manager.cc, core/files.h, core/intel.cc'in VM bölümleri) doğrudan satır satır okundu; kalan bölümler üç paralel inceleme turunda taranarak bulgular kod referanslarıyla doğrulandı. Tüm referanslar `vmp/` kök dizinine göredir.

**Kimlik tespiti:** Bu zip, **VMProtect 3.x'in tam kaynak kodudur** (`vmp/` dizin ağacı). İçinde üç büyük katman vardır:

| Katman | Dizin | Boyut | Ne işe yarar |
|---|---|---|---|
| **Koruma motoru** | `core/` | 79 dosya | Build-time: PE/Mach-O/ELF/IL işleme, Mutation, Virtualization, şifreleme |
| **Runtime** | `runtime/` | 36 dosya | Korunan exe'ye gömülen katman: unpack, anti-debug, lisans, sanal dosya/registry |
| **Araçlar** | `VMProtect/`, `VMProtectCon/`, `sdk/`, `shellext/`, `utils/` | — | Qt GUI, komut satırı derleyici, SDK stub, Explorer eklentisi, yardımcı araçlar |

Yardımcı kütüphaneler (`third-party/`): **lzma** (packing), **lua** (koruma otomasyonu script'i), **libudis86** (GUI disassembly görünümü), **scintilla** (script editörü), **tinyxml**, **demangle**, **libffi**, **diskid**, **gtest/gmock** (testler).

---

## BÖLÜM 1 — KORUMA YÖNTEMLERİ (Motorun Kalbi)

### 1.1 Compilation Type — Üç seviye
**Referans:** `core/files.h:309-315`

```c
enum CompilationType : uint8_t {
    ctVirtualization,   // 0
    ctMutation,         // 1
    ctUltra,            // 2  = Mutation + Virtualization birleşik
    ctNone = 0xFF
};
```

Her korunacak fonksiyona kullanıcı ayrı ayrı seviye atar (GUI: `VMProtect/property_editor.cc:1357-1383`). Seçim derleme sırasında dispatch edilir: `core/intel.cc:18434-18446` — `ctMutation → CompileToNative`, `ctVirtualization/ctUltra → Mutate() + CompileToVM()`.

### 1.2 Mutation — Komut eşdeğerleştirme + çöp komut enjeksiyonu
**Referans:** `core/intel.cc:16039` (`IntelFunction::Mutate`)

- **~60 çöp-komut şablonu** tanımlı (16053-16133); her gerçek komutun arasına **0-3 rastgele çöp komut** eklenir (16424-16548).
- Çöp komutların hangi register'lara yazabileceği **güvenli register analizi** ile bulunur (`GetFreeRegisters`, 15989) — yani dead-code'a zarar vermez.
- **Eşdeğer dönüşümler:** `xor reg,reg → sub` (16294), `add/sub → lea` (16307/16334), `jmp → push+ret` (16357), `call → push+xchg esp` (16215).
- İkinci bir motor (`IntelObfuscation`, intel.h:872) var ama gate'de `if(false)` ile **kapalı** (18148-18153) — geliştirme aşamasında kalmış.
- **Native çıktı hızlıdır** (imza gizleme amaçlı); native opcode'lar plaintext kalır.

### 1.3 Virtualization — x86 → stack-VM bytecode
**Referans:** `core/intel.cc:9744` (`IntelCommand::CompileToVM`), 28570 (`IntelVirtualMachine::InitCommands`)

Her x86 komutu, **stack makinesi işlemlerine** açılır: `cmPush/cmPop/cmAdd/cmNor/cmNand` vb. Örnekler: `cmBt` (9775-9946), `cmNeg` (9974-9991), `cmMov` (9958-9961). EFLAGS, sanal `regEFX` register'ında birleştirilir (`AddCombineFlagsSection`, 8947); flags'i kimse okumayan komutlar `roNoSaveFlags` ile optimize edilir (18325-18357).

**Native'den muaf tutulan komutlar** (VM'e çevrilemez, `ltNative` link ile kalır, 18245-18319): lock-prefixed, rep-string, relocation'lı, far jmp/call, FPU register komutları.

**Komut → VM block ayrımı:** 18359-18413; blok sınırlarına `AddExtSection` / `AddStoreEIPSection` konur — yani komutlar şifreli "section" parçalarına bölünüp karıştırılabiliyor (bkz. 1.6).

### 1.4 VM Handler Tablosu — Her build'de farklı VM
**Referans:** `core/intel.cc:28570-30062`, `30205` (`GetOpcode`), `30637` (`IntelVirtualMachineList::Prepare`)

- Kayıtlı sürümde **10 adet VM instance** gömülür, demo'da 1 (`core.cc:1745-1751`); fonksiyonlar VM'lere dağıtılır.
- Her VM'de `pcode/stack/jmp/crypt` register'ları **rastgele seçilir** (28593-28656), `registr_order_` shuffle edilir (28683-28685).
- Handler gövdeleri x86 olarak yazılır (28859-30062): push/pop registr, push value, push/pop [mem+segment], pushf/popf, add/nor/nand, jmp, call, syscall, cpuid, rdtsc, crc, div/mul/shl…
- **Her opcode'a kendi `OpcodeCryptor`'ı** verilir (28840-28905) — opcode baytları çalışırken zincirleme şifrelenir/çözülür.
- **vtClassic:** opcode byte baştadır, jmp tablosuyla handler'a atlanır (28769-28778). **vtAdvanced:** kayıtsız sürümler için kapalı, kayıtlıda: 4-baytlık **"sonraki handler ofset" zinciri** (voBeginOffset/voEndOffset, 30399-30418) + `jmp_reg` ile hesaplanan rastgele handler sonu (`AddEndHandlerCommands`, 27836) — sabit jump tablosu yok.
- **Handler sonu obfüksiyonu:** advanced modda handler bitişi rastgele 32-bit offset üzerinden bulunur.

### 1.5 Bytecode Şifreleme — Adrese bağlı CRC + cryptor zinciri
**Referans:** `core/intel.cc:30446` (`CompileBlock`), 30501-30599

Tüm bytecode dump'ı, **komut adresine bağlı CRC** + cryptor zinciriyle çözülür/şifrelenir — yani bir bayt yerinden oynarsa zincir bozulur, sonrası çöpe döner. Bazı bloklar `rtBackwardDirection` ile **tersten yazılır** (30586-30597). VM sabitleri `EncryptBuffer` ile rotasyon+xor'lanır (30215: rotr 7/11/17/23).

### 1.6 Şifreli Section Bölme — Parçalara ayırma + anahtar zincirleme
**Referans:** `core/intel.cc:9202` (`AddBeginSection`), `9430` (`AddEndSection`), `9274` (`AddCryptorSection`), `core/intel.h:693` (`SectionCryptor`)

Komut dizileri şifreli "section"lara bölünür; parçalar arası anahtar **zincirleme** taşınır (parça N'nin anahtarı parça N-1'in çözümünden türetilir). Blok/bölge sıraları rastgele karıştırılır (22295-22297, `processors.cc:2573, 2608`); register encoding blok başına rastgelelenir (`CommandBlock::GetRegistr`, processors.cc:1259).

### 1.7 Nor/Nand Obfüksiyonu — Aritmetiğin bozulması
**Referans:** `core/intel.h:4-321` (`cmNor, cmNand, cmCrc` VM komutları)

Add/Cmp/Sub gibi işlemler VM'de doğrudan yapılmaz; **Nor/Nand kombinasyonlarına** açılır. Saldırgan VM'i trace'lese bile "bu bir toplama"yı opcode düzeyinde göremez. VM içinde breakpoint bayt denetimi de aynı yöntemle obfüksiyonlanır (bkz. 3.4).

### 1.8 Gate — Native'den VM'e geçiş
**Referans:** `core/intel.cc:18132` (`AddGate`), `18182` (`AddShortGate`)

Native kod, VM'li fonksiyona şöyle düşer: `push vmaddr; call vm_entry`. VM'den dönenler için context restore. **"Trampoline" adı geçmez; karşılığı gate'tir.** Orijinal entry point ise PE header'da loader'a yönlendirilir (`core/pefile.cc:4339/4350/5213` — `entry_point_ = loader->entry()->address()`), orijinal EP loader verisinde saklanır.

### 1.9 ValueCryptor — Çok adımlı rastgele şifreleme zinciri
**Referans:** `core/processors.cc:711` (`ValueCryptor::Init`)

3-100 adımlı **rastgele** `add/sub/inc/dec/xor/bswap/rol/ror` zinciri üretir. Tek XOR yerine zincirli dönüşüm — tersine mühendislik maliyetini katlar. `OpcodeCryptor` (775-817) bunun opcode-bayt özel hâli.

### 1.10 .NET (IL) Virtualization — Delegate-dispatch VM
**Referans:** `core/il.cc:6349` (`ILVirtualMachine::Init`), `1449` (`ILCommand::CompileToVM`), `il.h:25` (icCallvm/icCallvmvirt/icEntertry)

.NET için ayrı IL VM: call/callvirt → `icCallvm`; runtime şablonundan delegate tablosu kurulur (6362-6378); **opcode'lar shuffle edilir** (6389-6393) ve **256'ya kadar rastgele klon** çoğaltılır (6394-6397); her opcode template klonlanıp `ldc.i4 id + ldftn method` ile dispatcher'a bağlanır (6405-6426).

---

## BÖLÜM 2 — PE KORUMA SEÇENEKLERİ

### 2.1 Section yönetimi ve `.vmp0/.vmp1/...` isimlendirme
**Referans:** `core/pefile.cc:4556` (`PEArchitecture::Save`), 4710/4800/4808/4842/5031/5065

Yeni section'lar `"%s%d"` kalıbıyla eklenir → `.vmp0`, `.vmp1`, `.vmp2`… (temel ad `core.cc:1743`; GUI'den değiştirilebilir — dokümanda ".vmp → .UPX" örneklenir). Runtime `.dll.inc` kaynak gömülüsünden section/fixup/SEH/CFG/runtime-function verileri birleştirilir (4712-4776). Ayrıca fixup, resource, IAT, security-cookie, TLS taşıma ve loader+processor section yazımı (4799-5070).

### 2.2 Memory Protection (CRC bütünlük)
**Referans:** `core/pefile.cc:4855-4943` (memory CRC tablosu), `5349-5446` (loader+header CRC), `5448-5476` (file CRC)

Korunan bellek bölgelerinin CRC'si tabloya yazılır; runtime'da (bkz. 3.3) bölge hash'leri kontrol edilir, patch bulunursa uyarı/çıkış. `CRC_INFO{Address, Size, Hash}` alanları `CRCValueCryptor` ile rolling-XOR'lu saklanır (rotl7, `runtime/crypto.h:364-386`).

### 2.3 Import Protection
**Referans:** `runtime/loader.cc:277-433`, `core/pefile.cc` (ImportData section)

DLL adları `LoaderGetModuleHandleEnc` ile çözülür (423-433); API adları `LoaderGetProcAddress` içinde **binary-search + şifreli ad karşılaştırması** ile bulunur (277-421). Çözülen adres `p - import_info->Key` formülüyle **Key-obfuskasyonlu** yazılır (2364) — IAT girişleri düz adres değil. Import section'ları toplu kurulum aşamasında bağlanır (2328-2332).

### 2.4 Resource Protection
**Referans:** `core/pefile.cc:2506/2555` (kaynak isim/veri XOR: `_rotl32(key,i)+i`), `runtime/resource_manager.cc:211-223, 289+`

Kaynaklar (icon, string, dialog) şifrelenir; runtime'da `LdrFindResource_U/LdrAccessResource/LoadStringA/W` hook'larıyla çözülüp sunulur.

### 2.5 Pack the Output File (LZMA)
**Referans:** `core/packer.cc:86-98`, `core/intel.cc:22974-23118` (PE), `24889+` (Mach-O), `26729+` (ELF)

Section verileri **LZMA level 9, 1<<24 dict** ile sıkıştırılıp loader'a taşınır, orijinal yerleri dosyadan silinir. **Önemli: sıkıştırma var, bölüm şifrelemesi YOK** (bkz. Bölüm 5 kritik sonuç).

### 2.6 Diğer dosya seçenekleri
- **Strip Debug Info / Strip Relocations** (help/en/project_options.htm:22-53; `core/pefile.cc`)
- **Watermark** (`core/core.cc:177` hex→dump+mask; `processors.cc:2070-2100` veriye 8-10 kopya, version/owner watermark'ları XOR'lu 2089)
- **Lock to Serial Number** — fonksiyon, lisans anahtarındaki bitlere kilitlenir: `coLockToKey` (`core/processors.h:632`, uygulama `core/files.cc:3135-3143`) — VM komutları serial'den türetilen anahtarla şifrelenir, serial yoksa o fonksiyon bytecode'u çözülemez.
- **Lua script** koruma otomasyonu (`core/script.cc:7384-7386` — "mutation/virtualization/ultra" adları script'ten çağrılabilir).

---

## BÖLÜM 3 — RUNTIME KATMANI (Korunan exe'nin içinde çalışan kod)

### 3.1 SetupImage — Paketlenmiş exe açılış akışı
**Referans:** `runtime/loader.cc:884` (`SetupImage`)

Adım adım: (1) **re-entry guard** — GlobalData varsa sadece status döner (896-905); yoksa `LoaderAlloc` ile oluşturulur (907). (2) NTDLL hazırlığı (3.2). (3) Anti-debug (3.4). (4) CRC denetimleri (3.3). (5) RW/RWX koruma geçişleri + toplu LZMA unpack (3.5). (6) Fixup (840-876, 2324-2326), IAT (2328-2332), delay-import, relocation (2848-2925). (7) LOADER_SUCCESS ile orijinal koda dönüş; unload'da `FreeImage` → `runtime_entry(false)` (797-822).

### 3.2 Direct Syscall — Usermode hook bypass
**Referans:** `runtime/loader.cc:262-273` (`LoaderParseSyscall`), `1005-1023`, `1061-1681`, `1683-1693`

NTDLL'nin **temiz bir kopyası** `NtCreateSection(SEC_IMAGE_NO_EXECUTE)` ile map edilir (1005-1012); syscall numaraları opcode'dan parse edilir — `mov eax, imm32` (0xB8) kalıbı aranır (262-273). **XP'den Win10 22H2'ye kadar hardcoded build-number → syscall tablosu** var (1061-1681); WOW64'te `WOW64_FLAG` (1683-1693). Amaç: usermode API hook'larını (AV, EDR, anti-cheat) bypasslamak.

### 3.3 CRC / Bütünlük Denetimleri
**Referans:** `runtime/loader.cc:1910-1956` (loader CRC), `1958-2178` (diskteki dosyanın geri okunması — exe kendi dosyasını mmap/NtMapViewOfSection ile açıp hash'ler), `2650-2715` (memory CRC + dump tespiti), `1929-1935` (patch bulununca: `LOADER_OPTION_CHECK_PATCH` varsa "FileCorrupted" + exit, yoksa `is_patch_detected` flag'i)

CRC alanlarına erişim koruması: `NtProtectVirtualMemory` hook'u (bkz. 3.4) ile CRC bölgelerine erişim `STATUS_ACCESS_DENIED` döndürülür (`runtime/core.cc:1266-1299`).

### 3.4 Anti-Debug — Tam liste
**Referans:** `runtime/core.cc:402-910`, `runtime/loader.cc:1799-1837, 2241-2458`

| Teknik | Referans |
|---|---|
| Loader flag kontrolü | core.cc:404 |
| Unix TracerPid | core.cc:408-444 |
| macOS P_TRACED | core.cc:448-473 |
| PEB.BeingDebugged | core.cc:764 |
| TF (trap flag) + rdtsc + SEH ile DR0-DR3 hardware BP taraması | core.cc:767-783 |
| ProcessDebugPort / ProcessDebugObjectHandle (direct syscall) | core.cc:786-801 |
| Kernel debugger + sice/siwvid/ntice/iceext/syser.sys modül taraması | core.cc:809-910 |
| InstrumentationCallback sıfırlama | loader.cc:1799-1806 |
| ThreadHideFromDebugger | loader.cc:1834-1837 |
| PAGE_GUARD tuzakları | loader.cc:2241/2274/2883 |
| 0xCC (int3) kontrolü | loader.cc:2256/2893 |
| DbgUiRemoteBreakin → TerminateProcess (attach önleme) | core.cc:1224-1227 |
| VM içi 0xCC / 0x03CD / ud2(0x0B0F) bayt denetimi (Nor/Nand obfüksiyonlu) | intel.cc:9305-9363 |
| VM içi rdtsc+CRC kontrolü | intel.cc:9366; iç call'larda 10862-10865 |
| Anti-trace REP×5 + PUSHF | intel.cc:15846-15861 |
| CPUID hash | intel.cc:15864-15889 |

Not: **int 2d dönüşümü YOK** (0x2d geçişleri SSE opcode'larıdır: 1795/2317/4830); self-debug da yok.

### 3.5 Bölge Koruma Geçişi ve Toplu Unpack
**Referans:** `runtime/loader.cc:2181-2283` (koruma geçişi), `2285-2322` (LZMA unpack), `2848-2925` (koruma geri)

Section'lar önce `NtProtectVirtualMemory` ile RW/RWX yapılır (`PAGE_EXECUTE_READWRITE` :2234), sonra **tüm sıkıştırılmış bölgeler TEK SEFERDE** `LzmaDecode` ile hedef görüntüye açılır (2285-2322). İşlem bitince koruma geri konur; okunamaz bölümler **`PAGE_NOACCESS`** yapılır (2874) — bu bir anti-dump etkisidir.

### 3.6 Anti-VM / Anti-Sandbox
**Referans:** `runtime/loader.cc:2464-2644`

CPUID hypervisor biti + firmware tabloları (VMware/VPC/VirtualBox) + sbiedll (Sandboxie) taraması. Ek hile: `CloseHandle(0xDEADC0DE)` SEH tabanlı kontrol (2427-2440); TF+rdtsc+SEH ile DR kayıt taraması (2442-2458).

### 3.7 Inline Detour Hooking — API hook sistemi
**Referans:** `runtime/hook_manager.cc:156-167, 212-614, 650-715, 717-736`

Amaç: memory-protection, sanal dosya/registry/kaynak sunumu. Yöntem: hedef API'nin başına **5 baytlık `E9` JMP** (156-167); orijinal komutlar **kendi mini length-disassembler** (`GetInstructionSize`, 212-614) ile ölçülüp API'ye yakın RWX sayfaya taşınır — x64'te `0x70000000` ileri taramayla `VirtualAlloc(PAGE_EXECUTE_READWRITE)` (650-668) — **trampoline** kurulur; rel32 fix (`MoveCode`, 616-640). İşlem sırasında tüm thread'ler suspend (84-150). Unhook'da E9+CRC karşılaştırmasıyla **üçüncü taraf hook tespiti** (717-736). IAT hook DEĞİL — tam inline detour.

### 3.8 Sanal Dosya Sistemi ve Sanal Registry
**Referans:** `runtime/file_manager.cc:183-199, 500`, `runtime/registry_manager.cc:336-349`

13 adet `Nt*` API hook'u, storage'daki sanal dosyaları gerçek gibi sunar (`ReadImage` :500). Registry hook'ları yazmaları bellek overlay'ine yönlendirir — lisans verileri diske sızmaz.

### 3.9 String Şifreleme ve Temizlik
**Referans:** `runtime/string_manager.cc:151, 160-168`

Şifreli string dizini `key ^ (rotl(key,i)+i)` ile çözülür. **Kod içindeki tek "wipe" kalıbı buradadır:** decrypt edilen string `volatile` zero + delete ile temizlenir — **veri için, kod için değil.**

### 3.10 Sahte Adres Sözleşmesi (FACE_*)
**Referans:** `runtime/common.h:78-203`

`FACE_*` sabitleri 0xFACE0000 tabanlı sahte adreslerdir; packer derleme sırasında bunları **gerçek offset'lerle yamalar** — packer ile runtime arasındaki sözleşme budur. `GlobalData` (253-283) loader durumunu salt-XOR'lu saklar; `LOADER_OPTION_*`/`CORE_OPTION_*` bayrakları (207-216) özellik aç/kapat.

---

## BÖLÜM 4 — KRİPTO, LİSANS, WATERMARK, SDK, ARAÇLAR

### 4.1 Kripto
**Referans:** `runtime/crypto.cc`, `runtime/crypto.h`

| Algoritma | Kullanım | Referans |
|---|---|---|
| **RC5-32/15/8** | Tüm konteyner/anahtar verisi; runtime build'de FACE_RC5 sabitleri | crypto.h:181-198, crypto.cc:22-78 |
| **RSA (BigNumber+modpow)** | Serial doğrulama, PKCS#1 v1.5 | crypto.cc:328, 440; licensing_manager.cc:245-256 |
| **SHA1** | HWID, blacklist, serial checksum | crypto.cc:922-1073 |
| **CRC32 tablo** | Bütünlük | crypto.h:308, crypto.cc:1075 |
| **Base64** | Serial/HWID kodlama | crypto.cc:821-920 |
| **CryptoContainer** | RC5-şifreli bloktan anlık GetDWord/GetByte | crypto.cc:678-763 |
| **RC5Key::Create** | `__rdtsc` türetmeli anahtar | crypto.cc:84-92 |

Anahtar türetme: tek gömülü RC5 anahtarı (`FACE_KEY_INFO`, core.cc:1154 — packer derleme anında gömer).

### 4.2 Lisans Sistemi
**Referans:** `runtime/licensing_manager.cc`, `VMProtect/license_dialog.cc:17-362`, help/en/manager/

- **Serial formatı** (blok yapısı, help/en/manager/keygen/serial_format.htm:45-186): 0x01 Version, 0x02 Name, 0x03 Email, 0x04 HWID (≤32B), 0x05 ExpDate, 0x06 TimeLimit (≤255 dk), 0x07 ProductCode (8B, zorunlu), 0x08 UserData (255B), 0x09 MaxBuildDate, 0xFF SHA-1 checksum. GUI karşılığı HAS_* flag'leri: license_dialog.cc:211-238.
- **RSA 1024-bit+ serial** — keygen yazmak matematiksel olarak imkânsız (özel anahtar GUI'de kalır).
- **Blacklist:** SHA1 binary-search (licensing_manager.cc:202-232).
- **Online aktivasyon:** WinHTTP (733-760).
- **HWID:** CPUID + makine adı + MAC + volume serial; her blok SHA1 → CryptoContainer (`runtime/hwid.cc:112+`); doğrulama: **CPU zorunlu + diğer tiplerden ≥3 eşleşme** (636-676).
- **Fonksiyonu serial'e kilitleme:** serial'deki bitlerden türeyen anahtarla VM bytecode şifrelenir (`files.cc:3135-3143`).

### 4.3 Watermark
**Referans:** `core/core.cc:177`, `core/processors.cc:2070-2100`, `VMProtect/watermarks_window.cc:23-59`

Sızan kopyanın sahibini tespit eden kullanıcıya-özgü bayt dizisi; veri içine **8-10 kopya**, XOR'lu olarak gömülür (2089). GUI: ekle/sil/rename/Blocked/Ara. `utils/ipn_tool/Program.cs:13-51` watermark export, blacklist merge, build task, taggant kontrolü yapar.

### 4.4 SDK
**Referans:** `sdk/sdk.cc:36-69, 92-95, 257-274`, `sdk/sdk.def:1-23`

`VMProtectBegin / BeginMutation / BeginVirtualization / BeginUltra / End` — **tamamı boş gövde stub'lar**; `VMProtectDecryptStringA` kimlik dönüş. Derlenmiş exe'de yalnız **import referansları** kalır; packer bu export isimlerini bularak çevrelediği bölgeyi korur ve stub çağrılarını kaldırır. Diğer API'ler: IsDebuggerPresent, IsVirtualMachinePresent, IsValidImageCRC, License API'leri (test build'de `VMProtectLicense.ini` okur: 257-274, 373-482).

### 4.5 Araçlar ve Arayüzler
- **GUI (Qt):** proje ağacı — Functions for Protection, Licenses, Files, Script, Options + mimari bilgi düğümleri (`VMProtect/models.cc:1604-1673, 2007-2171`); menü akışı `mainwindow.cc:337-402`; license generator `license_dialog.cc`; anahtar çifti dışa aktarma (MSVC/Delphi/.NET/PHP) `export_key_pair_dialog.cc:31-34`; settings, import license, remote control (`remotecontrol.cc:9-47`).
- **VMProtectCon:** komut satırı derleyici — input/output/-pf proje/-sf script/-wm watermark/-lf lisans/-bd build date/-we (`VMProtectCon/main.cc:56-231`); kendi serial'iyle self-check (63-67).
- **shellext:** Explorer sağ-tık "Protect with VMProtect" COM eklentisi (`shellext/context_menu.cc:188-212`).
- **Sembol okuma:** MAP, PDB (`core/pdb.h` 2407 satır), DWARF (`core/dwarf.cc`), Mach-O (`core/mach-o.h`), ELF (`core/elf.h`), .NET metadata (`core/dotnetfile.cc` 12.4K satır).
- **utils/x86disasm:** libudis86 ile 3-baytlık opcode/prefix kombinasyonlarını tarayıp benzersiz talimat tanımları üreten **offline üretici** (`disasm.cc:242-277`).
- **Testler:** 40+ Virtualization instrüksiyon testi + SEH/SDK-marker (`core/intel_tests.cc:13-4483`), RSA/watermark (`core_tests.cc:10-83`), runtime: ParseSerial, StringManager, HWID, Registry, CryptoContainer, SHA1/CRC (`win_runtime.Tests/core_tests.cc:65-408`).

---

## BÖLÜM 5 — KRİTİK KARŞILAŞTIRMA: V4method1 / V4method2 Bu Zip'te Var mı?

**Net cevap: ÇEKİRDEK MEKANİZMA OLARAK HAYIR — V4M yöntemleri bu kaynak kodda yok, bağımsız bir tasarımdır.**

VMProtect'in koruma modeli üç bacak üzerine kuruludur: (a) **build-time dönüşüm** (Mutation + Virtualization: kod ya native-çöp'lenir ya bytecode'a çevrilir), (b) **runtime'da TOPLU unpack** (LZMA, bir kez, başlangıçta), (c) **bütünlük + anti-debug çemberi** (CRC + PEB/TF/DR/sanaldünyalar). Zip'in **her yerinde** şu arandı: "fonksiyon opcode'ları şifreli durur; her çağrıda küçük parçalar çözülüp geçici RWX alana yazılır, geçilen parça SIFIRLANIR, bir sonraki parça yazılır" — **sonuç: sıfır eşleşme.**

### 5.1 Kanıt: Per-chunk decrypt + wipe NEDEN yok

| Aranan kalıp | Sonuç | Kanıt |
|---|---|---|
| `DecryptSection` / `EncryptData` fonksiyonu | **Yok** | runtime/ + core/ içinde grep: 0 eşleşme |
| Runtime'da bölüm çözümü | **Toplu LZMA unpack, bir kez** | `loader.cc:2285-2322` — `for` döngüsüyle tüm `PACKER_INFO` bölgeleri `LzmaDecode`; şifre değil sıkıştırma |
| Kod wipe (geçilen komutu sıfırlama) | **Yok** | Tek wipe kalıbı `string_manager.cc:160-168` — decrypt string **verisi** için, kod için değil |
| Per-call decrypt tüketeni | **Yok** | `session_key` sadece `__rdtsc` türetir (loader.cc:2786-2789), sonra per-call decrypt yok |
| Fonksiyonun şifreli durup parça parça çözülmesi | **Yok** | Virtualization'da kod native bile değildir (bytecode); Mutation'da plaintext'tir. "Native ama şifreli + JIT çözüm" kalıbı hiçbir yerde yok |
| Geçici RWX slot/arena per-fonksiyon | **Yok** | RWX `VirtualAlloc` yalnız 2 yerde: hook trampolini (hook_manager.cc:650-668) ve .NET CPUID shellcode (.NET CpuId.cs:50-79) — ikisi de parça-decrypt değil |

### 5.2 V4M1 özelliklerinin birebir karşılık tablosu

| V4method1 (wipe-behind, sabit slot) özelliği | VMProtect'te karşılığı |
|---|---|
| Fonksiyon şifreli olarak bellekte durur | **Yok** — Virt'te bytecode (native yok), Mutation'da native plaintext |
| Per-piece decrypt (çağrıda parça parça) | **Yok** — tek seferlik toplu unpack |
| Geçilen parçayı sıfırlama (wipe-behind) | **Yok** |
| Sabit RWX slot, parçalar sırayla aynı yere yazılır | **Yok** |
| Orijinal RVA'ya 5 bayt E9 trambolin | **Kısmi benzer:** E9 kullanımı var ama amacı **API inline hook** (`hook_manager.cc:156-167`); fonksiyon girişi için karşılık "gate"tir: `push vmaddr; call vm_entry` (`intel.cc:18132`) — E9 değil |
| XOR şifreleme (0xA14FC884A80CA3E1 çok baytlı) | **Kısmi benzer DNA:** `ValueCryptor`/`OpcodeCryptor` XOR tabanlı (`processors.cc:711-817`) ama **opcode baytları** için; fonksiyon gövdesi XOR'lanmaz |

### 5.3 V4M2 özelliklerinin birebir karşılık tablosu

| V4method2 (Stream, 24B slot, G1/G2/G3) özelliği | VMProtect'te karşılığı |
|---|---|
| 24 baytlık slot + wipe-behind (her an ≤24B plaintext) | **Yok** |
| G1: her çağrıda farklı slot adresi (dump-replay karşıtı) | **Yok** — VM'in bytecode'u statiktir; her çalıştırmada aynı |
| Per-call stage kurulumu (her çağrı kendi stage'ini kurar) | **Yok** |
| `.maze` thunk'ları (mov r10d, parca; jmp stage) | **Yok** |
| G2: CRC-8 parça-uğurlu anti-patch | **Kısmi benzer ama farklı niş:** dosya/bellek CRC'si var (`loader.cc:1910-2715`, `CRC_INFO` rotl7-XOR'lu) — **fonksiyon bütünlüğü** için, parça bazlı değil |
| G3: decoy enjeksiyonu | **Yok** |
| Lazy cold path (duvar varsa parça hiç decrypt edilmez) | **Yok** |
| Length-decoder (komut sınırları bulma) | **Benzer araç farklı amaç:** VM, komutları VM'e çevirirken full parse yapar (build-time); hook_manager'ın `GetInstructionSize`'ı runtime'da çalışır ama API hook taşımak için (212-614) |
| G1 benzeri "her build farklı" rastgelelik | **Farklı seviyede VAR:** VM instance'ları, register seçimi, opcode map, cryptor zincirleri her **build**'de farklı — ama çalışma anı (runtime) deterministik |

### 5.4 Zip'te V4M2'ye taşınmaya değer DNA (ilham listesi)

V4M2'yi zaten güçlü kılmak için bu kaynak koddan ödünç alınabilecek somut fikirler:

1. **Anahtar zincirleme (key chaining):** `CompileBlock` + `SectionCryptor` mantığı (`intel.cc:30446, 9274`) — parça N'nin şifre çözme anahtarı parça N-1'in plaintext'inden türetilsin. Bizde tek sabit XOR anahtarı var; zincirleme bir saldırganın "tek parçayı koparma" senaryosunu kilitler.
2. **OpcodeCryptor tarzı dönüşen şifre:** her parça başına ayrı cryptor, parça çözülünce bir sonraki parçanın cryptor'u değişir (`processors.cc:775-817`, `intel.cc:28840-28905`).
3. **ValueCryptor zinciri:** tek XOR yerine 3-100 adımlı rastgele add/sub/inc/dec/xor/bswap/rol/ror zinciri (`processors.cc:711`) — V4 parça decrypt fonksiyonuna takılabilir.
4. **Advanced VM offset-zinciri:** handler'ın bitişi 4-bayt ofset + `jmp_reg` ile hesaplanır (`intel.cc:30399-30418, 27836`) — bizim thunk zincirine benzer ama adres asla sabit yazılmaz; .maze thunk'larına uygulanabilir.
5. **VM içi CRC kontrolü:** rdtsc+CRC + 0xCC/ud2 bayt taramaları handler aralarına serpiştirilir (`intel.cc:9305-9363`) — G2'nin (CRC-8) üst modeli.
6. **Direct syscall katmanı:** NTDLL temiz kopya + syscall parse (`loader.cc:1005-1023`) — Loader simülasyonumuzun IAT/çözümleme aşamasına eklenebilir.
7. **CryptoContainer:** RC5-şifreli bloktan anlık okuma (`crypto.cc:678-763`) — .maze header'ına uygulanabilir model.

### 5.5 Ters yön: VMProtect'in V4M'ye karşı zaaf noktaları (bizim avantaj)

1. **Runtime deterministiği:** VMProtect build-time korur; çalışma anında her şey çözülür ve sonraki tüm çağrılar aynı görüntüyü sunar (trace+replay açıktır). V4M2'de her çağrıda stage yeniden kurulur, slot değişir (G1).
2. **Toplu unpack penceresi:** LZMA açılış anında **tüm korunan kod bir anda** çözülmüş olur (`loader.cc:2285-2322`) — açılış penceresinde dump edilebilir; V4M2'de hiçbir an 24 bayttan fazlası plaintext değildir.
3. **Wipe yok:** VMProtect hiçbir zaman "geçtim, siliyorum" yapmaz — V4M1/M2'nin temel ilkesi burada hiç yoktur.
4. **Mutation plaintext bırakır:** Mutate edilmiş kod native opcode olarak durur (imza gizlenir, mantık gizlenmez).

### 5.6 Nihai Puanlama (bu raporun bağlamında)

| Ölçüt | VMProtect 3.x (bu zip) | V4method2 |
|---|---|---|
| Koruma modeli | Build-time bytecode/mutation + toplu unpack | Runtime per-chunk decrypt + wipe + rastgelelik |
| Her an plaintext yüzeyi | Tüm kod (unpack sonrası) / bytecode (virt) | ≤24 bayt |
| Wipe-behind | Yok | Var (temel ilke) |
| Çalışma-anı rastgelelik (replay karşıtı) | Yok (statik) | Var (G1 + per-call stage) |
| Her-build rastgelelik (imza karşıtı) | **Çok güçlü** (10 VM, shuffle, cryptor zincirleri) | Yok (bizde tek sabit anahtar) |
| Bütünlük | Dosya+bellek CRC (fonksiyon düzeyi) | Parça-uğurlu CRC-8 (G2) |
| Anti-debug | **Devasa liste** (3.4'te 16+ teknik) | Yok (kapsam dışıydı) |
| Lisans/watermark entegrasyonu | Var (tam sistem) | Yok |

**Sonuç:** İki sistem farklı katmanları korur. VMProtect "analiz etme"yi pahalılaştırır (devirt, her-build değişen VM); V4M2 "bellekte kod toplama"yı imkânsızlaştırır (wipe + 24B pencere + replay ölümü). En iddialı kombinasyon: V4M2'nin çalışma-anı modeli + zip'ten ödünç anahtar-zincirleme ve her-build opcode-map shuffle (5.4.1-5.4.2) — bu, rapordaki G6 (mini-VM) hedefine L1-L2 seviyesinde, el yapımı bir VM ile ulaşmak olurdu.
