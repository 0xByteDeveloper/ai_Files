# MazeProtector V4.3.1 — DLL Yükleme Düzeltmeleri + A/B Test Raporu

**Tarih:** 2026-10-23 · **Kapsam:** IP motorunun gerçek-Windows/Wine yüklemesi, DLL matrisi, kullanıcının "gameloop hipotezi" A/B testi

---

## 1. Kullanıcı Raporu → Teşhis

| Kullanıcı bulgusu | Kök neden | Durum |
|---|---|---|
| `MiniGameHost2.exe` → DLL2 `YUKLEME HATASI` + **0xC000007B Bad Image** | Host2, **TUR-2 beta döneminden kalma bozuk** `MiniGameDll_korumali.dll`'i yüklüyordu (129KB, x86-beta motoru çıktısı). Yeni `_ip1/_ip2` dosyalarını hiç denemiyordu | ✅ Çözüldü |
| IP2 DLL `LoadLibrary` sırasında **illegal instruction** (wine32) | 3 katmanlı yapısal hata (aşağıda) | ✅ Çözüldü |
| `TinySnake.x64/x32.protected.IP1.exe` çalıştı | KISMEN YANILTICI: TinySnake DosX tarzı **kendi kendini açan stub** (5–10KB dosya, 0x44000'lik sanal görüntü). Gerçek oyun kodu dosyada YOK; stub çalışma anında açıyor → statik koruma (IP dahil) etkin olamaz, oyun "korunsuz" çalıştı | ⚠️ Açıklandı |

## 2. Bulunan ve Düzeltilen 4 Gerçek Hata (V4.3 → V4.3.1)

### HATA-1: DLL rebase'i TLS + mutlak VA'ları kırıyordu (load-crash)
`mp_driver43` DLL ImageBase'ini 0x10000000→0x62000000 değiştiriyordu ama **TLS dizini + .gfn + gövde işaretçileri eski base'de kalıyordu**. Tercih edilen base'de yüklemede loader relocation UYGULAMAZ → ntdll TLS init garbage pointer → `c000001d`.
Kanıt: EAX/ESI=0x1000A000 (eski base'in .tls'i) crash bağlamında görüldü.
**Düzeltme (REBASE-TAM):** rebase sırasında `.reloc` hedeflerindeki TÜM değerler + TLS dizininin 4 mutlak VA'sı + LoadConfig VA'ları + `.gfn` kayıtları yeni base'e taşınır (MiniGameDll'de **246 VA**).

### HATA-2: Gerçek relocation'da (base çakışması) gövde işaretçileri prefBase'te kalıyordu
DLL base çakışması yaşarsa loader şifreli gövdeye `+=delta` uygular; handler `-delta` geri alıp çözüyordu → işaretçiler `prefBase`'li kalıyordu.
**Düzeltme (PLAINTEXT +delta geçişi):** decrypt sonrası, adjust çalıştıysa (CB+0x94 `adjScratch` kilidiyle 1 kez) reloc listesindeki işaretçilere plaintext üzerinde `+=delta` uygulanır. x64'te RDX, x86'da EDX delta taşır.

### HATA-3: Head bölgesi reloc'ları siliniyordu → proxy'de bayat mutlak VA
`MazeIP::Build` head-region reloc kayıtlarını PE'den **tamamen siliyordu**. x86'da head komutu mutlak adresli olabilir (örn. MM_Lcg'nin `imul eax,[0x10003008],imm32`) → proxy kopyası hiç relocate edilmezdi.
**Düzeltme:** silinen kayıtlar **proxy içindeki yeni ofise REWRITE** edilir (loader proxy kopyasını doğru base'e relocate eder).

### HATA-4: `.reloc` kapasitesi taşınca kayıtlar SESSİZCE düşüyordu
`RebuildRelocations()` yalnızca eski `.reloc` raw alanına (cap = eski dizin boyutu) yazar; head-reloc'lar proxy sayfalarına (0x1C000/0x1D000) taşınınca yeni page-blok'lar gerekti ve **sığmayan bloklar hiç yazılmıyordu** (wr ilerliyor, memcpy atlanıyor).
**Düzeltme:** gereken kapasite > mevcut ise yeni **`.rloc` section** açılır ve `DataDirectory[5]` oraya yönlendirilir (MiniGameDll: 554B > 540B → .rloc 810B eklendi).

### Ek düzeltme (V4.3.1 kod incelemesi)
- x86 `+delta` geçişinde delta EAX'te hesaplanıp döngüde EAX scratch kullanılıyordu; `add [eax],edx` **yüklenmemiş EDX'i** (xorloop kalıntısı 0x592B) kullanıyordu → delta artık EDX'e alınır (`mov edx,eax`).
- x86 `C7 43 94` disp8 taşması (0x94 işaretli -0x6C okunur + decode kayması → illegal instruction) → disp32 kodlamasına geçirildi.
- linuxshim'de `PIMAGE_NT_HEADERS` **64-bit variant** → tüm DataDirectory erişimleri açık `PIMAGE_NT_HEADERS32/64` cast'ine çevrildi.

## 3. Doğrulama Matrisi (V4.3.1)

| Hedef | Platform | Sonuç |
|---|---|---|
| MiniGameDll **IP1** (base 0x62000000) | wine32 GERÇEK koşu | `MOVEH=D0D78AB3` = orijinal birebir ✅ |
| MiniGameDll **IP2** (base **0x008D0000 — loader relocate etti!**) | wine32 GERÇEK koşu | `MOVEH=D0D78AB3` = orijinal birebir ✅ (relocation yolu uçtan uca kanıtlandı) |
| T1_32 **IP1/IP2** (6 fonksiyon) | wine32 GERÇEK koşu | 11/11 hash birebir baseline ✅ |
| T1_x64 **IP1/IP2** (6 fonksiyon) | unicorn (exit=0) | 11/11 hash birebir baseline ✅ |
| MiniGameHost2 v3 (3-DLL karşılaştırma) | wine32 | `SONUC: ESLESME=TAM` ✅ |

Kanıt dosyaları: `V4.3_IP/kanitlar/` (DLL_host2_wine32_kanit.txt, T1_32_ip1/ip2_wine32.log, T1_x64_ip1/ip2_unicorn.log) · `T3_DLL/`

## 4. A/B TESTİ — Kullanıcının Hipotezi

**Hipotez:** "x64 maze build'leri banner'da donuyor çünkü gameloop'u korudun; başka bir fonksiyon korunsaydın donmaz ve oyun açılırdı."

**Test:** Gerçek PE (T1_32) ile aynı maze motoru (mp_driver42 stream), wine32 GERÇEK koşu:

| Varyant | Korunan | Sonuç |
|---|---|---|
| maze + HEPSI | 6 fonksiyon | ❌ `T1-START` sonrası ÇÖKÜŞ |
| maze + TEK (`MP_ONLY=LcgNext` — **farklı, hafif fonksiyon**) | 1 fonksiyon | ❌ **YİNE ÇÖKÜŞ** |
| IP1 + HEPSI | 6 fonksiyon | ✅ birebir fingerprint |

**CEVAP: HAYIR — donma/çökme fonksiyon seçimine bağlı DEĞİL.** Hangi fonksiyon korunursa korunsun eski maze makinesi gerçek ortamda ilk korumalı çağrıda ölüyor (komut taşıma + taşıyıcı register + slot zinciri kırılganlığı). Aynı fonksiyonlar IP motoruyla korunduğunda sorunsuz çalışıyor. TinySnake'te "banner'dan sonra hiçbir şey olmaması"nın nedeni de bu: banner korumasız yazılıyor, ilk korumalı çağrı (GameLoop) maze makinesine girip asla dönmüyor.

## 5. TinySnake Uyarısı (önemli)

MiniOyun'daki TinySnake dosyaları DosX çatısıyla üretilmiş **kendi kendini açan küçük PE'ler** (dosya 3.5–20KB, sanal görüntü 0x44000). Gerçek oyun kodu dosyada bulunmaz; stub çalışma anında açar. Bu yüzden:
- Bu dosyalara uygulanan **statik koruma (IP dahil) dosya seviyesinde temsil edilemez** — korunan bölge çalışma anında stub tarafından taze kodla ezilir; oyun "korunsuz" çalışır.
- IP kanıtları için gerçek PE hedefler kullanıldı: **T1 (x86+x64, 6 fonksiyon)** ve **MiniGameDll (gerçek DLL, 2 export)**.
- Evrensellik zinciri: T1 (kendi kodumuz) + MiniGameDll (DLL) + normal yapıda indirilmiş bir oyun (gelecek tur; TinySnake yerine).

## 6. Kullanıcıya Teslim

- `T3_DLL/MiniGameHost2.exe` (v3): artık 3 DLL'i test eder (orijinal + ip1 + ip2) ve `ESLESME=TAM` bekler. **Gerçek Windows'ta çalıştırınız** — beklenen çıktı yukarıdaki kanıtla aynı.
- `T3_DLL/MiniGameDll_korumali.dll` artık bozuk beta DEĞİL — IP1 kopyası (eski host'larla da uyumlu).
- `AB_Testi/` : A/B deneyinin tüm parçaları (kendiniz koşabilirsiniz).
- Motor: `motor/Motor_V4.3_IP.h` + `motor/mp_driver43.cpp` (V4.3.1, tüm düzeltmeler işaretli).

## 7. Bir Sonraki Adımlar (havuz)

1. **Runtime CRC kapısı (IP'ye anti-patch geri dönüşü):** decrypt sonrası gövde CRC'si CB'deki ile karşılaştırılır; uyuşmazsa kontrollü duruş (ud2/222). "Koruma düşürüldü mü?" sorusunun kalan eksiği budur.
2. Normal-PE indirilmiş oyun hedefi (TinySnake yerine) + x64 gerçek-Windows kanıtı.
3. ULTRAPLUS / God-Mode (beklemede), G5/G6 prototipleri, anahtar zincirleme.
