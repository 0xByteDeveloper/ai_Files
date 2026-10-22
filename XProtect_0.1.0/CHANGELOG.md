# XProtect — Sürüm Geçmişi

> VMProtect 3.5.1 mimarisi referans alınarak C++ ile yazılmış PE sanallaştırıcı (CPlusPort motoru)
> Her sürüm ZIP olarak `versions/` klasöründe yedeklenir. En son sürüm ana klasörde durur.

---

## 0.1.0 — 2026-10-20 (ilk resmi paket)

### Eklenen
- **CPlusPort.exe (x64)** — Win32 GUI koruyucu; PE32/PE32+ okuma-yazma, fonksiyon keşfi,
  x86/x64 alt-küme çözücü, lifter, VM stub üretimi, `.vmp0` bölümü, manifest gömme.
- **CPlusPort32.exe (x86)** — İLK KEZ paketlenen 32-bit GUI derlemesi.
  Statik doğrulama yapıldı (PE32/i386, import tablosu temiz). Gerçek Windows'ta ilk
  çalıştırma testi kullanıcıya aittir; sorun olursa `CPlusPort_debug.log` gönderilmelidir.
- **Test.exe (x64) / Test32.exe (x86)** — MiniPac test oyunu (fgets satır-bazlı güvenli giriş).
- **Test_vmp.exe (x64)** — 5 fonksiyon sanallaştırıldı: WrapPos, MovePlayer, GhostStep,
  CheckCollision, GameTick (trampoline + yerinde stub karma).
- **Test32_vmp.exe (x86)** — 4 fonksiyon sanallaştırıldı (GameTick x86'da native:
  yaprak-modu gereği).
- **VMPHelper.exe v1.3** — Canlı süreç doğrulama aracı (bölüm tablosu, manifest çapraz
  kontrol, stub bayt çıkarımı, CE yol haritası).

### Düzeltilen (bu sürüme kadar birikmiş 15 hata düzeltmesi)
- BUGFIX #12: x86 stub `ret 0xFFFF` yığın bozması → `C3` + u32 retimm.
- BUGFIX #13: Bayat `.reloc` girdileri ASLR altında VM anahtarını/jmp hedefini ezmesi
  → `filter_relocs()` (x86'da 26 girdi temizlendi). Test32_vmp w+Enter çökmesi bu ikisiyle
  çözüldü; gerçek Windows'ta doğrulandı.
- BUGFIX #14: VMPHelper x86 manifest'inde elle kopyalanan CheckCollision anahtarı bayat
  kalmıştı (0x4C80AE49A01823B1); doğru değer 0x4C80AE497AD22F21 → "FARK!?" giderildi.
- BUGFIX #15: VMPHelper "Tercih edilen ImageBase" artık diskteki dosyadan okunuyor
  (Windows loader bellekteki alanı gerçek tabanla güncelliyor; DYNAMIC_BASE notu eklendi).
- Erken dönem (#1–11): oyun LCG signed overflow, int3 doldurma taşması, NEG/NOT lifter,
  ret-sonrası çoklu çıkış, kuyruk-jmp, 0x83 imm8 sign-extension, acc-form, x64 stub
  REX/sıra, natcall clobber/hizalama, x86 pushad/SIB/64-bit anahtar kesmesi vb.

### Doğrulama durumu
- x64: wine64'te uçtan uca — orijinal Test.exe ile Test_vmp.exe çıktısı birebir aynı
  (aynı girişler, skor/yem/hayalet akışı diff = boş). Gerçek Windows'ta kullanıcı teyitli.
- x86: Unicorn emülasyon 44/44 (preferred) + 44/44 (ASLR + reloc) + tick 10/10;
  gerçek Windows'ta oyun çalışıyor (kullanıcı teyitli).
- VM semantiği ayrıca libgame.so harness 41/41 ve uc64 49/49.

### Bilinen sınırlar / notlar
- CPlusPort her iki mimaride de konsol penceresi açar (Subsystem=3); işlevi etkilemez,
  0.1.1'de GUI subsystem'a geçilebilir.
- CPlusPort32.exe loglarında u64 adresler `%x` ile kısaltılarak basılır (kozmik).
- Sanallaştırma talimat evreni alt-kümedir; kapsanmayan fonksiyon native kalır.
- Mutation pass / import koruma / anti-debug: sonraki sürümlerin gündemi.
