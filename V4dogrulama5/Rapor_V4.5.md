# Rapor V4.5 — mp_encoder EVRENSEL SIFRELEYICI: metin2client sinifinin acilmasi

Tarih: 2026-10-23
Kapsam: Kullanicinin rapor ettigi uc basarisiz denemenin kok-neden analizi + duzeltmeler
+ gercek-runtime kanitlari (wine64 / wine32 / unicorn ucgeni).

## 1. Kullanicinin denemeleri ve kok-nedenleri

### Deneme-1: `mp_encoder.exe deneme.exe denemeoutput.exe m2 E7B9E E7BA8`
- Sonuc: `start: 0x0 = RVA ... HATA: end <= start (0x0 <= 0x0)`
- Kok-neden: dagitilan mp_encoder.exe, V4.4.1 kaynak kodundaki bare-hex
  duzeltmesini ICERMIYORDU (bayat derleme).
- V4.5: kaynak yeniden derlendi + parse V4.5 ile gelistirildi (ciplak sayi =
  hex; `1523` artik 0x1523'tur, 0x5F3 DEGIL).

### Deneme-2: `m2 0xE7B9E 0xE7BA8` → `[ATLA] Bolge_1 (cok kucuk)`
- Kok-neden: E7B9E bir fonksiyon BASI degil, fonksiyonun cagri-ondasi kuyrugu
  (10 bayt). Motor min 16 bayt ister ve fonksiyon-basi bekler.
- V4.5 cozumu: **FN modu** — `m2 FN E7B9E` yazilinca encoder geriye dogru
  int3 (0xCC) dolgu sinirini arar, fonksiyonun gercek basini bulur, BFS ile
  sonunu bulur ve BUTUN fonksiyonu korur. MSVC (metin2) duzeninde bu sinir
  garantidir; motor talimat-siniri dogrulamasi + guvenli-red ile korur.

### Deneme-3: `m2 0xD7610 0xD766C` → `Fonksiyon govdesinde mutlak adres (reloc RVA 0x882252)`
- Kok-neden A (gorunum): hata mesaji `0x` + DECIMAL basiyordu; "0x882252"
  sanilan deger gercekte 882252 decimal = **RVA 0xD764C** = `push "Send Battle
  Attack Packet Error"` komutunun ABS adres alani. Metin2client ASLR'li
  (DYNAMICBASE; Cheat Engine 0xDE0000'te gostermisti — tercih-edilen base
  0x400000 degil) ve govdede loader'in yamalayacagi 1 reloc vardi. m1/m2
  stream motoru govde-tasima yaptigi icin ASLR altinda bunu KATI reddediyordu.
- V4.5 cozumu: m1/m2 (x64) icin govde-reloc tespit edilirse cikista
  DYNAMICBASE temizlenir (ASLR kapanir) → image tercih-edilen base'de yuklenir,
  mutlak adresler gecerli, loader sifreli bolgeye dokunmaz. x86'da ise (asagida)
  motor degisir, IP'nin reloc-guvenli yolu kullanilir.

### KOK-BULGU (yeni): V4.2-X86 stream motoru runtime-kararsiz
Kullanicinin "yilan oyununda neden yapamadin?" sorusunun ikinci ayagi burada
kapandi. Unicorn x86 izi (uni_maze86.py) ile mb86 benzeri sentetikte:
- dispatch zinciri 0..3 calisiyor, final ret-swap edx=0xFE ile farewell'e gidiyor,
- AMA veda/clDispatch hatti donus degerini (EAX) mahvediyor ve wine32'de m1
  sonsuz-dongu, m2 segfault uretiyor (6/6 deterministik).
- V4.3-IP motoru ayni dosyada 11/11 birebir (T1_32 + MiniGameDll kanitlari).
**Karar (V4.5):** x86 hedefte m1/m2 istegi ACIKCA bildirilerek kanitli IP
motoruna yonlendirilir (m1→ip1, m2→ip2). "ASLA cokmesin" ilkesi oncelidir.
Kullanici deneyimi degismez: ayni komut satiri, ayni koruma ailesi.

## 2. Kanitlar (hepsi GERCEK runtime)

### x86 metin2-benzeri sentetik (mb86_aslr.exe: ASLR acik + govdede reloc'lu
ABS string push'u + stdcall ret 8 + fonksiyonu cagiran bir caller)
| Yontem | Encoder | Runtime (wine32/qemu) |
|--------|---------|----------------------|
| m1  | 1 bolge korundu | caller=39 / bitis / exit=0 (baseline birebir) |
| m2  | 1 bolge korundu | birebir |
| ip1 | 1 bolge korundu | birebir |
| ip2 | 1 bolge korundu | birebir |
| m2 VA-form (401535 401584, 0x'siz) | 1 bolge korundu | birebir |
| m2 FN (fonksiyon ortasi hint) | bas+son dogru / birlesikte guvenli-red | - |
| ASLR kapanisi | DllCharacteristics 0x160 → 0x100 | dogrulandi |

### x64 (deneme.exe: mingw x64, CRT, 18 section)
| Yontem | Runtime (wine64) |
|--------|------------------|
| m2 0x14A4 0x150B | hash=5F2970E0 birebir |
| ip1 14A4 auto (bare-hex) | hash=5F2970E0 birebir |
| ip2 0x14A4 0x150B | hash=5F2970E0 birebir |
| x64rel.exe (govde ABS+reloc, E8'li) ip2 | korundu + E8 UYARISI |
| x64rel.exe m1/m2 | GUVENLI-RED (x64 stream E8'yi kabul etmez — ip kullan) |

## 3. Bilinen sinirlar (V4.5)
1. x64 m1/m2 (stream): govde icinde baska fonksiyona E8 cagrisi varsa red
   (slot gecici). Cozum: ip1/ip2. (x86'da IP cagrili govdeyi tam destekler.)
2. x64 ip + govde-E8 kombinasyonu sinirli dogrulandi (encoder UYARI basar).
   RelFn sentetiginde page-fault gozlendi — bir sonraki tur icin unicorn x64
   izi planlandi. x86'da ayni kombinasyon testli ve saglamdir.
3. FN: dolgusuz (int3'suz) duzenlerde belirsiz olabilir; birlesik bolge
   tespitinde guvenli-red verir.

## 4. Dosyalar
- motor/mp_encoder.exe (V4.5, PE32+), motor/mp_encoder.cpp
- motor/Motor_V4.2_MazeProtector.h (allowRelocBody + hex-hata mesajlari)
- motor/globals.h (x86 icin de DYNAMICBASE temizligi + mpX86Relocs uyesi)
- motor/OKUBENI_mp_encoder.txt (V4.5)
- Encoder_Test/KANIT_V4.5.txt + sentetikler (mb86/metin_benzeri, x64rel)
- Teşhis araci: Encoder_Test/uni_maze86.py (x86 maze izi)
