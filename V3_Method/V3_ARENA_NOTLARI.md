# V3 ARENA Modu — Yöntem Notları

V3, MazeProtector'ın ilk "kod asla diskte plaintext değil" uygulamasıdır. **Motor kodu `MazeProtector.h` içinde hâlâ korunmaktadır** (V4 paketlerine bakın: `../V4method1_TekTek/i4MConsoleLoader_kaynak/i4MConsoleLoader/MazeProtector.h` veya `../V4method2_Stream/.../MazeProtector.h`) — V3, V4'ün fallback modu olarak kodda yaşıyor.

## V3 Nasıl Çalışır (kullanıcının tarifiyle doğrulanmış)

V3'te fonksiyon **TÜM BİR KERE** plaintext olarak sanal "free memory" (VirtualAlloc RWX) arenaya decrypt edilir:

```
[fonksiyon çağrılır → trambolin → V3 routine]
1. 8 x push  (durum kaydı)
2. VirtualAlloc (RWX arena)
3. chunk kopya (şifreli parça → arena)
4. XOR 0xA14FC884A80CA3E1 (tüm arena tek anahtarla çözülür)
5. delta-fixup (relocation/absolute adresler düzeltilir)
6. JMP chunk1 (fonksiyon çalışır — komutlar parça parça akar ama hepsi plaintext)
7. farewell (fonksiyon dönüşü yakalanır)
8. memset(arena, 0) → VirtualFree  ("işi bitince sil")
```

## Neden V4'e Geçildi?

| Sorun | Açıklama |
|---|---|
| Dump penceresi | Çalışma anında **tüm fonksiyon plaintext** arenada durur — tek anlık dump tüm fonksiyonu verir |
| Şifreleme tek seferlik | XOR bir kez çözülür, arena kirlenene kadar tüm opcode'lar okunur |
| Wipe yok | Parça parça gidiş- geliş yok, bellekte birikim tam fonksiyondur |

V3'ün analiz kaydı: `../raporlar/MovePlayer_Analiz_V3.txt` ve `../raporlar/MovePlayer_Opcode_Struct.txt` (Move fonksiyonunun opcode yapısı — V4 parçalama stratejisinin temeli).

## V3 → V4 Geçiş Kararı

- **V4method1:** aynı arena yerine SABİT slot; her parçadan önce slot SIFIRLANIR (wipe-behind). "Tek tek aynı yere yaz" — silmezsen op0+op1+...+op28 yine tam fonksiyon olur.
- **V4method2:** 24B slot + her çağrıda farklı adres (G1) + thunk kapıları + lazy cold path. Detay: `../PROJE_HAFIZASI.md` bölüm 2.

## Test Kanıtı Durumu

V3 modu V4 paketlerindeki `MazeProtector.h`'da fallback olarak aktiftir; V4 kanıt dosyalarındaki `baseline_Sifresiz.txt` karşılaştırma referansıdır. V3'ün kendisi için ayrı kanıt seti üretilmedi — V4 WON=1 doğrulaması V3 fallback'i kapsamaktadır.
