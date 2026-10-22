# i4M Console Loader

Eski **i4MGUILoader** projesinin ImGui/D3D11 arayuzunden arindirilmis, tamamen
**konsol** surumu. Windows'un bir dosyayi actiginizda process bellegine cevirme
yontemi (**PE loader emulasyonu**) izole bir dosyada: `i4MConsoleLoader/PEManualMapper.h`

## Neler Degisti?

| Eski (i4MGUILoader)          | Yeni (i4MConsoleLoader)          |
|------------------------------|----------------------------------|
| main.cpp (5938 satir ImGui)  | main.cpp (~650 satir konsol menu)|
| ImGui/ klasoru (3.2 MB)      | SILINDI                          |
| GUI_Skills / GUI_Manager / Theme / Fonts / imports.h / Disasm.h / stb_image | SILINDI |
| SubSystem: Windows + D3D11   | SubSystem: **Console**           |
| Platformlar: Win32 + x64     | Platformlar: **sadece x64**      |
| PE yukleme GUI icine gomulu  | **PEManualMapper.h** (izole, main'den kontrol) |
| globals.h + InstanceManager.h| **AYNEN KORUNDU** (cekirdek motor) |

## PEManualMapper.h - Windows Loader Emulasyonu

`main.cpp` icerisinden kontrol edilir; Windows'un dosya -> process bellegi
cevirme akisinin birebir aynisi (kod calistirilmadan):

```
[1/8] DOS/NT header dogrulama
[2/8] VirtualAlloc (ImageBase tercih edilir, doluysa yeni yer -> relocation)
[3/8] Header'larin kopyalanmasi (SizeOfHeaders)
[4/8] Section'larin raw -> virtual map edilmesi
[5/8] Base relocation (base kaydiysa: HIGH/LOW/HIGHLOW/HIGHADJ/DIR64)
[6/8] Import cozumu (LoadLibraryA + GetProcAddress -> IAT doldurma)
[7/8] Mapped ImageBase guncellemesi
[8/8] Section korumalari (Characteristics -> PAGE_* VirtualProtect)
 + TLS callback raporu (calistirilmaz)
```

Ayarlama (main.cpp icinden):
```cpp
g_mapper.options.tryPreferredBase        = true;  // ImageBase'i dene
g_mapper.options.applyRelocations        = true;  // base kayarsa reloc uygula
g_mapper.options.resolveImports          = true;  // IAT doldur
g_mapper.options.setSectionProtections   = true;  // PAGE_* uygula
g_mapper.options.continueOnMissingImport = true;  // eksik DLL'de devam
```

## Derleme

1. Visual Studio 2019/2022 ile `i4MConsoleLoader.sln` dosyasini acin.
2. **capstone** gereklidir (Disasm/Assembler/ByteInjector icin):
   - Kolay yol: proje klasorune `i4MConsoleLoader/capstone/` olusturun;
     icine `capstone.lib` (x64) ve `include/` klasorunu (capstone.h) kopyalayin.
   - VEYA eski yolunuzdaki konumlar proje ayarlarinda yedek olarak duruyor
     (`C:\Users\Admin\source\repos\denemeee\...`).
3. **Debug|x64** veya **Release|x64** secip derleyin (F5 / Ctrl+Shift+B).

> Not: Tum konfigurasyonlar `SubSystem: Console` olarak ayarlandi; D3D11/ImGui
> bagimliligi tamamen kalkti. Kaynak dosyalar UTF-8 (/utf-8) derlenir, konsol
> otomatik olarak CP65001'e alinir.

## Kullanim (Konsol Menu)

```
 DOSYA
  [1]  PE Yukle                  [2]  PE Bilgisi (headers/sections/imports)
  [3]  String Tara               [4]  Disassembly (dosya gorunumu)
  [5]  Hexdump (dosya)           [6]  Adres Duzenle (asm / hex bayt)
  [7]  Undo / Redo               [8]  Kod Enjeksiyonu (ByteInjector Hook)
  [9]  Section Ekle / Bos Alan   [10] Dosyaya Kaydet
  [11] PE Kapat
 WINDOWS LOADER EMULASYONU
  [12] Bellege Map Et            [13] Loader Log / Rapor
  [14] Dump Al (mapped)          [15] Incele (mapped: hexdump/disasm)
  [16] Korumayi Degistir         [17] Map Kaldir (Unmap)
 PROCESS
  [18] Process'e Baglan (PID)    [19] Process Bilgisi / Moduller
  [20] Bellegi Oku (proc)        [21] Bellege Yaz (proc)
  [22] Ayir                      [0]  Cikis
```

Ornek akis (dosyayi Windows gibi bellege cevirme):
```
[1]  -> PE dosyasinin yolunu gir
[12] -> Bellege map et (loader log'unu izle)
[13] -> Adim adim loader raporu
[14] -> Mapped goruntuyu dosyaya dump et
[17] -> Bellek iadesi (Unmap)
```

## Dosya Yapisi

```
i4MConsoleLoader/
|-- i4MConsoleLoader.sln
|-- i4MConsoleLoader/
|   |-- i4MConsoleLoader.vcxproj         (x64, Console, /utf-8)
|   |-- i4MConsoleLoader.vcxproj.filters
|   |-- main.cpp                          <- konsol menu (kontrol katmani)
|   |-- PEManualMapper.h                  <- WINDOWS LOADER EMULASYONU (izole)
|   |-- globals.h                         <- cekirdek motor (degismedi)
|   |-- InstanceManager.h                 <- process motoru (degismedi)
|   |-- stdafx.h                          <- temizlendi (ImGui yok)
|   `-- capstone/                         <- SIZ EKLEYECEKSINIZ (lib + include)
`-- README.md
```

## Guvenlik Notu

Entry point / DllMain / TLS callback'ler **calistirilmaz** (secim:
"sadece map et"). Map islemi sonrasi bellek goruntusu dump'lanabilir ve
incelenebilir. Process modu icin yonetici yetkileri gerekebilir.
