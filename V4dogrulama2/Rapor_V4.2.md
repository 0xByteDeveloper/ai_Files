# V4 DOĞRULAMA RAPORU v4.2 — EVRENSEL DOĞRULAMA TUR-2
**Tarih:** 2026-10-22 | **Motor:** V4.2 (MazeProtector V4M1 + V4M2 Stream) | **Görev:** Kullanıcının gerçek-Windows test bulgularının çözümü + x86 emitter + T2

---

## 1. KULLANICININ BULGULARI → TANILAR

| Kullanıcı testi | Sonuç | Bu turdaki tanı |
|---|---|---|
| T1 (5 exe) | ✅ HEPSİ PASS, çıktılar birebir | x64 motor gerçek Windows'ta sağlam |
| TinySnake.x64.protected.exe | ❌ banner + "oyun yok / bazen çöküyo" | **Kök neden analizi aşağıda** |
| TinySnake.x32 / x64 | ✅ oynanıyor (korumasız orijinaller) | — |
| TinySnake_32.exe (9 bayt) | ❌ açılmadı | İndirme hatası ("Not Found" metni) — bu pakette temizlendi |
| DLL testleri | ❌ pakette yoktu | **Bu turda eklendi** (T3: MiniGameDll) |

## 2. TINYSNAKE.X64.PROTECTED TANISI (tam denetim zinciri)

Yapılan doğrulamalar (hepsi PASS — dosya statik olarak **kusursuz**):
1. **GameLoop (0x1158, 696B) komut-komut:** 6×rel8 jmp + 42×rel32 + 19×rip-rel; SITE kapsaması TAM (38 THUNK / 9 MODUL / 19 RIP — hedeflerin hepsi doğru).
2. **Blob çözümü:** 81 parça XOR-K çözümü; **CRC-8: 0 hata**; **148 site fixup formülü (stored = target − srcVA − insnEnd): 0 hata**; içerik farkları yalnız beklenen EB→E9 genişletmeleri.
3. **Stub/template/thunk/farewell disassembly:** stack dengesi + ABI-saydamlık OK.
4. **PE yapısı:** .pdata büyütme (RWX), import descriptor taşıma, UNWIND_INFO intakt, checksum.
5. **Emülasyon:** unicorn ile 76 oyun turu sorunsuz; **Monte-Carlo (rastgele rdtsc + tuş enjeksiyonu, 6 seed) OK**.

**Sızma noktası (motor tasarımı):** V4.1'de `r12` taşıyıcısı korunan fonksiyon boyunca YAŞIYOR (thunk'lar `jmp r12`, stage conv=r12). Korunan fonksiyon/kod yolu r12'yi bozarsa maze makinesi kırılır (TinySnake kullanmıyor ama **evrensellik için geçersiz varsayım**); ayrıca G1 slot stride 16<32 üst üste binme riski taşıyordu.

## 3. V4.2 MOTOR GÜNCELLEMESİ (x64) — TAMAMLANDI ✓

- **r12/conv bağımlılığı KALDIRILDI:** thunk'lar artık `jmp qword [blob+0x40 ARENA_PTR]`; stage her girişte `mov r12,[r11+0x40]` ile yeniden yükler → **korunan fonksiyon r12–r15'i serbest kullanabilir** (red kuralı da kalktı).
- Header 0x40→0x50 (0x40 ARENA_PTR, 0x48 jmpSlot); trambolin hedefi +0x50.
- **G1 slot stride 16→32** (32 slot × 32B, üst üste binme YOK).
- fbStage conv'suz rip-relative; crcFail scope düzeltmesi.

**TinySnake.x64.protected.exe V4.2 ile yeniden üretildi:** CRC 0 hata, site 0 hata, Monte-Carlo 3/3 OK. → **Kullanıcı gerçek Windows'ta yeniden test etmeli.** Hâlâ çökerse paketteki tanı matrisi (bölüm 7) kullanılacak.

## 4. x86 (PE32) EMITTER — YAZILDI (BETA) ✓/⚠

`Motor_V4.2_X86.h` (~1000 satır): EmitStreamStubX86 / EmitStreamStageX86 / EmitStreamFbStageX86 / EmitArenaFarewellX86 / BuildStreamX86.
- PEB'siz **absolute disp32/imm32 + .reloc HIGHLOW üreteci** (yeni .reloc section + DataDirectory[5]; mevcut .reloc varsa AddRelocation).
- x86'da rip-rel yok → site fixup yalnız rel32 dal (EB→E9, 7x→0F8x genişletme aynı).
- conv=esi (yalnız stage-ici), pid=edx, stdcall VirtualAlloc/VirtualFree.

**Bulunan ve düzeltilen 5 gerçek bug (bisection kanıtlı):**
1. **Import descriptor kopyası:** mingw import-dizin Size'ı PAD'li → NULL+çöp kopyalanıyor, yeni descriptor NULL arkasında kalıyordu → loader IAT'yi hiç çözmez (call [IAT] → RVA'ya atlar, 0x80C9 çökmesi). → copySz artık NULL'a kadar GEZEREK hesaplanıyor.
2. **w-uzayı çakışması (IAT=2 vs sitesOff=2):** stage'in sitesOff'u IAT VA'sı yazılıyordu (fixup çöpe) → w=45 (IAT), w=2 (sitesOff).
3. **Çakışma #2:** decoy dlen `imm(34)` = crcTblOff ile çakışıyordu → w=46/47.
4. **CLEANUP yaması MOV/LEA:** `mov ecx,[ebx+clJmpEnd]` DEĞER yüklüyordu; LEA (adres) olmalıydı.
5. **Farewell disp yönü:** `(arena+clJmpEnd) − farewell` TERSİNE hesaplanıyordu → `sub eax,ecx` (x64 ile aynı yön).
6. **x86 thunk `FF 25`:** 32-bit'te disp32 RIP-relatif DEĞİL — mutlak adres; thunk disp'leri patch+reloc'a bağlandı.
7. **EmitStreamStubX86 return S (başlangıç) → templateAbs=stub olurdu** → return blob.size() (son).

**Durum (dürüst):** T1-32/TinySnake.x32/DLL korumaları **üretiliyor ve dosya düzeyi doğrulamaları (CRC/site formülü) geçiyor**; ancak **gerçek wine32 çalıştırmasında hâlâ çöküyor** (arena-yolu 0xC42593, fb-yolu 0x40; TEKTEK 0xC102C0=slot başı → parça içeriği çalışma anında bozuk okunuyor). Kalan şüpheli: arena-yolundaki per-call yama alanı / fb deyim sırası. Sonraki oturum için tam bisection verisi + şablon dökümleri bu pakette (`x86_hata_ayiklama/`).

## 5. T2 — 32-BİT GERÇEK YÜRÜTME ALTYAPISI ✓

- **wine32 bu oturumda yeniden kuruldu ve PASS** (qemu-user + Kron4ek wine-11.20-x86 + patchelf + mingw-i686): `wine32 test → "[Merhaba 32-bit!]" exit=0`.
- **T1-32bit baseline:** x64 ile BİREBİR AYNI değerler (H1=71B1E1C5 … SEED=C16436A3) — kod mimari-bağımsız ✓.
- Test zinciri hazır: `wine32 T1_32_protected.exe` → diff (şu an x86 motor beta çökmesi).
- **T3 DLL seti:** MiniGameDll (MM_Move/MM_Lcg exportlu, oyun mantığı DLL'de) + MiniGameHost; **baseline wine32 PASS** (MOVEH=D0D78AB3); DLL koruması üretiyor (39+3 parça, 44 JMP) — yükleme hatası x86-beta kapsamında.

## 6. TESLİMATLAR (V4Dogrulama.zip)

- `Rapor_V4.2.md` (bu dosya)
- `MiniOyun/` TinySnake orijinaller + **TinySnake.x64.protected.exe (V4.2, fix)** + TinySnake.x32.protected.exe (beta) + Snake haritaları
- `T1/` T1_Validate.cpp + T1_32.c + baseline/çıktılar + korumalı x64/x32
- `T3_DLL/` MiniGameDll.c/.cpp + MiniGameHost.c + baseline + korumalı DLL + harita
- `motor/` Motor_V4.2_MazeProtector.h + Motor_V4.2_X86.h + mp_driver.cpp + mp_driver42
- `dogrulama_araclari/` verify_blob42.py, verify_x32.py, montecarlo_snake.py, emu32_run.py, analyze_snake.py
- `x86_hata_ayiklama/` şablon dökümleri + bisection kayıtları (sonraki oturum için)
- `kanitlar/` emülatör logları, wine32 kurulum kanıtı

## 7. KULLANICI İÇİN YENİDEN TEST TALİMATI

1. `MiniOyun/TinySnake.x64.protected.exe` → gerçek Windows'ta çalıştır (V4.2 fix). Banner sonrası oyun BAŞLAMALI.
2. Çökerse: `MiniOyun/TinySnake.x64.protected.tektek.exe` (G1/G2/G3 kapalı tanı sürümü) — o çalışırsa sorun G1/G3'te; o da çökerse raporu dön.
3. DLL testi: `T3_DLL/MiniGameHost.exe + MiniGameDll.dll` aynı klasörde → T3-START … T3-END.

## 8. SONRAKİ OTURUM PLANI

1. x86 arena-yolu çökmesi (0xC42593) — şüpheli: stub'un per-call yamalarının arena-kopyası konumları + TEKTEK'te slot başında garbage (parça çözüm verisi runtime'da bozuk → K/encOff okuma sırası).
2. x86 DLL LoadLibrary hatası (çift-geçiş reloc birikimi → Core.mpX86Relocs oturum-içi birikim sağlandı; tek-geçişte test edilecek).
3. x86 başarıdan sonra: TinySnake.x32 + T1-32 + DLL GERÇEK wine32 PASS kanıtları → V4Dogrulama.zip final.
4. ULTRAPLUS / God-Mode (V3 çoklu-JMP + V4M2 + VMProtect özellikleri) — beklemede.
