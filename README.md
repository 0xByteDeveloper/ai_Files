# ai_Files — MazeProtector Proje Arşivi

Bu repo, MazeProtector/i4MConsoleLoader/XProtect projesinin **kalıcı hafızasıdır**. Oturumlar arasında (ve sistem çökse bile) projenin tamamını buradan sürdürebilmek için her şey burada.

> **ÖNCE ŞUNU OKU:** [`PROJE_HAFIZASI.md`](PROJE_HAFIZASI.md) — projenin tamamı: mimari, V1→V4 evrimi, test kanıtları, port durumu, wine32 çözümü, sıradaki adımlar.

## İçerik Haritası

| Klasör | Ne var? |
|---|---|
| `PROJE_HAFIZASI.md` | **Ana hafıza dosyası** — önce bunu oku |
| `raporlar/` | V4 güvenlik raporu, VMProtect analiz raporu (satır referanslı), V3/opcode analizleri, OKUBENI dokümanları, V4 blueprint |
| `V4method1_TekTek/` | V4method1 (wipe-behind sabit slot) tam kaynak + test kanıtları + Linux doğrulama araçları |
| `V4method2_Stream/` | V4method2 (24B slot + G1/G2/G3 + thunk'lar) tam kaynak + kanıtlar |
| `V3_Method/` | V3 ARENA modu notları (motor kodu MazeProtector.h içinde korunmaktadır) |
| `i4MConsoleLoader/` | x64 PE manuel-map loader (konsol sürümü) — protector'a runtime doğrulama desteği |
| `XProtect_0.1.0/` | universalObfusPublicSrc (VMProtect kaynak) → **C++ portu** — motor + test ikilileri (port devam ediyor) |
| `wine32-skill/` | Root'suz 32-bit Wine kiti (qemu-user emülasyonlu) + kurulum/kanıt — 2026-10-22 PASS |
| `zipler/` | Tüm orijinal paketler (wine32, XProtect, i4MConsoleLoader, V4method1/2, universalObfusPublicSrc) |

## Hızlı Başlangıç (yeni oturum için)

1. `PROJE_HAFIZASI.md` oku (bölüm 7 = sıradaki adımlar)
2. V4 motoruna bak: `V4method2_Stream/i4MConsoleLoader_kaynak/i4MConsoleLoader/MazeProtector.h`
3. VMProtect analizine bak: `raporlar/universalObfusPublicSrc_Analiz.md` (bölüm 5 = V4M karşılaştırması)
4. 32-bit test gerekiyorsa: `wine32-skill/skill/scripts/setup-wine32.sh` çalıştır (bir kez, ~8 dk) → `wine32 <exe>`

## Proje Durumu (2026-10-22)

- [x] V3 ARENA modu — tamamlandı
- [x] V4method1 TekTek — tamamlandı (WON=1)
- [x] V4method2 Stream — tamamlandı (WON=1, kanıtlar taze)
- [x] VMProtect kaynak analizi — tamamlandı (1167 dosya, rapor üretildi)
- [x] Wine 32-bit çözümü — kuruldu ve doğrulandı (PASS)
- [ ] XProtect C++ portu — **DEVAM EDİYOR** (eksikler var, birebir port hedefi)
- [ ] Anahtar zincirleme (V4M2'ye) — planlandı
- [ ] G5 (TF/VEH) ve G6 (mini-VM) prototipleri — maliyet analizi hazır, bekliyor
