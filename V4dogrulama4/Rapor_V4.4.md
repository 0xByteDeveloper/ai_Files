# Rapor V4.4 — Evrensel Sifreleyici + TinySnake Stub Tespiti + Coklu-Bolge Fix
Tarih: 2026-10-23 (Tur-6)

## 1) Kullanicinin istekleri ve cevaplar
| Istek | Sonuc |
|---|---|
| "Bana sifreleyiciyi ver: dosya+base+end+m1/m2" | YAPILDI: motor/mp_encoder.exe (+kaynak) — m1/m2/ip1/ip2, VA/RVA otomatik, end=auto BFS bulucu, coklu bolge, MazeMap cikti |
| "Aynı yılanın kaynak kodunu bul, kendin derle, PDB'siyle aynı fonksiyonu şifrele" | YAPILDI: DosX-dev/TinySnake-game kaynagi mingw ile sembollu derlendi (game_main/logic/render/input/draw offsetleri COFF sembollerinden + .pdata) |
| "Orijinal disassembly'ye bak" | YAPILDI: GameLoop basi 0x1158 = `E8 33 FF FF FF call 0x401090` (mid-function, rel32 cagri ile basliyor) |
| "Korumali snake JMP acarken neyi nasil yaziyor" | YAPILDI: 0x1158'e `E9 <rel32=maze_entry>` + govde 0xCC doldurma; parcalar .maze blob'unda sifreli; giris stub'ı VirtualAlloc(arena)+slot |
| "gameloop yerine move fonksiyonunu şifrele" | YAPILDI: logic (Move) 0x18D9-0x1C74 (923B, 66 parca/152 site) m1 ile CANLI |

## 2) KRITIK TESPIT: TinySnake dosyalari self-unpacking stub
GERCEK wine64 + relay izi (kanitlar/stub_analiz/orig_m1_relay_stub_kanit.log):
- Yüklenen exe: 0x400000'de (EP=0x18DB). CRT startup cagrilari **ret=0x140003631** ile
  geliyor → GERCEK oyun imaji calisma aninda **0x140000000'e insa ediliyor**
  (dosya icindeki baytlar yer-tutucu; "kod dosyada YOK" — Tur-4 teshisinin runtime kaniti).
- strcmp("--init","--help","--end-session","--force") zinciri = DosX stub'in kendi
  baslangic mantigi; basarisizlikta free(NULL)/HeapFree(NULL) dongusu + temiz cikis.
- SONUC: statik dosyaya yapilan koruma (m1/m2/ip) yer-tutucu baytlara uygulanir;
  stub imaji kopyalarken IAT'yi kendi kurar → motorun ekledigi .mpimp
  VirtualAlloc/VirtualFree girdileri runtime kopyasinda YOK → maze makinesi arena
  acamaz → banner'dan once olum (HeapFree dongusu). IP1 bu yuzden calisiyor:
  VirtualAlloc ISTEMEZ, tum referanslari goreceli, kopyayla birlikte tasiyor.
- Base/end hatasi YOK — motor/mantik dogru; hedef dosya statik-koruma icin uygun degil.

## 3) KENDI DERLEDIGIM SNAKE'TE TAM MATRIS (gercek wine64)
game_main (GameLoop eslenigi) RVA 0x1C74-0x1E46; logic (Move) 0x18D9-0x1C74:
| Yontem | Bolge | Sonuc |
|---|---|---|
| m1 | GameLoop | CANLI |
| m2 | GameLoop | CANLI |
| m1 | Move | CANLI |
| m1 | GameLoop+Move (cift) | CANLI (V4.4 fix sonrasi) |
| m2 | GameLoop+Move (cift) | CANLI (V4.4 fix sonrasi) |
| ip1 | GameLoop | CANLI |
Tum koşularda oyun ekrani cizildi, 6-10 sn cokmeden calisti (exit=124=timeout-kill).

## 4) V4.4 duzeltmeleri (bu turda bulunan 2 gercek bug)
- BUG-A (mp_encoder SnapRange): verilen start geriye kayabiliyordu; onceki fonksiyonun
  ret'i bolgeye giriyor, CRT'nin `call main` i "ortaya gelen referans" saniliyordu.
  Fix: once verilen start'tan ileri-yuruyus (ForwardWalk), basariliysa start korunur.
- BUG-B (Motor_V4.2 coklu-bolge): arena hint = imgBase+imgSz — her machinery AYNI
  hint'i uretiyor; 2.'nin VirtualAlloc'u 1.'nin arenasina carpıyor, fallback dongusu
  0x400202 sabit argumanla sonsuz (667K call kaniti: cift_bolge_arena_cakisma_kanit.log).
  Fix: hint = imgSz + ((mazeRva>>4 & 0x3FFF)<<16) → machinery basina benzersiz.

## 5) Kullanima ozet
motor/OKUBENI_mp_encoder.txt — ornek komutlar + kurallar. Encoder Windows x64
exe olarak calisir (statik capstone + statik CRT, hicbir DLL gerektirmez).
