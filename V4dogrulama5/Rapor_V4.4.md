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

## 6) V4.4.1 — deneme.exe testinde yakalanan 3 kok-hata (KULLANICI SORUSU sonrasi)
Kullanici sozdizimini dogrularken ("mp_encoder.exe deneme.exe denemeoutput.exe m2
start end") uretilen canli demo (deneme.c: SecretHash(x,rounds) REGISTER-ARGUMANLI
+ 40 cagri) ilk kez IP makinesinin arguman yolunu gercekten test etti:

### BUG-C (KRITIK — Motor_V4.3_IP.h x64 emitter): push listesinde RAX eksik
- Yorum "push rcx,rdx,r8,r9,rax,rsi,rdi" (7) diyordu; baytlar "51 52 41 50 41 51
  56 57" = 6 push uretiyordu (50=push rax yok!). Epilogue 7 pop'lu.
- Etki zinciri: 7. pop cagiranin donus adresini RCX'e alir → register-argumanli
  fonksiyonlara cop arguman; rsp +8 kayar; ret-replacement [rsp+0x18] yanlis
  slot'a yazar (cagiranin shadow-slot'u ezilir); body'nin ret'i stub'i ATLAR;
  sonraki cagri recovery yolundan gecer; ret-stub yolu veri bolgesine duser
  → GERCEK WINDOWS c0000005 @rip=CB+0x30 (wine64'te aynen dogrulandi).
- Neden simdi? T1/TinySnake/MiniGameDll'de korunan fonksiyonlar VOID'du veya
  stub yolu test penceresinde hic calismadi. FIX: push rax (50) eklendi.

### BUG-D (Motor_V4.3_IP.h ret-stub): side-fetch REX.X biti yanlis
- "4B 8B 54 CA F8" = mov rdx,[r10+r9*8-8] → indeks R9 = govde artigi cop;
  realRet cop slot'tan okunuyor → ret → rastgele adres (wine64 cokusu).
  Yorum: mov r10,[r10+rcx*8-8]. FIX: 4B→4D.

### BUG-E (mp_encoder.cpp): end=auto iki kez mem.base dusmesi + bare-hex
- ComputeFnSizeCFG maxEnd'i relative biriktirip donuste tekrar mem.base
  dusuyordu → auto hep 0xC000150B cop'u → bolge atlanıyordu (guvenli-red).
- Bare-hex "14A4" strtoull(,,0) ile 14'e dusuyor ('A'de kesiyor) → PE
  header'larinda gezen bos BFS. FIX: ParseAddr (kismi parse'ta hex tamamla).
- EK: 0 bolge korunduysa cikis dosyasi yazilmaz; auto sonucu SnapRange'den
  gecer (start hizasi garanti).

### V4.4.1 kanitlari (Encoder_Test/KANIT_deneme_V4.4.1.txt)
| Yontem | Bolge | Sonuc (gercek wine64) |
|---|---|---|
| m2/m1 | SecretHash explicit+auto | hash=5F2970E0 exit=0 |
| ip1/ip2 | SecretHash (40 cagri) | hash=5F2970E0 exit=0 |
| ip2 | main+SecretHash IC-ICE 2 makine | hash=5F2970E0 exit=0 |
| ip1 | TinySnake GameMain (yeni motor) | oyun canli |
- Unicorn komut-izleme: IP1'den SecretHash(0x1234567,8) → rax=0xE6D0654C =
  yerli GCC ayni hesap BIREBIR; govde coz→calistir→YENIDEN SIFRELE dongusu tam.
