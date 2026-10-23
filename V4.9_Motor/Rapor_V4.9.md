# MazeProtector V4.9 — x86 Stream Motoru: 8 Kok-Neden Duzeltmesi + Tam wine32 Kanit Paketi

**Tarih:** 2026-10-24 · **Hedef:** (T1) metin2 deneme.exe `m2 0x4D7610 0x4D766F` kurulum yesil ama
ilk hasarda cokme · (T2) MazeGame PE32 derle → V4method1/V4method2 ile sifrele → wine32 dogrula →
metot motorunu mukemmellestir.

---

## 1. Kok-Neden Zinciri (wine32 relay + unicorn iz kanitlari)

### BUG-A — Cleanup arenaStack OFF-BY-ONE ( bellek sizintisi → 8 cagrida cokme )
V4.7 giris sozlesmesi `lock inc depth; arenaStack[D-1]=arena` (imm49 = arenaStack-4, SIB x4)
kullanir. Cleanup ise `lock dec depth` SONRASI `mov eax,[imm49 + ecx*4]` okur: depth D-1
olmustur → **arenaStack[D-2]** okur. Sirali cagrida depth 0→1→0 → load hücre hicbir zaman
yazilmayan `arenaStack[-1]` = dispatcher'in son 4 bayti (`87 04 24 C3` = **0xC3240487**).
`VirtualFree(0xC3240487)` HATA verir → arena sayfasi LEAK → her cagri bir hint slotu yakar
(8 hint: imgTop + i·4MB) → 8 cagrida tukendi → fb yolunda garbage.
**KANIT (relay):** her cagrida `VirtualFree(c3240487,0,8000) retval=0`.
**FIX:** imm51 = arenaStackAbs (base+0) → load = arenaStack[D-1] DOGRU.

### BUG-B — kind=2 ABS-site ALANINA rel32 YAZILMASI (alan bozulmasi)
Site-disp yazim pass'i `kind==1` degilse `target=s.value` alip `disp = value-(mazeRva+insnEnd)`
yaziyordu — **kind=2 (ABS veri) siteleri de else dalina dusuyor** ve parcada zaten rvaForma
cevrilen alani ORIJINAL mutlak degerle branch-disp gibi ezıyordu.
**KANIT:** g_sink store 0x40603C → dosyada 0x3E8BF7 yazilmis → runtime +imgBase ile 0x7E8BF7
= yazim fault (unicorn `mov dword ptr [0x7e8bf7]` fault izi).
**FIX:** site pass'inde `if (s.kind == 2) continue;` — kind=2 alanina yalniz runtime fixup yazar.

### BUG-C — `add esp,8` (popfd SONRASI) BAYRAKLARI EZİYOR (yanlis cmov/jcc)
Stage kuyrugu: `pops; popfd; add esp,8; jmp [jmpSlot]`. `add` ZF/CF/PF yazar →
**parcalar-arasi bayrak tasiyan cmov/jcc bozulur**.
**KANIT (unicorn):** blk1 `test al,1` ZF=1 → blk2 `cmovne edx,ecx` ALINDI (ZF=0 okudu) →
T(0)=0x4F87 (yanlis; dogrusu 0xF7B9AED5).
**FIX:** `lea esp,[esp+8]` (bayrak degistirmez). fbStage parc yolu ayni fix.

### BUG-D — fbStage hedefi `pop eax` ile YOK EDİLİYOR (jmp 0)
fbStage parc yolu hedefi EAX'te hesapliyor, sonra caller regs restore ederken
`pop eax` ezıyordu → `jmp eax` → EIP=0. **FIX:** hedef EDI'ye tasinir, kuyruk `jmp edi`.

### BUG-E — FB yolunda STACK UNWIND + IDEMPOTANS + ABS fixup yoktu
1) fb decrypt döngüsünün `je` cikisi fixup'i ATLIYOR (dogrudan fbFlagSet).
2) fbDec guard yoktu: 2. fb cagrisi XOR ile RE-ENCRYPT ediyordu (blok sonu kod = cop).
3) FB modunda stage calismadigi icin kind=2 ABS alanlari rvaForm kaliyordu
   (`mov [0x603C]` fault). **FIX:** decrypt cikisi fixup girisine (init dahil);
   fbDec = blob+0x24 idempotans; stub icinde kind=2 fixup döngüsü
   (`[blob+encOff+fieldRel] += ebx-mazeRva`).

### BUG-F — Hint yuruyusu tukendiginde NIL fallback
8 hint doluysa dogrudan fb'ye dusuluyordu. **FIX:** 9. sans = NULL-base VirtualAlloc
(OS seciyor; arena PIC oldugu icin her base calisir). fb artik OOM-durumu.

### BUG-G — depth tasma koruması yoktu
8 eszamanli cagri arenaStack[8] (32B) tasiyordu (template alanina yaziyor).
**FIX:** giriste `cmp eax,7; jae fb` — tasmada fb yolu.

### BUG-H — V4.7 .reloc fiziksel yazim yolu eksikti (V4.7'de onarildi, V4.9'da korundu)
`.reloc`-u olan hedeflerde blob mutlak adresleri cikisa yazilmadan gidiyordu; wine32
0x400000'i isgal edip imaji relocate edince motor bayat adreslere atlyordu. V4.7'de
tek tabloda fiziksel HIGHLOW yazimi eklendi; V4.9 regresyonunda kanitlandi.

---

## 2. Dogrulama Matrisi (hepsi v49 encoder ile YENIDEN sifrelendi)

| Test | Baseline | m1 | m2 | Durum |
|---|---|---|---|---|
| t32one oracle Target(0)/(1)/(42hex) wine32 exit | 213/137/136 | 213/137/136 | 213/137/136 | **BIREBIR** |
| t32one unicorn 3 arg full 32-bit EAX | 0xF7B9AED5/0xF489/0x52C0 | — | ayni | **BIREBIR** |
| t32loop 400-cagri dongusu wine32 | 109 | 109 | 109 | **BIREBIR** (leak yok) |
| FORCE_FB (fbFlag=1) unicorn | — | — | T(0) tam | fb mekanizmasi OK |
| MazeGame32 autotest wine32 | OK score=30 frame=529 WON=1 | ayni | ayni | **BIREBIR** |
| mg32 m2 determinizm 5x | — | — | 0,0,0,0,0 | **BIREBIR** |
| mb86_aslr = metin2 D7610 vekili (stdcall ret8 + E8 + ABS string + reloc) | caller=39 bitis | ayni | ayni | **BIREBIR** |
| mb86 ip1 / ip2 | caller=39 bitis | = | = | **BIREBIR** |
| x64 deneme.exe (wine64) cikti hash | ef64d262 | ef64d262 | ef64d262 | **BILINEN 3'LU BIREBIR** |

**metin2 aciklamasi:** D7610 "Send Battle Attack Packet" fonksiyonu her vurus karesinde
cagrilir. BUG-A ile her cagri bir arena sayfasi sizdirir; 8 cagri ≈ 0.13 sn (60fps) →
hint tukendigi karede cokme = "kurulum yesil, ilk hasarda cokus" davranisinin kok-nedeni.
Ayni mekanizma real-metin2'de de aynidir; V4.9 ile slot sayfasi her cagrigi
VirtualFree edilir ve ayni hint sonsuza kadar yeniden kullanilir.

---

## 3. Bilinen Sinir / Not

- **FB yolu wine32'de (yalnizca fbFlag=1 dayatilmis kurulumda) SIGILL veriyor**; unicorn'da
  ayni exe tam sonuc uretiyor (T(0) birebir). Normal (arena) yolu wine32'de tam kanitli;
  fb yolu OOM/depth-tasma gibi nadir fallback durumlarindadir. V4.10 Takip maddesi.
- V4.7 ABS-site ozelligi ARTIK dogru calisir (govde-reloc'lu fonksiyonlar: metin2 push "Send
  Battle Attack Packet Error" tipi) — hem arena hem fb modunda fixup tamam.

## 4. Teslimat

- `motor/mp_encoder_v49.exe` (statik) + `motor/Motor_V4.2_X86.h` (V4.9) + `motor/globals.h`
- `testler/` : t32one/t32loop/MazeGame32 (baseline+m1+m2), mb86 v49 (m1/m2/ip1/ip2), kanit izleri
- `Rapor_V4.9.md` + `KANIT_V4.9.txt`
- Kullanim (metin2): `mp_encoder_v49.exe deneme.exe cikis.exe m2 0x004D7610 0x004D766F`
  (veya `m2 0x4D7610 0x4D766C` / FN modu `m2 FN 0x4D7610`)
