# Rapor V4.6 — x86'da GERCEK m1/m2: V4method1_TekTek + V4method2_Stream artik PE32'de de calisiyor

Tarih: 2026-10-23
Kapsam: Kullanicinin x1 (yeni yapilanlar neden basarisiz / x32'de neden basarisiz)
ve x2 (x64'te calisan V4method1_TekTek + V4method2_Stream'in x32 versiyonu,
wine32-metot-ve-skill.zip) isteklerinin tam karsiligi.

## 1. x1 — Kok-neden analizi (6 hata)

V4.5'te x86 (PE32) hedefte m1/m2 istegi KANITLI IP motoruna yonlendiriliyordu,
cunku V4.2-X86 stream motoru wine32'de m1 hang / m2 segfault uretiyordu ve
unicorn izi "EAX veda hattinda bozuk" diyordu. Kullanici bunu "metodu
degistirdin" olarak dogru sekilde reddetti. V4.6'da motorun icine girildi ve
ASIL kok-nedenler bulundu — hepsi x64 motorunda olan ama x86 portune
eksik/yanlis gecen kurallar:

### H1 — Veda ret imm16 atiyor (KRITIK)
x64 EmitArenaFarewell(retOp, retImm16): her ayrik ret opcode'u icin ayri
farewell, sonu ORIJINAL `ret [imm16]`. x86 EmitArenaFarewellX86 parametre
almiyor, daima `ret` (C3) basiyordu. metin2client D7610 thiscall `ret 0008`
ile bitiyor: korumali fonksiyon dondugunde stack 8 bayt kayiyor -> cagiran
kodun kalaninin her push/pop/ret'i kayiyor -> cokus/hang. yilan oyunundaki
"slot bolgesi calisma hatasi" ile ayni ailenin ikinci ayagi.
FIX: retOp/retImm16 parametreleri + her ayrik ret icin ayri farewell (x64 ile
birebir sozlesme). Cikti farewell'i artik `83 C4 20 58 C2 08 00`.

### H2 — Stub prepatch yanlis register: 89 86 (esi) yerine 89 83 (ebx)
Stub, cleanup E9'larinin disp'ini arena kopyasina `mov [ebx+clDispPos],eax`
ile yazmali. Emit `89 86` (=[esi+disp]) — rep movsb sonrasi esi = blob'daki
template-sonu. Disp arena'ya YAZILMIYOR; E9 disp 0 kaliyor; cleanup'in
`jmp farewell`'i stage'e geri donuyor; unicorn izinde sonsuz dongu (esp her
tur kayiyor), wine32'de m1 hang / m2 segfault.
FIX: `89 83` (hardened crcDispPos yaziminda da ayni hata vardi — o da duzeltildi).

### H3 — Hardened CRC len'i ole aracagi eskitiyor
x64 CRC dongusu len'i edx KOPIASINDA tasiyor ([rsp+8] saglam). x86 decrypt
dongusu `sub dword [esp+0xC],8` ile ayni hucreyi 0'a indiriyor; CRC ayni
hucreyi len olarak okuyunca 0xFFFFFFFF tur atiyor, slot-sonrasi arena-disina
okuyor -> wine32 m2 SEGFAULT (deterministik).
FIX: len kaydi ecx'te tasinir; [esp+0xC] ORIJINAL kalir.

### H4 — G3 decoy tablo indeksi SIB 0x03 (x1)
x64 decoy erisimi `lea r9,[r11+rax*8+decoyTblOff]` — SIB 0xC3 (eax*8).
x86 emitter SIB 0x03 (eax*1) emit ediyordu; tablo girdileri 8 bayt oldugu
icin cop doff/dlen okunuyor, slot'a cop kopyalaniyor, calistirma wild-jump.
FIX: SIB C3 (iki erisimde de).

### H5 — Decoy 'jne nodec' off-by-one
x86: `put({0x75}); jneNd = blob.size(); blob.push_back(0);` — jneNd = DISP
byte'inin konumu. Patch `blob[jneNd+1] = size-(jneNd+2)` yaziyordu: disp-byte
yerine SHR opcode'u eziliyor, gercek disp 0 kaliyor (decoy hic atlanmiyor).
x64'te jneNd = opcode konumu oldugu icin ayni satir dogru — portte konum
sozlesmesi degismis. FIX: `blob[jneNd] = size-(jneNd+1)`.

### H6 — Tani araci hatasi: uni_maze86.py push sirasi
Harness cagri kurulumunda retaddr'i argumanlarin ALTINA basiyordu; fonksiyon
girisinde [esp]=arg1 gorunuyordu. V4.5'in "EAX bozuk" gozleminin bir parcasi
buydu. Duzeltildikten sonra iz: EAX = 0xBBB8 TAM, `ret 8` dogru adrese doner.

### Ek sağlamlaştırmalar
- crcFarewell (G2 fail yolu): arena artik [abs ARENA_PTR]'den okunur; VirtualFree
  stdcall argu sirasi duzeltildi (dwFreeType -> dwSize -> lpAddress).
- GrowAppendSection grow-last yolu: buyuyen section DISCARDABLE ise bayrak
  temizlenir (mingw /nn debug section'larina yasan .maze artik cope atilamaz;
  wine32 bunu affediyordu, gercek Windows affetmeyebilir).
- BuildStreamX86 artik rep.blobBytes raporlar (encoder "blob=0B" yaziyordu).

## 2. Encoder karari (V4.6)
x86 (PE32) hedefte m1/m2 istegi ARTIK GERCEK V4.2-X86 stream motoru ile
kurulur; IP yonlendirme KALDIRILDI. ip1/ip2 secenekleri aynen duruyor
(reloc-guvenli yol). Cikislarda DYNAMICBASE+NX temizlenir (Core::LoadFile
zaten yapiyor): image tercih-edilen base'de yuklenir, blob mutlak adresleri
reloc'suz gecerli.

## 3. Kanitlar (hepsi GERCEK runtime)
| Test | Hedef ozellikleri | Encoder | Runtime |
|---|---|---|---|
| mb86_aslr m1 | ASLR + govde-reloc + ret 8 + caller | 7 parca/14 site | caller=39 bitis exit=0 |
| mb86_aslr m2 | + G1/G2/G3 hardened | 7 parca/14 site | caller=39 bitis exit=0 |
| mb86_aslr m2 VA-form | 0x401535 formu | OK | birebir |
| mb86_aslr m2 5x | G1 rastgele slot | OK | 5/5 birebir |
| mb86_aslr ip2 | regresyon | OK | birebir |
| mt86 m1 | ret 12 + erken ret | 2 parca | acc=342 exit=0 |
| mt86 m2 | ret 12 | OK | acc=342 exit=0 |
| mt86 m2 CallerC | cdecl ret C3 + E8 dongu | 4 parca | acc=342 exit=0 |
| deneme.exe (x64) m1/m2 | x64 regresyon | OK | hash=5F2970E0 (uclu birebir) |
| unicorn mb86_m1 | tani | - | EAX=0xBBB8 TAM, ret 8 dogru donus |
| T3 MiniGameDll m1/m2 | ret 12, tercih-base'de yuklenirse | 23 parca | yuklenir (sinir notu: ayni-base coklu DLL'de IP kullan) |

## 4. Sinirlar (degisen yok, netlesti)
- Govdede loop/jcxz (E0-E3), far jmp: desteklenmez (guvenli-red).
- Parcalar-arasi CALL: guvenli-red.
- FN modu: MSVC/metin2 (saf int3) duzeninde kesin; mingw+ud2'de guvenli-red.
- m1/m2 + ASLR'li ayni-base coklu DLL: IP motoru kullan (reloc-guvenli).
- Minimum bolge: 16 bayt (10B cagri-sitesi icin FN veya manuel genis aralik).

## 5. Paket
- motor/mp_encoder.exe V4.6 (+ kaynak: mp_encoder.cpp, globals.h, Motor_*.h)
- wine32-metot-ve-skill.zip: V4.6 motor + wine32 kurulum/skill kiti + kanitlar
- V4Dogrulama.zip yenilendi; GitHub push (V4dogrulama6/)
