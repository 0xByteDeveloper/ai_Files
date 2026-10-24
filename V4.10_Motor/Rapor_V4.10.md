# MazeProtector V4.10 — ESP-İzleyici Düzeltmesi: Gerçek metin2 Fonksiyonu Artık Şifreleniyor

**Tarih:** 2026-10-24 · **Tetik:** `mp_encoder_v49.exe deneme.exe denemeoutput.exe m2 0x004D7610 0x004D766F`
komutu iki yeni v49 kontrolünden reddediyordu: `esp yazimi takipsiz form (RVA 0xD7611)` ve
`x86 STREAM son komut ret/join-jmp olmali ('pop')` (ikincisi yanlış end denemelerinde).

---

## 1. Kök-Neden: V4.7 ESP-İzleyici Yön (Direction) Hatasi — 2 yanlış pozitif + 1 eksik form

V4.9'un V4.7'den gelen ESP-delta izleyicisi `89/8B` MOV formlarında reg/mr alanlarını ters
anılamıştı. Gerçek metin2 `Send Battle Attack Packet` fonksiyonu (RVA 0xD7610, 95 bayt) tam da
bu formları kullanıyor:

| Gerçek komut | Baytlar | Eski davranış | Gerçek anlam |
|---|---|---|---|
| `mov ebp, esp` (prolog, 0xD7611) | `8B EC` | **RED** ("esp yazimi takipsiz form") — satır 787 rm==4'ü "yazım" sanıyordu | ESP **OKUMASI** (8B'de rm=KAYNAK) |
| `mov esp, ebp` (3 çıkış yolu) | `8B E5` | **RED** — satır 786 rge==4'ü kayıtsız reddediyordu | İzlenebilir restore (ebpKnown ile) |
| `mov ebp, esp` alternatif form | `89 E5` | Tanınıyordu (satır 762) | ebpKnown=true |

Sonuç: fonksiyonun İKİNCİ komutunda (0xD7611) encoder reddediyordu. mb86 vekili bu yüzden
geçiyordu: vekildeki prolog `89 E5` formundaydı; gerçek metin2 (MSVC) `8B EC` kullanıyor.

**V4.10 düzeltmesi (Motor_V4.2_X86.h):**
- `8B /r`: ESP'ye yazım **yalnız** `rge==4` (mov esp,r/m); `rm==4` (mov ebp,esp dahil) artık
  OKUMA olarak kabul edilir ve `ebpKnown` set edilir.
- `89 /r`: ESP'ye yazım **yalnız** `mmod==3 && rm==4` (mov esp,reg); `rge==4` (mov eax,esp
  gibi) artık yanlış pozitif DEĞİL.
- Takip edilen restore formları: `89 EC` ve `8B E5` = `mov esp,ebp` (ebpKnown gerekli;
  d=ebpD). Bilinmeyen gerçek ESP yazımları (mov esp,imm/mem, xchg esp,...) yine GÜVENLİ-RED.

## 2. Gerçek Fonksiyonun Kesin Yeniden İnşası (kanıt zinciri)

Kullanıcının orijinal `deneme.exe`si sandbox'ta yok; V4.6 çıktısındaki MZE3 blob'undan
orijinal 95 bayt KESİN olarak kuruldu (7 parça decrypt + site tablosu 13/13 + 4 E8 slot-disp
geri-çözümü + kısa-jne `75 xx` genişleme tersi + ret-swap E9→`C2 08 00`):

```
0xD7610: 55              push ebp
0xD7611: 8B EC           mov ebp, esp          <- v49'un reddettiği komut
0xD7613: 83 EC 08        sub esp, 8
0xD7616: 56 / 8B F1      push esi; mov esi, ecx
0xD7619: E8 (0xDC1A0)    call ...
0xD761E: 84 C0 / 75 09   test al,al; jne 0xD762B
0xD7622: B0 01 5E 8B E5 5D C2 08 00   mov al,1; pop esi; mov esp,ebp; pop ebp; ret 8
0xD762B: 8A 45 08 ... 8B CE             yapi doldur + lea + push + mov ecx,esi
0xD763E: C6 45 F8 02     mov byte [ebp-8], 2
0xD7642: E8 (0xD7670) / 84 C0 / 75 16   call; test; jne 0xD7661
0xD764B: 68 8033BC       push "Send Battle Attack Packet Error"   (reloc RVA 0xD764C)
0xD7650: E8 (0x141660) / 83 C4 04 / 32 C0
0xD765A: 5E 8B E5 5D C2 08 00           pop esi; mov esp,ebp; pop ebp; ret 8
0xD7661: 8B CE / E8 (0x152520)
0xD7668: 5E 8B E5 5D C2 08 00           pop esi; mov esp,ebp; pop ebp; ret 8
```

`deneme_orig.exe` = V4.6 çıktısından geri (gövde 95B + 6 section + SizeOfImage 0x542000 +
DYNAMICBASE geri + import dizini orijinal .rdata tablasına (RVA 0x4497C8) geri).
Bu dosyayla v49 çalıştırıldığında kullanıcının hatası HARFİYEN üretildi (yeniden
yapılandırmanın doğruluğu bağımsız kanıtlandı).

## 3. Doğrulama Matrisi (hepsi v4.10 encoder ile YENIDEN şifrelendi)

| Test | Baseline | v4.10 m2 | Durum |
|---|---|---|---|
| **Gerçek metin2 fonksiyonu** relay A (erken çıkış) | exit=1 | exit=1 | **BİREBİR** |
| relay B (hata yolu + ABS string push + fixup) | exit=0 | exit=0 | **BİREBİR** |
| relay C (başarı yolu) / D (al=0) | 1 / 0 | 1 / 0 | **BİREBİR** |
| Gerçek fonksiyon **400-çağrı sızıntı** testi | — | exit=42, kalan=0, **5x determinizm** | **SIZINTI YOK** |
| Gerçek fonksiyon blob statik doğrulama | — | 7/7 parça CRC-8 eşleşir, semantik birebir | PASS |
| G2 anti-patch (şifreli bayt çevirme) | — | patched=SIGILL(fail-closed), temiz=normal | PASS |
| mb86 (SendBattle vekil: ret8+E8+ABS+reloc) | caller=39 exit=0 | ayni | **BİREBİR** |
| t32one oracle (Target(0)) | 213 | 213 | **BİREBİR** |
| t32loop 400-çağrı (leak teshis) | 109 | 109 | **BİREBİR** |
| MazeGame32 autotest (3 bölge m2) | OK score=30 frame=529 hwid=650945844 WON=1 | ayni | **BİREBİR** |
| Kullanıcı komutu `m2 0x004D7610 0x004D766F` | v49: RED | **[OK-M2] +95 bayt → .maze blob=2217B parca=7 site=14** | ÇÖZÜLDÜ |

Not: `m2 0x004D7610 0x004D766C` / `0x004D766E` denemeleri YANLIŞTIR — fonksiyon sonu
0x004D766F'tir (son `ret 8` 0xD766C..0xD766E). v49'un "son komut ret olmali ('pop')" reddi o
durumda DOĞRU davranıştı.

## 4. Teslimat

- `motor/mp_encoder_v410.exe` (x64, statik) — kullanıcı komutu aynen çalışır
- `motor/mp_encoder_v49.exe` — aynı düzeltilmiş derlemenin drop-in kopyası (eski isimle)
- `motor/Motor_V4.2_X86.h` (V4.10) + `mp_encoder.cpp` + `globals.h` + diğer motor başlıkları
- `denemeoutput.exe` + `_MazeMap.txt` — gerçek client üzerinde V4.10 m2 çıktısı (wine32
  relay + 400-çağrı + G2 kanıtlı)
- `dogrulama_araclari/` : rebuild_deneme_orig.py, build_harness_v410.py, verify_v410_blob.py,
  emit_stub_dlls.py (hepsi yeniden koşulabilir kanıt zinciri)

## 5. Bilinen Sınır / Not

- x64 motoru (MazeProtector.h) Bu turda DEĞİŞMEDİ — V4.9 K8 üçlü-birebir kanıtı geçerli.
- fb (fallback) yolu wine32'de hâlâ SIGILL (V4.10 takip listesindeydi; bu turun kapsamı
  dışında — normal arena yolu 400-çağrı ile sızıntısız kanıtlandı, fb yalnız OOM/depth-8
  taşması gibi nadir durumlara düşer).
- V4.6 çıktısındaki .reloc, gövde girişini (0xD764C) içerir; V4.10 çıktısında da ölü bölgeye
  işaret eder (tercih-edilen base'de no-op, zararsız).
