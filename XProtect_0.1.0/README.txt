====================================================================
 XProtect 0.1.0 — CPlusPort PE Sanallastirici Paketi
====================================================================

XProtect; VMProtect 3.5.1 mimarisi referans alinarak C++ ile yazilan
CPlusPort motorunun surumlu resmi paketidir. Motor, secilen fonksiyonlari
x86/x64 makine kodundan kendi VM bytecode'una cevirir, fonksiyon basina
64-bit anahtarla pozisyon-bazli XOR ile sifreler ve .vmp0 bolumunde
statik yorumlayici (JIT yok, runtime kod uretimi yok) ile calistirir.

--------------------------------------------------------------------
1) PAKET ICERIGI
--------------------------------------------------------------------
  Test.exe          Orijinal test oyunu (MiniPac, 64-bit)
  Test32.exe        Orijinal test oyunu (32-bit)
  Test_vmp.exe      Korumali oyun (64-bit, 5 fonksiyon sanallastirildi)
  Test32_vmp.exe    Korumali oyun (32-bit, 4 fonksiyon; GameTick native)
  CPlusPort.exe     Koruyucu motor GUI (64-bit)
  CPlusPort32.exe   Koruyucu motor GUI (32-bit)
  VMPHelper.exe     Canli surec dogrulama araci (v1.3)
  Test_exe_Source/      Test oyununun kaynak kodu (Test.cpp, x64+x86 ortak)
  VMPHelper_Source/     VMPHelper kaynak kodu (VMPHelper.c, v1.3)
  CPlusPort_Source/     Motor kaynak kodu + derleme scripti
  CHANGELOG.md          Surum gecmisi ve hata duzeltme kayitlari

--------------------------------------------------------------------
2) HIZLI BASLANGIC — KORUMA
--------------------------------------------------------------------
  1. CPlusPort.exe'yi calistirin (64-bit hedef icin).
     32-bit hedef icin CPlusPort32.exe'yi kullanin.
  2. Giris PE olarak Test.exe (veya Test32.exe) secin.
  3. Sanallastirilacak fonksiyonlardan birini secin (hepsi onerilir).
  4. "Koru" ile islemi baslatin; cikti <ad>_vmp.exe olarak uretilir.
  5. Istersen CPlusPort_debug.log'u inceleyin (adim adim motor gunlugu).

  Islem sonunda orijinal RVA'lar korunur; CE ile adres kiyasi
  "ModulAdi"+RVA seklinde birebir yapilabilir.

--------------------------------------------------------------------
3) DOGRULAMA — VMPHelper
--------------------------------------------------------------------
  1. Korumali exe'yi calistirin (Test_vmp.exe / Test32_vmp.exe).
  2. VMPHelper.exe'yi ayri bir konsoldan calistirin.
  3. Cikti soyler: bolum tablosu (.vmp0 dahil), sanallastirilan
     fonksiyonlar (RVA/stub tipi/bc boyutu/anahtar), canli bellek
     dogrulamasi (stub'dan cekilen bc RVA + anahtar manifest ile
     kiyaslanir — hepsi "AYNI" olmali), sifreli bytecode orneklemi.
  4. v1.3 notu: 32-bit CheckCollision anahtari artik dogru basilir
     (0x4C80AE497AD22F21); eski surumdeki "FARK!?" bayat manifest
     kaynakliydi, VM/oyun etkilenmiyordu.

--------------------------------------------------------------------
4) CHEAT ENGINE SAHA GOREVLERI (ogrenim icin)
--------------------------------------------------------------------
  - "Test_vmp.exe"+1000: orijinalde WrapPos opcode'lari vardir;
    korumalida E9 (trampoline jmp) veya VM stub prologu gorursunuz.
  - vm_entry'ye (helper'in verdigi adrese) breakpoint koyun; her
    w/a/s/d + Enter'da buraya gelmeli.
  - Sifreli bytecode bolgesinde baytlar anlamsizdir — istenen durum;
    VM anahtari ctx+0x10'dadir, cozum calisma sirasinda yapilir.

--------------------------------------------------------------------
5) KAYNAKTAN DERLEME
--------------------------------------------------------------------
  Gereksinim: zig cc (ziglang), gcc (Linux CLI + VM blob'lar icin
  gcc-multilib), python3.

  cd CPlusPort_Source
  ./build_all.sh
    [1/4] VM blob'lari (vm_core.c -> vm64.bin / vmx86.bin)
    [2/4] Linux CLI (cplport_cli)
    [3/4] Test.exe x64 + Test32.exe x86  (zig cc, -fwrapv)
    [4/4] CPlusPort.exe x64 (Win32 GUI)

  CPlusPort32.exe (32-bit GUI) icin:
    zig c++ -target x86-windows-gnu -O2 -DUNICODE -D_UNICODE \
        cplport_gui.cpp engine_main.cpp engine_pe.cpp engine_disasm.cpp \
        engine_lift.cpp engine_stub.cpp engine_util.cpp vm_blob.cpp \
        -o CPlusPort32.exe -lcomdlg32 -lcomctl32 -luser32 -lgdi32 \
        -lshell32 -fno-sanitize=undefined

  VMPHelper.exe icin:
    zig cc -O2 VMPHelper.c -o VMPHelper.exe

--------------------------------------------------------------------
6) SURUM SISTEMI
--------------------------------------------------------------------
  - Surum adi: XProtect_0.x.x (CHANGELOG.md'de detaylar).
  - Her yeni surumde bu ZIP'in eski hali versions/ klasorunde
    yedek olarak tutulur; dosya adi surum numarasini tasiyabilir.
  - Hata bildiriminde lutfen surum numarasi + CPlusPort_debug.log
    + VMPHelper ciktisini ekleyin.

--------------------------------------------------------------------
7) BILINEN NOTLAR (0.1.0)
--------------------------------------------------------------------
  - CPlusPort GUI calisirken yaninda bir konsol penceresi acilir
    (log icin bilincli birakildi; islevi etkilemez).
  - Talimat evreni alt-kumedir: motor kapsamadigi fonksiyonu
    native birakir (orn. x86'da GameTick). Bu bir hata degildir.
  - Runtime'da kod uretilmez/yazilmaz; tum VM kodu .vmp0'dadir.
