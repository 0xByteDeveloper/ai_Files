# method.md — Root'suz 32-bit Wine yönteminin tam teknik dökümü

Bu doküman, yöntemin **neden** böyle çalıştığını ve her başarısız yolun **kanıtlı
hata anını** içerir. Kanıt ortam: Debian 13 (trixie), x86_64, root yok, seccomp
filter mode, cgroup RAM 4 GB, swap yok. Tüm çıktılar gerçek oturumdan alınmıştır.

## 0. Ortam imzası (ne zaman bu yöntem?)

```bash
uname -m                 # x86_64
sudo -n true             # başarısız → root yok
grep Seccomp /proc/self/status   # Seccomp: 2 (filter mode)
free -h; swapon --show   # RAM küçük + swap yoksa overcommit riski
cat /proc/sys/vm/overcommit_memory   # 0 = heuristic
```

- Root VARSA bile: klasik `dpkg --add-architecture i386 && apt install wine32`
  yoluna girme — seccomp'lu sandbox'ta native i386 süreç ilk syscall'de ölür
  (bkz. §3). Bu yöntem root'suz olduğu için her durumda çalışır.
- Hedef: **32-bit PE çalıştırmak**. 64-bit PE'ler sistem wine64'ünde
  çalışmaya devam eder (kit paralel kurulur, çakışmaz).

## 1. Başarısız yol A — klasik wine32 (root yok)

`dpkg --add-architecture i386` /var/lib/dpkg/arch'a yazar → root ister.
`apt install wine32:i386` aynı şekilde. Kullanıcı `z` sudo grubunda bile değil:

```
$ sudo -n true
sudo: a password is required
$ id
uid=1001(z) gid=1001(z) groups=1001(z)
```

## 2. Başarısız yol B — Kron4ek amd64-wow64 (overcommit ENOMEM)

İndirilen: `wine-11.20-amd64-wow64.tar.xz` (95 MB). `wine --version` çalışır,
`wineboot -u` SIGSEGV. strace kanıtı:

```
mmap(NULL, 34359742464, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = -1 ENOMEM
mmap(NULL, 34359873536, ...) = -1 ENOMEM
mmap(0x7ffe0000, 4096, PROT_READ, MAP_FIXED) = 0x7ffe0000
--- SIGSEGV {si_code=SEGV_MAPERR, si_addr=NULL} ---
```

Wine'ın yeni WoW64'ü 32-bit adres uzayını ~32 GB'lik TEK parça anonim mmap ile
rezerve ediyor. `overcommit_memory=0` (heuristic) modunda kernel, RAM+swap
toplamlından büyük tekil mmap'i reddeder (4 GB RAM, 0 swap → 32 GB = ENOMEM).
Wine NULL dönen rezervasyonla devam edip NULL deref ile çöküyor. Root olmadan
overcommit/swap değiştirilemez → **wow64 build bu ortamda matematiksel olarak
ölü**. Klasik x86 build'in preloader'ı ise rezervasyonu küçük parçalar halinde
`MAP_NORESERVE` ile yapar (qemu -strace kanıtı):

```
mmap2(0x00010000,1048576,  PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_NORESERVE) = 0x00010000
mmap2(0x00110000,1743716352, ... MAP_NORESERVE) = 0x00110000
mmap2(0x7f000000,16711680,  ... MAP_NORESERVE) = 0x7f000000
```

## 3. Başarısız yol C — native i386 Wine (seccomp SIGSYS)

x86 build + root'suz i386 glibc + patchelf sonrası `wine --version` native
çalıştırıldığında:

```
execve(".../bin/wine", ...) = 0
brk(NULL) = ?
+++ killed by SIGSYS +++
```

İlk syscall `brk` bile ölüyor: sandbox seccomp filtresi `seccomp_data.arch ==
AUDIT_ARCH_I386` olan TÜM syscall'leri KILL ile cezalandırıyor. amd64 süreçler
aynı syscall'leri sorunsuz yapıyor (64-bit wine uçtan uca çalışmıştı) → filtre
ABI-bazlı. **Hiçbir userspace hilesi native i386 yürütmeyi kurtaramaz.**

## 4. Yapı taşı — root'suz paket yönetimi

`apt-get download` + `dpkg -x` root istemez; i386 index'i için de root istemeyen
bir kullanıcı apt ağacı yeterli:

```bash
A=$HOME/aptroot
mkdir -p $A/etc/apt/{sources.list.d,preferences.d,apt.conf.d} \
         $A/var/lib/apt/lists/partial $A/var/cache/apt/archives/partial $A/var/lib/dpkg
touch $A/var/lib/dpkg/status
printf 'deb [arch=i386]  http://deb.debian.org/debian trixie main\ndeb [arch=amd64] ...' > $A/etc/apt/sources.list
apt-get -o Dir::Etc::SourceList=$A/etc/apt/sources.list \
        -o Dir::State=$A/var/lib/apt -o Dir::State::Status=$A/var/lib/dpkg/status \
        -o Dir::Cache=$A/var/cache/apt update
```

İndirilen ve ayıklanan paketler (kanıt sürümleri, trixie):

| Paket | Sürüm | Amaç |
|---|---|---|
| libc6:i386 | 2.41-12+deb13u4 | ld-linux.so.2 + libc/libpthread stub (i386 runtime) |
| libgcc-s1:i386 | 14.2.0-19 | pthread_exit çıkış uyarısını siler (kosmetik) |
| patchelf (amd64) | 0.18.0-1.4 | PT_INTERP + RPATH yamalama |
| qemu-user (amd64) | 10.0.13+ds-0+deb13u1 | i386 emülasyonu (qemu-i386) |
| qemu-user-static | 76 KB | `-static` symlink'leri |
| gcc-mingw-w64-i686-win32(+runtime) | 14.2.0-19+27+b1 | i686 PE derleyici (amd64 ikili) |
| binutils-mingw-w64-i686 | 2.44-3+12+b1 | i686 as/ld |
| mingw-w64-i686-dev / -common | 12.0.0-5 | header + import lib (arch:all) |

## 5. PT_INTERP kısalık kuralı

Kernel, ELF'i çalıştırırken PT_INTERP'teki MUTLAK yoldaki loader'ı açar.
`/lib/ld-linux.so.2` sistemde yok → patchelf ile kaydırıyoruz ama yol KISA
olmalı (interp segmentine sığması güvenli bant: ≤18 karakter):

```
/home/z/l/ld.so   → 15 karakter ✓   (kullanıcı adı uzunsa: /tmp/l/ld.so → 12 ✓)
```

patchelf: `--set-interpreter <kısa yol>` + `--set-rpath $I/usr/lib/i386-linux-gnu`
**Hem `bin/` hem `lib/wine/i386-unix/` altındaki TÜM ELF32'lere uygulanmalı** —
çünkü `wine-preloader`, yükleyeceği ELF'in PT_INTERP'ini KENDİ mini-loader'ıyla
okur. Sadece `bin/` yamalanınca hata: `/lib/ld-linux.so.2: could not open`.

## 6. qemu-user katmanı ve exec-zinciri problemi

`qemu-i386-static bin/wine --version` çalışır (qemu AMD64 süreç; tüm syscall'ler
AMD64 ABI → seccomp'tan geçer). Ama Wine süreç yaratarak yaşamıyor:

- `wine` başlarken `execve($W/lib/wine/i386-unix/wine-preloader, ...)`
- `wineboot`/`wine` wineserver'ı `execve` ile başlatır
- PE süreç yaratma: wineserver fork+exec ile loader'ı tekrar çalıştırır

qemu bu guest `execve`'yi **host'a NATIVE geçirir** (strace kanıtı):

```
2511  execve("/home/z/.../wine-preloader", [...]) = 0     ← kernel native exec
2511  +++ killed by SIGSYS +++                             ← i386 ilk syscall → öldü
```

Kanıtlanmış ölü sonlar (denemeyin):
- **LD_PRELOAD shim** (execve'yi yakalayıp qemu'ya yönlendiren .so): qemu
  **statik bağlı** (`nm -D qemu-i386` → 0 undefined sembol) → LD_PRELOAD
  uygulanmaz.
- **QEMU_EXECVE=1**: bu qemu derlemesinde etkisiz (yine native execve).

### Çözüm: shebang sarmalayıcıları

exec EDİLEN yollar gerçek ELF yerine bash script olur; gerçek ELF `.real` ismine
taşınır. Guest execve(script) → qemu host-execve(script) → kernel binfmt_script
→ **native bash (AMD64, seccomp-güvenli)** → script qemu'yu re-exec eder:

```bash
#!/bin/bash
export LD_LIBRARY_PATH="$HOME/i386root/usr/lib/i386-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$HOME/i386root/usr/bin/qemu-i386-static" -0 "$0" "$HOME/wine-wow64/wine-11.20-x86/bin/wine.real" "$@"
```

`-0 "$0"` guest argv[0]'ı korur — wine/wineboot/wineserver argv0-bazlı davranış
seçimi (dispatch) yapıyor. Sarmalanan üç yol (kanıtlanmış tam set):

| Script | Gerçek ELF | Kim exec'liyor |
|---|---|---|
| `bin/wine` | `bin/wine.real` | kullanıcı, launcher, wineserver (PE yaratma) |
| `bin/wineserver` | `bin/wineserver.real` | wine/wineboot başlangıcı |
| `lib/wine/i386-unix/wine-preloader` | `...real` | bin/wine startup, PE süreç yaratma |

`lib/wine/i386-unix/wine` (loader ELF) SARMALANMAZ — preloader onu exec etmez,
open+mmap ile kendi yükler; gerçek ELF kalmalı. Diğer ELF32'ler (widl, wrc,
winebuild...) sadece geliştirme araçları; gerekirse aynı desen uygulanır.

## 7. Prefix ve launcher

- `WINEARCH=win32` SADECE prefix ilk yaratılışta anlamlı; x86 build zaten 32-bit.
- `WINESERVER`/`WINELOADER` env'leri wine'ın iç arama yolunu sabitler.
- `wineboot -u` qemu altında ~12 s; `wine cmd /c "echo"` ~1.2 s (PE süreç yaratma
  kanıtı). İlk kurulumda FreeType uyarısı kozmetik: `libfreetype6:i386`'yı aynı
  dpkg -x yöntemiyle $I altına ayıklayıp LD_LIBRARY_PATH'e eklemek yeter.

## 8. Kanıtlanmış doğrulama (son durum)

```
$ file test32.exe
test32.exe: PE32 executable for MS Windows 4.00 (console), Intel i386, 16 sections
$ wine32 test32.exe
Merhaba 32-bit!
$ echo $?
0
```

## 9. Yeni ortama taşınırken kontrol listesi

1. `uname -m` = x86_64? (qemu-i386 amd64 host ister)
2. GitHub'a doğrudan `releases/download/<tag>/` erişimi var mı? (API rate-limit'e takılma)
3. Debian tabanlı mı? (`apt-get download` + `dpkg -x` gerekir; değilse paketleri
   başka yolla edin: statik patchelf/patchelf-binaries, conda vs.)
4. `readelf` yoksa: `apt-get download binutils && dpkg -x` → $I/usr/bin/readelf
5. Launcher'daki LPATH guard'ı: /tmp altı ld.so oturum temizliğine uğrarsa
   launcher yeniden kopyalar (setup scripti de idempotent)
6. Sürüm yükseltme: sadece `WINE_VER` değiştir (x86 varyantı mevcut olduğu
   sürece yöntem değişmez; wow64'e DÖNME)
