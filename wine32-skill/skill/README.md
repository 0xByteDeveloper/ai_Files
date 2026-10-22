# Wine 32-bit Runner — Yöntem, Skill ve Kanıtlar

Bu paket, root olunmayan Linux sandbox'larında (Debian/Ubuntu, seccomp korumalı,
RAM kısıtlı) **32-bit Windows .exe'lerin Wine altında çalıştırılmasını** sağlayan
kanıtlanmış yöntemi içerir. Yöntem, gerçek bir oturumda uçtan uca iki kez
doğrulanmıştır: (1) kurulum oturumu, (2) skill script'inin boş ortamda sıfırdan
tüm kurulumu yapması (`fresh-run` logları `proof/` altında).

## En kısa kullanım (yeni sohbet / yeni sandbox)

```
1. skill/wine-32bit-runner/ klasörünü skill dizininize kopyalayın
   (örn. ~/.claude/skills/ veya kullandığınız agent'ın skills/ dizini)
2. GLM'ye şunu sorun: "wine-32bit-runner skill'ini kullan, bu 32-bit exe'yi çalıştır"
3. GLM skill'i okuyup scripts/setup-wine32.sh'ı çalıştırır (~1 dk, root'suz)
4. Ardından:  wine32 program.exe
```

## Paket içeriği

| Yol | Ne |
|---|---|
| `README.md` | Bu dosya |
| `skill/wine-32bit-runner/SKILL.md` | Skill tanımı + kullanım kılavuzu (GLM okur) |
| `skill/wine-32bit-runner/scripts/setup-wine32.sh` | Tek komutluk root'suz kurulum + doğrulama scripti |
| `skill/wine-32bit-runner/references/method.md` | Derin teknik döküm: her başarısız yolun kanıtlı hatası + çözümü |
| `proof/test.c`, `proof/test32.exe` | Derlenen 32-bit test programı ve PE32 çıktısı |
| `proof/fresh-run-full.log` | BOŞ ortamda sıfırdan kurulum logu (indirme→prefix) |
| `proof/fresh-run-verify.log` | Aynı ortamda PASS doğrulaması |
| `proof/main-env-verify.log` | Kurulu ortamda doğrulama PASS logu |
| `worklog.md` | Tüm oturum çalışma kaydı |

## Yöntemin özeti (detay: references/method.md)

| Sorun | Kanıt | Çözüm |
|---|---|---|
| root yok → wine32 kurulamaz | `sudo: a password is required` | kullanıcı apt ağacı + `apt-get download` + `dpkg -x` |
| Wine WoW64 build çöküyor (SIGSEGV) | strace: `mmap(NULL, 34359742464) = -1 ENOMEM` | **x86 build** kullan (wow64 DEĞİL) |
| native i386 süreç ölüyor (SIGSYS / "Bad system call") | strace: ilk `brk(NULL)` → SIGSYS (seccomp `AUDIT_ARCH_I386` KILL) | **qemu-i386** emülasyonu + exec-zincirini qemu'ya kilitleyen bash sarmalayıcılar |
| guest execve host'a native geçiyor | strace: `execve(".../wine-preloader") = 0` → SIGSYS | `bin/wine`, `bin/wineserver`, `wine-preloader` → `.real` + shebang script (`exec qemu -0 "$0" real "$@"`) |
| `/lib/ld-linux.so.2: could not open` | preloader mini-loader'ı ELF interp'ini okur | `bin/` **ve** `lib/wine/i386-unix/`'deki tüm ELF32'lere patchelf (kısa yol ≤18 kar: `/home/u/l/ld.so`) |

**Wine'da yapılan değişiklikler (kurulum dosyaları değil, yalnızca yamalar):**
1. patchelf: tüm ELF32'lere `--set-interpreter <kısa ld.so yolu>` + `--set-rpath <i386root>/usr/lib/i386-linux-gnu`
2. Üç exec noktası `.real`'e taşınıp yerine qemu çağıran bash script kondu (yukarıda)
3. `WINEPREFIX` `WINEARCH=win32` ile oluşturulur; launcher `WINESERVER`/`WINELOADER` env'lerini sabitler
4. Sistem Wine'a (varsa wine64) **dokunulmaz** — kit paralel çalışır

## Kanıtlanmış sürümler

- Wine: **11.20** (Kron4ek Wine-Builds `wine-11.20-x86.tar.xz`)
- qemu-user: **10.0.13** (Debian trixie), libc6:i386 **2.41-12+deb13u4**
- patchelf **0.18.0**, gcc-mingw-w64-i686-win32 **14.2.0-19+27+b1**, binutils-mingw-w64 **2.44-3+12+b1**
- OS: Debian 13 (trixie) — türevlerinde (Ubuntu) suite otomatik tespit edilir

## Son doğrulama çıktısı

```
$ file test32.exe
test32.exe: PE32 executable for MS Windows 4.00 (console), Intel i386, 16 sections
$ wine32 test32.exe
Merhaba 32-bit!
$ echo $?
0
```
