# Worklog

---
Task ID: 1
Agent: Z.ai (main agent)
Task: Linux workspace'te Wine ile 32-bit exe çalıştırma (kullanıcı planı: teşhis → Çözüm A (wine32) → Çözüm B (Kron4ek wow64) → doğrulama (mingw + PE32))

Work Log:
- Teşhis: Debian 13 (trixie) x86_64, Wine YOK, kullanıcı `z` root/sudo değil (sudo grubunda bile değil), seccomp filter mode (Seccomp: 2), cgroup RAM = 4 GB, swap yok, overcommit_memory=0.
- Çözüm A (dpkg --add-architecture i386 + apt install wine32) BLOKE: root gerektirir.
- Çözüm B (Kron4ek wine-11.20-amd64-wow64): indirildi (95MB), ldd temiz; ancak wineboot/wine SIGSEGV. strace ile kök neden: WoW64 başlangıcında ~32 GB tek parça anonim mmap → ENOMEM (overcommit heuristic: RAM+swap=4GB sınırı) → Wine NULL deref. Kernel ayarı root'suz değiştirilemez → bu build bu ortamda çalışamaz.
- Çözüm C (uygulanan): Kron4ek wine-11.20-x86 (32-bit) + root'suz i386 glibc + qemu-user emülasyonu.
  1. Kullanıcı apt ağacı ($HOME/aptroot: Dir::Etc/Dir::State/Dir::Cache override) → apt-get download libc6:i386 (+libgcc-s1:i386), patchelf, qemu-user(-static), mingw-w64 paketleri — hepsi dpkg -x ile $HOME altına.
  2. patchelf: bin/* ELF32'lere --set-interpreter /home/z/l/ld.so (PT_INTERP ≤18 karakter kısıtı) + --set-rpath; ayrıca lib/wine/i386-unix/* (preloader'ın okuduğu interp buradan).
  3. Native i386 exec denemesi: brk(NULL) → SIGSYS (seccomp AUDIT_ARCH_I386 syscall'leri KILL). strace + qemu -strace ile iz sürüldü.
  4. qemu-user (qemu-i386 10.0.13) altında wine --version ✓; ancak guest execve zinciri (wine-preloader, wineserver) host'a native geçiyor (qemu statik bağlı, LD_PRELOAD hook'suz; QEMU_EXECVE etkisiz) → SIGSYS.
  5. FINAL ÇÖZÜM: exec edilen i386 yolları bash script'e çevrildi, gerçek ELF'ler .real'e taşındı:
     bin/wine→wine.real, bin/wineserver→wineserver.real, lib/wine/i386-unix/wine-preloader→wine-preloader.real
     Script'ler: exec qemu-i386-static -0 "$0" <real> "$@" (argv0 korunumlu; kernel shebang ile native bash → qemu zinciri).
  6. wineboot -u → EXIT 0, prefix ($HOME/.wine32, WINEARCH=win32) oluştu. wine cmd /c "echo" ✓ (PE süreç yaratma çalışıyor).
  7. Doğrulama: root'suz mingw (gcc-mingw-w64-i686-win32 14.2 + binutils + dev paketleri $HOME/mingw'a dpkg -x; i686-w64-mingw32-gcc sembolik linki elle) → test.c derlendi → file: "PE32 executable ... Intel i386" → wine32 test32.exe → "Merhaba 32-bit!", exit 0.

Stage Summary:
- GÖREV TAMAM: 32-bit Windows exe'leri bu workspace'te çalışıyor.
- Kullanım: /home/z/my-project/scripts/wine32 <program.exe veya wine-argümanları>
  (örn: wine32 program.exe, wine32 cmd /c "dir", wine32 regedit)
- Mimari: [bash] wine32 → [script] bin/wine → qemu-i386-static (AMD64, seccomp-uyumlu) → i386 Wine 11.20 → PE32.
- Kritik dosyalar: scripts/wine32 (launcher), scripts/setup_wine32_rootless.sh, scripts/test.c,
  download/test32.exe (PE32 test ürünü), $HOME/wine-wow64/wine-11.20-x86 (yamalı Wine), $HOME/i386root (i386 runtime),
  $HOME/mingw (root'suz cross-compiler), $HOME/aptroot (kullanıcı apt ağacı), /home/z/l/ld.so (i386 loader).
- Sınırlar: FreeType:i386 kurulmadı (font uyarısı kozmetik, konsol etkilenmez); grafik arayüzlü programlar X sunucusu gerektirir; 64-bit PE bu kurguda çalışmaz (x86 build + win32 prefix — istenirse wow64 ayrı ele alınmalı).
