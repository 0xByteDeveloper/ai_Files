#!/bin/bash
# setup-wine32.sh — root'suz 32-bit Wine kiti (qemu-user emülasyonlu)
#
# Bu script şurada kanıtlanmış yöntemi sıfırdan kurar: Deja GNU/Linux 13 (trixie)
# x86_64 sandbox, root yok, seccomp i386 ABI'yi KILL ediyor, RAM 4GB (overcommit
# heuristic). Debian türevlerinde ve benzer sandbox'larda çalışır.
#
# Kullanım:
#   bash setup-wine32.sh                 # tam kurulum + doğrulama
#   bash setup-wine32.sh --skip-mingw    # derleyici olmadan (hazır exe'ler için)
#   bash setup-wine32.sh --verify-only   # sadece doğrulama (kurulu kiti test et)
#
# Ortam değişkenleri:
#   WINE_VER     Kron4ek sürümü            (varsayılan: 11.20)
#   WINEPREFIX   prefix yolu               (varsayılan: $HOME/.wine32)

set -uo pipefail

WINE_VER="${WINE_VER:-11.20}"
A="$HOME/aptroot"                       # kullanıcı apt ağacı
I="$HOME/i386root"                      # i386 + araç ayıklama kökü
WINE_ROOT="$HOME/wine-wow64"
W="$WINE_ROOT/wine-${WINE_VER}-x86"     # yamalı Wine ağacı
M="$HOME/mingw"                         # root'suz mingw cross-compiler
PREFIX="${WINEPREFIX:-$HOME/.wine32}"
TESTDIR="$HOME/wine32-test"

# PT_INTERP kısa yol: mevcut interp segmentine sığmalı (<=18 karakter güvenli bant)
LDIR="/tmp/l"; LPATH="$LDIR/ld.so"
CAND="$HOME/l/ld.so"
if [ "${#CAND}" -le 18 ]; then LDIR="$HOME/l"; LPATH="$CAND"; fi

MODE="full"
[ "${1:-}" = "--verify-only" ] && MODE="verify"
[ "${1:-}" = "--skip-mingw" ] && MODE="skipmingw"

log(){ echo "=== $* ==="; }
die(){ echo "HATA: $*" >&2; exit 1; }

# ---------------------------------------------------------------- 0. ortam
log "0/9 ortam kontrolü"
[ "$(uname -m)" = "x86_64" ] || die "x86_64 gerekli (bulunan: $(uname -m))"
command -v curl  >/dev/null || die "curl yok"
command -v dpkg  >/dev/null || die "dpkg yok"
command -v file  >/dev/null || die "file yok"
command -v readelf >/dev/null || command -v patchelf >/dev/null || true
. /etc/os-release 2>/dev/null && SUITE="${VERSION_CODENAME:-trixie}" || SUITE=trixie
echo "OS: ${PRETTY_NAME:-?} | suite=$SUITE | HOME=$HOME | ld.so hedefi=$LPATH"

# ------------------------------------------------- 1. kullanıcı apt ağacı
setup_apt_tree(){
  mkdir -p "$A/etc/apt/sources.list.d" "$A/etc/apt/preferences.d" \
           "$A/etc/apt/apt.conf.d" "$A/var/lib/apt/lists/partial" \
           "$A/var/cache/apt/archives/partial" "$A/var/lib/dpkg" "$A/dl"
  touch "$A/var/lib/dpkg/status"
  cat > "$A/etc/apt/sources.list" <<EOF
deb [arch=i386]  http://deb.debian.org/debian $SUITE main
deb [arch=amd64] http://deb.debian.org/debian $SUITE main
EOF
}
APT(){ apt-get -o Dir::Etc::SourceList="$A/etc/apt/sources.list" \
       -o Dir::Etc::SourceParts="$A/etc/apt/sources.list.d" \
       -o Dir::State="$A/var/lib/apt" \
       -o Dir::State::Status="$A/var/lib/dpkg/status" \
       -o Dir::Cache="$A/var/cache/apt" "$@"; }
apt_update_if_needed(){
  ls "$A"/var/lib/apt/lists/*binary-i386_Packages >/dev/null 2>&1 && return 0
  log "1/9 apt update (kullanıcı ağacı, $SUITE)"
  setup_apt_tree
  APT update 2>&1 | tail -1 || true
}

# ------------------------------------------------------- 2. paket indirme
dl_extract(){
  local dest="$1"; shift
  mkdir -p "$dest"; ( cd "$A/dl" && APT download "$@" ) 2>&1 | grep -E "^Get:|^E:" || true
  local d p
  for pkg in "$@"; do
    p="${pkg%%:*}"   # libc6:i386 -> libc6 (dosya adında :arch yok)
    d=$(cd "$A/dl" && ls -t ${p}_*.deb 2>/dev/null | head -1) || true
    [ -n "${d:-}" ] || die "indirilemedi: $pkg"
    dpkg -x "$A/dl/$d" "$dest"
  done
}

install_runtime(){
  log "2/9 root'suz paketler (libc6:i386, libgcc-s1:i386, patchelf, qemu-user)"
  apt_update_if_needed
  dl_extract "$I" libc6:i386 libgcc-s1:i386 patchelf qemu-user qemu-user-static
  [ -x "$I/usr/bin/qemu-i386" ] || [ -x "$I/usr/bin/qemu-i386-static" ] || die "qemu-i386 ayıklanamadı"
  mkdir -p "$LDIR"
  local ld
  ld=$(find "$I" -name "ld-linux.so.2" -o -name "ld-linux.so.2.*" 2>/dev/null | head -1)
  [ -n "$ld" ] || die "ld-linux.so.2 bulunamadı (libc6:i386?)"
  cp -L "$ld" "$LPATH"
  file -b "$LPATH" | grep -q "ELF 32-bit" || die "ld.so kopyası ELF32 değil"
  echo "i386 loader: $LPATH ($(du -h "$LPATH" | cut -f1))"
}

# ------------------------------------------------------------ 3. Wine x86
install_wine(){
  if [ -x "$W/bin/wine.real" ]; then echo "Wine zaten kurulu: $W"; return 0; fi
  log "3/9 Kron4ek Wine ${WINE_VER}-x86 indiriliyor (NOT: amd64-wow64 KULLANILMAZ — overcommit ENOMEM)"
  mkdir -p "$WINE_ROOT" && cd "$WINE_ROOT"
  local url="https://github.com/Kron4ek/Wine-Builds/releases/download/${WINE_VER}/wine-${WINE_VER}-x86.tar.xz"
  curl -sL --retry 3 -o "wine-${WINE_VER}-x86.tar.xz" "$url" || die "indirme başarısız: $url"
  [ -s "wine-${WINE_VER}-x86.tar.xz" ] || die "boş arşiv"
  tar -xf "wine-${WINE_VER}-x86.tar.xz"
  [ -x "$W/bin/wine" ] || die "arşiv açıldı ama $W/bin/wine yok"
}

# --------------------------------------------------- 4. patchelf (interp+rpath)
patch_wine(){
  log "4/9 patchelf: ELF32'lere interpreter + rpath"
  local pe="$I/usr/bin/patchelf"
  [ -x "$pe" ] || die "patchelf ayıklanamadı"
  local f patched=0
  for f in "$W"/bin/* "$W"/lib/wine/i386-unix/*; do
    [ -f "$f" ] || continue
    case "$f" in *.real) continue;; esac
    if file -b "$f" | grep -q "ELF 32-bit"; then
      if readelf -l "$f" 2>/dev/null | grep -q INTERP; then
        $pe --set-interpreter "$LPATH" "$f"
      fi
      $pe --set-rpath "$I/usr/lib/i386-linux-gnu" "$f" 2>/dev/null || true
      patched=$((patched+1))
    fi
  done
  echo "patched: $patched ELF32"
  # kritik doğrulama: preloader'ın kullandığı loader ELF'inin interpi
  readelf -l "$W/lib/wine/i386-unix/wine" 2>/dev/null | grep -q "$LPATH" \
    || die "lib/wine/i386-unix/wine interp patch'i doğrulanamadı"
}

# --------------------------------------- 5. exec zinciri sarmalayıcıları
make_wrapper(){
  # $1 = hedef dosya (x), gerçek ELF'i x.real'e taşır, x'i script yapar
  local x="$1" real="${1}.real"
  [ -f "$real" ] && { echo "wrapper var: $x"; return 0; }
  mv "$x" "$real"
  cat > "$x" <<EOF
#!/bin/bash
export LD_LIBRARY_PATH="$I/usr/lib/i386-linux-gnu\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
exec "$I/usr/bin/qemu-i386-static" -0 "\$0" "$real" "\$@"
EOF
  chmod +x "$x"
}
install_wrappers(){
  log "5/9 exec-zinciri sarmalayıcıları (native i386 exec'i qemu'ya kilitler)"
  make_wrapper "$W/bin/wine"
  make_wrapper "$W/bin/wineserver"
  make_wrapper "$W/lib/wine/i386-unix/wine-preloader"
  chmod +x "$W/bin/wine" "$W/bin/wineserver" "$W/lib/wine/i386-unix/wine-preloader"
}

# ------------------------------------------------------------ 6. launcher
install_launcher(){
  log "6/9 launcher: \$HOME/.local/bin/wine32 (+ \$HOME/wine32)"
  mkdir -p "$HOME/.local/bin"
  cat > "$HOME/.local/bin/wine32" <<EOF
#!/bin/bash
# wine32 — 32-bit Wine launcher (qemu-user + wrapper zinciri)
export LD_LIBRARY_PATH="$I/usr/lib/i386-linux-gnu\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
[ -x "$LPATH" ] || { mkdir -p "$(dirname "$LPATH")"; cp -L "$(find "$I" -name 'ld-linux.so.2' -o -name 'ld-linux.so.2.*' | head -1)" "$LPATH"; }
export WINEPREFIX="\${WINEPREFIX:-$PREFIX}"
export WINEARCH="win32"
export WINEDEBUG="\${WINEDEBUG:--all}"
export WINESERVER="$W/bin/wineserver"
export WINELOADER="$W/bin/wine"
case "\$1" in
  wineboot|wineserver|winecfg|wineconsole|regedit|regsvr32|msiexec|notepad|msidb)
    T="\$1"; shift; exec "$W/bin/\$T" "\$@" ;;
  *) exec "$W/bin/wine" "\$@" ;;
esac
EOF
  chmod +x "$HOME/.local/bin/wine32"
  cp "$HOME/.local/bin/wine32" "$HOME/wine32"
  echo "launcher hazır: wine32 (PATH'e ~/.local/bin ekleyin)"
}

# --------------------------------------------------- 7. prefix başlatma
init_prefix(){
  log "7/9 WINEPREFIX başlatma (WINEARCH=win32)"
  if [ -f "$PREFIX/drive_c/windows/explorer.exe" ]; then
    echo "prefix zaten var: $PREFIX"; return 0
  fi
  rm -rf "$PREFIX"
  "$HOME/.local/bin/wine32" wineboot -u > /tmp/wine32-boot.log 2>&1 \
    || { tail -5 /tmp/wine32-boot.log; die "wineboot başarısız (log: /tmp/wine32-boot.log)"; }
  [ -d "$PREFIX/drive_c/windows" ] || die "prefix oluşmadı"
  echo "prefix hazır: $PREFIX"
}

# ------------------------------------------------------------ 8. mingw
install_mingw(){
  if [ -x "$M/usr/bin/i686-w64-mingw32-gcc-win32" ]; then echo "mingw zaten kurulu"; return 0; fi
  log "8/9 root'suz mingw-w64-i686 cross-compiler"
  apt_update_if_needed
  dl_extract "$M" gcc-mingw-w64-i686-win32 gcc-mingw-w64-i686-win32-runtime \
                 gcc-mingw-w64-base binutils-mingw-w64-i686 \
                 mingw-w64-i686-dev mingw-w64-common
  ln -sf i686-w64-mingw32-gcc-win32 "$M/usr/bin/i686-w64-mingw32-gcc"
  # sürücü çalıştırılabilirliği: eksik runtime lib varsa sisteme dokunmadan üstüne yaz
  local missing
  missing=$(ldd "$M/usr/bin/i686-w64-mingw32-gcc-win32" 2>/dev/null | grep "not found" || true)
  if [ -n "$missing" ]; then
    echo "gcc sürücüsü için eksik lib'ler — libc6/libgcc-s1(i386 değil, amd64) indiriliyor:"
    dl_extract "$M" libgmp10 libisl23 libmpc3 libmpfr6 libzstd1 zlib1g 2>/dev/null || true
  fi
}

# --------------------------------------------------------- 9. doğrulama
verify(){
  log "9/9 uçtan uca doğrulama"
  [ -x "$W/bin/wine.real" ] || die "Wine kiti yok — önce tam kurulum çalıştırın"
  mkdir -p "$TESTDIR"
  cat > "$TESTDIR/test.c" <<'EOF'
#include <stdio.h>
int main(void){ printf("Merhaba 32-bit!\n"); return 0; }
EOF
  if [ -x "$M/usr/bin/i686-w64-mingw32-gcc" ]; then
    local ldl=""
    ldd "$M/usr/bin/i686-w64-mingw32-gcc-win32" 2>/dev/null | grep -q "not found" \
      && ldl="$M/usr/lib/x86_64-linux-gnu"
    PATH="$M/usr/bin:$PATH" LD_LIBRARY_PATH="${ldl:+$ldl:}${LD_LIBRARY_PATH:-}" \
      i686-w64-mingw32-gcc "$TESTDIR/test.c" -o "$TESTDIR/test32.exe" \
      || die "mingw derlemesi başarısız"
    file -b "$TESTDIR/test32.exe" | grep -q "PE32" \
      || die "çıktı PE32 değil: $(file -b "$TESTDIR/test32.exe")"
    echo "derleme OK: $(file -b "$TESTDIR/test32.exe" | cut -c1-60)..."
  else
    echo "mingw yok (--skip-mingw?) — doğrulama hazırlanmış PE ile devam"
    [ -f "$TESTDIR/test32.exe" ] || die "test PE'si de yok"
  fi
  local out rc
  out=$("$HOME/.local/bin/wine32" "$TESTDIR/test32.exe" 2>/dev/null); rc=$?
  echo "wine çıktısı: [$out] | exit=$rc"
  [ "$rc" = "0" ] && printf '%s' "$out" | grep -q "Merhaba 32-bit!" \
    || die "32-bit exe beklenen çıktıyı vermedi"
  echo ""
  echo "############################ PASS ############################"
  echo "# 32-bit Wine çalışıyor. Kullanım:"
  echo "#   export PATH=\"\$HOME/.local/bin:\$PATH\""
  echo "#   wine32 program.exe        # 32-bit PE çalıştır"
  echo "#   wine32 cmd /c \"echo test\" # Windows komutu"
  echo "###############################################################"
}

# ---------------------------------------------------------------- main
case "$MODE" in
  verify)
    verify
    ;;
  skipmingw)
    install_runtime; install_wine; patch_wine; install_wrappers
    install_launcher; init_prefix; verify
    ;;
  *)
    install_runtime; install_wine; patch_wine; install_wrappers
    install_launcher; init_prefix; install_mingw; verify
    ;;
esac
