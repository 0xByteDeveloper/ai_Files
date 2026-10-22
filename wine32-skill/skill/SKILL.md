---
name: wine-32bit-runner
description: Run 32-bit Windows .exe (PE32) programs under Wine on Linux WITHOUT root/sudo — even when Wine is missing entirely, only 64-bit Wine works, or every 32-bit app crashes instantly (SIGSEGV/SIGSYS/Bad system call) in sandboxed Debian/Ubuntu containers with seccomp. Use this skill whenever the user wants to run, test, or verify a 32-bit Windows exe/program/game/installer with Wine, says "wine 32 bit çalışmıyor", "wine32 yok", "PE32 çalıştır", asks for wine32/i386 support, needs to compile a 32-bit test exe with mingw, or reports that a 32-bit exe segfaults under Wine while 64-bit exes work. Provides a fully rootless, self-contained kit (user-space apt, Kron4ek Wine x86 build, qemu-user i386 emulation, patchelf interpreter binding, exec-chain wrappers, WINEARCH=win32 prefix, mingw-w64-i686 cross-compiler for verification) that also works when root IS available but native wine32 still dies from seccomp.
---

# wine-32bit-runner — root'suz 32-bit Wine (qemu-user emülasyonlu)

## Problem space (read this first, it decides everything)

On locked-down Linux sandboxes (Debian/Ubuntu containers, cgroup VMs), running a
32-bit Windows exe with Wine fails in ways that look fatal but each has a known
cause and a known fix. Diagnose BEFORE acting — the three failure modes need
completely different remedies:

| Symptom | Root cause | Remedy |
|---|---|---|
| `wine32` / i386 packages uninstallable; no sudo | no root | this skill (fully rootless) |
| 32-bit process dies **SIGSEGV at startup**, strace shows `mmap(NULL, ~34359742464, ...) = -1 ENOMEM` | new-WoW64 Wine reserves the whole 32-bit address space as one huge anonymous mmap; kernel heuristic overcommit refuses mappings > RAM+swap | use the **x86 (pure 32-bit) Wine build** — its preloader reserves the address space in small `MAP_NORESERVE` chunks (do NOT use amd64-wow64 builds) |
| 32-bit process dies **SIGSYS / "Bad system call"** on its first syscall (strace: kill right after `execve`+`brk`) | sandbox seccomp filter kills every syscall made with `AUDIT_ARCH_I386` ABI — native i386 code can never run, **even with root** | run Wine under **qemu-i386** (qemu makes AMD64-ABI syscalls) and keep the whole exec chain inside qemu via script wrappers (see step 5) |

Key facts to internalize:
- Adding i386 architecture + installing wine32 (the classic fix) is useless here:
  even when installable, native i386 processes get killed by seccomp at `brk()`.
- `qemu-user` is not optional — it is THE execution vehicle for i386 code.
- The final chain: `bash launcher → wrapper script → qemu-i386-static (AMD64) →
  32-bit Wine → PE32 exe`. Nothing ever executes as native i386.

## Setup (one command, ~5–10 min, fully idempotent)

Bundled script — run it from the skill's directory:

```bash
bash <skill-dir>/scripts/setup-wine32.sh
```

What it does, in order (all rootless, all under $HOME):

1. Environment check: x86_64, curl, apt-get/dpkg present (Debian trixie or compatible).
2. User-space apt tree in `$HOME/aptroot` (`Dir::Etc`, `Dir::State`, `Dir::Cache`,
   `Dir::State::Status` overrides) so `apt-get download pkg:i386` works without root.
3. Downloads and extracts into `$HOME/i386root`: `libc6:i386` (provides
   `ld-linux.so.2`, libc, libpthread stub), `libgcc-s1:i386`, `patchelf` (amd64),
   `qemu-user` + `qemu-user-static`.
4. Copies the i386 dynamic loader to a **very short path** (`/home/<u>/l/ld.so` if
   ≤18 chars, else `/tmp/l/ld.so`) — see reference for the PT_INTERP length story.
5. Downloads **Kron4ek Wine-Builds `wine-<ver>-x86.tar.xz`** (pure 32-bit build;
   default ver 11.20) to `$HOME/wine-wow64/`. NOT amd64, NOT amd64-wow64.
6. `patchelf` every ELF32 in `bin/` and `lib/wine/i386-unix/`:
   `--set-interpreter <short ld.so path>` (only when PT_INTERP present) and
   `--set-rpath <i386root>/usr/lib/i386-linux-gnu`.
7. **Exec-chain wrappers** (the trick that makes process creation work):
   `bin/wine`, `bin/wineserver`, `lib/wine/i386-unix/wine-preloader` are renamed to
   `*.real` and replaced by tiny bash scripts that `exec qemu-i386-static -0 "$0"
   <real> "$@"`. Every guest `execve()` of an i386 ELF then lands on a shebang
   script → kernel runs native bash (AMD64, seccomp-safe) → qemu re-enters.
8. Writes launcher `$HOME/.local/bin/wine32` (+ `$HOME/wine32`) with baked paths,
   `WINEPREFIX=$HOME/.wine32`, `WINEARCH=win32`, `WINESERVER`/`WINELOADER` env.
9. Initializes the prefix: `wine32 wineboot -u` (takes ~12 s under emulation).
10. Installs a **rootless mingw cross-compiler** (`gcc-mingw-w64-i686-win32` etc.)
    to `$HOME/mingw` and symlinks `i686-w64-mingw32-gcc`.
11. Verifies end-to-end: compiles a hello-world to PE32, `file` confirms
    "PE32 executable ... Intel i386", runs it, expects `Merhaba 32-bit!` + exit 0.

Flags: `--verify-only` (skip installs, just re-run stage 11 checks),
`--skip-mingw` (no compiler — for running prebuilt exes only).

## Running 32-bit exes

```bash
export PATH="$HOME/.local/bin:$PATH"   # if not already
wine32 program.exe                     # any PE32
wine32 cmd /c "echo test"              # Windows shell
wine32 wineboot -u                     # (re)init prefix
WINEPREFIX=$HOME/.wine-custom wine32 installer.exe   # per-app prefix
```

- The kit is a **separate, parallel Wine** — it never touches a system `wine64`;
  keep using the system wine for 64-bit exes, `wine32` for 32-bit ones.
- Console apps work out of the box. GUI apps additionally need an X server
  (`DISPLAY`) and ideally `libfreetype6:i386` extracted the same way as libc
  (otherwise you get a harmless FreeType warning and ugly font fallback).

## Verification pattern (use this to prove any exe runs)

```bash
cat > /tmp/t.c <<'EOF'
#include <stdio.h>
int main(void){ printf("OK-32\n"); return 0; }
EOF
PATH="$HOME/mingw/usr/bin:$PATH" i686-w64-mingw32-gcc /tmp/t.c -o /tmp/t32.exe
file /tmp/t32.exe          # must say: PE32 executable ... Intel i386
wine32 /tmp/t32.exe        # must print OK-32, exit 0
```

If `file` says PE32 and `wine32` prints the expected output with exit 0, the
pipeline is proven. Apply the same two checks to the user's actual exe.

## Troubleshooting (exact messages → exact fixes)

| Message / behavior | Fix |
|---|---|
| `wine: could not load ntdll.so: libpthread.so.0: cannot open shared object file` | guest `LD_LIBRARY_PATH` missing → launcher must export `$HOME/i386root/usr/lib/i386-linux-gnu` |
| `/lib/ld-linux.so.2: could not open` (from wine-preloader) | PT_INTERP of `lib/wine/i386-unix/wine` not patched → re-run patchelf loop over BOTH `bin/` and `lib/wine/i386-unix/` |
| `Bad system call` / exit 159 (128+31) during `wineboot` | some i386 ELF was exec'd natively → re-create the step-7 wrappers; strace `-e trace=execve` will show the uncaptured path |
| `ERROR: ld.so: object '...execwrap.so' ... wrong ELF class` + SIGSYS | you tried LD_PRELOAD on qemu — pointless (qemu is statically linked, ignores LD_PRELOAD) and the native i386 exec happened anyway → use script wrappers |
| `mmap ... = -1 ENOMEM` then SIGSEGV with wow64 build | overcommit limit; switch to the x86 build |
| `wineserver: chdir to .../.wine32: No such file or directory` | prefix was deleted mid-flight; `rm -rf` the prefix and `wine32 wineboot -u` again |
| mingw `i686-w64-mingw32-gcc: command not found` | dpkg -x does not run postinst; create the symlink manually: `ln -sf i686-w64-mingw32-gcc-win32 $HOME/mingw/usr/bin/i686-w64-mingw32-gcc` |
| GitHub API rate limit | never resolve releases via api.github.com; use direct `releases/download/<tag>/` URLs |

## Deep dive

Read `references/method.md` for the full narrative: every dead end, the exact
strace evidence for each failure mode, version numbers of every artifact used in
the proven setup, and the reasoning behind each wrapper. Read it when something
behaves differently from the tables above, or when adapting the method to a new
distro/sandbox.
