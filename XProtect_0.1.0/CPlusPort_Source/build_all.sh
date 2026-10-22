#!/bin/bash
# ============================================================
# build_all.sh — CPlusPort zincirini bastan sona derler
#  1) VM blob'lari (vm_core.c -> vm64.bin / vmx86.bin -> vm_blob.cpp)
#  2) Motor CLI (Linux, cikti uretimi icin)
#  3) Oyun: Test.exe (x64) + Test32.exe (x86)  [zig cc, -fwrapv]
#  4) CPlusPort.exe (Win32 GUI, x64)          [zig cc]
# ============================================================
set -e
cd /home/z/my-project/scripts
ZIG="python3 -m ziglang"

echo "== [1/4] VM blob x64 =="
gcc -O2 -ffreestanding -fno-stack-protector -fno-jump-tables \
    -fno-asynchronous-unwind-tables -fomit-frame-pointer -fno-ident \
    -DVM_IS_X64 -DVM_WINDOWS -c vm_core.c -o vm64.o
ld -Ttext=0x100000 -e vm_entry vm64.o -o vm64.elf
objcopy -O binary vm64.elf vm64.bin

echo "== [1/4] VM blob x86 =="
gcc -m32 -O2 -ffreestanding -fno-stack-protector -fno-jump-tables \
    -fno-asynchronous-unwind-tables -fomit-frame-pointer -fno-ident \
    -DVM_IS_X86 -DVM_WINDOWS -c vm_core.c -o vmx86.o
ld -m elf_i386 -Ttext=0x100000 -e vm_entry vmx86.o -o vmx86.elf
objcopy -O binary vmx86.elf vmx86.bin

echo "== [1/4] vm_blob.cpp uretimi =="
python3 gen_blob.py

echo "== [2/4] Motor CLI (Linux) =="
g++ -O2 -std=c++17 -Wall -Wno-unused-result -o cplport_cli \
    cplport_cli.cpp engine_main.cpp engine_pe.cpp engine_disasm.cpp \
    engine_lift.cpp engine_stub.cpp engine_util.cpp vm_blob.cpp

echo "== [3/4] Oyun x64 =="
$ZIG c++ -target x86_64-windows-gnu -O2 -fwrapv -DVM_WRAPPOS \
    Test.cpp -o Test64.exe -fno-sanitize=undefined
echo "== [3/4] Oyun x86 =="
$ZIG c++ -target x86-windows-gnu -O1 -fwrapv -DVM_X86LEAF -mno-sse2 -mno-sse \
    Test.cpp -o Test32.exe -fno-sanitize=undefined

echo "== [4/4] CPlusPort.exe (Win32 GUI) =="
$ZIG c++ -target x86_64-windows-gnu -O2 -DUNICODE -D_UNICODE \
    cplport_gui.cpp engine_main.cpp engine_pe.cpp engine_disasm.cpp \
    engine_lift.cpp engine_stub.cpp engine_util.cpp vm_blob.cpp \
    -o CPlusPort.exe -lcomdlg32 -lcomctl32 -luser32 -lgdi32 -lshell32 -fno-sanitize=undefined

echo "== TAMAM =="
ls -la Test64.exe Test32.exe CPlusPort.exe cplport_cli vm64.bin vmx86.bin
