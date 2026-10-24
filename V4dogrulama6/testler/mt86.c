/* mt86.c - V4.6 x86 stream ek kapsam: cdecl + stdcall ret12 + coklu ret + dongu */
#include <stdio.h>

static const char TAG[] = "mt86-rezerve";

__attribute__((noinline)) static int Helper3(int a, int b, int c) { return a * 7 + b * 3 + c; }

__attribute__((noinline))
static int __stdcall Move3(int dx, int dy, int dz) {   /* ret 12 (C2 0C 00) */
    int s = Helper3(dx, dy, dz);
    if (dx > 100) return -1;          /* erken ret (ayni opcode, ayni farewell) */
    if (s == 0)  return -2;
    for (int i = 0; i < 3; i++) s += i * dy;   /* dongu + geri dal */
    return s;
}

__attribute__((noinline))
static int CallerC(int n) {           /* cdecl, coklu cagri */
    int acc = 0;
    for (int i = 0; i < n; i++) acc += Move3(i, i & 3, 2) & 0xFF;
    return acc;
}

int main(void) {
    int a = CallerC(9);
    printf("%s acc=%d\n", TAG, a);
    return 0;
}
