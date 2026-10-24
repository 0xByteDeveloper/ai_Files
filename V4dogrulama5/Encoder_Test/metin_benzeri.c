#include <stdio.h>
/* metin2client benzeri yapi + MSVC tarzi int3 dolgu (PadCC) */
static const char ERRMSG[] = "Send Battle Attack Packet Error";

__attribute__((noinline)) static int Helper(int v) { return v * 3 + 1; }

__attribute__((naked, used)) static void PadCC1(void) { __asm__ volatile(".byte 0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC"); }

__attribute__((noinline))
int __stdcall SendBattle(int thisp, int type) {   /* C2 08 00 (ret 8) ile biter */
    int ok = Helper(thisp + type);
    if (!ok) {
        printf("%s\n", ERRMSG);   /* push offset ERRMSG -> govdede ABS + reloc */
        return 0;
    }
    if (type == 2) return Helper(thisp);
    return ok ^ type;
}

__attribute__((naked, used)) static void PadCC2(void) { __asm__ volatile(".byte 0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC"); }

__attribute__((noinline))
static void Caller(int n) {        /* FN-modu hint hedefi (fonksiyonun ortasi) */
    int acc = 0;
    for (int i = 0; i < n; i++) acc += SendBattle(i, i & 1);
    printf("caller=%d\n", acc);
}

int main(void) {
    Caller(5);
    printf("bitis\n");
    return 0;
}
