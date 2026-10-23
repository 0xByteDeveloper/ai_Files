/* t32loop.c — x86 stream LEAK/COKME test hedefi (V4.9 dogrulama)
 * Target(): korumaya alinacak fonksiyon (E8 cagri + dal + ret; 30-80B arasi)
 * main():  400 kez cagirir — eski motorda 8 cagrida sonra hint tukendigi icin
 *          400 cagri = kesin leak/kok teshis testi.
 * Cikti:   deterministik hash yazdirmaz; exit kodu = (hash % 251) + 5
 * Baseline ile korumali cikis kodu birebir ayni olmali.                    */
#include <windows.h>

static volatile int g_sink = 0;

__declspec(noinline) int Target(int a)
{
    int s = a * 2654435761u;
    s = s ^ (s >> 13);
    s = s * 1274126177u;
    s = s ^ (s >> 16);
    if (s & 1) s += 0x5A5A;
    else       s -= 0x1234;
    for (int i = 0; i < 3; i++) s = s * 31 + i;
    if (s > 1000) s &= 0xFFFF;
    g_sink = s;
    return s;
}

int main(void)
{
    int acc = 0;
    for (int i = 0; i < 400; i++)
        acc = acc + Target(i) - (acc >> 3);
    g_sink = acc;
    return (int)((unsigned)acc % 251u) + 5;
}
