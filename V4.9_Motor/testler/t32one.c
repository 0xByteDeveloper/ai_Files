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
int main(int argc, char** argv) { int a = argc > 1 ? atoi(argv[1]) : 0; return Target(a) & 0xFF; }
int atoi(const char* s){int v=0;while(*s>='0'&&*s<='9')v=v*10+(*s++-'0');return v;}
