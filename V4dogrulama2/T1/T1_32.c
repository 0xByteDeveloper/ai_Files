// T1_32.c - T1_Validate.cpp'nin C karsiligi (x86 dogrulama hedefi)
#include <stdint.h>
typedef uint8_t  u8;  typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int32_t  i32;
__attribute__((stdcall))
extern void* __stdcall GetStdHandle(u32 which);
__attribute__((stdcall))
extern int __stdcall WriteFile(void* h, const void* buf, u32 len, u32* written, void* ov);
__attribute__((stdcall))
extern void __stdcall ExitProcess(u32 code);
__attribute__((stdcall))
extern void* __stdcall VirtualAlloc(void* addr, u64 size, u32 type, u32 prot);
__attribute__((stdcall))
extern int __stdcall VirtualFree(void* addr, u64 size, u32 freeType);

static void* memset_(void* d, int c, unsigned n) { u8* p = (u8*)d; while (n--) *p++ = (u8)c; return d; }

static u32 slen(const char* s) { u32 n = 0; while (s[n]) n++; return n; }
static void putsRaw(const char* s) { u32 w; WriteFile(GetStdHandle((u32)-11), s, slen(s), &w, 0); }
static void putsHex32(const char* tag, u32 v) {
    char buf[64]; int n = 0;
    while (tag[n]) { buf[n] = tag[n]; n++; }
    buf[n++] = '=';
    for (int i = 7; i >= 0; i--) { u32 d = (v >> (i * 4)) & 0xF; buf[n++] = (char)(d < 10 ? '0' + d : 'A' + d - 10); }
    buf[n++] = '\n';
    u32 w; WriteFile(GetStdHandle((u32)-11), buf, (u32)n, &w, 0);
}

static u32 g_seed = 0x5EED1234;
static u32 g_hits = 0;
static u32 g_table[16] = {
    0x11111111, 0x22222222, 0x33333333, 0x44444444,
    0x55555555, 0x66666666, 0x77777777, 0x88888888,
    0x99999999, 0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC,
    0xDDDDDDDD, 0xEEEEEEEE, 0xFFFFFFFF, 0x0A0B0C0D
};

__attribute__((noinline)) u32 FnvHash1a(const u8* p, u32 n) {
    u32 h = 2166136261u;
    for (u32 i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}
__attribute__((noinline)) u32 LcgNext(void) {
    g_seed = g_seed * 1103515245u + 12345u;
    g_hits++;
    return g_seed >> 8;
}
__attribute__((noinline)) void XorCipher(u8* buf, u32 n, u32 key) {
    u32 k = key | 1u;
    for (u32 i = 0; i < n; i++) { k = k * 1664525u + 1013904223u; buf[i] ^= (u8)(k >> 16); }
}
__attribute__((noinline)) u32 ChecksumBlock(const u32* p, u32 words) {
    u32 c1 = 0, c2 = 0, acc = 0;
    for (u32 i = 0; i < words; i++) {
        u32 v = p[i];
        c1 += v + i;
        c2 ^= (v << (i & 15)) | (v >> (32 - (i & 15)) - ((i & 15) ? 0 : 32));
        if (c2 & 1) acc = acc * 3 + c1; else acc += c2;
        if (v == 0xFFFFFFFFu) g_hits += 2;
    }
    acc ^= g_table[words & 15];
    return c1 ^ c2 ^ acc;
}
__attribute__((noinline)) u32 MergeHash(const u8* p, u32 n) {
    u32 a = FnvHash1a(p, n);
    u32 b = LcgNext();
    u32 t[8];
    for (int i = 0; i < 8; i++) t[i] = a ^ (b * (u32)(i + 3)) ^ g_table[i];
    u32 c = ChecksumBlock(t, 8);
    return a * 31u + b + c;
}
__attribute__((noinline)) u32 ClampAdd(u32 a, u32 b, u32 maxv) {
    u32 s = a + b;
    if (s > maxv) s = maxv;
    if (s == 0) s = 1;
    return s ^ (g_hits & 0xF);
}

typedef struct { const char* name; void* fn; } GFnEntry;
__attribute__((used, section(".gfn")))
GFnEntry g_gfn[] = {
    {"FnvHash1a",    (void*)FnvHash1a},
    {"LcgNext",      (void*)LcgNext},
    {"XorCipher",    (void*)XorCipher},
    {"ChecksumBlock",(void*)ChecksumBlock},
    {"MergeHash",    (void*)MergeHash},
    {"ClampAdd",     (void*)ClampAdd},
    {0, 0}
};

static u8 workspace[64];
static void run_suite(void) {
    for (int i = 0; i < 64; i++) workspace[i] = (u8)(i * 7 + 3);
    u32 h1 = FnvHash1a(workspace, 64);
    u32 l1 = LcgNext();
    u32 l2 = LcgNext();
    XorCipher(workspace, 64, 0xDEADBEEF);
    u32 h2 = FnvHash1a(workspace, 64);
    XorCipher(workspace, 64, 0xDEADBEEF);
    u32 h3 = FnvHash1a(workspace, 64);
    u32 c1 = ChecksumBlock(g_table, 16);
    u32 m1 = MergeHash(workspace, 64);
    u32 k1 = ClampAdd(10, 20, 25);
    u32 k2 = ClampAdd(0xFFFFFFFFu, 5, 0x7FFFFFFF);
    putsHex32("H1", h1); putsHex32("L1", l1); putsHex32("L2", l2);
    putsHex32("H2", h2); putsHex32("H3", h3); putsHex32("C1", c1);
    putsHex32("M1", m1); putsHex32("K1", k1); putsHex32("K2", k2);
    putsHex32("HITS", g_hits); putsHex32("SEED", g_seed);
}
void NtMain(void) {
    putsRaw("T1-START\n");
    run_suite();
    putsRaw("T1-END\n");
    ExitProcess(0);
}
