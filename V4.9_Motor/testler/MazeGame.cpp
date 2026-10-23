// ============================================================================
//  MazeGame.cpp - MazeProtector demo hedefi (labirent + pacman yem + puan)
//  - kernel32/user32 disinda bagimlilik yok (CRT'siz -nostdlib derlenir)
//  - "autotest" modu: AI kendi oynar, deterministik, cikis kodu 0
//  - .gfn section: fonksiyon adlari + adresleri (PDB rolunu ustlenir)
// ============================================================================

#include <stdint.h>
#include <stddef.h>

typedef uint8_t  u8;  typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
typedef int8_t   i8;  typedef int16_t  i16; typedef int32_t  i32; typedef int64_t  i64;
typedef char16_t wchar;

extern "C" {
// ---- kernel32 ----
void*   __stdcall GetStdHandle(u32 which);
int     __stdcall WriteFile(void* h, const void* buf, u32 len, u32* written, void* ov);
int     __stdcall SetConsoleCursorPosition(void* h, u32 coord);
int     __stdcall SetConsoleTextAttribute(void* h, u16 attr);
u32     __stdcall GetTickCount();
void    __stdcall ExitProcess(u32 code);
#if defined(__x86_64__) || defined(_WIN64)
void*   __stdcall VirtualAlloc(void* addr, u64 size, u32 type, u32 prot);
int     __stdcall VirtualFree(void* addr, u64 size, u32 freeType);
#else
void*   __stdcall VirtualAlloc(void* addr, u32 size, u32 type, u32 prot);
int     __stdcall VirtualFree(void* addr, u32 size, u32 freeType);
#endif
const char* __stdcall GetCommandLineA();
void    __stdcall Sleep(u32 ms);
// ---- user32 ----
i16     __stdcall GetAsyncKeyState(int key);
}

extern "C" void* memset(void* d, int c, size_t n) {
    u8* p = (u8*)d; while (n--) *p++ = (u8)c; return d;
}
extern "C" void* memcpy(void* d, const void* s, size_t n) {
    u8* a = (u8*)d; const u8* b = (const u8*)s; while (n--) *a++ = *b++; return d;
}

#define VK_LEFT  0x25
#define VK_UP    0x26
#define VK_RIGHT 0x27
#define VK_DOWN  0x28
#define MAZE_W   24
#define MAZE_H   14

struct Game {
    int  px, py;          // oyuncu
    int  fx, fy;          // yem
    int  score, target;
    int  dir;             // son yon (0-3, -1 yok)
    int  frame;
    int  won;
    int  hwid;            // HwidDogrulama sonucu
    char maze[MAZE_H][MAZE_W];
};

static Game      g_game;
static u32       g_rngState = 0x1234ABCD;
static int       g_decoyCounter;
static u64       g_timerBase;
static u64       g_timerAccum;

// ---- RNG (deterministik) ---------------------------------------------------
__attribute__((noinline)) static u32 RngNext() {
    g_rngState = g_rngState * 1664525u + 1013904223u;
    return (g_rngState >> 8);
}
__attribute__((noinline)) static u32 RngRange(u32 mod) { return mod ? RngNext() % mod : 0; }

// ---- "Hwid Dogrulama" (kullanicinin ornek fonksiyonu, kucuk hash) ----------
__attribute__((noinline)) static int HwidDogrulama(int seed) {
    int h = 0x4D617A65 ^ seed;
    for (int i = 0; i < 8; i++) {
        h = h * 31 + i;
        h = h ^ (h >> 5);
    }
    return h & 0x7FFFFFFF;
}

// ---- Labirent uretimi (DFS carve) ------------------------------------------
__attribute__((noinline)) static void FillMaze(Game* g) {
    for (int y = 0; y < MAZE_H; y++)
        for (int x = 0; x < MAZE_W; x++)
            g->maze[y][x] = '#';
}

__attribute__((noinline)) static int CanCarve(Game* g, int x, int y) {
    if (x < 1 || y < 1 || x >= MAZE_W - 1 || y >= MAZE_H - 1) return 0;
    if (g->maze[y][x] != '#') return 0;
    int walls = 0;
    if (g->maze[y - 1][x] == '#') walls++;
    if (g->maze[y + 1][x] == '#') walls++;
    if (g->maze[y][x - 1] == '#') walls++;
    if (g->maze[y][x + 1] == '#') walls++;
    return walls >= 3;
}

struct CarveSpot { int x, y; };
static CarveSpot g_carveStack[512];

__attribute__((noinline)) static void GenerateMaze(Game* g) {
    FillMaze(g);
    int sp = 0;
    g_carveStack[sp].x = 1; g_carveStack[sp].y = 1; sp++;
    g->maze[1][1] = '.';
    while (sp > 0) {
        sp--;
        int cx = g_carveStack[sp].x, cy = g_carveStack[sp].y;
        int d = RngRange(4);
        for (int t = 0; t < 4; t++) {
            int dir = (d + t) & 3;
            int nx = cx + (dir == 0 ? 2 : dir == 1 ? -2 : 0);
            int ny = cy + (dir == 2 ? 2 : dir == 3 ? -2 : 0);
            if (CanCarve(g, nx, ny)) {
                g->maze[(cy + ny) / 2][(cx + nx) / 2] = '.';
                g->maze[ny][nx] = '.';
                if (sp < 511) { g_carveStack[sp].x = nx; g_carveStack[sp].y = ny; sp++; }
            }
        }
    }
}

// ---- Yem --------------------------------------------------------------------
__attribute__((noinline)) static void SpawnFood(Game* g) {
    for (int tries = 0; tries < 400; tries++) {
        int x = 1 + (int)RngRange(MAZE_W - 2);
        int y = 1 + (int)RngRange(MAZE_H - 2);
        if (g->maze[y][x] == '.' && !(x == g->px && y == g->py)) { g->fx = x; g->fy = y; return; }
    }
    g->fx = 1; g->fy = 1;
}

// ---- Oyuncu hareket ---------------------------------------------------------
__attribute__((noinline)) static int IsWall(Game* g, int x, int y) {
    if (x < 0 || y < 0 || x >= MAZE_W || y >= MAZE_H) return 1;
    return g->maze[y][x] == '#' ? 1 : 0;
}

__attribute__((noinline)) static void MovePlayer(Game* g, int dx, int dy) {
    int nx = g->px + dx, ny = g->py + dy;
    if (!IsWall(g, nx, ny)) { g->px = nx; g->py = ny; }
}

__attribute__((noinline)) static void EatFood(Game* g) {
    if (g->px == g->fx && g->py == g->fy) {
        g->score++;
        if (g->score < g->target) SpawnFood(g);
    }
}

__attribute__((noinline)) static void UpdateScore(Game* g) {
    if (g->score >= g->target) g->won = 1;
}

// ---- Timer / decoy ----------------------------------------------------------
__attribute__((noinline)) static void UpdateTimer(Game* g) {
    u64 now = GetTickCount();
    if (g->frame == 0) g_timerBase = now;
    g_timerAccum = now - g_timerBase;   // sadece gosterim amacli
    (void)g_timerAccum;
}

__attribute__((noinline)) static void DecoyAlloc() {
    // kullanicinin "free bellek ac/kapa" decoy fikri: gercek alloc + free
    void* p = VirtualAlloc(0, 0x1000, 0x3000 /*MEM_COMMIT|RESERVE*/, 0x04 /*PAGE_READWRITE*/);
    g_decoyCounter++;
    if (p) VirtualFree(p, 0, 0x8000 /*MEM_RELEASE*/);
}

// ---- Cizim ------------------------------------------------------------------
__attribute__((noinline)) static int BuildFrame(Game* g, char* buf) {
    int p = 0;
    for (int y = 0; y < MAZE_H; y++) {
        for (int x = 0; x < MAZE_W; x++) {
            char c = g->maze[y][x];
            if (x == g->px && y == g->py) c = '@';
            else if (x == g->fx && y == g->fy) c = '*';
            buf[p++] = c; buf[p++] = ' ';
        }
        buf[p++] = '\n';
    }
    // HUD
    const char* h1 = "Puan: ";
    for (int i = 0; h1[i]; i++) buf[p++] = h1[i];
    int sc = g->score; char digits[12]; int nd = 0;
    if (!sc) digits[nd++] = '0';
    while (sc) { digits[nd++] = (char)('0' + sc % 10); sc /= 10; }
    while (nd) buf[p++] = digits[--nd];
    const char* h2 = "  /  Hedef: ";
    for (int i = 0; h2[i]; i++) buf[p++] = h2[i];
    int tg = g->target; nd = 0;
    while (tg) { digits[nd++] = (char)('0' + tg % 10); tg /= 10; }
    while (nd) buf[p++] = digits[--nd];
    buf[p++] = '\n';
    return p;
}

static void* g_hOut;

__attribute__((noinline)) static void DrawFrame(Game* g) {
    char buf[MAZE_H * (MAZE_W * 2 + 1) + 64];
    int n = BuildFrame(g, buf);
    SetConsoleCursorPosition(g_hOut, 0);      // (0,0)
    u32 wr = 0;
    WriteFile(g_hOut, buf, (u32)n, &wr, 0);
}

// ---- Girdi ------------------------------------------------------------------
__attribute__((noinline)) static int ReadKeyDir() {
    if (GetAsyncKeyState(VK_UP) & 0x8000)    return 0;
    if (GetAsyncKeyState(VK_DOWN) & 0x8000)  return 1;
    if (GetAsyncKeyState(VK_LEFT) & 0x8000)  return 2;
    if (GetAsyncKeyState(VK_RIGHT) & 0x8000) return 3;
    return -1;
}

__attribute__((noinline)) static void HandleInput(Game* g, int dir) {
    if (dir == 0)      MovePlayer(g, 0, -1);
    else if (dir == 1) MovePlayer(g, 0, 1);
    else if (dir == 2) MovePlayer(g, -1, 0);
    else if (dir == 3) MovePlayer(g, 1, 0);
}

// ---- Oyun dongusu -----------------------------------------------------------
__attribute__((noinline)) static void GameTick(Game* g, int dir) {
    HandleInput(g, dir);
    EatFood(g);
    UpdateScore(g);
    UpdateTimer(g);
    g->frame++;
}

// ---- Autotest AI ------------------------------------------------------------
__attribute__((noinline)) static int AiPickDir(Game* g) {
    int dx = g->fx - g->px, dy = g->fy - g->py;
    int d = -1;
    if (dy < 0 && dx >= 0) d = 0;       // yukari
    else if (dy > 0 && dx >= 0) d = 1;  // asagi
    else if (dx < 0) d = 2;             // sol
    else if (dx > 0) d = 3;             // sag
    // basit kacis: yon tikandigini hareketle dene
    return d;
}

// BFS ile yeme giden ilk adim (deterministik)
static int g_bfsDist[MAZE_H][MAZE_W];
static int g_bfsQX[MAZE_H * MAZE_W], g_bfsQY[MAZE_H * MAZE_W];

__attribute__((noinline)) static int BfsNextDir(Game* g) {
    static const int dirs[4][2] = {{0, -1}, {0, 1}, {-1, 0}, {1, 0}};
    for (int y = 0; y < MAZE_H; y++)
        for (int x = 0; x < MAZE_W; x++) g_bfsDist[y][x] = -1;
    int qh = 0, qt = 0, found = 0;
    g_bfsDist[g->py][g->px] = 0;
    g_bfsQX[qt] = g->px; g_bfsQY[qt] = g->py; qt++;
    while (qh < qt && !found) {
        int cx = g_bfsQX[qh], cy = g_bfsQY[qh]; qh++;
        for (int d = 0; d < 4; d++) {
            int nx = cx + dirs[d][0], ny = cy + dirs[d][1];
            if (nx < 0 || ny < 0 || nx >= MAZE_W || ny >= MAZE_H) continue;
            if (g_bfsDist[ny][nx] != -1 || g->maze[ny][nx] == '#') continue;
            g_bfsDist[ny][nx] = g_bfsDist[cy][cx] + 1;
            g_bfsQX[qt] = nx; g_bfsQY[qt] = ny; qt++;
            if (nx == g->fx && ny == g->fy) { found = 1; break; }
        }
    }
    if (!found) return -1;
    int cx = g->fx, cy = g->fy;
    while (g_bfsDist[cy][cx] > 1) {
        for (int d = 0; d < 4; d++) {
            int nx = cx + dirs[d][0], ny = cy + dirs[d][1];
            if (nx < 0 || ny < 0 || nx >= MAZE_W || ny >= MAZE_H) continue;
            if (g_bfsDist[ny][nx] == g_bfsDist[cy][cx] - 1) { cx = nx; cy = ny; break; }
        }
    }
    if (cy == g->py - 1) return 0;
    if (cy == g->py + 1) return 1;
    if (cx == g->px - 1) return 2;
    if (cx == g->px + 1) return 3;
    return -1;
}

__attribute__((noinline)) static int TryDir(Game* g, int d) {
    int x = g->px, y = g->py;
    if (d == 0) y--; else if (d == 1) y++; else if (d == 2) x--; else if (d == 3) x++;
    return IsWall(g, x, y) ? 0 : 1;
}

__attribute__((noinline)) static void AutotestRun(Game* g, int frames) {
    for (int f = 0; f < frames && !g->won; f++) {
        int d = BfsNextDir(g);
        if (d < 0) d = AiPickDir(g);
        GameTick(g, d);
        DecoyAlloc();
        if ((f % 500) == 0) { HwidDogrulama(f); }
    }
}

static void PutStr(const char* s) {
    u32 wr = 0;
    int n = 0; while (s[n]) n++;
    WriteFile(g_hOut, s, (u32)n, &wr, 0);
}

static void PutNum(int v) {
    char d[12]; int n = 0;
    if (!v) d[n++] = '0';
    while (v) { d[n++] = (char)('0' + v % 10); v /= 10; }
    char out[14]; int m = 0;
    while (n) out[m++] = d[--n];
    u32 wr = 0;
    WriteFile(g_hOut, out, (u32)m, &wr, 0);
}

// ---- GIRIS (CRT'siz) ---------------------------------------------------------
extern "C" void MyStart() {
    g_hOut = GetStdHandle((u32)-11);
    const char* cl = GetCommandLineA();
    const char* s = cl; int isAuto = 0;
    while (*s) {
        if (s[0] == 'a' && s[1] == 'u' && s[2] == 't' && s[3] == 'o') { isAuto = 1; break; }
        s++;
    }
    Game* g = &g_game;
    memset(g, 0, sizeof(Game));
    g->target = 30;
    GenerateMaze(g);
    g->px = 1; g->py = 1;
    SpawnFood(g);
    g->hwid = HwidDogrulama(g->frame);

    if (isAuto) {
        AutotestRun(g, 20000);
        PutStr("AUTOTEST OK score=");
        PutNum(g->score);
        PutStr(" frame=");
        PutNum(g->frame);
        PutStr(" hwid=");
        PutNum(g->hwid);
        PutStr(g->won ? " WON=1\n" : " WON=0\n");
        ExitProcess(g->won ? 0 : 3);
    }

    // interaktif mod
    SetConsoleTextAttribute(g_hOut, 0x0A);
    DrawFrame(g);
    while (!g->won) {
        int d = ReadKeyDir();
        if (d >= 0) GameTick(g, d);
        DrawFrame(g);
        Sleep(60);
        DecoyAlloc();
    }
    SetConsoleTextAttribute(g_hOut, 0x0E);
    PutStr("KAZANDIN! Puan: ");
    PutNum(g->score);
    PutStr("\n");
    ExitProcess(0);
}

// ---- PDB rolu: fonksiyon adlari + adresleri (.gfn section) ------------------
extern "C" {
struct GFnEntry { const char* name; void* fn; };
__attribute__((used, section(".gfn")))
struct GFnEntry g_gfn[] = {
    {"RngNext",        (void*)RngNext},
    {"RngRange",       (void*)RngRange},
    {"HwidDogrulama",  (void*)HwidDogrulama},
    {"FillMaze",       (void*)FillMaze},
    {"CanCarve",       (void*)CanCarve},
    {"GenerateMaze",   (void*)GenerateMaze},
    {"SpawnFood",      (void*)SpawnFood},
    {"IsWall",         (void*)IsWall},
    {"MovePlayer",     (void*)MovePlayer},
    {"EatFood",        (void*)EatFood},
    {"UpdateScore",    (void*)UpdateScore},
    {"UpdateTimer",    (void*)UpdateTimer},
    {"DecoyAlloc",     (void*)DecoyAlloc},
    {"BuildFrame",     (void*)BuildFrame},
    {"DrawFrame",      (void*)DrawFrame},
    {"ReadKeyDir",     (void*)ReadKeyDir},
    {"HandleInput",    (void*)HandleInput},
    {"GameTick",       (void*)GameTick},
    {"AiPickDir",      (void*)AiPickDir},
    {"BfsNextDir",     (void*)BfsNextDir},
    {"TryDir",         (void*)TryDir},
    {"AutotestRun",    (void*)AutotestRun},
};
}
