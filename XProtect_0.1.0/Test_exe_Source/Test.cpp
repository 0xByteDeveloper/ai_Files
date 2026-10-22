// ============================================================
// Test.cpp — "MiniPac" : turn-based konsol pacman benzeri oyun
// Amac: CPlusPort sanallastirmasi icin temiz, izole fonksiyonlar
// Iceren test programi (x64 + x86).
//
// KRITIK: Giris fgets() ile SATIR bazli okunur. Yalniz Enter'a
// basmak -> uyari + tekrar prompt. EOF -> temiz cikis. Bu, eski
// surumdeki "WASD + Enter -> cokme" hatasini giderir.
//
// Sanallastirma hedefleri (extern "C", noinline, saf mantik,
// CRT cagrisi yok, bolme/modulo yok):
//   WrapPos, MovePlayer, GhostStep, CheckCollision, GameTick
// ============================================================
#include <cstdio>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#define COLS 15
#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __attribute__((visibility("default")))
#endif
#define GEXPORT EXPORT

#define ROWS 11

// ---- global oyun durumu (sanallastirilan fonksiyonlar bunlara erisir) ----
GEXPORT int  g_score = 0;
GEXPORT int  g_lives = 3;
GEXPORT int  g_dots  = 0;
GEXPORT int  g_seed  = 20261;   // deterministik hayalet AI (LCG)
GEXPORT int  g_px = 1, g_py = 1;

struct Ghost { int x; int y; int dir; };
GEXPORT Ghost g_ghosts[3];

GEXPORT char g_maze[ROWS][COLS + 1] = {   // +1: string init null'i icin
    "###############",
    "#@....#.......#",
    "#.##..#..###..#",
    "#.#...........#",
    "#.#.##.####.##.",
    "#......#......#",
    "#.####.#.####.#",
    "#.......#.....#",
    "#..###.....##.#",
    "#....#....#...#",
    "###############"
};

// ------------------------------------------------------------
// Sanallastirma HEDEF 1: koordinati [0,max) araligina sarar.
// Bilincli olarak % kullanilmadi (bolme VM destegi gerekmesin).
// ------------------------------------------------------------
extern "C" __attribute__((noinline)) EXPORT
int WrapPos(int v, int max) {
    while (v < 0)    { v = v + max; }
    while (v >= max) { v = v - max; }
    return v;
}

// ------------------------------------------------------------
// Sanallastirma HEDEF 2: oyuncuyu hareket ettirir, yem yer.
// dir: 1=sol(a) 2=sag(d) 3=yukari(w) 4=asagi(s)
// ------------------------------------------------------------
extern "C" __attribute__((noinline)) EXPORT
int MovePlayer(int dir) {
    int dx = 0, dy = 0;
    if (dir == 1)      { dx = -1; }
    else if (dir == 2) { dx = 1; }
    else if (dir == 3) { dy = -1; }
    else if (dir == 4) { dy = 1; }

    int nx = g_px + dx;
    int ny = g_py + dy;
#ifdef VM_X86LEAF
    if (nx < 0) nx = nx + COLS; else if (nx >= COLS) nx = nx - COLS;
    if (ny < 0) ny = ny + ROWS; else if (ny >= ROWS) ny = ny - ROWS;
#else
    nx = WrapPos(nx, COLS);
    ny = WrapPos(ny, ROWS);
#endif

    if (g_maze[ny][nx] != '#') {
        g_px = nx;
        g_py = ny;
        if (g_maze[ny][nx] == '.') {
            g_maze[ny][nx] = ' ';
            g_score = g_score + 10;
            g_dots  = g_dots - 1;
        }
    }
    return 0;
}

// ------------------------------------------------------------
// Sanallastirma HEDEF 3: i. hayaleti bir adim oynatir.
// %80 takip, %20 LCG rastgele yon. Duvara carpassa kalir.
// ------------------------------------------------------------
extern "C" __attribute__((noinline)) EXPORT
int GhostStep(int i) {
    Ghost* g = &g_ghosts[i];
    int dx = 0, dy = 0;

    // LCG: UNSIGNED aritmetik — int tasmasi TANIMLI (wrap).
    // Not: zig ile derlenirken signed int tasmasi Windows'ta panic
    // uretiyordu (oyun w+a+s+d+Enter'da cokiya). Unsigned + -fwrapv
    // ile hem zig hem gcc'de ayni deterministik sonuc uretilir.
    g_seed = (int)((unsigned)g_seed * 1103515245u + 12345u);
    int rnd = (int)(((unsigned)g_seed >> 16) & 7);

    if (rnd == 0) {
        rnd = (int)(((unsigned)g_seed >> 20) & 3);
        if (rnd == 0)      { dx = -1; }
        else if (rnd == 1) { dx = 1; }
        else if (rnd == 2) { dy = -1; }
        else               { dy = 1; }
    } else {
        if (g->x < g_px)      { dx = 1; }
        else if (g->x > g_px) { dx = -1; }
        else if (g->y < g_py) { dy = 1; }
        else if (g->y > g_py) { dy = -1; }
    }

    int nx = g->x + dx;
    int ny = g->y + dy;
#ifdef VM_X86LEAF
    if (nx < 0) nx = nx + COLS; else if (nx >= COLS) nx = nx - COLS;
    if (ny < 0) ny = ny + ROWS; else if (ny >= ROWS) ny = ny - ROWS;
#else
    nx = WrapPos(nx, COLS);
    ny = WrapPos(ny, ROWS);
#endif

    if (g_maze[ny][nx] != '#') {
        g->x = nx;
        g->y = ny;
    }
    return 0;
}

// ------------------------------------------------------------
// Sanallastirma HEDEF 4: oyuncu-hayalet carpismasi var mi?
// ------------------------------------------------------------
extern "C" __attribute__((noinline)) EXPORT
int CheckCollision(void) {
    int i;
    for (i = 0; i < 3; i = i + 1) {
        if (g_ghosts[i].x == g_px && g_ghosts[i].y == g_py) {
            return 1;
        }
    }
    return 0;
}

// ------------------------------------------------------------
// Sanallastirma HEDEF 5: bir tur icerigi (ust fonksiyon).
// ------------------------------------------------------------
extern "C" __attribute__((noinline)) EXPORT
int GameTick(int dir) {
    MovePlayer(dir);
    GhostStep(0);
    GhostStep(1);
    GhostStep(2);
    return CheckCollision();
}

// ---- oyun cizimi (sanallastirilmaz) ----
static void Draw(void) {
    int y, x;
    for (y = 0; y < ROWS; y = y + 1) {
        for (x = 0; x < COLS; x = x + 1) {
            if (x == g_px && y == g_py) { putchar('@'); }
            else                        { putchar(g_maze[y][x]); }
        }
        putchar('\n');
    }
    printf("Skor: %d   Can: %d   Kalan yem: %d\n", g_score, g_lives, g_dots);
}

static void ResetPositions(void) {
    g_px = 1; g_py = 1;
    g_ghosts[0].x = 13; g_ghosts[0].y = 1; g_ghosts[0].dir = 2;
    g_ghosts[1].x = 1;  g_ghosts[1].y = 9; g_ghosts[1].dir = 1;
    g_ghosts[2].x = 13; g_ghosts[2].y = 9; g_ghosts[2].dir = 3;
}

int main(void) {
    char line[256];
    int  i, j;

    // yemleri say
    g_dots = 0;
    for (i = 0; i < ROWS; i++)
        for (j = 0; j < COLS; j++)
            if (g_maze[i][j] == '.') g_dots = g_dots + 1;

    ResetPositions();

    printf("=== MiniPac (CPlusPort test oyunu) ===\n");
    printf("Komutlar: w=yukari a=sol d=sag s=asagi  q=cikis\n");
    printf("Komutu yazip Enter'a basin. (Yalniz Enter = zararsiz)\n\n");

    while (1) {
        Draw();
        printf("Komut > ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            printf("\nGiris bitti (EOF), oyun kapatiliyor.\n");
            break;                                   // EOF -> temiz cikis
        }

        // satirdaki ilk gecerli komut karakterini bul
        char cmd = 0;
        for (char* p = line; *p; ++p) {
            char c = *p;
            if (c == 'w' || c == 'W' || c == 'a' || c == 'A' ||
                c == 's' || c == 'S' || c == 'd' || c == 'D' ||
                c == 'q' || c == 'Q') { cmd = c; break; }
        }

        if (cmd == 0) {
            printf("(!) Gecersiz/bos giris (Enter?) — tekrar deneyin.\n\n");
            continue;                                // Enter'a basmak CRASH ETMEZ
        }
        if (cmd == 'q' || cmd == 'Q') { printf("Cikis istendi. Gorusuruz!\n"); break; }

        int dir = 0;
        if (cmd == 'a' || cmd == 'A') dir = 1;
        if (cmd == 'd' || cmd == 'D') dir = 2;
        if (cmd == 'w' || cmd == 'W') dir = 3;
        if (cmd == 's' || cmd == 'S') dir = 4;

        int hit = GameTick(dir);
        printf("\n");

        if (hit) {
            g_lives = g_lives - 1;
            printf("!!! Yakalandiniz! Kalan can: %d\n", g_lives);
            if (g_lives <= 0) {
                printf("*** OYUN BITTI. Skor: %d ***\n", g_score);
                break;
            }
            ResetPositions();
        } else if (g_dots <= 0) {
            printf("*** KAZANDINIZ! Tum yemler yendi. Skor: %d ***\n", g_score);
            break;
        }
    }
    return 0;
}
