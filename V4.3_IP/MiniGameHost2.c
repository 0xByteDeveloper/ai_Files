// ============================================================================
//  MiniGameHost2.c - T3 DLL testi v2 (aciklayici surum)
//  Ne yapar:
//   1) MiniGameDll.dll          (ORIJINAL) LoadLibraryA ile yukler -> 40 hamle
//      testi kosar, FNV hash'i alir
//   2) MiniGameDll_korumali.dll (MAZEPROTECTOR IP ile sifreli) ayni testi
//      kosar, hash'i alir
//   3) Iki hash'i KARSILASTIRIR -> "ESLESME=TAM" yazdirir
//   4) Cikmadan once Enter bekler (cift tikla acilan pencere kapanmaz)
//  Ciktilardaki degerler:
//   MODn       = DLL'in yuklendigi temel adres (HMODULE) - DLL GERCEKTE yuklendi
//   EXP=n/4    = GetProcAddress ile bulunan export sayisi
//   MOVEHn     = 40 hamle + 2 LCG cagrisinin FNV-1a hash'i (sonuca gomulu)
//   SCORE/X/Y  = oyun durumunun son hali (belirleyici akis)
//   LCGn       = son LCG degeri
//   ESLESME    = TAM (hash'ler ayni -> korumali DLL birebir ayni davrandi)
// ============================================================================
#include <stdint.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
__attribute__((stdcall)) extern void* __stdcall GetStdHandle(u32 w);
__attribute__((stdcall)) extern int __stdcall WriteFile(void* h,const void* b,u32 l,u32* w,void* o);
__attribute__((stdcall)) extern int __stdcall ReadFile(void* h,void* b,u32 l,u32* r,void* o);
__attribute__((stdcall)) extern void __stdcall ExitProcess(u32 c);
__attribute__((stdcall)) extern void* __stdcall LoadLibraryA(const char* n);
__attribute__((stdcall)) extern void* __stdcall GetProcAddress(void* m,const char* n);

static u32 slen(const char* s){u32 n=0; while(s[n])n++; return n;}
static void putsRaw(const char* s){u32 w; WriteFile(GetStdHandle((u32)-11),s,slen(s),&w,0);}
static void putsHex(const char* tag,u32 v){
    char buf[64]; int n=0,i; u32 w;
    while(tag[n]){buf[n]=tag[n];n++;}
    buf[n++]='=';
    for(i=7;i>=0;i--){u32 d=(v>>(i*4))&0xF; buf[n++]=(char)(d<10?'0'+d:'A'+d-10);}
    buf[n++]='\n';
    WriteFile(GetStdHandle((u32)-11),buf,(u32)n,&w,0);
}
typedef u32 (__stdcall *FnMove)(u32,u32*,u32*);
typedef u32 (__stdcall *FnLcg)(void);
typedef u32 (__stdcall *FnScore)(void);
typedef void (__stdcall *FnReset)(void);

// Bir DLL'i yukle + 40 hamle testi kosar; hash doner (0 = yukleme hatasi)
static u32 TestDll(const char* path, const char* tag){
    void* mod = LoadLibraryA(path);
    if(!mod){ putsRaw(tag); putsRaw(": YUKLEME HATASI!\n"); return 0; }
    FnMove mv; FnLcg lc; FnScore sc; FnReset rs;
    mv=(FnMove)GetProcAddress(mod,"MM_Move");
    lc=(FnLcg)GetProcAddress(mod,"MM_Lcg");
    sc=(FnScore)GetProcAddress(mod,"MM_Score");
    rs=(FnReset)GetProcAddress(mod,"MM_Reset");
    int ok = (mv&&lc&&sc&&rs);
    putsRaw(tag); putsRaw(": YUKLENDI base=");
    putsHex("",(u32)(uintptr_t)mod);
    putsHex("EXPORT", ok ? 4 : 0);
    if(!ok){ putsRaw(tag); putsRaw(": EXPORT BULUNAMADI!\n"); return 0; }
    u32 x=0,y=0,r=0,hash=2166136261u,i,l;
    rs();
    for(i=0;i<40;i++){
        r=mv(i&3,&x,&y);
        hash^=r;hash*=16777619u;
        hash^=x;hash*=16777619u;
        hash^=y;hash*=16777619u;
        if(i==7||i==23){l=lc();hash^=l;hash*=16777619u;}
    }
    putsHex("MOVEH",hash);
    putsHex("SCORE",sc());
    putsHex("X",x); putsHex("Y",y);
    putsHex("LCG",lc());
    return hash;
}

int main(void){
    u32 h1,h2;
    putsRaw("=== T3-DLL TESTI v2 (MazeProtector IP) ===\n");
    putsRaw("[1/3] ORIJINAL DLL testi\n");
    h1=TestDll("MiniGameDll.dll","DLL1");
    putsRaw("[2/3] KORUMALI DLL testi (govde .text'te sifreli)\n");
    h2=TestDll("MiniGameDll_korumali.dll","DLL2");
    putsRaw("[3/3] KARSILASTIRMA\n");
    if(h1 && h2 && h1==h2){
        putsRaw("SONUC: ESLESME=TAM (korumali DLL orijinal ile birebir ayni davrandi)\n");
        putsRaw("MANA: DLL yuklendi, 4 export bulundu, 42 cagri, sifreli\n");
        putsRaw("      fonksiyonlar yerinde cozulup calisti, cokme YOK.\n");
    } else {
        putsRaw("SONUC: ESLESME=YOK (hata - yukaridaki satirlara bak)\n");
    }
    putsRaw("\n[KAPATMAK ICIN ENTER]\n");
    { u8 b[16]; u32 r; ReadFile(GetStdHandle((u32)-10),b,sizeof(b),&r,0); }
    ExitProcess(0);
}
