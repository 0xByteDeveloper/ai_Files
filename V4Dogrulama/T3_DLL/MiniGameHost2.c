// ============================================================================
//  MiniGameHost2.c - T3 DLL testi v3 (uc-DLL karsilastirmali surum)
//  ----------------------------------------------------------------------------
//  NE YAPAR:
//   [1/4] MiniGameDll.dll               (ORIJINAL)  -> 40 hamle testi, FNV hash
//   [2/4] MiniGameDll_korumali_ip1.dll  (IP1)       -> ayni test
//   [3/4] MiniGameDll_korumali_ip2.dll  (IP2)       -> ayni test
//   [4/4] KARSILASTIRMA: h1==h2==h3 -> ESLESME=TAM
//  NOT: Eski paketteki MiniGameDll_korumali.dll (129KB) TUR-2 BETA donemine
//  aitdi ve bozuktu (0xC000007B Bad Image). O dosya kaldirildi; yerine IP1
//  kopyasi kondu. Bu host artik yalnizca ip1/ip2 dosyalarini yukler.
//  ----------------------------------------------------------------------------
//  CIKTI ALANLARI:
//   DLLn   : YUKLENDI base=0x.........  (LoadLibraryA basarili)
//   EXPORT : 4 = MM_Move/MM_Lcg/MM_Score/MM_Reset hepsi bulundu
//   MOVEHn : 40 hamle + 2 LCG cagrisinin FNV-1a hash'i (SONUC PARMAK IZI)
//   SCORE/X/Y/LCGn : oyun durumu (belirleyici akisin son hali)
//   ESLESME: TAM -> korumali DLL'ler orijinal ile BIREBIR ayni davrandi
// ============================================================================
#include <stdint.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
__attribute__((stdcall)) extern void* __stdcall GetStdHandle(u32 w);
__attribute__((stdcall)) extern int __stdcall WriteFile(void* h,const void* b,u32 l,u32* w,void* o);
__attribute__((stdcall)) extern int __stdcall ReadFile(void* h,void* b,u32 l,u32* r,void* o);
__attribute__((stdcall)) extern void __stdcall ExitProcess(u32 c);
__attribute__((stdcall)) extern void* __stdcall LoadLibraryA(const char* n);
__attribute__((stdcall)) extern void* __stdcall GetProcAddress(void* m,const char* n);
__attribute__((stdcall)) extern u32 __stdcall GetLastError(void);

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
    if(!mod){
        putsRaw(tag); putsRaw(": YUKLEME HATASI! GetLastError=");
        putsHex("",GetLastError());
        putsRaw("  (0x7B=193/BadImage 0x7E=126/bulunamadi 0xC1=193/zaten var)\n");
        return 0;
    }
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
    u32 h1,h2,h3;
    putsRaw("=== T3-DLL TESTI v3 (MazeProtector IP, uc DLL) ===\n");
    putsRaw("[1/4] ORIJINAL DLL testi\n");
    h1=TestDll("MiniGameDll.dll","DLL1");
    putsRaw("[2/4] KORUMALI DLL testi (IP1: yerinde sifreli, sabit anahtar)\n");
    h2=TestDll("MiniGameDll_korumali_ip1.dll","DLL2");
    putsRaw("[3/4] KORUMALI DLL testi (IP2: her cagrida yeni rastgele anahtar)\n");
    h3=TestDll("MiniGameDll_korumali_ip2.dll","DLL3");
    putsRaw("[4/4] KARSILASTIRMA\n");
    if(h1 && h2 && h3 && h1==h2 && h2==h3){
        putsRaw("SONUC: ESLESME=TAM (IP1 ve IP2 DLL'leri orijinal ile birebir ayni davrandi)\n");
        putsRaw("MANA: DLL yuklendi, 4 export bulundu, 2x42 cagri, sifreli\n");
        putsRaw("      fonksiyonlar yerinde cozulup calisti, cokme YOK.\n");
    } else {
        putsRaw("SONUC: ESLESME=YOK (hata - yukaridaki satirlara bak)\n");
        if(!h2) putsRaw("NOT: DLL2 yuklenemedi (IP1 DLL dosyasi bozuk/kayip?)\n");
        if(!h3) putsRaw("NOT: DLL3 yuklenemedi (IP2 DLL dosyasi bozuk/kayip?)\n");
    }
    putsRaw("\n[KAPATMAK ICIN ENTER]\n");
    { u8 b[16]; u32 r; ReadFile(GetStdHandle((u32)-10),b,sizeof(b),&r,0); }
    ExitProcess(0);
}
