#include <stdint.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
__attribute__((stdcall)) extern void* __stdcall GetStdHandle(u32 w);
__attribute__((stdcall)) extern int __stdcall WriteFile(void* h,const void* b,u32 l,u32* w,void* o);
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
int main(void){
    void* mod; FnMove mv; FnLcg lc; FnScore sc; FnReset rs;
    u32 x=0,y=0,r=0,hash=2166136261u,i,l;
    putsRaw("T3-START\n");
    mod=LoadLibraryA("MiniGameDll.dll");
    if(!mod){putsRaw("T3-ERR LoadLibrary\n");ExitProcess(2);}
    mv=(FnMove)GetProcAddress(mod,"MM_Move");
    lc=(FnLcg)GetProcAddress(mod,"MM_Lcg");
    sc=(FnScore)GetProcAddress(mod,"MM_Score");
    rs=(FnReset)GetProcAddress(mod,"MM_Reset");
    if(!mv||!lc||!sc||!rs){putsRaw("T3-ERR GetProcAddress\n");ExitProcess(2);}
    putsHex("MOD",(u32)(unsigned long long)mod);
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
    putsRaw("T3-END\n");
    ExitProcess(0);
}
