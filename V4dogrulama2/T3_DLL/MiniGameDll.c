#include <stdint.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;
__attribute__((stdcall)) extern void* __stdcall VirtualAlloc(void* a, unsigned long long s, unsigned long t, unsigned long p);
__attribute__((stdcall)) extern int __stdcall VirtualFree(void* a, unsigned long long s, unsigned long f);
__attribute__((stdcall)) extern void __stdcall ExitProcess(u32 c);
static void* memset_(void* d,int c,unsigned n){u8* p=(u8*)d; while(n--) *p++=(u8)c; return d;}
static u32 g_x=10,g_y=10,g_score=0,g_lcg=0x12345678u;
static u32 g_wall[64];
static u32 g_inited=0;
static void InitWorld(void){
    u32 i; for(i=0;i<64;i++) g_wall[i]=0;
    g_wall[3]=1;g_wall[12]=1;g_wall[20]=1;g_wall[27]=1;
    g_wall[36]=1;g_wall[45]=1;g_wall[51]=1;g_wall[60]=1;
    g_inited=1;
}
__attribute__((dllexport)) u32 __stdcall MM_Move(u32 dir,u32* outX,u32* outY){
    u32 nx=g_x,ny=g_y,cell,r=1;
    if(!g_inited) InitWorld();
    if(dir==0){ if(ny==0) return 0; ny--; }
    else if(dir==1){ if(nx>=7) return 0; nx++; }
    else if(dir==2){ if(ny>=7) return 0; ny++; }
    else { if(nx==0) return 0; nx--; }
    cell=ny*8+nx;
    if(g_wall[cell&63]) return 0;
    if(cell==((g_lcg>>20)&63)){ g_score+=10; g_lcg=g_lcg*1103515245u+12345u; r=2; }
    g_x=nx; g_y=ny; *outX=nx; *outY=ny;
    return r;
}
__attribute__((dllexport)) u32 __stdcall MM_Lcg(void){
    g_lcg=g_lcg*1103515245u+12345u; return g_lcg>>8;
}
__attribute__((dllexport)) u32 __stdcall MM_Score(void){ return g_score; }
__attribute__((dllexport)) void __stdcall MM_Reset(void){
    g_x=2; g_y=2; g_score=0; g_lcg=0x12345678u; g_inited=0;
}
typedef struct { const char* name; void* fn; } GFnEntry;
__attribute__((used,section(".gfn"))) GFnEntry g_gfn[]={
    {"MM_Move",(void*)MM_Move},
    {"MM_Lcg",(void*)MM_Lcg},
    {0,0}
};
__attribute__((stdcall)) int __stdcall DllMain(void* h,u32 reason,void* r){ (void)h;(void)reason;(void)r; return 1; }
