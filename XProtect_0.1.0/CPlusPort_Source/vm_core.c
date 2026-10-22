// ============================================================
// vm_core.c — MiniVM: bayt-kod yorumlayici (korumali PE'ye gomulur)
// DERLEME (pozisyon-bagimsiz duz ikili):
//   x64: gcc -O2 -ffreestanding -fno-stack-protector -fno-jump-tables
//        -fno-asynchronous-unwind-tables -fomit-frame-pointer -fno-ident
//        -DVM_IS_X64 [-DVM_WINDOWS] -c vm_core.c
//        ld -Ttext=0x100000 -e vm_entry vm_core.o -o vm.elf
//        objcopy -O binary vm.elf vm.bin
//   x86: aynisi -DVM_IS_X86 (i386 hedefi)
// KURAL: libc YOK, switch/jump-table YOK, string literal YOK.
// Bayt-kod akis formati: vm_opcodes.h (encoder ile birebir ayna)
// ============================================================
#include "vm_opcodes.h"
#ifdef VM_TRACE
#include <stdio.h>
#include <stdlib.h>
static int vm_trace_on = -1;   /* ilk VM_TRACE env okumasiyla 1 olur */
#define VM_TRACE_CHECK() do { if (vm_trace_on < 0) vm_trace_on = getenv("VM_TRACE") ? 1 : 0; } while (0)
#else
#define VM_TRACE_CHECK()
#endif

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;
typedef long long i64;

typedef struct {
    u64 bc;         // +0x00 bayt-kod gostergesi
    u64 bc_len;     // +0x08
    u64 key;        // +0x10 rolling anahtar
    u64 base;       // +0x18 modul image base
    u64 regs[16];   // +0x20
    u64 flags;      // +0xA0
    u64 push_area;  // +0xA8 stub push alani
    u64 init_rsp;   // +0xB0
    u64 extra_pop;  // +0xB8 (x86 stdcall)
    u64 done;       // +0xC0  0=devam 1=ret 2=zehir
    u64 scratch[8]; // +0xC8
} VMContext;

#if defined(VM_IS_X64)
  #define PUSHSZ 8
  #define NMAP 15
  #define VM_DELTA VM_DELTA64
#elif defined(VM_IS_X86)
  #define PUSHSZ 4
  #define NMAP 8
  #define VM_DELTA VM_DELTA86
#endif
// pushmap fonksiyon icinde kurulur (statik veri yok -> tam PIC)

static void* u2p(u64 v) { return (void*)(unsigned long)v; }

// --- sifreli bayt akisi okuyucu ---
typedef struct { u8* bc; u64 key; u64 ic; } STRM;

static u8 sf8(STRM* s) {
    u8 v = s->bc[s->ic] ^ VM_KS(s->key, s->ic);   /* pozisyon-bazli */
    s->ic++;
    return v;
}
static u32 sf32(STRM* s) {
    u32 v = 0; int i;
    for (i = 0; i < 4; i++) v |= ((u32)sf8(s)) << (8*i);
    return v;
}
static u64 sf64(STRM* s) {
    u64 v = 0; int i;
    for (i = 0; i < 8; i++) v |= ((u64)sf8(s)) << (8*i);
    return v;
}

// --- bellek ---
static u64 mrd(u64 a, int sz) {
    u8* p = (u8*)u2p(a); u64 v = 0; int i;
    for (i = 0; i < sz; i++) v |= ((u64)p[i]) << (8*i);
    return v;
}
static void mwr(u64 a, int sz, u64 v) {
    u8* p = (u8*)u2p(a); int i;
    for (i = 0; i < sz; i++) p[i] = (u8)(v >> (8*i));
}

// --- register ---
static u64 rget(VMContext* c, int enc, int sz) {
    if (enc >= 16) return (c->regs[enc-16] >> 8) & 0xFF;
    if (sz == 1) return c->regs[enc] & 0xFF;
    if (sz == 2) return c->regs[enc] & 0xFFFF;
    if (sz == 4) return c->regs[enc] & 0xFFFFFFFF;
    return c->regs[enc];
}
static void rset(VMContext* c, int enc, int sz, u64 v) {
    if (enc >= 16) {
        c->regs[enc-16] = (c->regs[enc-16] & ~0xFF00ULL) | ((v & 0xFF) << 8);
        return;
    }
    if (sz == 1)      c->regs[enc] = (c->regs[enc] & ~0xFFULL) | (v & 0xFF);
    else if (sz == 2) c->regs[enc] = (c->regs[enc] & ~0xFFFFULL) | (v & 0xFFFF);
    else if (sz == 4) c->regs[enc] = v & 0xFFFFFFFF;   /* x64: 32-bit yazim ust 32 biti SIFIRLAR */
    else              c->regs[enc] = v;
}

static u64 szmask(int sz) {
    if (sz == 1) return 0xFFULL;
    if (sz == 2) return 0xFFFFULL;
    if (sz == 4) return 0xFFFFFFFFULL;
    return ~0ULL;
}

// MEM operandini akistan oku ve gercek adresi coz.
// Encoder sirasi: form:1 -> DISP: disp32 | SIB: base,idx,scale,disp32
static u64 mem_addr(STRM* s, VMContext* c) {
    int form = sf8(s);
    if (form == MEMF_DISP) {
        return c->base + (u64)(u32)sf32(s);
    } else {
        int b = sf8(s), ix = sf8(s), sc = sf8(s);
        u32 d = sf32(s);
        /* MEMF_SIB_IMG: disp image-RVA'dir (x86 mutlak adresleme) ->
           c->base eklenir. MEMF_SIB (eski): x64 yigin SIB'i -> disp ham. */
        u64 img = (form == MEMF_SIB_IMG) ? c->base : 0;
        u64 a;
        if (b == SIB_NOBASE)      a = img + (u64)(i64)(int)d;
        else if (b == REG_RSP)    a = c->regs[REG_RSP] - (u64)VM_DELTA + (u64)(i64)(int)d;
        else                      a = img + c->regs[b] + (u64)(i64)(int)d;
        if (ix != SIB_NOBASE) a += c->regs[ix] << sc;
        return a;
    }
}

static int sext32(i64* out, u32 v) { *out = (i64)(int)v; return 0; }

// --- ALU + bayraklar ---
static u64 do_alu(int alu, u64 a, u64 b, int sz, u64* fl) {
    u64 m = szmask(sz);
    int sb = sz * 8 - 1;
    u64 r = 0, f = 0;
    if (alu == ALU_ADD) {
        u64 s = a + b;
        r = s & m;
        if (sz == 8) { if (s < a) f |= FCF; }
        else         { if (s & ~m) f |= FCF; }
        if (((a ^ r) & (b ^ r)) >> sb & 1) f |= FOF;
    } else if (alu == ALU_SUB || alu == ALU_CMP) {
        r = (a - b) & m;
        if (a < b) f |= FCF;
        if (((a ^ b) & (a ^ r)) >> sb & 1) f |= FOF;
    } else if (alu == ALU_AND || alu == ALU_TEST) {
        r = a & b;
    } else if (alu == ALU_OR) {
        r = a | b;
    } else {
        r = a ^ b;
    }
    if (r == 0) f |= FZF;
    if ((r >> sb) & 1) f |= FSF;
    *fl = f;
    return r;
}

static int cond_eval(VMContext* c, int cc) {
    u64 f = c->flags;
    int C = (f & FCF) != 0, Z = (f & FZF) != 0, S = (f & FSF) != 0, O = (f & FOF) != 0;
    if (cc == CC_O)  return O;
    if (cc == CC_NO) return !O;
    if (cc == CC_B)  return C;
    if (cc == CC_AE) return !C;
    if (cc == CC_E)  return Z;
    if (cc == CC_NE) return !Z;
    if (cc == CC_BE) return (C | Z);
    if (cc == CC_A)  return !(C | Z);
    if (cc == CC_S)  return S;
    if (cc == CC_NS) return !S;
    if (cc == CC_P)  return 0;    /* PF izlenmiyor (float sonrasi kullanilmaz) */
    if (cc == CC_NP) return 1;
    if (cc == CC_L)  return (S != O);
    if (cc == CC_GE) return (S == O);
    if (cc == CC_LE) return (Z | (S != O));
    if (cc == CC_G)  return (!Z) && (S == O);
    return 0;
}

static u64 do_shift(int shi, u64 a, int n, int sz, u64* fl) {
    int sbits = sz * 8;
    u64 r = a, f = 0;
    if (n) {
        if (shi == SHI_SHL) {
            if (n <= sbits) { if ((a >> (sbits - n)) & 1) f |= FCF; }
            r = (a << n) & szmask(sz);
        } else if (shi == SHI_SHR) {
            if (n <= sbits) { if ((a >> (n - 1)) & 1) f |= FCF; }
            r = (a >> n) & szmask(sz);
        } else {
            i64 sv = (i64)(a << (64 - sbits)) >> (64 - sbits);
            if (n <= sbits) { if (((u64)sv >> (n-1)) & 1) f |= FCF; }
            r = ((u64)(sv >> n)) & szmask(sz);
        }
        if (r == 0) f |= FZF;
        if ((r >> (sbits-1)) & 1) f |= FSF;
    }
    *fl = f;
    return r;
}

#ifdef VM_IS_X64
// Native cagri. VM_WINDOWS: Win64 ABI (rcx,rdx,r8,r9). VM_SYSV_NATCALL:
// Linux test duzenegi (rdi,rsi,rdx,rcx,r8,r9).
#ifdef VM_SYSV_NATCALL
static u64 vm_natcall(u64 t, const u64* regs) {
    u64 ret;
    register u64 va7 __asm__("rdi") = regs[7];
    register u64 va6 __asm__("rsi") = regs[6];
    register u64 va2 __asm__("rdx") = regs[2];
    register u64 va1 __asm__("rcx") = regs[1];
    register u64 vr8 __asm__("r8")  = regs[8];
    register u64 vr9 __asm__("r9")  = regs[9];
    register u64 vt  __asm__("r11") = t;
    /* KRITIK: callee (SysV) rax,rcx,rdx,rsi,rdi,r8-r11'i EZER. "+X" bildirimi
       olmadan derleyici canli degerleri bu register'larda tutar -> callee
       ezer -> wild pointer. Ayrica cagri oncesi rsp 16-hizali OLMALI (SysV +
       Win64 ayni kural): hizali degilse callee'deki movaps/sse cerceveleri
       SIGSEGV verir. rsp eski degerine r10 uzerinden geri getirilir. */
    __asm__ volatile(
        "mov %%rsp, %%r10 \n\t"
        "and $-16, %%rsp \n\t"
        "sub $0x20, %%rsp \n\t"
        "call *%%r11 \n\t"
        "mov %%r10, %%rsp \n\t"
        : "=a"(ret), "+D"(va7), "+S"(va6), "+d"(va2), "+c"(va1),
          "+r"(vr8), "+r"(vr9), "+r"(vt)
        :
        : "memory", "cc", "r10");
    return ret;
}
#else
static u64 vm_natcall(u64 t, const u64* regs) {
    u64 ret;
    register u64 va0 __asm__("rax") = regs[0];
    register u64 va1 __asm__("rcx") = regs[1];
    register u64 va2 __asm__("rdx") = regs[2];
    register u64 vr8 __asm__("r8")  = regs[8];
    register u64 vr9 __asm__("r9")  = regs[9];
    register u64 vt  __asm__("r11") = t;
    /* KRITIK: callee (Win64) rax,rcx,rdx,r8,r9,r10,r11'i EZER (volatile).
       "+X" bildirimi yoksa derleyici canli degerleri bu register'larda
       tutabilir ve callee ezer -> bc isaretcisi bozulur -> wild read.
       Ayrica rsp 16-hizalanmali: hizasizsa callee'nin movaps'i SIGSEGV. */
    __asm__ volatile(
        "mov %%rsp, %%r10 \n\t"
        "and $-16, %%rsp \n\t"
        "sub $0x20, %%rsp \n\t"
        "call *%%r11 \n\t"
        "mov %%r10, %%rsp \n\t"
        : "+a"(ret), "+c"(va1), "+d"(va2), "+r"(vr8), "+r"(vr9), "+r"(vt)
        :
        : "memory", "cc", "r10");
    (void)va0;
    return ret;
}
#endif
#endif

// --- yorumlayici ---
static void vm_run(VMContext* c) {
    STRM s;
    s.bc  = (u8*)u2p(c->bc);
    s.key = c->key;
    s.ic  = 0;

    VM_TRACE_CHECK();
    while (!c->done) {
        u8 op = sf8(&s);
        int alu, shi, cc, ud, sz, ssz, r1, r2, form, n;
        u32 v32;
        u64 a, b, r, addr, fl;
        i64 sv;
        c->scratch[0] = op;        /* hata ayiklama izi */
        c->scratch[1] = s.ic;
        c->scratch[2] = s.key;
#ifdef VM_TRACE
        if (vm_trace_on == 1)
            fprintf(stderr, "[vm] ic=%llu op=0x%02X key=%llu\n",
                    (unsigned long long)s.ic, (unsigned)op, (unsigned long long)s.key);
#endif

        if (op == OP_NOP) {
            /* junk */

        } else if (op == OP_MOV_RR) {
            sz = sf8(&s); r1 = sf8(&s); r2 = sf8(&s);
            rset(c, r1, sz, rget(c, r2, sz));

        } else if (op == OP_MOV_RI) {
            sz = sf8(&s); r1 = sf8(&s); sext32(&sv, sf32(&s));
            rset(c, r1, sz, (u64)sv);

        } else if (op == OP_MOV_RI64) {
            r1 = sf8(&s);
            rset(c, r1, 8, sf64(&s));

        } else if (op == OP_CMOV) {
            cc = sf8(&s); sz = sf8(&s); r1 = sf8(&s); form = sf8(&s);
            if (form == 0) a = rget(c, sf8(&s), sz);
            else           a = mrd(mem_addr(&s, c), sz);
            if (cond_eval(c, cc)) rset(c, r1, sz, a);

        } else if (op == OP_MOV_RM) {
            sz = sf8(&s); r1 = sf8(&s);
            addr = mem_addr(&s, c);
            rset(c, r1, sz, mrd(addr, sz));

        } else if (op == OP_MOV_MR) {
            sz = sf8(&s);
            addr = mem_addr(&s, c);
            r1 = sf8(&s);
            mwr(addr, sz, rget(c, r1, sz));

        } else if (op == OP_MOV_MI) {
            sz = sf8(&s);
            addr = mem_addr(&s, c);
            sext32(&sv, sf32(&s));
            mwr(addr, sz, (u64)sv);

        } else if (op == OP_LEA_RM) {
            r1 = sf8(&s);
            rset(c, r1, 8, mem_addr(&s, c));

        } else if (op == OP_ALU_RR) {
            alu = sf8(&s); sz = sf8(&s); r1 = sf8(&s); r2 = sf8(&s);
            r = do_alu(alu, rget(c, r1, sz), rget(c, r2, sz), sz, &fl);
            c->flags = fl;
            if (alu != ALU_CMP && alu != ALU_TEST) rset(c, r1, sz, r);

        } else if (op == OP_ALU_RI) {
            alu = sf8(&s); sz = sf8(&s); r1 = sf8(&s); sext32(&sv, sf32(&s));
            b = (u64)sv;
            if (sz == 4) b &= 0xFFFFFFFFULL;
            if (sz == 2) b &= 0xFFFFULL;
            if (sz == 1) b &= 0xFFULL;
            r = do_alu(alu, rget(c, r1, sz), b, sz, &fl);
            c->flags = fl;
            if (alu != ALU_CMP && alu != ALU_TEST) rset(c, r1, sz, r);

        } else if (op == OP_ALU_RM) {
            alu = sf8(&s); sz = sf8(&s); r1 = sf8(&s);
            addr = mem_addr(&s, c);
            r = do_alu(alu, rget(c, r1, sz), mrd(addr, sz), sz, &fl);
            c->flags = fl;
            if (alu != ALU_CMP && alu != ALU_TEST) rset(c, r1, sz, r);

        } else if (op == OP_ALU_MR) {
            alu = sf8(&s); sz = sf8(&s);
            addr = mem_addr(&s, c);
            r2 = sf8(&s);
            r = do_alu(alu, mrd(addr, sz), rget(c, r2, sz), sz, &fl);
            c->flags = fl;
            if (alu != ALU_CMP && alu != ALU_TEST) mwr(addr, sz, r);

        } else if (op == OP_ALU_MI) {
            alu = sf8(&s); sz = sf8(&s);
            addr = mem_addr(&s, c);
            sext32(&sv, sf32(&s));
            b = (u64)sv;
            if (sz == 4) b &= 0xFFFFFFFFULL;
            if (sz == 2) b &= 0xFFFFULL;
            if (sz == 1) b &= 0xFFULL;
            r = do_alu(alu, mrd(addr, sz), b, sz, &fl);
            c->flags = fl;
            if (alu != ALU_CMP && alu != ALU_TEST) mwr(addr, sz, r);

        } else if (op == OP_SHI_RI) {
            shi = sf8(&s); sz = sf8(&s); r1 = sf8(&s); n = sf8(&s);
            r = do_shift(shi, rget(c, r1, sz), n, sz, &fl);
            c->flags = fl;
            rset(c, r1, sz, r);

        } else if (op == OP_SHI_CL) {
            shi = sf8(&s); sz = sf8(&s); r1 = sf8(&s);
            n = (int)(c->regs[REG_RCX] & 0x3F);
            r = do_shift(shi, rget(c, r1, sz), n, sz, &fl);
            c->flags = fl;
            rset(c, r1, sz, r);

        } else if (op == OP_SHI_RM_RI || op == OP_SHI_RM_CL) {
            shi = sf8(&s); sz = sf8(&s);
            addr = mem_addr(&s, c);
            if (op == OP_SHI_RM_RI) n = sf8(&s);
            else                    n = (int)(c->regs[REG_RCX] & 0x3F);
            r = do_shift(shi, mrd(addr, sz), n, sz, &fl);
            c->flags = fl;
            mwr(addr, sz, r);

        } else if (op == OP_IMUL_RRI) {
            sz = sf8(&s); r1 = sf8(&s); r2 = sf8(&s); sext32(&sv, sf32(&s));
            a = (u64)(i64)rget(c, r2, sz);
            if (sz == 4) a = (u64)(i64)(int)(a & 0xFFFFFFFF);
            r = (u64)(sv * (i64)a);
            c->flags = 0;
            rset(c, r1, sz, r);

        } else if (op == OP_IMUL_RMRI) {
            sz = sf8(&s); r1 = sf8(&s);
            addr = mem_addr(&s, c);
            sext32(&sv, sf32(&s));
            a = (u64)(i64)rget(c, 0, 0);           /* kullanilmaz */
            b = (u64)(i64)rget(c, 0, 0);           /* yer tutici */
            (void)a; (void)b;
            {
                u64 mv = mrd(addr, sz);
                i64 mvx = (sz == 8) ? (i64)mv : (i64)(int)(mv & 0xFFFFFFFF);
                r = (u64)(sv * mvx);
            }
            c->flags = 0;
            rset(c, r1, sz, r);

        } else if (op == OP_IMUL_RR) {
            sz = sf8(&s); r1 = sf8(&s); r2 = sf8(&s);
            a = (u64)(i64)rget(c, r1, sz);
            b = (u64)(i64)rget(c, r2, sz);
            if (sz == 4) {
                a = (u64)(i64)(int)(a & 0xFFFFFFFF);
                b = (u64)(i64)(int)(b & 0xFFFFFFFF);
            }
            r = (u64)((i64)a * (i64)b);
            c->flags = 0;
            rset(c, r1, sz, r);

        } else if (op == OP_INCDEC_R) {
            ud = sf8(&s); sz = sf8(&s); r1 = sf8(&s);
            r = do_alu(ud ? ALU_SUB : ALU_ADD, rget(c, r1, sz), 1, sz, &fl);
            c->flags = fl;
            rset(c, r1, sz, r);

        } else if (op == OP_INCDEC_M) {
            ud = sf8(&s); sz = sf8(&s);
            addr = mem_addr(&s, c);
            r = do_alu(ud ? ALU_SUB : ALU_ADD, mrd(addr, sz), 1, sz, &fl);
            c->flags = fl;
            mwr(addr, sz, r);

        } else if (op == OP_NEG_R) {
            sz = sf8(&s); r1 = sf8(&s);
            r = do_alu(ALU_SUB, 0, rget(c, r1, sz), sz, &fl);
            c->flags = fl;
            rset(c, r1, sz, r);

        } else if (op == OP_NOT_R) {
            sz = sf8(&s); r1 = sf8(&s);
            rset(c, r1, sz, ~rget(c, r1, sz) & szmask(sz));

        } else if (op == OP_NEG_M) {
            sz = sf8(&s); addr = mem_addr(&s, c);
            r = do_alu(ALU_SUB, 0, mrd(addr, sz), sz, &fl);
            c->flags = fl;
            mwr(addr, sz, r);

        } else if (op == OP_NOT_M) {
            sz = sf8(&s); addr = mem_addr(&s, c);
            mwr(addr, sz, ~mrd(addr, sz) & szmask(sz));

        } else if (op == OP_MOVZX || op == OP_MOVSX) {
            sz = sf8(&s); ssz = sf8(&s); r1 = sf8(&s); form = sf8(&s);
            if (form == 0) {
                a = rget(c, sf8(&s), ssz);
            } else {
                addr = mem_addr(&s, c);
                a = mrd(addr, ssz);
            }
            if (op == OP_MOVZX) r = a & szmask(ssz);
            else {
                if (ssz == 1) r = (u64)(i64)(signed char)(a & 0xFF);
                else          r = (u64)(i64)(short)(a & 0xFFFF);
            }
            rset(c, r1, sz, r);

        } else if (op == OP_PUSH_R) {
            r1 = sf8(&s);
            c->regs[REG_RSP] -= PUSHSZ;
            mwr(c->regs[REG_RSP] - (u64)VM_DELTA, PUSHSZ, rget(c, r1, PUSHSZ));

        } else if (op == OP_PUSH_I) {
            sext32(&sv, sf32(&s));
            c->regs[REG_RSP] -= PUSHSZ;
            mwr(c->regs[REG_RSP] - (u64)VM_DELTA, PUSHSZ, (u64)sv);

        } else if (op == OP_POP_R) {
            r1 = sf8(&s);
            rset(c, r1, PUSHSZ, mrd(c->regs[REG_RSP] - (u64)VM_DELTA, PUSHSZ));
            c->regs[REG_RSP] += PUSHSZ;

        } else if (op == OP_JMP) {
            sext32(&sv, sf32(&s));
            s.ic = s.ic + (u64)sv;

        } else if (op == OP_JCC) {
            cc = sf8(&s); sext32(&sv, sf32(&s));
            if (cond_eval(c, cc)) s.ic = s.ic + (u64)sv;

        } else if (op == OP_NCALL) {
            v32 = sf32(&s);
#ifdef VM_IS_X64
            c->regs[0] = vm_natcall(c->base + (u64)v32, c->regs);
#else
            (void)v32;
            c->done = 1;   // x86: dis cagri desteklenmez (encoder engeller)
#endif

        } else if (op == OP_RET) {
            c->done = 1;

        } else if (op == OP_SETCC) {
            cc = sf8(&s); r1 = sf8(&s);
            rset(c, r1, 1, cond_eval(c, cc) ? 1 : 0);

        } else if (op == OP_CQO) {
#if defined(VM_IS_X64)
            c->regs[REG_RDX] = (c->regs[0] >> 63) ? ~0ULL : 0ULL;
#else
            c->regs[REG_RDX] = (c->regs[0] & 0x80000000ULL) ? 0xFFFFFFFFULL : 0ULL;
#endif

        } else if (op == OP_IDIV_R) {
            sz = sf8(&s); r1 = sf8(&s);
#if defined(VM_IS_X64)
            if (sz == 4) {
                i64 dd = ((i64)(int)(c->regs[REG_RDX] & 0xFFFFFFFF) << 32)
                       |  (i64)(int)(c->regs[0] & 0xFFFFFFFF);
                i64 dv = (i64)(int)(c->regs[r1] & 0xFFFFFFFF);
                if (dv == 0) { c->regs[0] = 0; c->regs[REG_RDX] = 0; }
                else { c->regs[0] = (u64)(int)(dd / dv); c->regs[REG_RDX] = (u64)(int)(dd % dv); }
            } else {
                i64 dd = (i64)c->regs[REG_RDX];
                i64 dv = (i64)c->regs[r1];
                if (dv == 0) { c->regs[0] = 0; c->regs[REG_RDX] = 0; }
                else { c->regs[0] = (u64)(dd / dv); c->regs[REG_RDX] = (u64)(dd % dv); }
            }
#else
            if (sz == 4) {
                int dv = (int)(c->regs[r1] & 0xFFFFFFFF);
                if (dv == 0) { c->regs[0] = 0; c->regs[REG_RDX] = 0; }
                else {
                    int q = (int)(c->regs[0] & 0xFFFFFFFF) / dv;
                    int rm = (int)(c->regs[0] & 0xFFFFFFFF) % dv;
                    c->regs[0] = (u32)q; c->regs[REG_RDX] = (u32)rm;
                }
            } else { c->done = 1; }
#endif

        } else if (op == OP_ANTIDBG) {
#ifdef VM_WINDOWS
#if defined(VM_IS_X64)
            { u64 peb; __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
              u8* p = (u8*)u2p(peb);
              if (p[2] || (p[0xBC] & 0x70)) c->done = 2; }
#else
            { u32 peb; __asm__ volatile("movl %%fs:0x30, %0" : "=r"(peb));
              u8* p = (u8*)u2p((u64)peb);
              if (p[2] || (p[0x68] & 0x70)) c->done = 2; }
#endif
#endif

        } else if (op == OP_STRDEC) {
            u32 strva = sf32(&s), stva = sf32(&s), k = sf32(&s), len = sf32(&s);
            u8* st = (u8*)u2p(c->base + (u64)stva);
            if (*st == 0) {
                u8* p = (u8*)u2p(c->base + (u64)strva);
                u32 i2;
                for (i2 = 0; i2 < len; i2++) p[i2] ^= (u8)(k + i2 * 31);
                *st = 1;
            }

        } else {
            c->done = 1;   // bilinmeyen opcode -> guvenli dur
        }
    }
}

void vm_entry(VMContext* c) {
    int k;
    int map[NMAP];
#if defined(VM_IS_X64)
    { int t[15] = {0,1,2,3,5,6,7,8,9,10,11,12,13,14,15};
      for (k = 0; k < 15; k++) map[k] = t[k]; }
#else
    /* x86 pushad sirasi: EAX once push edilir -> EN YUKSEK adreste; EDI enson
       -> EN ALCAK adreste. push_area[k] ARTAN okundugu icin siralama ters:
       [0]=EDI(7), [1]=ESI(6), [2]=EBP(5), [3]=ESP_orig(atla), [4]=EBX(3),
       [5]=EDX(2), [6]=ECX(1), [7]=EAX(0). Eski map {0,1,2,3,..} reg'leri
       tamamen karistiriyordu (dir=copuk deger -> yanlis hareket). */
    { int t[8] = {7,6,5,(int)0xFFFFFFFFu,3,2,1,0};
      for (k = 0; k < 8; k++) map[k] = t[k]; }
#endif
#if defined(VM_IS_X64)
    u64* src = (u64*)u2p(c->push_area);          /* x64: 8B slot (push'lar) */
    #define SRC_LOAD(k)  src[k]
    #define SRC_STORE(k, v) (src[k] = (v))
#else
    u32* src = (u32*)u2p(c->push_area);          /* x86 pushad: 4B slot! */
    #define SRC_LOAD(k)  (u64)src[k]
    #define SRC_STORE(k, v) (src[k] = (u32)(v))
#endif

    for (k = 0; k < NMAP; k++) {
        if (map[k] != (int)0xFFFFFFFFu) c->regs[map[k]] = SRC_LOAD(k);
    }
    c->regs[4] = c->init_rsp;
    c->flags = 0;
    c->done = 0;

    vm_run(c);

    if (c->done == 2) {
        c->regs[0] = 0xDEADBEEFDEADBEEFULL;   // debugger -> zehirli donus
        c->done = 1;
    }
    for (k = 0; k < NMAP; k++) {
        if (map[k] != (int)0xFFFFFFFFu) SRC_STORE(k, c->regs[map[k]]);
    }
    (void)c->extra_pop;
}
