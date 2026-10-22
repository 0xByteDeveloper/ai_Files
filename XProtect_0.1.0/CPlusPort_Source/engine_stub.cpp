// ============================================================
// engine_stub.cpp — elle kodlanmis VM giris stub'lari
// x64: 15 reg push + ctx kur + call vm_entry(RDI) + pop'lar + ret
// x86: pushad + ctx kur + push ctx + call vm_entry(cdecl) + popad + ret[imm16]
// DELTA sabitleri vm_opcodes.h ile birebir ayni olmali!
// ============================================================
#include "engine.hpp"

struct Patch32 { u32 off, val; };

static void put(std::vector<u8>& v, std::initializer_list<u8> b) {
    for (u8 x : b) v.push_back(x);
}
static void put32(std::vector<u8>& v, u32 x) {
    for (int k = 0; k < 4; k++) v.push_back((u8)(x >> (8 * k)));
}
static void put64(std::vector<u8>& v, u64 x) {
    for (int k = 0; k < 8; k++) v.push_back((u8)(x >> (8 * k)));
}

std::vector<u8> build_stub_x64(u32 stub_rva, u32 vm_entry_rva, u64 key,
                               u32 bc_rva, u32 bc_len) {
    std::vector<u8> s;
    Patch32 p_key{}, p_l1{}, p_bc{}, p_len{}, p_rel{}, p_call2{};
    u32 off_pop = 0;

    // --- 15 register push: SIRA ONEMILI! vm_entry push_area[k]'yi YUKARI
    // dogru okur: push_area[0]=rax, [1]=rcx, ... [14]=r15. Yigin asagi
    // uzandigi icin rax'in EN ALCAK adreste olmasi gerekir -> push'lari
    // TERSTEN yap (r15 once ... rax enson). x86 pushad duzeniyle ayni model
    // (EAX en alcak). Eski sirada src[1]=[entry] oluyor ve copy-back
    // DONUS ADRESINI EZIYORDU (wild ret -> crash).
    for (int r = 15; r >= 8; r--) put(s, {0x41, (u8)(0x50 + (r - 8))});
    put(s, {0x57,0x56,0x55,0x53,0x52,0x51,0x50});       // push rdi,rsi,rbp,rbx,rdx,rcx,rax
    // --- ctx kurulumu ---
    // r12 = push_area = rax'in yuvasi (push'lar sonrasi rsp'nin kendisi).
    // REX=0x4C (W|R): 0x49 olsayd reg=rsp olurdu -> "lea rsp,[rsp+0]" olurdu.
    put(s, {0x49,0x89,0xE4});                           // mov r12, rsp (push_area)
    put(s, {0x48,0x81,0xEC}); put32(s, VM_STUB_SUB64); // sub rsp (ctx+marj)
    put(s, {0x4C,0x89,0xA4,0x24,0xA8,0,0,0});           // mov [rsp+0xA8], r12 (push_area)
    put(s, {0x49,0x8D,0x84,0x24,0x78,0,0,0});           // lea rax,[r12+0x78] (init_rsp = giris rsp)
    put(s, {0x48,0x89,0x84,0x24,0xB0,0,0,0});           // mov [rsp+0xB0], rax (init_rsp)
    put(s, {0x48,0xB8}); p_key = {(u32)s.size(), 0}; put64(s, 0);   // mov rax,key
    put(s, {0x48,0x89,0x44,0x24,0x10});                 // mov [rsp+0x10], rax
    p_call2 = {(u32)s.size() + 1, 0};                   // call L1'in rel32 alani
    put(s, {0xE8,0,0,0,0});                             // call L1
    off_pop = (u32)s.size();                            // L1: <- call buraya doner
    put(s, {0x58});                                     // pop rax
    put(s, {0x48,0x2D}); p_l1 = {(u32)s.size(), 0}; put32(s, 0);    // sub rax, L1_rva
    put(s, {0x48,0x89,0x44,0x24,0x18});                 // mov [rsp+0x18], rax (base)
    put(s, {0x48,0x05}); p_bc = {(u32)s.size(), 0}; put32(s, 0);    // add rax, bc_rva
    put(s, {0x48,0x89,0x04,0x24});                      // mov [rsp], rax (bc)
    put(s, {0x48,0xB8}); p_len = {(u32)s.size(), 0}; put64(s, 0);   // mov rax,bc_len
    put(s, {0x48,0x89,0x44,0x24,0x08});                 // mov [rsp+0x08], rax
    // NOT: blob Linux gcc ile derlenir -> vm_entry SysV ABI (ilk arg RDI).
    // (Windows'ta da ayni: blob kendi icinde tutarli; VM_WINDOWS sadece
    //  natcall'un Win64 konvansiyonunu secar — dis fonksiyon cagrilari icin.)
    put(s, {0x48,0x89,0xE7});                           // mov rdi, rsp (ctx)
    put(s, {0xE8,0,0,0,0});                             // call vm_entry
    u32 off_call2 = (u32)s.size() - 5;
    put(s, {0x48,0x81,0xC4}); put32(s, VM_STUB_SUB64); // add rsp
    // pop'lar push'larin TERSTEN (rax once ... r15 enson)
    put(s, {0x58,0x59,0x5A,0x5B,0x5D,0x5E,0x5F});       // pop rax,rcx,rdx,rbx,rbp,rsi,rdi
    for (int r = 8; r <= 15; r++) put(s, {0x41, (u8)(0x58 + (r - 8))});
    put(s, {0xC3});                                     // ret

    // --- yamalar ---
    u32 l1_rva = stub_rva + off_pop;
    u32 buf[8]; (void)buf;
    // key (imm64)
    for (int k = 0; k < 8; k++) s[p_key.off + k] = (u8)(key >> (8 * k));
    // L1 rva
    s[p_l1.off]     = (u8)(l1_rva);
    s[p_l1.off + 1] = (u8)(l1_rva >> 8);
    s[p_l1.off + 2] = (u8)(l1_rva >> 16);
    s[p_l1.off + 3] = (u8)(l1_rva >> 24);
    // bc rva
    s[p_bc.off]     = (u8)(bc_rva);
    s[p_bc.off + 1] = (u8)(bc_rva >> 8);
    s[p_bc.off + 2] = (u8)(bc_rva >> 16);
    s[p_bc.off + 3] = (u8)(bc_rva >> 24);
    // bc len
    for (int k = 0; k < 8; k++) s[p_len.off + k] = (u8)((u64)bc_len >> (8 * k));
    // vm_entry rel32
    i32 rel = (i32)(vm_entry_rva - (stub_rva + off_call2 + 5));
    s[off_call2 + 1] = (u8)(u32)rel;
    s[off_call2 + 2] = (u8)((u32)rel >> 8);
    s[off_call2 + 3] = (u8)((u32)rel >> 16);
    s[off_call2 + 4] = (u8)((u32)rel >> 24);
    (void)p_rel;
    return s;
}

std::vector<u8> build_stub_x86(u32 stub_rva, u32 vm_entry_rva, u64 key,
                               u32 bc_rva, u32 bc_len, u32 retimm) {
    // BUGFIX #12 (x86 w+Enter cokmesi): retimm eskiden u16 idi.
    // engine.hpp'deki "ret yok" sentinel'i 0xFFFFFFFF (u32) u16'ya
    // kirpilinca 0xFFFF oluyor, asagidaki sentinel kontrolu atlaniyor
    // ve "ret 0xFFFF" uretiliyordu -> her sanallastirilmis cagri
    // donusunde ESP +0x10003 kayiyor -> ilk VM cagrisinda (w+Enter)
    // stack corba -> SIGSEGV. Simdi param u32; sentinel veya 0 -> C3.
    std::vector<u8> s;
    u32 off_key, off_key2, off_l1, off_bc, off_len, off_call2, off_pop;

    put(s, {0x60});                                     // pushad
    put(s, {0x81,0xEC}); put32(s, VM_STUB_SUB86);       // sub esp
    put(s, {0x8D,0x84,0x24}); put32(s, VM_STUB_SUB86);   // lea eax,[esp+SUB] (push_area)
    put(s, {0x89,0x84,0x24}); put32(s, VMOFF_PUSHAREA); // mov [esp+0xA8], eax
    put(s, {0x05}); put32(s, 0x20);                     // add eax,0x20
    put(s, {0x89,0x84,0x24}); put32(s, VMOFF_INITRSP);  // mov [esp+0xB0], eax
    put(s, {0xB8}); off_key = (u32)s.size(); put32(s, 0);           // mov eax,key_lo
    put(s, {0x89,0x44,0x24,0x10});                      // mov [esp+0x10], eax
    // ctx->key 64 BITTIR: yuksek 32 bit de yazilmali (eski kod sadece lo
    // yaziyor, hi yigin copu kaliyor -> VM_KS yanlis -> tum bc corba!)
    put(s, {0xB8}); off_key2 = (u32)s.size(); put32(s, 0);          // mov eax,key_hi
    put(s, {0x89,0x44,0x24,0x14});                      // mov [esp+0x14], eax
    put(s, {0xE8,0,0,0,0});                             // call L1
    off_pop = (u32)s.size();
    put(s, {0x58});                                     // pop eax
    put(s, {0x2D}); off_l1 = (u32)s.size(); put32(s, 0);            // sub eax,L1_rva
    put(s, {0x89,0x44,0x24,0x18});                      // mov [esp+0x18], eax
    put(s, {0x05}); off_bc = (u32)s.size(); put32(s, 0);            // add eax,bc_rva
    put(s, {0x89,0x04,0x24});                           // mov [esp], eax
    put(s, {0xB8}); off_len = (u32)s.size(); put32(s, 0);           // mov eax,len
    put(s, {0x89,0x44,0x24,0x08});                      // mov [esp+0x08], eax
    put(s, {0x54});                                     // push esp (ctx)
    put(s, {0xE8,0,0,0,0});                             // call vm_entry
    off_call2 = (u32)s.size() - 5;
    put(s, {0x83,0xC4,0x04});                           // add esp,4
    put(s, {0x81,0xC4}); put32(s, VM_STUB_SUB86);       // add esp
    put(s, {0x61});                                     // popad
    if (retimm != 0 && retimm != 0xFFFFFFFF) {
        put(s, {0xC2});
        put32(s, retimm); s.pop_back(); s.pop_back();   // ret imm16 (C2 + 2 bayt)
        // (eski kod tek pop_back yapiyordu, ucuncu byte cop kaliyordu)
    } else {
        put(s, {0xC3});                                 // plain ret (cdecl)
    }

    u32 l1_rva = stub_rva + off_pop;
    for (int k = 0; k < 4; k++) s[off_key + k] = (u8)((u32)key >> (8 * k));
    for (int k = 0; k < 4; k++) s[off_key2 + k] = (u8)((u32)(key >> 32) >> (8 * k));
    for (int k = 0; k < 4; k++) s[off_l1 + k]  = (u8)(l1_rva >> (8 * k));
    for (int k = 0; k < 4; k++) s[off_bc + k]  = (u8)(bc_rva >> (8 * k));
    for (int k = 0; k < 4; k++) s[off_len + k] = (u8)(bc_len >> (8 * k));
    i32 rel = (i32)(vm_entry_rva - (stub_rva + off_call2 + 5));
    for (int k = 0; k < 4; k++) s[off_call2 + 1 + k] = (u8)((u32)rel >> (8 * k));
    return s;
}
