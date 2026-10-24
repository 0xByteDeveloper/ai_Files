// ============================================================================
//  MazeProtector.h - "benikoru" fonksiyon koruyucu
//  JMP labirenti + calisma aninda XOR ile cozen sifreli parcalar
//
//  KONSEP (benikoru):
//   - Hedef fonksiyon (RVA + boyut, PDB'den alinir) komut komut cozulur,
//     KOMUT SINIRLARI BOZULMADAN parcalara (chunk) bolunur (varsayilan max 20 bayt).
//   - Parcalar yeni bir .maze section'ina KARISTIRILMIS sirada + aralara
//     hic calismayan "yem" bloklari (rdtsc/timer/int degiskenleri gorunumlu)
//     yerlestirilir; parcalar JCC/JMP (rel32) ile birbirine baglanir.
//     Stack'in disassembly ilerleme kurali korunur -> uygulama crash vermez.
//   - Fonksiyon icindeki tum rel32/rel8 dallanmalar ve RIP-relatif veri
//     erisimleri yeni konumlara gore yeniden hesaplanir ("address belirten
//     rva'lar korunur"). Diger fonksiyonlardan bu fonksiyona gelen
//     call/jmp'ler de yeni girise yonlendirilir.
//   - SIFRELI MOD: parcalarin gercek opcode'lari dosyada XOR sifreli durur.
//     Fonksiyon girisine yazilan stub, calisma aninda (fonksiyon cagrildigi
//     anda) parcalari yerinde cozer ve ilk parcalya atlar. Statik analizde
//     gercek komutlar ASLA gorunmez; dosya diskte sifreli kalir.
//   - Orijinal fonksiyon govdesine 5 baytlik JMP trambolini yazilir,
//     kalan baytlar INT3 ile doldurulur.
//
//  SINIRLAR (dostum, bunlar onemli):
//   - loop/jcxz/loopne iceren fonksiyonlar desteklenmez (rel32 karsiligi yok).
//   - Fonksiyon kendi icindeki verilere RIP-relatif isaret ediyorsa
//     (jump table govde icindeyse) desteklenmez.
//   - "Cikista tekrar sifrele" secenekte recursion/-thread sorunu olabilir
//     (varsayilan kapali). Detay asagida.
//   - Diger modullerden fonksiyonun ORTASINA atlayan vtable/switch verisi
//     varsa o girisler bozulur (girise atlayanlar sorunsuz).
//
//  Bu dosya globals.h'tan SONRA include edilir (Core/PEFile/MemImage kullanir).
// ============================================================================
#pragma once
#include "stdafx.h"

namespace MazeProtect {

// ---- AYARLAR ---------------------------------------------------------------

struct Options {
    u32 fnRva   = 0;      // fonksiyonun RVA'si (VA - ImageBase), PDB'den
    u32 fnSize  = 0;      // fonksiyonun bayt boyutu (PDB'den)
    u32 chunkMax = 20;    // maksimum parca boyutu (bayt) - 8..64
    bool encrypt = true;  // true: XOR sifreli parcalar + runtime-decrypt stub
    bool reencryptOnExit = false; // fonksiyon dondugunde tekrar sifrele
                                  // DIKKAT: recursion/thread'li fonksiyonlarda KAPALI kalsin
    u64 key  = 0;         // XOR anahtari (0 = otomatik uretilir)
    u32 seed = 0;         // karistirma tohumu (0 = fnRva'den turetilir)
    int decoyChance = 70; // parcalar arasina yem blok koyma olasiligi (%)
    bool arena = false;   // ARENA MODU (v3): free-mem JIT - her cagride VirtualAlloc
                          // ile RWX arena acilir, sifreli parcalar ORAYA cozulup
                          // oradan calisir, ret'te arena serbest birakilir.
                          // .maze'deki baytlar HICBIR ZAMAN cozulmez (diskte + bellekte
                          // hep sifreli). IAT'de VirtualAlloc/VirtualFree sart;
                          // yoksa guvenli sekilde YERINDE moda duser (non-breaking).
    bool stream = false;         // V4 TEK TEK (STREAM): parcalar tek tek TEK bir slot'a
                                 // cozulur, WIPE-BEHIND ile onceki parca silinir.
                                 // Her an arenada max 1 parca plaintext; tam fonksiyon
                                 // HICBIR an bitisik var olmaz. Kenarlar .maze'deki
                                 // 9 baytlik thunk'lardan (mov r10d,pid; jmp conv) gecer.
    bool streamHardened = false; // V4 god-tier katmanlari: G1 slot rastgelelestirme
                                 // (her cagride baska adres), G2 CRC-8 anti-patch,
                                 // G3 decoy enjeksiyonu. stream=false ise etkisiz.
    bool allowRelocBody = false; // V4.5: govdede reloc'lu mutlak adres varsa RED
                                 // yerine izin ver. SADECE encoder cikista ASLR'i
                                 // kapattiysa kullanin (Core::LoadFile artik her
                                 // cikista DYNAMICBASE temizler): image tercih-
                                 // edilen base'de yuklenir, mutlak adresler gecerli
                                 // kalir, loader sifreli/tasinan bolgeye dokunmaz.
};

struct Report {
    bool ok = false;
    std::string err;
    u32 insnCount = 0, chunkCount = 0, fixupCount = 0, extFixCount = 0, decoyCount = 0;
    u32 fnRva = 0, fnSize = 0, mazeRva = 0, mazeSize = 0, entryRva = 0;
    u32 encBytes = 0, blobBytes = 0;
    u64 keyUsed = 0;
    bool reencrypt = false;
    // ARENA (v3)
    bool arenaActive = false;   // gercekten arena modunda kuruldu mu
    u32  arenaSites = 0;        // calisma aninda delta-duzeltilecek disp sayisi
    u32  arenaCleanup = 0;      // ret -> cleanup blok sayisi (farkli ret encoding)
    u32  arenaSize = 0;         // VirtualAlloc ile acilacak arena boyutu (bayt)
    // V4 STREAM
    bool streamActive = false;  // gercekten stream modunda kuruldu mu
    u32  streamBlocks = 0;      // parca sayisi (c1..cN)
    u32  streamSites  = 0;      // calisma aninda delta-fix uygulanacak disp sayisi
    u32  streamThunks = 0;      // .maze'deki 9 baytlik thunk sayisi (parca + cleanup)
    u32  slotSize     = 0;      // slot boyutu (bayt) - tek tek cozulen bolge
    u32  maxPieceLen  = 0;      // en buyuk sifreli parca span'i (govde+tail+pad)
    u32  templateLen  = 0;      // arena'ya kopyalanan stage+cleanup boyutu
    u32  edgeTblOff   = 0;      // .maze'de thunk tablosu ofseti
    std::vector<std::string> streamMap; // BLK/EDGE/SITE/INFO satirlari (MazeMap icin)
    std::vector<std::string> warnings;
    std::vector<std::string> preview; // labirentin DUZ (cozulmus) disassembly onizlemesi
    std::vector<u32> jmpSites;        // labirentteki tum JMP dalma adresleri (maze RVA) - Helper icin
};

// ---- IC YAPILAR ------------------------------------------------------------

enum InsnKind : u8 {
    K_NONE = 0,    // yerinden oynatilabilir, duzeltme gerektirmez (veya dolayli jmp/call)
    K_BR,          // E8 call rel32 / E9 jmp rel32  -> disp @1
    K_JCC,         // 0F 8x jcc rel32               -> disp @2
    K_EXPJMP,      // EB jmp rel8 -> E9 rel32'ye genisler (5 bayt)
    K_EXPJCC       // 7x jcc rel8 -> 0F 8x rel32'ye genisler (6 bayt)
};

struct MInsn {
    u32 rva = 0;            // orijinal RVA
    u8  size = 0;           // orijinal boyut
    u8  bytes[16] = {};
    std::string mn;         // capstone mnemonic (dogrulama icin)
    u32 blobOff = 0;        // .maze blob icindeki konumu
    u32 newRva = 0;         // yerlesim sonrasi RVA
    u32 newSize = 0;        // yerlesim sonrasi boyut
    InsnKind kind = K_NONE;
    u32 targetRva = 0;      // dallanma hedefi (orijinal)
    bool hasRip = false;    // RIP-relatif veri erisimi var
    i32  ripDisp = 0;
    u32  ripTargetRva = 0;
    u32  ripOff = 0;        // disp32'nin komut icindeki bayt ofseti
    bool isRet = false;
    u32  regs = 0;          // dokunulan registerlar (bit = reg - X86_REG_RAX) - V4 conv-reg kontrolu
    i32  espDelta = 0;      // V4.7 x86: bu komuttan SONRAKI esp - giris esp (takipci yazar)
};

struct Chunk {
    size_t i0 = 0, n = 0;   // insns[i0 .. i0+n)
    u32 blobOff = 0;        // blob icindeki baslangici
    u32 spanOff = 0, spanLen = 0; // sifrelenecek bolge (govde + connector + nop dolgu)
};

struct Patch {
    enum Kind : u8 { P_BR, P_RIP, P_CONN, P_CC, P_STUBJ, P_TBL,
                     P_ARENA_RET,   // ret yerine yazilan E9 -> cleanup blok (blob-ici, yer-bagimsiz)
                     P_ARENA_IMM,   // stub/cleanup icindeki imm32 gec yamalanir (immWhich)
                     P_ARENA_VA,    // stub'daki VirtualAlloc call [rip] disp (maze'de calisir, yerinde yama)
                     P_ARENA_VF } kind; // cleanup'taki VirtualFree call [rip] disp (maze yamasi + RUNTIME delta site)
    u32 insnIdx = 0;        // P_BR/P_RIP: site komut
    u32 dispOff = 0;        // P_BR: disp alaninin komut icindeki ofseti
    u32 targetInsn = 0;     // P_BR: hedef komut | P_ARENA_RET: cleanup blok blob-ofseti
    u32 siteOff = 0;        // disp alaninin BLOB OFSETI (tum turlerde ayni semantik)
    u32 chunkIdx = 0;       // P_CONN: hedef chunk (mantiksal siradaki)
    u32 immWhich = 0;       // P_ARENA_IMM: 0=imgSize 1=tableOff 2=sitesOff 3=arenaSize 4=blobRva 5=firstOff
    u32 immValue = 0;       // P_ARENA_VA/VF: IAT slot RVA'si
    static const u32 NO_TARGET = 0xFFFFFFFFu;
};

// ---- YARDIMCILAR -----------------------------------------------------------

static void Poke32(std::vector<u8>& b, size_t off, i32 v) { if (off + 4 <= b.size()) memcpy(b.data() + off, &v, 4); }

struct Rng { // xorshift32 - ayni anahtar -> ayni labirent (tekrar uretilebilir)
    u32 s;
    explicit Rng(u32 seed_) : s(seed_ ? seed_ : 0x9E3779B9u) {}
    u32 Next() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; }
    u32 Next(u32 mod) { return mod ? Next() % mod : 0; }
};

static u32 NewSizeOf(const MInsn& m) {
    switch (m.kind) {
    case K_EXPJMP: return 5;
    case K_EXPJCC: return 6;
    default:       return m.size;
    }
}

// RIP-relatif disp32'nin komut icindeki ofsetini hesaplar:
// prefix sayisi + REX + opcode uzunlugu -> ModRM (+SIB) -> disp32
// capstone'un prefix[]/rex/opcode[]/modrm alanlarindan turetilir ve
// bayt bayt dogrulanir; tutmazsa -1 (hata).
static int CalcRipDispOff(const u8* b, u8 size, const cs_x86* x) {
    // V4.1: disp'i komut baytlarinda TERSTEN tara. Neden ters: disp'den SONRA
    // imm gelebilir (83 05 d32 imm8 / C7 05 d32 imm32) — eski "ModRM sonrasi
    // disp, son 4 bayt" varsayimi bu formlarda kayiyordu. Son eslesen konum
    // dogru disp konumudur (imm baytlari disp bayt dizisiyle nadir cakisir).
    if (x->op_count > 0) {
        i32 want = (i32)x->disp;
        for (int i = (int)size - 4; i >= 1; i--) {
            i32 dv; memcpy(&dv, b + i, 4);
            if (dv == want) return i;
        }
    }
    // yedek yol: eski elle cozum (bayt eslesmesi tutmazsa)
    int prefixLen = 0;
    for (int i = 0; i < 4; i++) if (x->prefix[i]) prefixLen++; // legacy prefix'ler kesintisizdir
    int opLen = 1;
    if (x->opcode[0] == 0x0F) opLen = (x->opcode[1] == 0x38 || x->opcode[1] == 0x3A) ? 3 : 2;
    int off = prefixLen + ((x->rex) ? 1 : 0) + opLen;
    if (off + 1 < (int)size && b[off] == x->modrm) {
        int mo = off + 1;
        if ((x->modrm & 0x07) == 0x04) mo++; // SIB var (RIP-relatifte SIB olmaz ama garanti)
        if (mo + 4 <= (int)size) {
            i32 dv; memcpy(&dv, b + mo, 4);
            if (dv == (i32)x->disp) return mo;
        }
    }
    return -1;
}

// ---- YEM (DECOY) URETECI ---------------------------------------------------
// Unconditional JMP'nin arkasina gizlenen, HIC CALISMAYAN ama gercek kod gibi
// gorunen blok: rdtsc / int degiskenleri / test-cmp zincirleri.
// Statik analizde (IDA) fonksiyonun parcası sanilir; bayt harcar ve yol kaybettirir.

static void EmitDecoy(std::vector<u8>& blob, Rng& rng, u32& decoyCount) {
    size_t jmpPos = blob.size();
    blob.push_back(0xE9); blob.resize(blob.size() + 4, 0); // E9 rel32 (doldurulacak)
    int want = 8 + (int)rng.Next(40);                       // 8..47 bayt yem
    int made = 0;
    while (made < want) {
        int room = want - made;
        u32 t = rng.Next(10);
        if (t == 0 && room >= 2) { blob.push_back(0x0F); blob.push_back(0x31); made += 2; }          // rdtsc
        else if (t == 1 && room >= 5) { blob.push_back((u8)(0xB8 + rng.Next(8)));                     // mov r32, imm32
            u32 v = rng.Next(0xFFFFFFFF); for (int i = 0; i < 4; i++) blob.push_back((u8)(v >> (8 * i))); made += 5; }
        else if (t == 2 && room >= 5) { blob.push_back(0x3D);                                         // cmp eax, imm32
            u32 v = rng.Next(0xFFFFFFFF); for (int i = 0; i < 4; i++) blob.push_back((u8)(v >> (8 * i))); made += 5; }
        else if (t == 3 && room >= 3) { blob.push_back(0xC1); blob.push_back(0xC0); blob.push_back((u8)(1 + rng.Next(31))); made += 3; } // rol eax, n
        else if (t == 4 && room >= 2) { blob.push_back(0x85); blob.push_back(0xC0); made += 2; }      // test eax, eax
        else if (t == 5 && room >= 2) { blob.push_back(0x31); blob.push_back(0xC0); made += 2; }      // xor eax, eax
        else if (t == 6 && room >= 2) { blob.push_back(0x66); blob.push_back(0x90); made += 2; }      // xchg ax,ax (2 bayt nop)
        else if (t == 7 && room >= 4) { blob.push_back(0x0F); blob.push_back(0x1F); blob.push_back(0x40); blob.push_back(0x00); made += 4; } // nop dword [rax]
        else if (t == 8 && room >= 3) { blob.push_back(0xA8); blob.push_back((u8)rng.Next(256)); made += 3; } // test al, imm8
        else if (t == 9 && room >= 2) { blob.push_back(0x8B); blob.push_back((u8)(0xC0 | (rng.Next(8) << 3) | rng.Next(8))); made += 2; } // mov r32, r32
        else { blob.push_back(0x90); made += 1; }
    }
    i32 d = (i32)made; // hedef = yem sonrasi ilk bayt
    Poke32(blob, jmpPos + 1, d);
    decoyCount++;
}

// ---- XOR COZUCU STUB (el ile kodlanmis, bayt bayt dogrulanmis x64) ---------
//
//  push rax/rcx/rdx/rbx/r8/r9/r10/r11  ; arguman registerlari KORUNUR (8 push
//                                       ; = stack align %16 korunur)
//  lea  r8,  [rip+D]                  ; r8 = blob tabani (header)
//  mov  r9d, [r8]                     ; bolge sayisi
//  lea  r10, [r8+tableOff]            ; bolge tablosu {u32 off; u32 len}*
//  mov  rdx, [r8+8]                   ; 8 bayt XOR anahtari
//  cmp  dword [r8+0x28], 0            ; DECRYPT-ONCE FLAGI: zaten cozuldu mu?
//  jne  bitti                         ; evet -> cozmeye girisma (2. cagri guvenli)
//  bolge: test r9d,r9d / je bitti
//        movsxd r11,[r10] / mov ecx,[r10+4] / add r10,8 / add r11,r8
//        ic: test ecx,ecx / je sonraki
//            mov rax,[r11] / xor rax,rdx / mov [r11],rax / add r11,8 / sub ecx,8 / jne ic
//        sonraki: dec r9d / jmp bolge
//  bitti: mov dword [r8+0x28], 1      ; flagi kur (bir dahaki cagri atlar)
//         pop'lar + [jmp ilk-parca | ret/ret imm16]
//
// Stack dengesi korunur, bayraklar fonksiyon girisinde onemsizdir,
// rax (donus degeri) push/pop ile korunur, XMM'e dokunulmaz.

static u32 EmitXorStub(std::vector<u8>& blob, bool entry, std::vector<Patch>& patches,
                       u8 retOpcode = 0xC3, u16 retImm16 = 0) {
    u32 S = (u32)blob.size();
    auto put = [&blob](std::initializer_list<u8> bs) { for (u8 b : bs) blob.push_back(b); };

    put({0x50, 0x51, 0x52, 0x53, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53}); // push rax,rcx,rdx,rbx,r8..r11
    // lea r8, [rip + (0 - (S+12+7))]  -> blob tabani (header)
    // (DIKKAT: once 4 sifir bayt yerlestir, SONRA poke et - Poke32 sinir kontrolu var)
    // 0x4C = REX.W|R -> 64-bit lea r8. 0x44 olsaydi lea r8d (32-bit, zero-extent)
    // olurdu ve ImageBase yuksek bitleri kesilirdi -> stub yanlis adresten okurdu!
    put({0x4C, 0x8D, 0x05});
    blob.resize(blob.size() + 4, 0);
    Poke32(blob, blob.size() - 4, (i32)(0 - (i64)(S + 12 + 7)));
    put({0x45, 0x8B, 0x08});                       // mov r9d, [r8]   (nRegions @0x00)
    put({0x4D, 0x8D, 0x90});                       // lea r10, [r8+tableOff]  (P_TBL)
    Patch tbl; tbl.kind = Patch::P_TBL; tbl.siteOff = (u32)blob.size();
    patches.push_back(tbl); blob.resize(blob.size() + 4, 0);
    put({0x49, 0x8B, 0x50, 0x08});                 // mov rdx, [r8+8] (anahtar @0x08)
    u32 jneDone = 0;
    if (entry) {
        put({0x41, 0x83, 0x78, 0x28, 0x00});       // cmp dword [r8+0x28], 0 (decrypt-once flagi)
        put({0x0F, 0x85}); jneDone = (u32)blob.size(); blob.resize(blob.size() + 4, 0); // jne bitti
        put({0x90, 0x90});                         // 2 x nop pad (zararsiz, akis devam eder)
    }

    u32 loopOff = (u32)blob.size();                // bolge dongusu
    put({0x45, 0x85, 0xC9});                       // test r9d, r9d
    put({0x0F, 0x84}); u32 jeSite = (u32)blob.size(); blob.resize(blob.size() + 4, 0); // je bitti
    put({0x4D, 0x63, 0x1A});                       // movsxd r11, dword [r10]  (off)
    put({0x41, 0x8B, 0x4A, 0x04});                 // mov ecx, [r10+4]         (len)
    put({0x49, 0x83, 0xC2, 0x08});                 // add r10, 8
    put({0x4D, 0x01, 0xC3});                       // add r11, r8              (r11 = blob+off)
    u32 innerOff = (u32)blob.size();               // ic dongu
    put({0x85, 0xC9});                             // test ecx, ecx
    put({0x0F, 0x84}); u32 je2Site = (u32)blob.size(); blob.resize(blob.size() + 4, 0); // je sonraki
    put({0x49, 0x8B, 0x03});                       // mov rax, [r11]
    put({0x48, 0x31, 0xD0});                       // xor rax, rdx
    put({0x49, 0x89, 0x03});                       // mov [r11], rax
    put({0x49, 0x83, 0xC3, 0x08});                 // add r11, 8
    put({0x83, 0xE9, 0x08});                       // sub ecx, 8
    put({0x0F, 0x85});                             // jne ic dongu
    blob.resize(blob.size() + 4, 0);
    Poke32(blob, blob.size() - 4, (i32)((i64)innerOff - (i64)blob.size()));
    u32 nextOff = (u32)blob.size();                // sonraki bolge
    put({0x41, 0xFF, 0xC9});                       // dec r9d
    put({0xE9});                                   // jmp bolge dongusu
    blob.resize(blob.size() + 4, 0);
    Poke32(blob, blob.size() - 4, (i32)((i64)loopOff - (i64)blob.size()));
    u32 doneOff = (u32)blob.size();                // bitti (flag kur + pop'lar)
    if (entry) {
        put({0x41, 0xC7, 0x40, 0x28, 0x01, 0x00, 0x00, 0x00}); // mov dword [r8+0x28], 1
        Poke32(blob, jneDone, (i32)((i64)doneOff - (i64)(jneDone + 4)));
    }
    Poke32(blob, jeSite,  (i32)((i64)doneOff - (i64)(jeSite + 4)));
    Poke32(blob, je2Site, (i32)((i64)nextOff - (i64)(je2Site + 4)));

    put({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5B, 0x5A, 0x59, 0x58}); // pop r11,r10,r9,r8,rbx,rdx,rcx,rax
    if (entry) {
        put({0xE9});                               // jmp ilk parca (P_STUBJ)
        Patch p; p.kind = Patch::P_STUBJ; p.siteOff = (u32)blob.size();
        patches.push_back(p); blob.resize(blob.size() + 4, 0);
    } else {
        blob.push_back(retOpcode);                 // ret / ret imm16
        if (retOpcode == 0xC2) { blob.push_back((u8)(retImm16 & 0xFF)); blob.push_back((u8)(retImm16 >> 8)); }
    }
    return S;
}

// ---- ARENA (v3) YARDIMCILARI -----------------------------------------------
static bool IeqStr(const std::string& a, const char* b) {
    size_t la = a.size(), lb = strlen(b);
    if (la != lb) return false;
    for (size_t i = 0; i < la; i++)
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return false;
    return true;
}
// IAT'de kernle32!VirtualAlloc / VirtualFree slotu ara (RVA dondurur)
static bool FindIatRva(const Core& c, const char* fn, u32& outRva) {
    for (auto& d : c.pe.imps) {
        std::string dn = d.name;
        for (auto& ch : dn) ch = (char)toupper((unsigned char)ch);
        if (dn.find("KERNEL32") == std::string::npos) continue;
        for (auto& f : d.funcs)
            if (IeqStr(f.name, fn)) { outRva = (u32)(f.iatAddr - c.pe.imgBase); return true; }
    }
    return false;
}

// ---- IAT IMPORT EKLEYICI (EVRENSELLIK: V4.1 guvenlik duzeltmesi) -----------
// Problemi: korunacak programin IAT'sinde VirtualAlloc/VirtualFree/ExitProcess
// OLMAYABILIR (as-needed link, nostdlib, mini oyunlar) -> stream/arena motoru
// build-time'da reddediyordu. Cevap: eksik API'leri IAT'ye EKLE.
//
// Yontem: yeni ".mpimp" section'i acilir, icerisine IKINCI bir kernel32 import
// descriptor'u yazilir (sadece eksik API'ler) ve ImportDirectory (DataDirectory
// [1]) yeni genisletilmis diziyi gosterecek sekilde yenilenir. Mevcut IAT
// slotlarina HICBIR sekilde dokunulmaz (programin fixup'li IAT adresleri
// korunur). Windows loader ayni DLL'i iki descriptor'dan da yukler (refcount)
// -> sorunsuz. Bound-imports temizlenir (cakisma onlenir).
// ---- GENISLETILEBILIR SECTION EKLEME (V4.1 EVRENSELLIK) -------------------
// 1) ByteInjector::AddSection (temiz yol — header'da slot varsa)
// 2) header doluysa: SizeOfHeaders buyutup header-pad'e yeni slot
// 3) o da olmazsa: SON SECTION'I raw+virtual buyutup sonuna ekle (chars birlestir)
// outRva = eklenen bos alanin basi. Kirmizi yol: son section chars'i zenginlesir.
static bool GrowAppendSection(PEFile& pe, MemImage& mem, const char* name, u32 size, u32 chars, u32& outRva) {
    ByteInjector bij;
    if (bij.AddSection(pe, mem, name, size, chars)) { outRva = pe.secs.back().va; return true; }
    auto dos = (PIMAGE_DOS_HEADER)pe.raw.data();
    auto nt  = (PIMAGE_NT_HEADERS)(pe.raw.data() + dos->e_lfanew);
    auto sh  = IMAGE_FIRST_SECTION(nt);
    u32 fa = pe.is64 ? ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.FileAlignment
                     : ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.FileAlignment;
    if (!fa) fa = 0x200;
    u32 sa = pe.is64 ? ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.SectionAlignment
                     : ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.SectionAlignment;
    if (!sa) sa = 0x1000;
    // 2) header-pad slot
    u8* slotAddr = (u8*)&sh[nt->FileHeader.NumberOfSections];
    size_t needEnd = (size_t)(slotAddr + sizeof(IMAGE_SECTION_HEADER) - pe.raw.data());
    u32 newHdr = ((u32)needEnd + fa - 1) / fa * fa;
    u32 firstRaw = 0xFFFFFFFF;
    for (auto& s : pe.secs) if (s.raw && s.raw < firstRaw) firstRaw = s.raw;
    if (newHdr <= firstRaw && firstRaw != 0xFFFFFFFF) {
        IMAGE_SECTION_HEADER nh = {};
        strncpy((char*)nh.Name, name, 8);
        nh.Misc.VirtualSize = size;
        u32 lve = 0, lre = 0;
        for (auto& s : pe.secs) { u32 ve = s.va + ((s.vSz + sa - 1) / sa) * sa; u32 re = s.raw + s.rawSz; if (ve > lve) lve = ve; if (re > lre) lre = re; }
        nh.VirtualAddress = lve; nh.SizeOfRawData = size; nh.PointerToRawData = lre;
        nh.Characteristics = chars;
        nt->FileHeader.NumberOfSections++; pe.numSec++;
        memcpy(slotAddr, &nh, sizeof(nh));
        if (pe.is64) ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.SizeOfHeaders = newHdr;
        else         ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.SizeOfHeaders = newHdr;
        u32 nis = lve + ((size + sa - 1) / sa) * sa;
        if (pe.is64) ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.SizeOfImage = nis;
        else         ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.SizeOfImage = nis;
        pe.raw.resize(lre + size, 0);
        SecInfo si; strncpy(si.name, name, 8); si.va = lve; si.vSz = size; si.raw = lre; si.rawSz = size; si.chars = chars;
        pe.secs.push_back(si); pe.imgSz = nis;
        mem.data.resize(nis, 0);
        outRva = lve;
        return true;
    }
    // 3) son section'i buyut
    {
        SecInfo& ls = pe.secs.back();
        auto lsh = &sh[nt->FileHeader.NumberOfSections - 1];
        u32 oldVSz = ls.vSz;
        u32 gap = (sa - (oldVSz & (sa - 1))) & (sa - 1);        // vSz->page kenarina kadar
        u32 appOff = oldVSz + gap;                              // yeni alan section-ici ofseti
        u32 newVSz = appOff + size;
        u32 newRawSz = ((newVSz + fa - 1) / fa) * fa;
        ls.vSz = newVSz; ls.rawSz = newRawSz;
        ls.chars |= chars;                                      // X/W/R birlestir
        // V4.6: buyuyen section DISCARDABLE ise bayragi temizle - mingw /nn debug
        // section'lari (mb86 sinifi) discardable; Windows loader bellek baskisinda
        // o sayfalari cope atabilir -> icine yazilan .maze/.mpimp kodu BUHARLASIR
        // (wine32'yi atlatir, gercek sistemde rastgele cokus). Kod artık o
        // section'da yasiyorsa discard edilemez olmali.
        if (ls.chars & 0x02000000u) ls.chars &= ~0x02000000u;
        lsh->Misc.VirtualSize = newVSz; lsh->SizeOfRawData = newRawSz;
        lsh->Characteristics = ls.chars;
        u32 nis = ls.va + ((newVSz + sa - 1) / sa) * sa;
        if (pe.is64) ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.SizeOfImage = nis;
        else         ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.SizeOfImage = nis;
        if (pe.raw.size() < (size_t)ls.raw + newRawSz) pe.raw.resize((size_t)ls.raw + newRawSz, 0);
        pe.imgSz = nis;
        mem.data.resize(nis, 0);
        outRva = ls.va + appOff;
        return true;
    }
}

static bool EnsureIatImports(Core& c, std::vector<std::string>& notes) {
    static const char* kWanted[] = { "VirtualAlloc", "VirtualFree", "ExitProcess" };
    std::vector<std::string> missing;
    for (auto* w : kWanted) { u32 r; if (!FindIatRva(c, w, r)) missing.push_back(w); }
    if (missing.empty()) return true;

    PEFile& pe = c.pe;
    MemImage& mem = c.mem;
    const u32 dSz = 20;                      // IMAGE_IMPORT_DESCRIPTOR
    u32 oldDitVa = 0, oldDitSize = 0;
    {
        auto dos = (PIMAGE_DOS_HEADER)pe.raw.data();
        auto nt  = (PIMAGE_NT_HEADERS)(pe.raw.data() + dos->e_lfanew);
        PIMAGE_DATA_DIRECTORY id = pe.is64
            ? &((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
            : &((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        oldDitVa = id->VirtualAddress; oldDitSize = id->Size;
        // bound imports ucur (yeni descriptor ile cakisma)
        PIMAGE_DATA_DIRECTORY bd = pe.is64
            ? &((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.DataDirectory[11]
            : &((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.DataDirectory[11];
        bd->VirtualAddress = 0; bd->Size = 0;
    }
    u32 copySz = 0;                          // NULL HARIC eski descriptor kopyasi
    // V4.2 DUZELTME: mingw import-dizin Size'i PAD'li (0x90 gibi); eski "Size-dSz"
    // hesabi NULL + ardindaki copu de kopyaliyor, yeni descriptor NULL'un arkasinda
    // kaliyor ve loader ORAYA HIC GELMIYOR (IAT cozulmez -> call [IAT] RVA'ya atlar).
    // Dogrusu: eski diziyi NULL'a kadar GEZ, gercek descriptor sayisini bul.
    if (oldDitVa && oldDitSize >= dSz) {
        u32 raw = pe.RvaToRaw(oldDitVa);
        if (raw && raw + oldDitSize <= pe.raw.size()) {
            while (copySz + dSz <= oldDitSize) {
                u32 oft = *(u32*)(pe.raw.data() + raw + copySz + 0);
                u32 nm  = *(u32*)(pe.raw.data() + raw + copySz + 12);
                u32 ft  = *(u32*)(pe.raw.data() + raw + copySz + 16);
                if (!oft && !nm && !ft) break;   // NULL terminator
                copySz += dSz;
            }
        }
        if (!copySz) copySz = oldDitSize - dSz;  // gezilemediyse eski davranis
    }

    u32 m = (u32)missing.size();
    u32 thunkSz = pe.is64 ? 8 : 4;
    u32 iltSize = (m + 1) * thunkSz;         // + NULL thunk
    u32 nameSize = 13;                       // "KERNEL32.DLL\0"
    u32 hintTotal = 0;
    for (auto& s : missing) hintTotal += 2 + (u32)s.size() + 1;
    hintTotal = (hintTotal + 1u) & ~1u;      // align2
    u32 ditSize = copySz + dSz + dSz;        // eski'ler + yeni desc + NULL
    u32 total = ditSize + iltSize + iltSize + nameSize + hintTotal + 16;

    // V4.1: AddSection header'da yer yoksa Basarisiz doner (UPX-unpack PE'lerde
    // header dolu). Yedek yol: SizeOfHeaders'i FileAlignment'a BUYUTUP section
    // header dizisini dosyanin ilk section raw'ina kadar uzanan pad'de
    // genisletmek (raw'lar dokunulmaz, klasik "header growth" tekniği).
    u32 base = 0;
    if (!GrowAppendSection(pe, mem, ".mpimp", total,
                        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE, base)) {
        return false;
    }
    u8* img = mem.data.data();

    auto poke32 = [&](u32 off, u32 v) {
        img[base + off + 0] = (u8)(v & 0xFF);       img[base + off + 1] = (u8)((v >> 8) & 0xFF);
        img[base + off + 2] = (u8)((v >> 16) & 0xFF); img[base + off + 3] = (u8)((v >> 24) & 0xFF);
    };
    auto pokeThunk = [&](u32 off, u64 v) {
        for (u32 i = 0; i < thunkSz; i++) img[base + off + i] = (u8)(v >> (8 * i));
    };

    u32 offDit = 0, offIlt = ditSize, offIat = offIlt + iltSize, offName = offIat + iltSize, offHint = offName + nameSize;
    memset(img + base, 0, total);            // guvenli bosluk (0xCC kalmasin)

    // 1) eski descriptor'lari KOPYALA (NULL hariic)
    if (copySz) {
        u32 oldRaw = pe.RvaToRaw(oldDitVa);
        for (u32 i = 0; i < copySz; i++)
            img[base + offDit + i] = (oldRaw + i < pe.raw.size()) ? pe.raw[oldRaw + i] : 0;
    }
    // 2) yeni descriptor: ILT + Name + IAT
    poke32(offDit + copySz + 0,  base + offIlt);    // OriginalFirstThunk
    poke32(offDit + copySz + 12, base + offName);   // Name
    poke32(offDit + copySz + 16, base + offIat);    // FirstThunk
    // 3) ILT + IAT (hint RVA'lari; loader uzerine adres yazar)
    u32 hintOff = offHint;
    for (u32 i = 0; i < m; i++) {
        pokeThunk(offIlt + i * thunkSz, (u64)(base + hintOff));
        pokeThunk(offIat + i * thunkSz, (u64)(base + hintOff));
        // hint name: u16 hint=0 + "Isim\0"
        img[base + hintOff] = 0; img[base + hintOff + 1] = 0;
        memcpy(img + base + hintOff + 2, missing[i].c_str(), missing[i].size() + 1);
        hintOff += 2 + (u32)missing[i].size() + 1;
        hintOff = (hintOff + 1) & ~1u;       // align2
    }
    // 4) DLL adi
    memcpy(img + base + offName, "KERNEL32.DLL\0", 13);
    // 5) DataDirectory[1] repoint
    {
        auto dos = (PIMAGE_DOS_HEADER)pe.raw.data();
        auto nt  = (PIMAGE_NT_HEADERS)(pe.raw.data() + dos->e_lfanew);
        PIMAGE_DATA_DIRECTORY id = pe.is64
            ? &((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
            : &((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        id->VirtualAddress = base + offDit;
        id->Size = ditSize;
    }
    // 6) motor icin imps'e ekle (FindIatRva boylece bulur)
    {
        ImpDll d; d.name = "KERNEL32.DLL";
        for (u32 i = 0; i < m; i++) {
            ImpFunc f; f.name = missing[i];
            f.iatAddr = pe.imgBase + base + offIat + (u64)i * thunkSz;
            d.funcs.push_back(f);
        }
        pe.imps.push_back(d);
    }
    for (auto& s : missing) notes.push_back("IAT'ye eklendi: kernel32!" + s + " (.mpimp section)");
    return true;
}

// ARENA CLEANUP BLOK (her benzersiz ret encoding'i icin bir tane) - ARENA ICINDE
// YASAR. HICBIR API CAGIRMAZ (freed-memory fetch yasak!) - selfBase'i stack
// shadow'a yazar, arena/maze ayrimini flag'ler ve MAZE'deki farewell'e atlar.
// Gercek Windows'ta arena'dan VirtualFree + ret = freed fetch = crash olurdu;
// free islemini MAZE'deki farewell yapar (o hep yasar) -> crash yok.
//
//  push rax                       50                   ; donus degeri korunur
//  sub  rsp, 0x20                 48 83 EC 20          ; shadow space
//  lea  r8, [rip - X]             4C 8D 05 dd32        ; r8 = selfBase (arena veya maze blob)
//  mov  [rsp], r8                 4C 89 04 24          ; shadow[0] = selfBase
//  mov  rax, gs:[0x60]            65 48 8B 04 25 60... ; PEB
//  mov  rax, [rax+0x10]           48 8B 40 10          ; PEB.ImageBaseAddress
//  mov  edx, imgSize              BA imm32             ; (P_ARENA_IMM which=0)
//  add  rax, rdx                  48 01 D0             ; limit = imgBase + imgSize
//  cmp  rax, r8                   4C 39 C0             ; limit < selfBase -> ARENA
//  jb   arenaFlag                 72 rel8
//  mov  dword [rsp+8], 0          C7 44 24 08 00...    ; maze/fallback -> free YOK
//  jmp  farewell                  E9 rel32             ; blob-ici, yer-bagimsiz
// arenaFlag:
//  mov  dword [rsp+8], 1          C7 44 24 08 01...    ; arena -> farewell free yapar
//  jmp  farewell                  E9 rel32
struct ArenaJmpSite { u32 siteOff; u32 key; };   // cleanup->farewell jmp yamalari
static u32 EmitArenaCleanup(std::vector<u8>& blob, std::vector<Patch>& patches,
                            std::vector<ArenaJmpSite>& jmpSites, u32 key) {
    u32 S = (u32)blob.size();
    auto put = [&blob](std::initializer_list<u8> bs) { for (u8 b : bs) blob.push_back(b); };
    put({0x50});                                   // push rax
    put({0x48, 0x83, 0xEC, 0x20});                 // sub rsp,0x20
    put({0x4C, 0x8D, 0x05});                       // lea r8,[rip - (S+5+7)] (push1+sub4+lea7)
    blob.resize(blob.size() + 4, 0);
    Poke32(blob, blob.size() - 4, (i32)(0 - (i64)(S + 5 + 7)));
    put({0x4C, 0x89, 0x04, 0x24});                 // mov [rsp],r8
    put({0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00}); // mov rax,gs:[0x60]
    put({0x48, 0x8B, 0x40, 0x10});                 // mov rax,[rax+0x10]
    put({0xBA});                                   // mov edx, imgSize
    { Patch p; p.kind = Patch::P_ARENA_IMM; p.siteOff = (u32)blob.size(); p.immWhich = 0; patches.push_back(p); }
    blob.resize(blob.size() + 4, 0);
    put({0x48, 0x01, 0xD0});                       // add rax,rdx
    put({0x4C, 0x39, 0xC0});                       // cmp rax,r8
    put({0x72}); u32 jbSite = (u32)blob.size(); blob.push_back(0); // jb arenaFlag
    put({0xC7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00, 0x00});       // mov dword [rsp+8],0
    put({0xE9}); u32 jm1 = (u32)blob.size(); blob.resize(blob.size() + 4, 0);
    u32 arenaFlag = (u32)blob.size();
    blob[jbSite] = (u8)(arenaFlag - (jbSite + 1));
    put({0xC7, 0x44, 0x24, 0x08, 0x01, 0x00, 0x00, 0x00});       // mov dword [rsp+8],1
    put({0xE9}); u32 jm2 = (u32)blob.size(); blob.resize(blob.size() + 4, 0);
    jmpSites.push_back({ jm1, key });
    jmpSites.push_back({ jm2, key });
    return S;
}

// ARENA FAREWELL (MAZE'DE YASAR - her zaman erisilebilir): VirtualFree'i MAZE'DEN
// cagirir (disp maze-static, runtime delta-fix GEREKMEZ), sonra ORIJINAL ret'i.
//
//  mov  rcx, [rsp]                48 8B 0C 24          ; selfBase (cleanup yazdi)
//  cmp  dword [rsp+8], 0          83 7C 24 08 00
//  je   nofree                    74 rel8
//  xor  edx, edx                  31 D2                ; dwSize=0
//  mov  r8d, 0x8000               41 B8 00 80 00 00    ; MEM_RELEASE (3. arg = r8d!)
//  call qword [rip+d]             FF 15 dd32           ; VirtualFree (P_ARENA_VF, maze-static)
// nofree:
//  add  rsp, 0x20                 48 83 C4 20
//  pop  rax                       58
//  ret [imm16]                    C3 / C2 iw           ; ORIJINAL ret
static u32 EmitArenaFarewell(std::vector<u8>& blob, std::vector<Patch>& patches,
                             u8 retOp, u16 retImm16, u32 iatVfRva) {
    auto put = [&blob](std::initializer_list<u8> bs) { for (u8 b : bs) blob.push_back(b); };
    u32 S = (u32)blob.size();
    put({0x48, 0x8B, 0x0C, 0x24});                 // mov rcx,[rsp]
    put({0x83, 0x7C, 0x24, 0x08, 0x00});           // cmp dword [rsp+8],0
    put({0x74}); u32 jeSite = (u32)blob.size(); blob.push_back(0); // je nofree
    put({0x31, 0xD2});                             // xor edx,edx
    put({0x41, 0xB8, 0x00, 0x80, 0x00, 0x00});     // mov r8d,0x8000 (MEM_RELEASE)
    put({0xFF, 0x15});                             // call qword [rip+d] VirtualFree
    { Patch p; p.kind = Patch::P_ARENA_VF; p.siteOff = (u32)blob.size(); p.immValue = iatVfRva; patches.push_back(p); }
    blob.resize(blob.size() + 4, 0);
    u32 nofree = (u32)blob.size();
    blob[jeSite] = (u8)(nofree - (jeSite + 1));
    put({0x48, 0x83, 0xC4, 0x20});                 // add rsp,0x20
    put({0x58});                                   // pop rax
    blob.push_back(retOp);
    if (retOp == 0xC2) { blob.push_back((u8)(retImm16 & 0xFF)); blob.push_back((u8)(retImm16 >> 8)); }
    return S;
}

// ARENA GIRIS STUB (trambolin buraya gelir; header 0x40 bayt, stub +0x40'ta)
//
//  push rax,rcx,rdx,rbx,r8,r9,r10,r11,r12,r15 (10 push = 80)
//  sub  rsp, 0x28                                 ; 8+80+40 = 128 -> %16 = 0 (call hazir)
//  lea  rbx, [rip - X]                            ; rbx = blob tabani (maze'de)
//  mov  rax, gs:[0x60] / mov rax,[rax+0x10]       ; imgBase (PEB)
//  mov  edx, imgSize / add rax,rdx                ; + SizeOfImage
//  add rax,0xFFFF / shr 16 / shl 16               ; 64K hizala -> HINT (module yakin!)
//  mov r11, rax / mov r10d, 8                     ; hint, deneme sayisi
// try: VirtualAlloc(hint, arenaSize, 0x3000, 0x40)
//      rax!=0 -> got | hint += 0x400000, dec, loop
// FALLBACK (8 deneme bitti): v2 yerinde cozme (decrypt-once flagi ile) -> maze'de kos
// got:  r12 = arenaBase - blobBase (delta)
//       bolge tablosunu gezip sifreli span'lari arena'ya KOPYALA+COZ (ayni offsetler)
//       site tablosunu gezip disp'lerden delta'yi CIKAR (modul -> arena tasindi)
//       target = arenaBase + ilkParca -> jmpSlot'a yaz
// restore: pop'lar + jmp qword [rip->jmpSlot]      ; jmpSlot maze header'da (0x38)
static u32 EmitArenaStub(std::vector<u8>& blob, std::vector<Patch>& patches, u32 iatVaRva) {
    u32 S = (u32)blob.size();
    auto put = [&blob](std::initializer_list<u8> bs) { for (u8 b : bs) blob.push_back(b); };
    auto imm = [&](u32 which) { Patch p; p.kind = Patch::P_ARENA_IMM; p.siteOff = (u32)blob.size(); p.immWhich = which; patches.push_back(p); blob.resize(blob.size() + 4, 0); };

    put({0x50, 0x51, 0x52, 0x53, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x57}); // 10 push
    put({0x48, 0x83, 0xEC, 0x28});                 // sub rsp,0x28
    put({0x48, 0x8D, 0x1D});                       // lea rbx,[rip - (S+16+4+7)]
    blob.resize(blob.size() + 4, 0);
    Poke32(blob, blob.size() - 4, (i32)(0 - (i64)(S + 16 + 4 + 7)));
    put({0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00}); // mov rax,gs:[0x60]
    put({0x48, 0x8B, 0x40, 0x10});                 // mov rax,[rax+0x10]
    put({0xBA}); imm(0);                           // mov edx, imgSize
    put({0x48, 0x01, 0xD0});                       // add rax,rdx
    put({0x48, 0x05, 0xFF, 0xFF, 0x00, 0x00});     // add rax,0xFFFF
    put({0x48, 0xC1, 0xE8, 0x10});                 // shr rax,16
    put({0x48, 0xC1, 0xE0, 0x10});                 // shl rax,16
    put({0x4C, 0x8B, 0xD8});                       // mov r11,rax   (hint)
    put({0x41, 0xBA, 0x08, 0x00, 0x00, 0x00});     // mov r10d,8
    u32 tryOff = (u32)blob.size();
    put({0x4C, 0x89, 0xD9});                       // mov rcx,r11   (lpAddress = hint)
    put({0xBA}); imm(3);                           // mov edx, arenaSize
    put({0x41, 0xB8, 0x00, 0x30, 0x00, 0x00});     // mov r8d,0x3000 (COMMIT|RESERVE)
    put({0x41, 0xB9, 0x40, 0x00, 0x00, 0x00});     // mov r9d,0x40   (PAGE_EXECUTE_READWRITE)
    put({0xFF, 0x15});                             // call qword [rip+d] VirtualAlloc
    { Patch p; p.kind = Patch::P_ARENA_VA; p.siteOff = (u32)blob.size(); p.immValue = iatVaRva; patches.push_back(p); }
    blob.resize(blob.size() + 4, 0);
    put({0x48, 0x85, 0xC0});                       // test rax,rax
    put({0x0F, 0x85}); u32 jneGot = (u32)blob.size(); blob.resize(blob.size() + 4, 0);
    put({0x49, 0x81, 0xC3, 0x00, 0x00, 0x40, 0x00}); // add r11,0x400000
    put({0x41, 0xFF, 0xCA});                       // dec r10d
    put({0x75}); u32 jneTry = (u32)blob.size(); blob.push_back(0);
    put({0xEB}); u32 jmpFb = (u32)blob.size(); blob.push_back(0);
    u32 gotOff = (u32)blob.size();
    Poke32(blob, jneGot, (i32)((i64)gotOff - (i64)(jneGot + 4)));
    blob[jneTry] = (u8)(tryOff - (jneTry + 1));

    // ---- got: rax = arenaBase ----
    put({0x49, 0x89, 0xC4});                       // mov r12,rax
    put({0x49, 0x29, 0xDC});                       // sub r12,rbx   (delta)
    put({0x48, 0x8B, 0x53, 0x08});                 // mov rdx,[rbx+8]  (anahtar)
    put({0x44, 0x8B, 0x0B});                       // mov r9d,[rbx]    (nRegions)
    put({0x4C, 0x8D, 0x93}); imm(1);               // lea r10,[rbx+tableOff]
    u32 cpReg = (u32)blob.size();
    put({0x45, 0x85, 0xC9});                       // test r9d,r9d
    put({0x0F, 0x84}); u32 jeCpDone = (u32)blob.size(); blob.resize(blob.size() + 4, 0);
    put({0x4D, 0x63, 0x1A});                       // movsxd r11,[r10]  (off)
    put({0x41, 0x8B, 0x4A, 0x04});                 // mov ecx,[r10+4]   (len)
    put({0x49, 0x83, 0xC2, 0x08});                 // add r10,8
    put({0x49, 0x01, 0xDB});                       // add r11,rbx       (src = blob+off)
    put({0x4F, 0x8D, 0x3C, 0x23});                 // lea r15,[r11+r12] (dst = src+delta)
    u32 cpIn = (u32)blob.size();
    put({0x85, 0xC9});                             // test ecx,ecx
    put({0x0F, 0x84}); u32 jeCpNext = (u32)blob.size(); blob.resize(blob.size() + 4, 0);
    put({0x49, 0x8B, 0x03});                       // mov rax,[r11]
    put({0x48, 0x31, 0xD0});                       // xor rax,rdx
    put({0x49, 0x89, 0x07});                       // mov [r15],rax
    put({0x49, 0x83, 0xC3, 0x08});                 // add r11,8
    put({0x49, 0x83, 0xC7, 0x08});                 // add r15,8
    put({0x83, 0xE9, 0x08});                       // sub ecx,8
    put({0x0F, 0x85}); u32 jneCpIn = (u32)blob.size(); blob.resize(blob.size() + 4, 0);
    u32 cpNext = (u32)blob.size();
    Poke32(blob, jeCpNext, (i32)((i64)cpNext - (i64)(jeCpNext + 4)));
    Poke32(blob, jneCpIn, (i32)((i64)cpIn - (i64)(jneCpIn + 4)));
    put({0x41, 0xFF, 0xC9});                       // dec r9d
    put({0xE9}); u32 jmpCpReg = (u32)blob.size(); blob.resize(blob.size() + 4, 0);
    u32 cpDone = (u32)blob.size();
    Poke32(blob, jeCpDone, (i32)((i64)cpDone - (i64)(jeCpDone + 4)));
    Poke32(blob, jmpCpReg, (i32)((i64)cpReg - (i64)(jmpCpReg + 4)));

    // ---- delta-fix: disp'lerden delta cikar (modul -> arena) ----
    put({0x44, 0x8B, 0x4B, 0x2C});                 // mov r9d,[rbx+0x2C] (nSites)
    put({0x4C, 0x8D, 0x93}); imm(2);               // lea r10,[rbx+sitesOff]
    u32 fxLp = (u32)blob.size();
    put({0x45, 0x85, 0xC9});                       // test r9d,r9d
    put({0x0F, 0x84}); u32 jeFxDone = (u32)blob.size(); blob.resize(blob.size() + 4, 0);
    put({0x4D, 0x63, 0x1A});                       // movsxd r11,[r10]  (site blob off)
    put({0x49, 0x83, 0xC2, 0x04});                 // add r10,4
    put({0x49, 0x01, 0xDB});                       // add r11,rbx       (blob+site - RBX YOKSA YAZI HEAP'E GIDER!)
    put({0x4D, 0x01, 0xE3});                       // add r11,r12       (arena+off)
    put({0x41, 0x8B, 0x03});                       // mov eax,[r11]
    put({0x44, 0x29, 0xE0});                       // sub eax,r12d      ; disp -= (i32)delta
    put({0x41, 0x89, 0x03});                       // mov [r11],eax
    put({0x41, 0xFF, 0xC9});                       // dec r9d
    put({0xE9}); u32 jmpFx = (u32)blob.size(); blob.resize(blob.size() + 4, 0);
    u32 fxDone = (u32)blob.size();
    Poke32(blob, jeFxDone, (i32)((i64)fxDone - (i64)(jeFxDone + 4)));
    Poke32(blob, jmpFx, (i32)((i64)fxLp - (i64)(jmpFx + 4)));

    // ---- hedef = arenaBase + ilkParca ----
    put({0x4C, 0x8B, 0xDB});                       // mov r11,rbx
    put({0x4D, 0x01, 0xE3});                       // add r11,r12       (arenaBase)
    put({0x49, 0x81, 0xC3}); imm(5);               // add r11, firstOff
    put({0x4C, 0x89, 0x5B, 0x38});                 // mov [rbx+0x38],r11 (jmpSlot) - REX 4C: rm=rbx, reg=r11
    put({0xEB}); u32 jmpRest = (u32)blob.size(); blob.push_back(0);

    // ---- fallback: yerinde cozme (v2 yolu, taban rbx) ----
    u32 fbOff = (u32)blob.size();
    blob[jmpFb] = (u8)(fbOff - (jmpFb + 1));
    put({0x8B, 0x43, 0x28});                       // mov eax,[rbx+0x28] (decrypt-once flagi)
    put({0x85, 0xC0});                             // test eax,eax
    put({0x0F, 0x84}); u32 jeFbDone = (u32)blob.size(); blob.resize(blob.size() + 4, 0);
    put({0x44, 0x8B, 0x0B});                       // mov r9d,[rbx]
    put({0x48, 0x8B, 0x53, 0x08});                 // mov rdx,[rbx+8]
    put({0x4C, 0x8D, 0x93}); imm(1);               // lea r10,[rbx+tableOff]
    u32 fbReg = (u32)blob.size();
    put({0x45, 0x85, 0xC9});
    put({0x0F, 0x84}); u32 jeFbFlag = (u32)blob.size(); blob.resize(blob.size() + 4, 0);
    put({0x4D, 0x63, 0x1A});
    put({0x41, 0x8B, 0x4A, 0x04});
    put({0x49, 0x83, 0xC2, 0x08});
    put({0x49, 0x01, 0xDB});                       // add r11,rbx
    u32 fbIn = (u32)blob.size();
    put({0x85, 0xC9});
    put({0x0F, 0x84}); u32 jeFbNext = (u32)blob.size(); blob.resize(blob.size() + 4, 0);
    put({0x49, 0x8B, 0x03});
    put({0x48, 0x31, 0xD0});
    put({0x49, 0x89, 0x03});
    put({0x49, 0x83, 0xC3, 0x08});
    put({0x83, 0xE9, 0x08});
    put({0x0F, 0x85}); u32 jneFbIn = (u32)blob.size(); blob.resize(blob.size() + 4, 0);
    u32 fbNext = (u32)blob.size();
    Poke32(blob, jeFbNext, (i32)((i64)fbNext - (i64)(jeFbNext + 4)));
    Poke32(blob, jneFbIn, (i32)((i64)fbIn - (i64)(jneFbIn + 4)));
    put({0x41, 0xFF, 0xC9});
    put({0xE9}); u32 jmpFbReg = (u32)blob.size(); blob.resize(blob.size() + 4, 0);
    u32 fbFlag = (u32)blob.size();
    Poke32(blob, jeFbFlag, (i32)((i64)fbFlag - (i64)(jeFbFlag + 4)));
    Poke32(blob, jmpFbReg, (i32)((i64)fbReg - (i64)(jmpFbReg + 4)));
    put({0xC7, 0x43, 0x28, 0x01, 0x00, 0x00, 0x00}); // mov dword [rbx+0x28],1
    u32 fbDone = (u32)blob.size();
    Poke32(blob, jeFbDone, (i32)((i64)fbDone - (i64)(jeFbDone + 4)));
    put({0x4C, 0x8D, 0x9B}); imm(5);               // lea r11,[rbx+firstOff]
    put({0x4C, 0x89, 0x5B, 0x38});                 // mov [rbx+0x38],r11 (jmpSlot)
    blob[jmpRest] = (u8)((u32)blob.size() - (jmpRest + 1));

    // ---- restore + slot'tan jmp ----
    put({0x48, 0x83, 0xC4, 0x28});                 // add rsp,0x28
    put({0x41, 0x5F, 0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5B, 0x5A, 0x59, 0x58});
    put({0xFF, 0x25});                             // jmp qword [rip+d] -> jmpSlot (blob+0x38 = S-8)
    u32 cur = (u32)blob.size();
    blob.resize(cur + 4, 0);                       // ONCE rezerve et (Poke32 sinir kontrolu sessiz atlamasin!)
    Poke32(blob, cur, (i32)((i64)(S - 8) - (i64)(cur + 4)));  // slot = header'in 0x38'i = S-8
    return (u32)blob.size();  // stubEnd (mutlak blob ofseti)
}

// ============================================================================
//  V4 TEK TEK (STREAM) YARDIMCILARI
//  Tasarim: V4_TekTek_Blueprint.txt (MZE3 / MzBlk / MzSite / thunk / stage)
//  Konvansiyon: r10d = parca id (thunk kurar), conv-reg = stage adresi
//  (conv: cagirilan fonksiyonun KULLANMADIGI callee-saved reg; dis call'lar
//   ABI geregi callee-saved'i korur -> konvansiyon call'lerden sag kalir).
//  Stage yigin cercevesi: pushfq + 7 push + sub 0x30 (lokal: pid,len,siteFirst,
//  nSitesCrc,delta,slot) -> komutun kendi yigin goruntusuna dokunulmaz.
// ============================================================================

// Stage + cleanup blok(lari) emay eder; template = [stage][cleanup..]
// conv-reg SINIRI: yalniz r12/r13/r14/r15 (tum REX formlari ayni sabitler:
// B=1 her zaman, reg3 = conv&7). BuildStream baska reg secerse reddeder.
struct StreamStageInfo {
    u32 stageOff = 0;                    // template-relatif (0)
    u32 templateLen = 0;
    u32 slotImmPos = 0;                  // slotOff imm32'nin template-relatif konumu
    std::vector<u32> clDispPos;          // cleanup jmp farewell disp (template-rel)
    std::vector<u32> clJmpEnd;           // disp sonrasi (template-rel)
    u32 crcDispPos = 0;                  // G2 CRC-fail jmp crcFarewell disp (template-rel; runtime yama)
    u32 crcJmpEnd = 0;                   // disp sonrasi (template-rel)
};
static void EmitStreamStage(std::vector<u8>& blob, std::vector<Patch>& patches,
                            bool hardened, u32 nPieces, u32 nCleanup,
                            u8 convReg, StreamStageInfo& out) {
    u32 S = (u32)blob.size();
    auto put = [&blob](std::initializer_list<u8> bs) { for (u8 b : bs) blob.push_back(b); };
    auto put4 = [&](u32 v) { for (int i = 0; i < 4; i++) blob.push_back((u8)(v >> (8 * i))); };
    auto imm = [&](u32 which) {
        Patch p; p.kind = Patch::P_ARENA_IMM; p.siteOff = (u32)blob.size(); p.immWhich = which;
        patches.push_back(p); put4(0);
    };
    u8 c3 = (u8)(convReg & 7);           // reg3 (r12..r15 -> 0..3)

    out.stageOff = 0;
    // ---- giris: bayraklar + registerlar + cerceve ----
    put({0x9C});                                                    // pushfq
    put({0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53}); // push rax,rcx,rdx,r8,r9,r10,r11
    put({0x48, 0x83, 0xEC, 0x30});                                  // sub rsp,0x30
    put({0x44, 0x89, 0x54, 0x24, 0x00});                            // mov [rsp+0x00],r10d (pid; REX 44: B=0 -> base=rsp)
    put({0x41, 0x81, 0xFA}); put4(nPieces);                         // cmp r10d,nPieces
    put({0x0F, 0x83});
    u32 jaCl = (u32)blob.size(); put4(0);                                     // jae clDispatch (sonradan)
    // V4.2: blobBase -> r11 ONCE; r12 her stage girisinde blob'daki ARENA_PTR'den
    //  YENIDEN yuklenir -> korunan fonksiyon r12'yi serbest kullanabilir (ABI-saydam).
    put({0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00});    // mov rax,gs:[0x60]
    put({0x48, 0x8B, 0x40, 0x10});                                  // mov rax,[rax+0x10]
    put({0x41, 0xB9}); imm(4);                                      // mov r9d,mazeRva
    put({0x4C, 0x01, 0xC8});                                        // add rax,r9 (R=1: r9 REG-field)
    put({0x49, 0x89, 0xC3});                                        // mov r11,rax
    put({0x4D, 0x8B, 0xA3, 0x40, 0x00, 0x00, 0x00});                // mov r12,[r11+0x40] (ARENA_PTR; V4.2)
    // ---- slot = conv + slotOff ----
    put({0x41, 0xB9});                                              // mov r9d, slotOff
    out.slotImmPos = (u32)blob.size() - S;
    imm(16);                                                        // slotBase (stub per-call yamar)
    put({0x4B, 0x8D, 0x0C, (u8)(0x08 | c3)});                       // lea rcx,[conv+r9*1]
    put({0x48, 0x89, 0x4C, 0x24, 0x28});                            // mov [rsp+0x28],rcx
    // ---- &blk[pid] -> r9 ----
    put({0x44, 0x89, 0xD0});                                        // mov eax,r10d
    put({0xC1, 0xE0, 0x04});                                        // shl eax,4
    put({0x05}); imm(6);                                            // add eax,blockTblOff
    put({0x4D, 0x8D, 0x0C, 0x03});                                  // lea r9,[r11+rax] (R=1)
    // ---- blk alanlari ----
    put({0x41, 0x8B, 0x51, 0x04});                                  // mov edx,[r9+4] (len)
    put({0x89, 0x54, 0x24, 0x08});                                  // mov [rsp+8],edx
    put({0x45, 0x8B, 0x51, 0x08});                                  // mov r10d,[r9+8] (siteFirst; rm=001=r9)
    put({0x44, 0x89, 0x54, 0x24, 0x10});                            // mov [rsp+0x10],r10d
    put({0x45, 0x8B, 0x51, 0x0C});                                  // mov r10d,[r9+12] (nSitesCrc; rm=001=r9)
    put({0x44, 0x89, 0x54, 0x24, 0x18});                            // mov [rsp+0x18],r10d
    put({0x45, 0x8B, 0x01});                                        // mov r8d,[r9] (encOff; reg=000+R=r8, rm=001=r9)
    // ---- WIPE-BEHIND: slot 32B sifirla ----
    put({0x31, 0xC0});                                              // xor eax,eax
    put({0x48, 0x89, 0x01});                                        // mov [rcx],rax
    put({0x48, 0x89, 0x41, 0x08});                                  // mov [rcx+8],rax
    put({0x48, 0x89, 0x41, 0x10});                                  // mov [rcx+16],rax
    put({0x48, 0x89, 0x41, 0x18});                                  // mov [rcx+24],rax
    // ---- G3 decoy (yalniz hardened) ----
    if (hardened) {
        u32 jneNd = 0;
        put({0x0F, 0x31});                                          // rdtsc
        put({0x48, 0x31, 0xD0});                                    // xor rax,rdx
        put({0xA8, 0x03});                                          // test al,3
        jneNd = (u32)blob.size(); put({0x75, 0x00});                // jne nodec
        put({0xC1, 0xE8, 0x0C});                                    // shr eax,12
        put({0x25, 0x03, 0x00, 0x00, 0x00});                        // and eax,3
        put({0x4D, 0x8D, 0x8C, 0xC3}); imm(30);                     // lea r9,[r11+rax*8+decoyTblOff] (R=1)
        put({0x41, 0x8B, 0x51, 0x04});                              // mov edx,[r9+4] (dlen)
        put({0x41, 0x8B, 0x01});                                    // mov eax,[r9] (doff)
        put({0x4D, 0x8D, 0x0C, 0x03});                              // lea r9,[r11+rax] (src; R=1)
        put({0x4D, 0x8B, 0x53, 0x08});                              // mov r10,[r11+8] (K)
        u32 dlp = (u32)blob.size();
        put({0x49, 0x8B, 0x01});                                    // mov rax,[r9]
        put({0x4C, 0x31, 0xD0});                                    // xor rax,r10
        put({0x48, 0x89, 0x01});                                    // mov [rcx],rax
        put({0x49, 0x83, 0xC1, 0x08});                              // add r9,8
        put({0x48, 0x83, 0xC1, 0x08});                              // add rcx,8
        put({0x83, 0xEA, 0x08});                                    // sub edx,8
        put({0x75}); blob.push_back((u8)(dlp - (blob.size() + 1))); // jne dloop
        // slot'u geri al + tekrar sil (decoy izini yok et)
        put({0x48, 0x8B, 0x4C, 0x24, 0x28});                        // mov rcx,[rsp+0x28]
        put({0x31, 0xC0});                                          // xor eax,eax
        put({0x48, 0x89, 0x01});                                    // mov [rcx],rax
        put({0x48, 0x89, 0x41, 0x08});                              // mov [rcx+8],rax
        put({0x48, 0x89, 0x41, 0x10});                              // mov [rcx+16],rax
        put({0x48, 0x89, 0x41, 0x18});                              // mov [rcx+24],rax
        blob[jneNd + 1] = (u8)((u32)blob.size() - (jneNd + 2));     // nodec:
    }
    // ---- gercek parca: blobBase+encOff -> slot (XOR K) ----
    put({0x4F, 0x8D, 0x0C, 0x03});                                  // lea r9,[r11+r8] (R=1,X=1)
    put({0x4D, 0x8B, 0x53, 0x08});                                  // mov r10,[r11+8] (K)
    put({0x8B, 0x54, 0x24, 0x08});                                  // mov edx,[rsp+8] (len)
    u32 clp = (u32)blob.size();
    put({0x49, 0x8B, 0x01});                                        // mov rax,[r9]
    put({0x4C, 0x31, 0xD0});                                        // xor rax,r10
    put({0x48, 0x89, 0x01});                                        // mov [rcx],rax
    put({0x49, 0x83, 0xC1, 0x08});                                  // add r9,8
    put({0x48, 0x83, 0xC1, 0x08});                                  // add rcx,8
    put({0x83, 0xEA, 0x08});                                        // sub edx,8
    put({0x75}); blob.push_back((u8)(clp - (blob.size() + 1)));     // jne cpy
    put({0x48, 0x8B, 0x4C, 0x24, 0x28});                            // mov rcx,[rsp+0x28] (slot geri yukle; copy loop rcx'i len ilerletti)
    // ---- delta = slot - (blobBase+encOff) ----
    put({0x4F, 0x8D, 0x0C, 0x03});                                  // lea r9,[r11+r8] (R=1,X=1)
    put({0x48, 0x89, 0xC8});                                        // mov rax,rcx
    put({0x4C, 0x29, 0xC8});                                        // sub rax,r9 (R=1)
    put({0x48, 0x89, 0x44, 0x24, 0x20});                            // mov [rsp+0x20],rax
    // ---- G2 CRC-8 (yalniz hardened): poly 0x07, slot[0..len), TABANLI ----
    //  DUZELTME 1: CRC fixup'tan ONCE hesaplanmali (build CRC'si yamali final
    //  baytlar uzerinden; runtime cozulen slot baytlari fixup oncesi aynidir).
    //  DUZELTME 2: eski dongu byte basina 1 tur yapiyordu (gercek CRC-8 8 tur
    //  ister) + "mov r8d,edx" 44 89 D0 olarak emit edilmisti (o = mov eax,r10d!).
    //  Yeni yol: 256B tabanli CRC-8 (.maze'de plaintext jenerik tablo):
    //  acc = tbl[acc ^ byte] - build tarafindaki bit-serial CRC-8 ile birebir.
    //  r11 (blobBase) BOZULMAZ -> geri yukleme bloku kaldirildi (9B kazanc).
    u32 crcJne = 0;
    u32 crcFailJne = 0;   // jne crcFail disp konumu (crcFail bloku tail'den SONRA emit edilir)
    if (hardened) {
        put({0x8B, 0x54, 0x24, 0x18});                              // mov edx,[rsp+0x18] (packed)
        put({0xC1, 0xEA, 0x08});                                    // shr edx,8 (beklenen crc -> dl)
        put({0x49, 0x89, 0xC9});                                    // mov r9,rcx (ptr = SLOT! DUZELTME: eksikti - r9 decrypt loop'unun src ucunda kalmisti, CRC sifreli kaynak sonrasi baytlari okuyordu)
        put({0x44, 0x8B, 0x54, 0x24, 0x08});                        // mov r10d,[rsp+8] (len)
        put({0x45, 0x31, 0xC0});                                    // xor r8d,r8d (acc)
        u32 cl = (u32)blob.size();
        put({0x41, 0x0F, 0xB6, 0x01});                              // movzx eax,byte [r9]
        put({0x49, 0xFF, 0xC1});                                    // inc r9
        put({0x44, 0x31, 0xC0});                                    // xor eax,r8d (index = b ^ acc)
        put({0x83, 0xE0, 0xFF});                                    // and eax,0xFF (not: 83 imm8 isaret genisletir -> 0xFFFFFFFF no-op; zararsiz cunku b^acc zaten <=0xFF)
        put({0x45, 0x0F, 0xB6, 0x84, 0x03});                        // movzx r8d,byte [r11+rax+crcTblOff] (ModRM 84: mod10=disp32 VAR; 04 olsaydi disp'siz okur, disp baytlari komut sanilirdi!)
        imm(34);                                                    // disp32 = crcTblOff
        put({0x41, 0xFF, 0xCA});                                    // dec r10d
        put({0x75}); blob.push_back((u8)(cl - (blob.size() + 1)));  // jne crcloop
        put({0x41, 0x38, 0xD0});                                    // cmp r8b,dl (38 /r: reg=dl kaynak, rm=r8b+REX.B)
        put({0x0F, 0x85});
        crcFailJne = (u32)blob.size(); put4(0);                     // jne crcFail (hedefi TAIL'den SONRA yamalanir - fixup yolunu bogmamasi icin!)
        // r11=blobBase korunmus durumda -> site-fixup dogrudan devam eder
    }
    // ---- site tablosu: *(u32*)(slot+fieldOff) -= (i32)delta ----
    put({0x44, 0x8B, 0x54, 0x24, 0x10});                            // mov r10d,[rsp+0x10] (siteFirst)
    put({0x45, 0x6B, 0xD2, 0x0C});                                  // imul r10d,r10d,12 (site kaydi 12B! index*12)
    put({0x4F, 0x8D, 0x0C, 0x13});                                  // lea r9,[r11+r10*1] (R=1,X=1; SIB=00_010_011)
    put({0x49, 0x81, 0xC1}); imm(2);                                // add r9,sitesOff
    put({0x44, 0x8B, 0x54, 0x24, 0x18});                            // mov r10d,[rsp+0x18]
    put({0x41, 0x81, 0xE2, 0xFF, 0x00, 0x00, 0x00});                // and r10d,0xFF (nSites; imm32 - imm8 0xFF isaret genisletme tuzagi)
    put({0x48, 0x8B, 0x54, 0x24, 0x20});                            // mov rdx,[rsp+0x20] (delta)
    u32 fxl = (u32)blob.size();
    put({0x45, 0x85, 0xD2});                                        // test r10d,r10d
    put({0x0F, 0x84});
    u32 jeFxd = (u32)blob.size(); put4(0);                                     // je fxDone
    put({0x41, 0x8B, 0x01});                                        // mov eax,[r9] (fieldOff; rm=001=r9)
    put({0x49, 0x83, 0xC1, 0x0C});                                  // add r9,12 (site kaydi 12B: fieldOff,kind,value)
    put({0x44, 0x8B, 0x04, 0x01});                                  // mov r8d,[rcx+rax] (R=1 B=0: base=rcx)
    put({0x41, 0x29, 0xD0});                                        // sub r8d,edx (B=1: rm=000=r8d)
    put({0x44, 0x89, 0x04, 0x01});                                  // mov [rcx+rax],r8d (R=1 B=0: base=rcx)
    put({0x41, 0xFF, 0xCA});                                        // dec r10d
    put({0xE9}); put4(0);                                           // jmp fx
    u32 fxDone = (u32)blob.size();
    Poke32(blob, jeFxd, (i32)((i64)fxDone - ((i64)jeFxd + 4)));
    Poke32(blob, fxDone - 4, (i32)((i64)fxl - (i64)fxDone));        // jmp fxl (disp alan fxDone-4, sonu fxDone)
    // ---- bitti: slot adresini arena kuyruguna yaz, cerceveyi geri ver ----
    //  DUZELTME: "jmp rcx" YANLISTI - pop rcx caller'in rcx'ini geri getiriyordu
    //  (parca 1. komutu arg ecx'i okur). Slot adresi arena+0xFF8'e yazilir,
    //  poplar+popfq SONRASI oradan mem-indirect jmp edilir (register kirletmez).
    put({0x49, 0x89, (u8)(0x8C), (u8)(0x20 | c3), 0xF8, 0x0F, 0x00, 0x00}); // mov [conv+0xFF8],rcx (slot abs)
    put({0x48, 0x83, 0xC4, 0x30});                                  // add rsp,0x30
    put({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58}); // pop r11,r10,r9,r8,rdx,rcx,rax
    put({0x9D});                                                    // popfq
    put({0x41, 0xFF, (u8)(0xA4), (u8)(0x20 | c3), 0xF8, 0x0F, 0x00, 0x00}); // jmp qword [conv+0xFF8] -> slot
    // ---- crcFail (G2, hardened): TAIL'DEN SONRA - fixup yolunu BOGMAMASI ICIN ----
    //  KRITIK: bu blok jne'nin hedefi; normal (CRC OK) yolu fixup+tail'den gecer.
    //  Buraya varildiginde parca 0'in prolog frame'i (push rbp + sub rsp,0x40)
    //  HALA AKTIF olabilir -> caller'a ret ile DONEMEYIZ (farewell ret'i cop
    //  poplar, arena ortasina dusulur). Cozum: caller'a donme, tamamen cik:
    //  arena'yi free et + ExitProcess(0xDE) (fail-closed anti-patch).
    //  Stage frame'i tamamen sar (pushfq+7push+0x30 = 112B), r12=arena saglam kalir.
    if (hardened) {
        u32 crcFail = (u32)blob.size();
        Poke32(blob, crcFailJne, (i32)((i64)crcFail - ((i64)crcFailJne + 4)));
        put({0x48, 0x83, 0xC4, 0x30});                              // add rsp,0x30
        put({0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58}); // pop r11,r10,r9,r8,rdx,rcx,rax
        put({0x9D});                                                // popfq ([rsp] = geri adres - DOKUNULMAZ, ExitProcess onu kullanmaz)
        out.crcDispPos = (u32)blob.size() - S + 1;                  // E9 disp konumu
        put({0xE9}); put4(0);                                       // jmp crcFarewell (.maze'de; disp RUNTIME stub yamar)
        out.crcJmpEnd = (u32)blob.size() - S;
    }
    // ---- clDispatch: cerceveyi AT, cleanup'a git (pid 0xFE-i) ----
    u32 clD = (u32)blob.size();
    Poke32(blob, jaCl, (i32)((i64)clD - ((i64)jaCl + 4)));
    if (crcJne) Poke32(blob, crcJne, (i32)((i64)clD - ((i64)crcJne + 4)));
    // DUZELTME: eski kod poplar+popfq SONRASI cmp r10d,0xFE yapiyordu; pop r10
    // pid'i caller'in r10'uyla eziyordu. Simdi: pid [rsp+0] yedeginden r10d'ye
    // yuklenir ve pop r10 ATLANIR (add rsp,8) -> dispatch dogru pid ile calisir;
    // cleanup -> ret yolunda caller r10 zaten gecerli degil (volatile).
    put({0x44, 0x8B, 0x14, 0x24});                                  // mov r10d,[rsp] (pid yedegi)
    put({0x48, 0x83, 0xC4, 0x30});                                  // add rsp,0x30
    put({0x41, 0x5B});                                              // pop r11
    put({0x48, 0x83, 0xC4, 0x08});                                  // add rsp,8 (r10 yuvasi atlanir: pid r10d'de)
    put({0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58});                // pop r9,r8,rdx,rcx,rax
    put({0x9D});                                                    // popfq
    // dispatch zinciri: cmp 0xFE / je c0; cmp 0xFD / je c1; ...; jmp c0
    std::vector<u32> jeSite(nCleanup);
    for (u32 i = 0; i < nCleanup; i++) {
        put({0x41, 0x81, 0xFA}); put4(0xFE - (u32)i);               // cmp r10d,0xFE-i
        put({0x0F, 0x84});
        jeSite[i] = (u32)blob.size(); put4(0);                                 // je c_i
    }
    put({0xE9});
    u32 defJmp = (u32)blob.size(); put4(0);                         // jmp c0 (varsayilan; disp konumu)
    for (u32 i = 0; i < nCleanup; i++) {
        u32 ci = (u32)blob.size();
        Poke32(blob, jeSite[i], (i32)((i64)ci - ((i64)jeSite[i] + 4)));
        if (i == 0) Poke32(blob, defJmp, (i32)((i64)ci - ((i64)defJmp + 4)));
        // CLEANUP (arena ici): [rsp]=arena+0, [rsp+8]=1, jmp farewell (disp RUNTIME'da stub yamar)
        put({0x50});                                                // push rax
        put({0x48, 0x83, 0xEC, 0x20});                              // sub rsp,0x20
        u32 leaPos = (u32)blob.size();
        put({0x4C, 0x8D, 0x05}); put4(0);                           // lea r8,[rip+X] -> arena+0
        Poke32(blob, leaPos + 3, (i32)(0 - ((i64)(leaPos - S) + 7)));
        put({0x4C, 0x89, 0x04, 0x24});                              // mov [rsp],r8
        put({0xC7, 0x44, 0x24, 0x08, 0x01, 0x00, 0x00, 0x00});      // mov dword [rsp+8],1
        out.clDispPos.push_back((u32)blob.size() - S + 1);          // disp konumu (E9 sonrasi)
        out.clJmpEnd.push_back((u32)blob.size() - S + 5);
        put({0xE9}); put4(0);                                       // jmp farewell (placeholder 0)
    }
    out.templateLen = (u32)blob.size() - S;
}

// V4 GIRIS STUB: 7 push + sub 0x20; got: template kopyala + arena yamalari +
// conv=arena (mov conv,rax), xor r10d + jmp conv; fb: yerinde decrypt-once +
// conv=fbStage + jmpSlot=ilk parca; iki kuyruk ayri.
static u32 EmitStreamStub(std::vector<u8>& blob, std::vector<Patch>& patches,
                          u32 iatVaRva, u8 convReg, u32 nCleanup, bool hardened) {
    u32 S = (u32)blob.size();
    auto put = [&blob](std::initializer_list<u8> bs) { for (u8 b : bs) blob.push_back(b); };
    auto put4 = [&](u32 v) { for (int i = 0; i < 4; i++) blob.push_back((u8)(v >> (8 * i))); };
    auto imm = [&](u32 which) {
        Patch p; p.kind = Patch::P_ARENA_IMM; p.siteOff = (u32)blob.size(); p.immWhich = which;
        patches.push_back(p); put4(0);
    };
    u8 c3 = (u8)(convReg & 7);

    put({0x56, 0x57, 0x50, 0x51, 0x52, 0x53, 0x41, 0x50, 0x41, 0x51}); // push rsi,rdi,rax,rcx,rdx,rbx,r8,r9
    put({0x48, 0x83, 0xEC, 0x20});                                  // sub rsp,0x20
    put({0x48, 0x8D, 0x1D});                                        // lea rbx,[rip - (10+4+7)]
    { u32 here = (u32)blob.size(); blob.resize(here + 4, 0);
      Poke32(blob, here, (i32)(0 - ((i64)S + 10 + 4 + 7))); }
    // ---- FB FLAGI: fallback bir kez kullanildiysa bu cagri da dogrudan fb ----
    //  DUZELTME: aksi halde 2. cagri arena'yi tekrar dener; ama .maze span'lari
    //  fb'de decrypt-once ile PLAINTEXT oldu -> arena cozerken Xor-K ile cop
    //  uretir (TekTek: invalid insn; Stream: CRC-fail 0xDE). Mod karisimi yasak.
    put({0x8B, 0x43, 0x20});                                        // mov eax,[rbx+0x20] (fb flag)
    put({0x85, 0xC0});                                              // test eax,eax
    put({0x0F, 0x85});
    u32 jneFbFlag = (u32)blob.size(); put4(0);                      // jne fb (disp fbOff belli olunca)
    put({0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00});    // mov rax,gs:[0x60]
    put({0x48, 0x8B, 0x40, 0x10});                                  // mov rax,[rax+0x10]
    put({0xBA}); imm(0);                                            // mov edx,imgSize
    put({0x48, 0x01, 0xD0});                                        // add rax,rdx
    put({0x48, 0x05, 0xFF, 0xFF, 0x00, 0x00});                      // add rax,0xFFFF
    put({0x48, 0xC1, 0xE8, 0x10});                                  // shr rax,16
    put({0x48, 0xC1, 0xE0, 0x10});                                  // shl rax,16
    put({0x4C, 0x8B, 0xD8});                                        // mov r11,rax (hint)
    put({0x41, 0xBA, 0x08, 0x00, 0x00, 0x00});                      // mov r10d,8
    u32 tryOff = (u32)blob.size();
    put({0x4C, 0x89, 0xD9});                                        // mov rcx,r11
    put({0xBA}); imm(3);                                            // mov edx,arenaSize
    put({0x41, 0xB8, 0x00, 0x30, 0x00, 0x00});                      // mov r8d,0x3000
    put({0x41, 0xB9, 0x40, 0x00, 0x00, 0x00});                      // mov r9d,0x40
    put({0xFF, 0x15});                                              // call [rip] VirtualAlloc
    { Patch p; p.kind = Patch::P_ARENA_VA; p.siteOff = (u32)blob.size(); p.immValue = iatVaRva;
      patches.push_back(p); blob.resize(blob.size() + 4, 0); }
    put({0x48, 0x85, 0xC0});                                        // test rax,rax
    put({0x0F, 0x85});
    u32 jneGot = (u32)blob.size(); put4(0);                                     // jne got
    put({0x49, 0x81, 0xC3, 0x00, 0x00, 0x40, 0x00});                // add r11,0x400000
    put({0x41, 0xFF, 0xCA});                                        // dec r10d
    put({0x75}); blob.push_back((u8)(tryOff - (blob.size() + 1)));  // jne try
    put({0xEB});
    u32 jmpFb = (u32)blob.size(); blob.push_back(0);                // jmp fb (disp konumu)
    // ---- got: template kopyala + arena yamalari ----
    u32 gotOff = (u32)blob.size();
    Poke32(blob, jneGot, (i32)((i64)gotOff - ((i64)jneGot + 4)));
    {   // V4.2: mov [rbx+0x40],rax (ARENA_PTR; thunk'lar [blob+0x40] uzerinden atlar)
        //       mov r11,rax (arena base - per-call yamalar r11 uzerinden)
        put({0x48, 0x89, 0x83, 0x40, 0x00, 0x00, 0x00});            // mov [rbx+0x40],rax
        put({0x49, 0x89, 0xC3});                                    // mov r11,rax
    }
    put({0x48, 0x89, 0xC7});                                        // mov rdi,rax
    put({0xFC});                                                    // cld
    put({0x48, 0x8D, 0xB3}); imm(7);                                // lea rsi,[rbx+templateOff]
    put({0xB9}); imm(8);                                            // mov ecx,templateLen
    put({0xF3, 0xA4});                                              // rep movsb
    put({0x0F, 0x31});                                              // rdtsc
    put({0x48, 0x31, 0xD0});                                        // xor rax,rdx
    put({0x48, 0xC1, 0xE8, 0x0C});                                  // shr rax,12
    put({0x25}); imm(17);                                           // and eax,slotMask (0 -> sabit slot)
    put({0xC1, 0xE0, 0x05});                                        // shl eax,5 (V4.2: 32B slot stridesi, ust uste binme YOK)
    put({0x05}); imm(16);                                           // add eax,slotBase
    put({0x41, 0x89, 0x84, 0x23}); imm(9);                          // mov [r11+slotImmPos],eax (V4.2: r11=arena)
    for (u32 i = 0; i < nCleanup; i++) {
        put({0x4D, 0x8D, 0x8C, 0x23}); imm(11 + 3 * i);             // lea r9,[r11+clJmpEnd_i] (V4.2)
        put({0x4C, 0x8D, 0x83}); imm(12 + 3 * i);                   // lea r8,[rbx+farewellOff_i]
        put({0x4D, 0x29, 0xC8});                                    // sub r8,r9 (R=1: r9 REG-field)
        put({0x45, 0x89, 0x84, 0x23}); imm(10 + 3 * i);             // mov [r11+clDispPos_i],r8d (V4.2)
    }
    if (hardened) {
        // G2 CRC-fail jmp'inin hedefi .maze'deki crcFarewell -> her cagri arena-icin yama
        put({0x4D, 0x8D, 0x8C, 0x23}); imm(37);                     // lea r9,[r11+crcJmpEnd] (V4.2)
        put({0x4C, 0x8D, 0x83}); imm(35);                           // lea r8,[rbx+crcFarewellOff]
        put({0x4D, 0x29, 0xC8});                                    // sub r8,r9
        put({0x45, 0x89, 0x84, 0x23}); imm(36);                     // mov [r11+crcDispPos],r8d (V4.2)
    }
    put({0x45, 0x31, 0xD2});                                        // xor r10d,r10d (pid=0)
    put({0xEB});
    u32 jmpAT = (u32)blob.size(); blob.push_back(0);                // jmp arenaTail (disp konumu)
    // ---- fb: yerinde decrypt-once + conv=fbStage + jmpSlot=ilk parca ----
    u32 fbOff = (u32)blob.size();
    Poke32(blob, jneFbFlag, (i32)((i64)fbOff - ((i64)jneFbFlag + 4)));
    blob[jmpFb] = (u8)(fbOff - (jmpFb + 1));
    put({0x8B, 0x43, 0x20});                                        // mov eax,[rbx+0x20] (flag)
    put({0x85, 0xC0});                                              // test eax,eax
    put({0x0F, 0x84});
    u32 jeFbSkip = (u32)blob.size(); put4(0);                                     // je fbDo
    put({0xEB});
    u32 jmpFbSkip = (u32)blob.size(); blob.push_back(0);            // jmp fbSkip (disp konumu)
    u32 fbDo = (u32)blob.size();
    Poke32(blob, jeFbSkip, (i32)((i64)fbDo - ((i64)jeFbSkip + 4)));
    put({0x44, 0x8B, 0x0B});                                        // mov r9d,[rbx] (nBlocks)
    put({0x48, 0x8B, 0x53, 0x08});                                  // mov rdx,[rbx+8] (K)
    put({0x4C, 0x8D, 0x93}); imm(6);                                // lea r10,[rbx+blockTblOff]
    u32 freg = (u32)blob.size();
    put({0x45, 0x85, 0xC9});                                        // test r9d,r9d
    put({0x0F, 0x84});
    u32 jeFbFlag = (u32)blob.size(); put4(0);                                     // je fbFlag
    put({0x4D, 0x63, 0x1A});                                        // movsxd r11,[r10] (encOff)
    put({0x41, 0x8B, 0x4A, 0x04});                                  // mov ecx,[r10+4] (len)
    put({0x49, 0x83, 0xC2, 0x10});                                  // add r10,16 (blk 16B)
    put({0x49, 0x01, 0xDB});                                        // add r11,rbx
    u32 fin = (u32)blob.size();
    put({0x85, 0xC9});                                              // test ecx,ecx
    put({0x0F, 0x84});
    u32 jeFbNext = (u32)blob.size(); put4(0);                                     // je fbNext
    put({0x49, 0x8B, 0x03});                                        // mov rax,[r11]
    put({0x48, 0x31, 0xD0});                                        // xor rax,rdx
    put({0x49, 0x89, 0x03});                                        // mov [r11],rax
    put({0x49, 0x83, 0xC3, 0x08});                                  // add r11,8
    put({0x83, 0xE9, 0x08});                                        // sub ecx,8
    put({0x0F, 0x85});                                              // jne fin
    { u32 here = (u32)blob.size(); blob.resize(here + 4, 0);
      Poke32(blob, here, (i32)((i64)fin - ((i64)here + 4))); }   // DUZELTME: here=disp BASI; hedef-(here+4) olmali (fin-here 4 eksikti -> jne je'nin ortasina dusuyor, fallback crash)
    u32 fbNext = (u32)blob.size();
    Poke32(blob, jeFbNext, (i32)((i64)fbNext - ((i64)jeFbNext + 4)));
    put({0x41, 0xFF, 0xC9});                                        // dec r9d
    put({0xE9}); put4(0);                                           // jmp freg
    { u32 here = (u32)blob.size(); Poke32(blob, here - 4, (i32)((i64)freg - (i64)here)); }
    u32 fbFlag = (u32)blob.size();
    Poke32(blob, jeFbFlag, (i32)((i64)fbFlag - ((i64)jeFbFlag + 4)));
    put({0xC7, 0x43, 0x20, 0x01, 0x00, 0x00, 0x00});                // mov dword [rbx+0x20],1
    u32 fbSkip = (u32)blob.size();
    blob[jmpFbSkip] = (u8)(fbSkip - (jmpFbSkip + 1));
    {   // V4.2: mov [rbx+0x40],lea(rax=rbx+fbStageOff) -> thunk'lar fb modunda fbStage'a atlar
        put({0x48, 0x8D, 0x83}); imm(31);                           // lea rax,[rbx+fbStageOff]
        put({0x48, 0x89, 0x43, 0x40});                              // mov [rbx+0x40],rax (ARENA_PTR=fbStage)
    }
    put({0x48, 0x8D, 0x83}); imm(5);                                // lea rax,[rbx+firstOff]
    put({0x48, 0x89, 0x43, 0x48});                                  // mov [rbx+0x48],rax (jmpSlot; S-8=0x48 V4.2)
    // ---- iki kuyruk ----
    u32 arenaTail = (u32)blob.size();
    blob[jmpAT] = (u8)(arenaTail - (jmpAT + 1));
    put({0x48, 0x83, 0xC4, 0x20});                                  // add rsp,0x20
    put({0x41, 0x59, 0x41, 0x58, 0x5B, 0x5A, 0x59, 0x58, 0x5F, 0x5E}); // pop r9,r8,rbx,rdx,rcx,rax,rdi,rsi
    put({0x45, 0x31, 0xD2});                                        // xor r10d,r10d (pid=0)
    put({0x41, 0xFF, 0xE3});                                        // jmp r11 (V4.2: arena base r11'de)
    u32 fbTail = (u32)blob.size();
    put({0x48, 0x83, 0xC4, 0x20});                                  // add rsp,0x20
    put({0x41, 0x59, 0x41, 0x58, 0x5B, 0x5A, 0x59, 0x58, 0x5F, 0x5E}); // pop r9,r8,rbx,rdx,rcx,rax,rdi,rsi
    put({0xFF, 0x25});                                              // jmp qword [rip+d] -> jmpSlot (blob+0x38 = S-8)
    { u32 cur = (u32)blob.size(); blob.resize(cur + 4, 0);
      Poke32(blob, cur, (i32)((i64)(S - 8) - ((i64)cur + 4))); }
    return (u32)blob.size();
}

// V4 FALLBACK STAGE (maze icinde, plaintext): r10d=pid, conv=self.
// pid >= 0xF0 -> per-encoding bye bloklari (free YOK); aksi: jmp blobBase+blk[pid].encOff
static u32 EmitStreamFbStage(std::vector<u8>& blob, std::vector<Patch>& patches,
                             u8 convReg, u32 nCleanup, const std::vector<u32>& farewellOffs) {
    auto put = [&blob](std::initializer_list<u8> bs) { for (u8 b : bs) blob.push_back(b); };
    auto put4 = [&](u32 v) { for (int i = 0; i < 4; i++) blob.push_back((u8)(v >> (8 * i))); };
    auto imm = [&](u32 which) {
        Patch p; p.kind = Patch::P_ARENA_IMM; p.siteOff = (u32)blob.size(); p.immWhich = which;
        patches.push_back(p); put4(0);
    };
    u8 c3 = (u8)(convReg & 7);
    u32 S0 = (u32)blob.size();   // DUZELTME: return START olmali - eski kod END donduruyordu:
    //  lea conv,[rbx+fbStageOff] stage SONUNA isaret ediyordu (Stream'de crcFarewell
    //  basi! -> fb modunda direkt ExitProcess(0xDE); TekTek'te zero-pad faultu).
    //  Veri adreslemesi (blkTbl/piece/bye) zaten conv-relative farklarla iptal
    //  ediyordu; yalniz GIRIS adresi yanlisti.
    //  DUZELTME 2 (rax): parcalar rax uzerinden haberisir (piece4: mov [rbp-0x18],eax
    //  = ny yazimi). Arena yolu stage tail'inde pop rax ile caller rax'ini geri koyar;
    //  fb ise jmp rax ile hedef adresi rax'ta BIRAKIYORDU -> ny cop (y=0x3FFFD002,
    //  oyuncu hic hareket etmiyor). Cozum: hedef r11'e al, pop rax + popfq + jmp r11.
    //  DUZELTME 3 (FLAGS - KRITIK): parcalar arasi bayrak tasimasi var (piece5: cmp
    //  eax,0 -> thunk -> stage -> piece6: jne). Arena yolu pushfq/popfq ile korur;
    //  fb'nin cmp/add komutlari bayraklari bozuyor -> jne YANLIS karar veriyor
    //  (eax=0 free olmasina ragmi epilog'a dusuyor, oyuncu hic hareket etmiyor).
    //  Cozum: pushfq giriste, popfq cikista. r11 scratch (volatile, cagri-siniri).
    put({0x9C});                                                    // pushfq (parcalar arasi bayrak zinciri)
    put({0x50});                                                    // push rax (caller rax kaydet)
    put({0x41, 0x81, 0xFA, 0xF0, 0x00, 0x00, 0x00});                // cmp r10d,0xF0
    put({0x0F, 0x83});
    u32 jaBye = (u32)blob.size(); put4(0);                                     // jae byeDispatch
    // V4.2: r11 = blobBase (rip-relative; fbStage blob icinde STATIK, conv YOK)
    { u32 leaPos = (u32)blob.size();
      put({0x4C, 0x8D, 0x1D});
      blob.resize(leaPos + 7, 0);
      Poke32(blob, leaPos + 3, (i32)(0 - ((i64)leaPos + 7))); }     // lea r11,[rip-(leaPos+7)] -> blobBase
    // normal parca: hedef = blobBase + blk[pid].encOff
    put({0x44, 0x89, 0xD0});                                        // mov eax,r10d
    put({0xC1, 0xE0, 0x04});                                        // shl eax,4
    put({0x05}); imm(32);                                           // add eax,blockTblOff (V4.2: blob-ofseti)
    put({0x48, 0x63, 0xC0});                                        // movsxd rax,eax
    put({0x4C, 0x01, 0xD8});                                        // add rax,r11 (&blk[pid])
    put({0x8B, 0x00});                                              // mov eax,[rax] (encOff)
    put({0x48, 0x63, 0xC0});                                        // movsxd rax,eax (encOff < 4GB, pozitif)
    put({0x4C, 0x01, 0xD8});                                        // add rax,r11 (hedef = blob+encOff)
    put({0x49, 0x89, 0xC3});                                        // mov r11,rax (hedefi r11'e al)
    put({0x58});                                                    // pop rax (caller rax GERI)
    put({0x9D});                                                    // popfq (bayraklar GERI)
    put({0x41, 0xFF, 0xE3});                                        // jmp r11 (parcaya atla - rax+flags temiz!)
    // byeDispatch: fbStage'un pushfq+push rax'unu sar (popfq bayraklari geri - zararsiz),
    //  sonra klasik bye yapisi (push rax; sub 0x20; selfBase; free=0; jmp farewell).
    //  Stack dengesi: [pop rax+popfq]=16B (fbStage girdisi) + [push rax+sub 0x20]=40B
    //  <-> farewell [add 0x20+pop rax]=40B ✓
    u32 byeD = (u32)blob.size();
    Poke32(blob, jaBye, (i32)((i64)byeD - ((i64)jaBye + 4)));
    put({0x58});                                                    // pop rax (caller rax geri)
    put({0x9D});                                                    // popfq
    std::vector<u32> jeBye(nCleanup);
    for (u32 i = 0; i < nCleanup; i++) {
        put({0x41, 0x81, 0xFA}); put4(0xFE - (u32)i);               // cmp r10d,0xFE-i
        put({0x0F, 0x84});
        jeBye[i] = (u32)blob.size(); put4(0);                                 // je bye_i
    }
    put({0xE9});
    u32 defBye = (u32)blob.size(); put4(0);                         // jmp bye0 (disp konumu)
    for (u32 i = 0; i < nCleanup; i++) {
        u32 bye = (u32)blob.size();
        Poke32(blob, jeBye[i], (i32)((i64)bye - ((i64)jeBye[i] + 4)));
        if (i == 0) Poke32(blob, defBye, (i32)((i64)bye - ((i64)defBye + 4)));
        put({0x50});                                                // push rax (farewell pop ile geri koyar)
        put({0x48, 0x83, 0xEC, 0x20});                              // sub rsp,0x20
        { u32 lea2 = (u32)blob.size();
          put({0x48, 0x8D, 0x05});
          blob.resize(lea2 + 7, 0);
          Poke32(blob, lea2 + 3, (i32)(0 - ((i64)lea2 + 7))); }     // lea rax,[rip-...] -> blobBase (V4.2; free=0 zaten)
        put({0x48, 0x89, 0x04, 0x24});                              // mov [rsp],rax
        put({0xC7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00, 0x00});      // mov dword [rsp+8],0
        u32 jmpPos = (u32)blob.size();
        put({0xE9}); put4(0);                                       // jmp farewell_i (blob-ici, build-time)
        Poke32(blob, jmpPos + 1, (i32)((i64)farewellOffs[i] - ((i64)jmpPos + 5)));
    }
    return S0;
}

// ============================================================================
//  V4 ANA KURULUM - STREAM (tek tek, blueprint [2])
//  .maze layout: [0x40 header MZE3][stub][template(stage+cleanups)][span'ler
//  karisik sira][decoy blob'lar][thunk tablosu][site tablosu][blk tablosu]
//  [farewell'ler][fbStage]  (span+decoy sifreli, gerisi plaintext)
// ============================================================================
struct V4Site {          // calisma aninda delta-fix uygulanacak disp
    u32 fieldAbs = 0;    // disp alaninin MUTLAK blob ofseti
    u32 insnAbs = 0;     // komutun mutlak blob ofseti (sim dogrulamasi)
    u32 insnLen = 0;
    u8  kind = 0;        // 0: modul-hedef, 1: THUNK hedefi, 2: RIP-rel
    u32 value = 0;       // kind0/2: RVA; kind1: thunk pid (>=0xF0 -> cleanup)
    u32 piece = 0;
};
struct StreamPiece {
    size_t i0 = 0, n = 0;
    u32 encOff = 0, len = 0;      // sifreli span (govde + tail + pad)
    u32 siteFirst = 0, nSites = 0;
    u8  crc = 0;
};

struct V4Local {         // ayni-parca dallanma: disp degismez (slot-uzayinda korunur)
    u32 fieldAbs = 0;
    u32 insnAbs = 0;
    u32 insnLen = 0;
    u32 targetInsn = 0;
};
inline bool BuildStream(Core& c, const Options& optIn, Report& rep) {
    Options opt = optIn;
    auto& pe  = c.pe;
    auto& mem = c.mem;
    rep.fnRva = opt.fnRva; rep.fnSize = opt.fnSize;
    bool hardened = opt.streamHardened;

    // ---- [1] TEMEL DOGRULAMA (V3 kurallari) ----
    if (!pe.valid || mem.data.empty())          { rep.err = "PE yuklu degil"; return false; }
    if (!pe.is64)                               { rep.err = "Sadece x64 (PE32+) destekleniyor"; return false; }
    if (opt.fnSize < 5)                         { rep.err = "Fonksiyon cok kucuk (en az 5 bayt gerekli, trambolin icin)"; return false; }
    if (opt.fnRva == 0 || opt.fnRva >= pe.imgSz){ rep.err = "RVA goruntu disinda"; return false; }
    if (opt.fnRva + opt.fnSize > pe.imgSz)      { rep.err = "Fonksiyon araligi SizeOfImage'i asiyor"; return false; }

    // ---- [1.1] EVRENSELLIK: eksik kernel32 API'lerini IAT'ye ekle (V4.1) ----
    // Programin IAT'sinde VirtualAlloc/VirtualFree/ExitProcess olmayabilir
    // (as-needed link, nostdlib, yabanci oyunlar) -> motorun calismasi icin
    // .mpimp section'i ile ikinci kernel32 descriptor'u eklenir.
    {
        u32 prVa = 0, prVf = 0;
        bool hasVA = FindIatRva(c, "VirtualAlloc", prVa), hasVF = FindIatRva(c, "VirtualFree", prVf);
        if (!hasVA || !hasVF) {
            if (!EnsureIatImports(c, rep.warnings)) {
                rep.err = "IAT'ye import eklenemedi (.mpimp section/header yeri dolu olabilir)";
                return false;
            }
        }
    }
    fprintf(stderr, "[bs-in] %s fnRva=0x%X fnSize=%u (u32 fnRva+fnSize=0x%llX)\n",
            __func__, opt.fnRva, opt.fnSize, (unsigned long long)(opt.fnRva + opt.fnSize));
    if (opt.chunkMax < 8)  opt.chunkMax = 8;
    if (opt.chunkMax > 64) opt.chunkMax = 64;
    bool inExec = false;
    for (auto& s : pe.secs)
        if (opt.fnRva >= s.va && opt.fnRva + opt.fnSize <= s.va + (std::max)(s.vSz, s.rawSz))
            { inExec = (s.chars & IMAGE_SCN_MEM_EXECUTE) != 0; break; }
    if (!inExec) { rep.err = "Fonksiyon calistirilabilir (X) bir section'da degil"; return false; }
    for (auto& r : pe.relocs) {
        if (r.rva + 8 > opt.fnRva && r.rva < opt.fnRva + opt.fnSize) {
            if (!opt.allowRelocBody) {
                char eb[192]; snprintf(eb, sizeof(eb),
                    "Fonksiyon govdesinde mutlak adres var (reloc RVA 0x%X) - stream modu reddetti (cozum: encoder V4.5 bu durumda ASLR'i kapatabilir)", r.rva);
                rep.err = eb;
                return false;
            }
            char wb[160]; snprintf(wb, sizeof(wb),
                "Govdede mutlak adres (reloc RVA 0x%X): cikista ASLR KAPALI (DYNAMICBASE temizlendi), mutlak adresler tercih-edilen base'de gecerli", r.rva);
            rep.warnings.push_back(wb);
            break;
        }
    }
    u32 iatVaRva = 0, iatVfRva = 0, iatEpRva = 0;
    {
        bool va = FindIatRva(c, "VirtualAlloc", iatVaRva);
        bool vf = FindIatRva(c, "VirtualFree", iatVfRva);
        if (!va || !vf) { rep.err = "STREAM modu IAT'de kernel32!VirtualAlloc/VirtualFree istiyor (bulunamadi)"; return false; }
        // G2 CRC-fail fail-closed cikisi icin ExitProcess (yoksa G2 devre disi + uyari)
        bool hasEp = FindIatRva(c, "ExitProcess", iatEpRva);
        if (!hasEp) rep.warnings.push_back("IAT'de ExitProcess yok -> G2 CRC fail-closed cikisi devre disi (CRC-fail clDispatch'a duser)");
        if (opt.streamHardened && !hasEp) { opt.streamHardened = false; hardened = false; }
    }

    // ---- [2] REFERANSLAR ----
    if (!c.refs.built) c.BuildRefs();

    // ---- [3] KOMUT KOMUT COZ + regs toplama ----
    u64 startVA = mem.base + opt.fnRva;
    u64 endVA   = startVA + opt.fnSize;
    std::vector<MInsn> insns;
    {
        u64 a = startVA;
        while (a < endVA) {
            const u8* p = &mem.data[(size_t)(a - mem.base)];
            size_t rm = (size_t)(mem.data.size() - (a - mem.base));
            cs_insn* i0 = nullptr;
            size_t n = cs_disasm(c.dis.handle, p, (std::min)(rm, (size_t)16), a, 1, &i0);
            if (!n) { rep.err = "Cozulamayan bayt: RVA 0x" + std::to_string(a - mem.base); return false; }
            MInsn m;
            m.rva  = (u32)(a - mem.base);
            m.size = (u8)i0[0].size;
            memcpy(m.bytes, i0[0].bytes, (m.size <= 16) ? m.size : 16);
            m.mn = i0[0].mnemonic;
            cs_detail* d = i0[0].detail;
            u8 op0 = m.bytes[0];
            u8 op1 = (m.size >= 2) ? m.bytes[1] : 0;
            bool grpJmp = false, grpCall = false, grpRet = false;
            if (d) {
                for (u8 g = 0; g < d->groups_count; g++) {
                    if (d->groups[g] == CS_GRP_JUMP) grpJmp = true;
                    if (d->groups[g] == CS_GRP_CALL) grpCall = true;
                    if (d->groups[g] == CS_GRP_RET)  grpRet  = true;
                }
                // regs bitmask (V4 conv-reg kontrolu)
                for (int oi = 0; oi < d->x86.op_count; oi++) {
                    auto& o = d->x86.operands[oi];
                    if (o.type == X86_OP_REG && o.reg >= X86_REG_RAX && o.reg <= X86_REG_R15)
                        m.regs |= 1u << (o.reg - X86_REG_RAX);
                    if (o.type == X86_OP_MEM) {
                        if (o.mem.base  >= X86_REG_RAX && o.mem.base  <= X86_REG_R15) m.regs |= 1u << (o.mem.base  - X86_REG_RAX);
                        if (o.mem.index >= X86_REG_RAX && o.mem.index <= X86_REG_R15) m.regs |= 1u << (o.mem.index - X86_REG_RAX);
                    }
                }
            }
            m.isRet = grpRet;
            if (op0 >= 0xE0 && op0 <= 0xE3) { cs_free(i0, 1);
                rep.err = "loop/jcxz komutu tespit edildi - stream modu desteklemiyor"; return false; }
            u64 immTarget = 0; bool hasImm = false;
            if (d) for (int i = 0; i < d->x86.op_count; i++)
                if (d->x86.operands[i].type == X86_OP_IMM) { hasImm = true; immTarget = (u64)d->x86.operands[i].imm; break; }
            if (grpCall && op0 == 0xE8) {
                m.kind = K_BR; m.targetRva = (u32)(immTarget - mem.base);
            } else if (grpJmp && m.mn == "jmp") {
                if (op0 == 0xE9)      { m.kind = K_BR; m.targetRva = (u32)(immTarget - mem.base); }
                else if (op0 == 0xEB) { m.kind = K_EXPJMP; m.targetRva = (u32)(immTarget - mem.base); }
                else if (hasImm)      { cs_free(i0, 1); rep.err = "Far/segment jmp desteklenmiyor"; return false; }
            } else if (grpJmp) {
                if (op0 >= 0x70 && op0 <= 0x7F)                     { m.kind = K_EXPJCC; m.targetRva = (u32)(immTarget - mem.base); }
                else if (op0 == 0x0F && op1 >= 0x80 && op1 <= 0x8F) { m.kind = K_JCC;   m.targetRva = (u32)(immTarget - mem.base); }
                else { cs_free(i0, 1); rep.err = "Bilinmeyen dallanma formu (RVA 0x" + std::to_string(m.rva) + ")"; return false; }
            }
            if ((m.kind == K_BR || m.kind == K_JCC || m.kind == K_EXPJMP || m.kind == K_EXPJCC) &&
                m.targetRva >= pe.imgSz) { cs_free(i0, 1); rep.err = "Dallanma goruntu disina cikiyor"; return false; }
            if (d) for (int i = 0; i < d->x86.op_count; i++) {
                auto& o = d->x86.operands[i];
                if (o.type == X86_OP_MEM && o.mem.base == X86_REG_RIP) {
                    if (m.hasRip) { cs_free(i0, 1); rep.err = "Coklu RIP-relatif operand desteklenmiyor"; return false; }
                    m.hasRip  = true;
                    m.ripDisp = (i32)o.mem.disp;
                    i64 t = (i64)m.rva + m.size + (i64)o.mem.disp;
                    if (t < 0 || t >= (i64)pe.imgSz) { cs_free(i0, 1); rep.err = "RIP-relatif hedef goruntu disinda"; return false; }
                    m.ripTargetRva = (u32)t;
                    if (t >= (i64)opt.fnRva && t < (i64)(opt.fnRva + opt.fnSize)) {
                        cs_free(i0, 1); rep.err = "Fonksiyon KENDI icindeki veriye isaret ediyor (jump table?) - desteklenmiyor";
                        return false;
                    }
                    int off = CalcRipDispOff(m.bytes, m.size, &d->x86);
                    if (off < 0) { cs_free(i0, 1); rep.err = "RIP-relatif disp konumu bulunamadi"; return false; }
                    m.ripOff = (u32)off;
                }
            }
            cs_free(i0, 1);
            insns.push_back(m);
            a += m.size;
        }
    }
    if (insns.empty()) { rep.err = "Hic komut cozulamadi"; return false; }
    while (insns.size() >= 2) {
        MInsn& last = insns.back();
        if (last.size == 1 && (last.bytes[0] == 0xCC || last.bytes[0] == 0x90)) {
            MInsn& prev = insns[insns.size() - 2];
            if (prev.isRet || (prev.kind == K_BR && prev.mn == "jmp")) {
                insns.pop_back(); opt.fnSize -= 1;
                rep.warnings.push_back("Sondaki INT3/NOP dolgusu temizlendi");
                continue;
            }
        }
        break;
    }
    rep.fnSize = opt.fnSize;
    {
        // V4.1 FIX: son komut ret olmak ZORUNDA degil — derleyiciler fonksiyon
        // sonunu fonksiyon-ici ortak join noktasina TAIL-JMP ile bitirebilir
        // (mingw -O2: xor/jmp join). Artik: ret YA DA fonksiyon-ici hedefli
        // koşulsuz jmp (K_BR) kabul edilir; motor kind==1 site mekanizmasi
        // jmp'i join komutunun parçasina dogru yonlendirir.
        MInsn& last = insns.back();
        bool lastJoinJmp = (!last.isRet && (last.kind == K_BR || last.kind == K_EXPJMP) && last.mn == "jmp" &&
                            last.targetRva >= opt.fnRva && last.targetRva < opt.fnRva + opt.fnSize);
        fprintf(stderr, "[last] fnRva=0x%X fnSize=%u last.rva=0x%X mn=%s kind=%d isRet=%d tgt=0x%X join=%d\n",
                opt.fnRva, opt.fnSize, last.rva, last.mn.c_str(), (int)last.kind, (int)last.isRet, last.targetRva, (int)lastJoinJmp);
        if (!last.isRet && !lastJoinJmp) { rep.err = "STREAM modu son komut ret olmak ZORUNDA ('" + last.mn + "' RVA 0x" +
                                   std::to_string(last.rva) + ") - fonksiyon boyutu yanlis olabilir"; return false; }
    }
    rep.insnCount = (u32)insns.size();

    // ---- [4] CONV-REG SECIMI (V4.2: conv SADECE stage-ICI tasiyici; her giriste
    //  ARENA_PTR'den yeniden yuklenir -> korunan fonksiyon r12-r15'i SERBEST kullanabilir,
    //  red yok; kalan tek rol ModRM k-isaltmasi) ----
    u8 convReg = 4;                                                  // varsayilan r12
    {
        const char* convNames[4] = { "r12", "r13", "r14", "r15" };
        for (int ci = 0; ci < 4; ci++) {
            u32 reg = X86_REG_R12 + ci;
            u32 bit = 1u << (reg - X86_REG_RAX);
            bool used = false;
            for (auto& m : insns) if (m.regs & bit) { used = true; break; }
            if (!used) { convReg = (u8)(4 + ci); break; }
        }
        rep.streamMap.push_back(std::string("INFO conv-reg: ") + convNames[convReg - 4] +
                                " (V4.2: yalniz stage-ici; parcalar serbest bozabilir)");
    }

    // ---- [5] KESIM: bodyMax + "dal hedefi = parca basi" kurali ----
    std::vector<char> isTarget(insns.size(), 0);
    for (auto& m : insns)
        if (m.kind == K_BR || m.kind == K_JCC || m.kind == K_EXPJMP || m.kind == K_EXPJCC)
            for (size_t j = 0; j < insns.size(); j++)
                if (insns[j].rva == m.targetRva) { isTarget[j] = 1; break; }
    std::vector<StreamPiece> pcs;
    {
        size_t i = 0;
        while (i < insns.size()) {
            StreamPiece ch; ch.i0 = i; u32 len = 0;
            while (i < insns.size()) {
                if (i > ch.i0 && isTarget[i]) break;                          // dal hedefi -> yeni parca
                u32 isz = NewSizeOf(insns[i]);
                if (len > 0 && len + isz > opt.chunkMax) break;
                len += isz; i++;
            }
            ch.n = i - ch.i0;
            pcs.push_back(ch);
        }
    }
    u32 nPieces = (u32)pcs.size();
    if (nPieces >= 0xF0) { rep.err = "STREAM: parca sayisi 0xF0'u asiyor (pid alani)"; return false; }
    // parca -> insn esleme + capraz-parca CALL reddi
    std::vector<u32> insnPiece(insns.size(), 0xFFFFFFFFu);
    for (u32 ci = 0; ci < nPieces; ci++)
        for (size_t k = 0; k < pcs[ci].n; k++) insnPiece[pcs[ci].i0 + k] = ci;
    for (auto& m : insns) {
        if (m.kind == K_BR && m.mn == "call") {
            for (size_t j = 0; j < insns.size(); j++)
                if (insns[j].rva == m.targetRva) {
                    if (insnPiece[j] != insnPiece[&m - &insns[0]]) {
                        rep.err = "V4 STREAM: parcalar-arasi CALL tespit edildi (RVA 0x" + std::to_string(m.rva) +
                                  ") - slot gecici oldugu icin donus adresi yasamaz; V3 arena modu kullanin";
                        return false;
                    }
                    break;
                }
        }
    }

    // ---- [6] ret encoding listesi ----
    std::vector<u32> encKeys;
    std::map<u32, u32> encIdx;
    for (auto& m : insns) {
        if (!m.isRet) continue;
        u32 key = (u32)m.bytes[0] | ((u32)((m.size >= 3) ? (m.bytes[1] | ((u32)m.bytes[2] << 8)) : 0) << 8);
        if (!encIdx.count(key)) { encIdx[key] = (u32)encKeys.size(); encKeys.push_back(key); }
    }
    u32 nCleanup = (u32)encKeys.size();

    // ---- [7] BLOB: header + stub + template ----
    Rng rng(opt.seed ? opt.seed : (opt.fnRva ^ 0x5A17A5A5u ^ 0x57545245u));
    if (!opt.key) {
        u64 t = (u64)GetTickCount64();
        t ^= (u64)(uintptr_t)&c << 32;
        t ^= (u64)opt.fnRva * 0x9E3779B97F4A7C15ull;
        t ^= t >> 29; t *= 0xBF58476D1CE4E5B9ull; t ^= t >> 32;
        opt.key = t ? t : 0x0123456789ABCDEFull;
    }
    rep.keyUsed = opt.key;
    std::vector<u8> blob;
    std::vector<Patch> patches;
    std::vector<V4Site> v4sites;
    std::vector<V4Local> v4locals;              // ayni-parca dallanmalar
    blob.resize(0x50, 0);        // V4.2: header 0x50 (0x40 ARENA_PTR, 0x48 jmpSlot)
    u32 stubEnd = EmitStreamStub(blob, patches, iatVaRva, convReg, nCleanup, opt.streamHardened);  // convReg = reg3 (4..7)
    StreamStageInfo ssi;
    EmitStreamStage(blob, patches, hardened, nPieces, nCleanup, convReg, ssi);
    u32 templateOff = stubEnd;
    u32 templateLen = ssi.templateLen;
    u32 slotBase = (templateOff + templateLen + 15u) & ~15u;

    // ---- [8] PARCA SPAN'LARI (fiziksel sira karisik; govde + tail-E9 + pad) ----
    std::vector<u32> order(nPieces);
    for (u32 i = 0; i < nPieces; i++) order[i] = i;
    for (size_t i = nPieces - 1; i > 0; i--) std::swap(order[i], order[rng.Next((u32)i + 1)]);
    u32 maxSpanLen = 0;
    for (u32 oi = 0; oi < nPieces; oi++) {
        u32 ci = order[oi];
        StreamPiece& ch = pcs[ci];
        ch.encOff = (u32)blob.size();
        ch.siteFirst = (u32)v4sites.size();
        bool endsWithRetSwap = false;
        for (size_t k = 0; k < ch.n; k++) {
            size_t ii = ch.i0 + k;
            MInsn& m = insns[ii];
            m.blobOff = (u32)blob.size();
            if (m.isRet) {
                // ret -> E9 cleanup-thunk (pid 0xFE-encIdx); ret baytlari YAZILMAZ
                blob.push_back(0xE9); blob.resize(blob.size() + 4, 0);
                m.newSize = 5;
                u32 key = (u32)m.bytes[0] | ((u32)((m.size >= 3) ? (m.bytes[1] | ((u32)m.bytes[2] << 8)) : 0) << 8);
                V4Site s;
                s.fieldAbs = (u32)blob.size() - 4; s.insnAbs = m.blobOff; s.insnLen = 5;
                s.kind = 1; s.value = 0xFE - encIdx[key]; s.piece = ci;
                v4sites.push_back(s);
                if (k + 1 == ch.n) endsWithRetSwap = true;
                continue;
            }
            switch (m.kind) {
            case K_BR: case K_JCC: {
                for (int b = 0; b < m.size; b++) blob.push_back(m.bytes[b]);
                m.newSize = (u32)m.size;
                break;
            }
            case K_EXPJMP: {
                blob.push_back(0xE9); blob.resize(blob.size() + 4, 0);
                m.newSize = 5;
                break;
            }
            case K_EXPJCC: {
                blob.push_back(0x0F); blob.push_back((u8)(0x80 | (m.bytes[0] - 0x70)));
                blob.resize(blob.size() + 4, 0);
                m.newSize = 6;
                break;
            }
            default: {
                for (int b = 0; b < m.size; b++) blob.push_back(m.bytes[b]);
                m.newSize = (u32)m.size;
                break;
            }
            }
            // dal/RIP hedef kaydi
            if (m.kind == K_BR || m.kind == K_JCC || m.kind == K_EXPJMP || m.kind == K_EXPJCC) {
                bool foundT = false;
                for (size_t j = 0; j < insns.size(); j++)
                    if (insns[j].rva == m.targetRva) {
                        foundT = true;
                        if (insnPiece[j] == ci)
                            v4locals.push_back({ m.blobOff + ((m.kind == K_JCC || m.kind == K_EXPJCC) ? 2u : 1u), m.blobOff, m.newSize, (u32)j });
                        else {
                            V4Site s; s.fieldAbs = m.blobOff + ((m.kind == K_JCC || m.kind == K_EXPJCC) ? 2u : 1u);
                            s.insnAbs = m.blobOff; s.insnLen = m.newSize;
                            s.kind = 1; s.value = insnPiece[j]; s.piece = ci;
                            v4sites.push_back(s);
                        }
                        break;
                    }
                if (!foundT) {
                    if (m.targetRva >= opt.fnRva && m.targetRva < opt.fnRva + opt.fnSize) {
                        rep.err = "Ic dallanma hedefi komut sinirinda degil (RVA 0x" + std::to_string(m.targetRva) + ")";
                        return false;
                    }
                    V4Site s; s.fieldAbs = m.blobOff + ((m.kind == K_JCC || m.kind == K_EXPJCC) ? 2u : 1u);
                    s.insnAbs = m.blobOff; s.insnLen = m.newSize;
                    s.kind = 0; s.value = m.targetRva; s.piece = ci;
                    v4sites.push_back(s);
                }
            }
            if (m.hasRip) {
                V4Site s; s.fieldAbs = m.blobOff + m.ripOff;
                s.insnAbs = m.blobOff; s.insnLen = m.newSize;
                s.kind = 2; s.value = m.ripTargetRva; s.piece = ci;
                v4sites.push_back(s);
            }
        }
        if (!endsWithRetSwap) {
            // tail-E9 -> sonraki mantiksal parcanin thunk'i
            blob.push_back(0xE9); blob.resize(blob.size() + 4, 0);
            V4Site s; s.fieldAbs = (u32)blob.size() - 4;
            s.insnAbs = (u32)blob.size() - 5; s.insnLen = 5;
            s.kind = 1; s.value = (ci + 1 < nPieces) ? (ci + 1) : 0; s.piece = ci;
            // son parca ret ile bittigi icin bu yol pratikte olmaz; garanti icin cleanup'a bagla
            if (ci + 1 >= nPieces) s.value = 0xFE;
            v4sites.push_back(s);
        }
        while ((blob.size() - ch.encOff) % 8) blob.push_back(0x90);
        ch.len = (u32)blob.size() - ch.encOff;
        maxSpanLen = (std::max)(maxSpanLen, ch.len);
    }

    // ---- [9] DECOY BLOKLARI (G3, hardened) ----
    u32 decoyTblOff = 0;
    if (hardened) {
        // DUZELTME: eski kod "decoyTblOff = size+32" deyip 32B ayirmiyordu; blob'lar
        // tablonun ustune yaziliyor, sifreleme tablo girdilerini bozuyor -> stage
        // cop doff okuyordu (0x2109CF18F fault). Tablo GERCEKTEN ayirtilir.
        while (blob.size() % 8) blob.push_back(0x90);
        decoyTblOff = (u32)blob.size();
        blob.resize(blob.size() + 32, 0x90);              // tablo 4x8 = 32B (gercek rezervasyon)
        std::vector<std::pair<u32,u32>> dts;              // {off,len}
        for (int di = 0; di < 4; di++) {
            while (blob.size() % 8) blob.push_back(0x90);
            u32 off = (u32)blob.size();
            u32 len = 8 * (2 + rng.Next(2));              // 16-24 bayt
            for (u32 i = 0; i < len; i++) blob.push_back((u8)rng.Next(256));
            dts.push_back({ off, len });
        }
        // decoy tablosunu simdi yaz (yeri başta ayrildi)
        for (int di = 0; di < 4; di++) {
            for (int i = 0; i < 4; i++) blob[decoyTblOff + di * 8 + i] = (u8)(dts[di].first >> (8 * i));
            for (int i = 0; i < 4; i++) blob[decoyTblOff + di * 8 + 4 + i] = (u8)(dts[di].second >> (8 * i));
        }
    }

    // ---- [9.5] CRC-8 TABLOSU (G2, hardened; PLAINTEXT jenerik sabit) ----
    //  256B standart CRC-8 (poly 0x07) tablosu: tbl[i] = i baytinin 8 turu.
    //  Runtime stage: acc = tbl[acc ^ byte] — build'deki bit-serial ile ayni.
    //  Parca span'lerinin DISINDA -> sifreleme dokunmaz (thunk tablosu gibi).
    u32 crcTblOff = 0;
    if (hardened) {
        while (blob.size() % 16) blob.push_back(0x90);
        crcTblOff = (u32)blob.size();
        for (int i = 0; i < 256; i++) {
            u8 c = (u8)i;
            for (int b = 0; b < 8; b++)
                c = (u8)((c & 0x80) ? ((c << 1) ^ 0x07) : (c << 1));
            blob.push_back(c);
        }
    }

    // ---- [10] THUNK TABLOSU (plaintext, V4.2: 12B mov r10d,pid; jmp qword [blob+0x40]) ----
    //  V4.2 KRITIK: conv-reg BAĞIMLILIĞI KALDIRILDI - thunk artık ARENA_PTR alanından
    //  dolaylı atlar (stub arena modunda arena+0, fb modunda fbStage adresini yazar).
    //  disp32 = (blob+0x40) - (thunkRVA+12): mazeRva iptal olur, BUILD-TIME hesap.
    u32 edgeTblOff = (u32)blob.size();
    {
        for (u32 pid = 0; pid < nPieces + nCleanup; pid++) {
            u32 effPid = (pid < nPieces) ? pid : 0xFE - (pid - nPieces);
            blob.push_back(0x41); blob.push_back(0xBA);
            for (int i = 0; i < 4; i++) blob.push_back((u8)(effPid >> (8 * i)));
            blob.push_back(0xFF); blob.push_back(0x25);          // jmp qword [rip+disp32]
            i32 d = (i32)(0x40 - (i64)(edgeTblOff + pid * 12 + 12));
            for (int i = 0; i < 4; i++) blob.push_back((u8)((u32)d >> (8 * i)));
        }
    }

    // ---- [11] SITE + BLK TABLOLARI ----
    u32 sitesOff = (u32)blob.size();
    for (auto& s : v4sites) {
        u32 fieldRel = s.fieldAbs - pcs[s.piece].encOff;
        for (int i = 0; i < 4; i++) blob.push_back((u8)(fieldRel >> (8 * i)));
        blob.push_back(s.kind); blob.push_back(0); blob.push_back(0); blob.push_back(0);
        for (int i = 0; i < 4; i++) blob.push_back((u8)(s.value >> (8 * i)));
    }
    u32 blockTblOff = (u32)blob.size();
    for (auto& ch : pcs) {
        for (int i = 0; i < 4; i++) blob.push_back((u8)(ch.encOff >> (8 * i)));
        for (int i = 0; i < 4; i++) blob.push_back((u8)(ch.len >> (8 * i)));
        for (int i = 0; i < 4; i++) blob.push_back((u8)(ch.siteFirst >> (8 * i)));
        for (int i = 0; i < 4; i++) blob.push_back(0);   // nSites|crc<<8 (patch fazinda)
    }
    for (u32 ci = 0; ci < nPieces; ci++) pcs[ci].nSites = 0;
    for (auto& s : v4sites) pcs[s.piece].nSites++;

    // ---- [12] FAREWELL'LER + FBSTAGE ----
    std::vector<u32> farewellOffs;
    for (u32 i = 0; i < nCleanup; i++) {
        u8 op = (u8)(encKeys[i] & 0xFF);
        u16 iw = (u16)((encKeys[i] >> 8) & 0xFFFF);
        u32 off = EmitArenaFarewell(blob, patches, op, iw, iatVfRva);
        while ((blob.size() - off) % 8) blob.push_back(0x90);
        farewellOffs.push_back(off);
    }
    u32 fbStageOff = EmitStreamFbStage(blob, patches, convReg, nCleanup, farewellOffs);

    // ---- [12.5] CRC-FAIL FAREWELL (G2, hardened; .maze'de plaintext) ----
    //  CRC eslesmezse stage buraya duser (disp'i stub her cagri yamar):
    //  arena'yi VirtualFree ile geri ver + ExitProcess(0xDE) -> FAIL-CLOSED.
    //  Yarida kalmis prolog frame'i caller'a geri donmekle COZULEMEZ (ret cop
    //  poplar) -> bilincli cikis tek dogru anti-patch davranisi.
    u32 crcFarewellOff = 0;
    if (hardened) {
        crcFarewellOff = (u32)blob.size();
        auto putc = [&blob](std::initializer_list<u8> bs) { for (u8 b : bs) blob.push_back(b); };
        putc({0x4C, 0x89, 0xE1});                                   // mov rcx,r12 (arena; conv=saglam)
        putc({0x31, 0xD2});                                         // xor edx,edx
        putc({0x41, 0xB8, 0x00, 0x80, 0x00, 0x00});                 // mov r8d,0x8000 (MEM_RELEASE)
        putc({0xFF, 0x15});                                         // call [rip] VirtualFree
        { Patch p; p.kind = Patch::P_ARENA_VF; p.siteOff = (u32)blob.size(); p.immValue = iatVfRva; patches.push_back(p); }
        blob.resize(blob.size() + 4, 0);
        putc({0xB9, 0xDE, 0x00, 0x00, 0x00});                       // mov ecx,0xDE (anti-patch tetiklendi)
        putc({0xFF, 0x15});                                         // call [rip] ExitProcess (dönmez)
        { Patch p; p.kind = Patch::P_ARENA_VF; p.siteOff = (u32)blob.size(); p.immValue = iatEpRva; patches.push_back(p); }
        blob.resize(blob.size() + 4, 0);
        putc({0xCC});                                               // int3 (ulasilmaz)
    }

    // ---- [13] .maze SECTION ----
    u32 chars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    u32 mazeRva = 0;
    {
        SecInfo* exist = nullptr;
        for (auto& s : pe.secs) if (!strncmp(s.name, ".maze", 8)) { exist = &s; break; }
        bool reuse = (exist != nullptr);
        if (exist) {
            u32 offInSec = ((std::max)(exist->vSz, exist->rawSz) + 15u) & ~15u;
            u32 needVSz  = offInSec + (u32)blob.size();
            u32 newFileEnd = (size_t)exist->raw + ((needVSz + 0xFFFF) & ~0xFFFFu);
            u32 newImgSz  = exist->va + ((needVSz + 0xFFF) & ~0xFFFu);
            if (newFileEnd > pe.raw.size()) pe.raw.resize(newFileEnd, 0xCC);
            auto dos = (PIMAGE_DOS_HEADER)pe.raw.data();
            auto nt = (PIMAGE_NT_HEADERS)(pe.raw.data() + dos->e_lfanew);
            u32 secAlign, fileAlign;
            if (pe.is64) { secAlign = ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.SectionAlignment; fileAlign = ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.FileAlignment; }
            else         { secAlign = ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.SectionAlignment; fileAlign = ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.FileAlignment; }
            auto sh = IMAGE_FIRST_SECTION(nt);
            IMAGE_SECTION_HEADER* hh = nullptr;
            for (u16 i = 0; i < nt->FileHeader.NumberOfSections; i++)
                if (!strncmp((const char*)sh[i].Name, ".maze", 8)) { hh = &sh[i]; break; }
            if (hh) {
                u32 newVSz   = ((needVSz + secAlign - 1) / secAlign) * secAlign;
                u32 newRawSz = ((needVSz + fileAlign - 1) / fileAlign) * fileAlign;
                hh->Misc.VirtualSize = newVSz; hh->SizeOfRawData = newRawSz;
                exist->vSz = newVSz; exist->rawSz = newRawSz;
                if (pe.is64)((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.SizeOfImage = newImgSz;
                else ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.SizeOfImage = newImgSz;
                pe.imgSz = newImgSz;
                if (mem.data.size() < pe.imgSz) mem.data.resize(pe.imgSz, 0);
                mazeRva = exist->va + offInSec;
            } else reuse = false;
        }
        if (!reuse) {
            u32 addSz = (u32)blob.size() + 8;
            u32 mrva2 = 0;
            if (!GrowAppendSection(pe, mem, ".maze", addSz, chars, mrva2)) {
                rep.err = ".maze section eklenemedi (header yer yok + buyutme basarisiz)";
                return false;
            }
            mazeRva = mrva2;
        }
    }
    rep.mazeRva = mazeRva;
    rep.entryRva = mazeRva + pcs[0].encOff;
    for (auto& m : insns) m.newRva = mazeRva + m.blobOff;

    // ---- [14] YAMA FAZI ----
    // V4.1 FIX: rel32 hedefi nextIP (komutun sonu) uzerinden hesaplanir.
    // Eski "fieldAbs + 4" varsayimi sadece disp SON 4 bayt oldugunda dogruydu;
    // add/mov dword [rip+d], imm formlarinda disp'den sonra imm geldigi icin
    // yama 1 bayt kayiyor ve hedef sapitiyordu (sim testi LcgNext'te yakaladi).
    auto applyRel32V4 = [&](u64 fieldAbs, u64 insnEndAbs, i64 targetRva, const char* what) -> bool {
        i64 disp = targetRva - ((i64)mazeRva + insnEndAbs);
        if (disp < -2147483648LL || disp > 2147483647LL) { rep.err = std::string("rel32 tasmasi: ") + what; return false; }
        Poke32(blob, (size_t)fieldAbs, (i32)disp);
        rep.fixupCount++;
        return true;
    };
    for (auto& lc : v4locals)
        if (!applyRel32V4(lc.fieldAbs, lc.insnAbs + lc.insnLen, (i64)insns[lc.targetInsn].newRva, "ayni-parca dal")) return false;
    for (auto& s : v4sites) {
        i64 target;
        if (s.kind == 1) {
            u32 thunkIdx = (s.value < 0xF0) ? s.value : (nPieces + (0xFE - s.value));
            target = (i64)mazeRva + edgeTblOff + (i64)thunkIdx * 12;
        } else target = (i64)s.value;
        if (!applyRel32V4(s.fieldAbs, s.insnAbs + s.insnLen, target, "v4 site")) return false;
    }
    for (auto& p : patches) {
        switch (p.kind) {
        case Patch::P_ARENA_IMM: {
            u32 v = 0;
            u32 w = p.immWhich;
            if (w == 0) v = pe.imgSz + (((mazeRva >> 4) & 0x3FFFu) << 16);
            // V4.4-FIX: arena hint'i machinery basina BENZERSIZ (mazeRva'den turetilmis
            // 64K granuler ofset). Eski hali (yalniz imgSz) coklu korumada HER machinery
            // ayni hint'i uretiyordu -> 2.'nin VirtualAlloc'u 1.'nin arenasina cakiliyor,
            // retry/fallback dongusu cikmazsira giriyor (0x400202 sonsuz VirtualAlloc).
            else if (w == 2) v = sitesOff;
            else if (w == 3) v = 0x1000;
            else if (w == 4) v = mazeRva;
            else if (w == 5) v = pcs[0].encOff;
            else if (w == 6) v = blockTblOff;
            else if (w == 7) v = templateOff;
            else if (w == 8) v = templateLen;
            else if (w == 9) v = ssi.slotImmPos;
            else if (w == 16) v = slotBase;
            else if (w == 17) v = hardened ? 0x1Fu : 0u;   // V4.2: 32 slot x 32B (ust uste binme YOK)
            else if (w == 30) v = decoyTblOff;
            else if (w == 34) v = crcTblOff;
            else if (w == 35) v = crcFarewellOff;
            else if (w == 36) v = ssi.crcDispPos;
            else if (w == 37) v = ssi.crcJmpEnd;
            else if (w == 31) v = fbStageOff;
            else if (w == 32) v = blockTblOff;             // V4.2: fbStage blobBase-relative
            else if (w == 33) v = (u32)(0 - (i64)fbStageOff);
            else if (w >= 10 && w < 30) {
                u32 rem = w - 10, i = rem / 3, sub = rem % 3;
                if (i < farewellOffs.size()) {
                    if (sub == 0) v = ssi.clDispPos[i];
                    else if (sub == 1) v = ssi.clJmpEnd[i];
                    else v = farewellOffs[i];
                }
            }
            Poke32(blob, p.siteOff, (i32)v);
            break;
        }
        case Patch::P_ARENA_VA: case Patch::P_ARENA_VF: {
            i64 disp = (i64)p.immValue - ((i64)mazeRva + (i64)p.siteOff + 4);
            Poke32(blob, p.siteOff, (i32)disp);
            rep.fixupCount++;
            break;
        }
        default: break;
        }
    }
    // blk crc (span FINAL plaintext baytlari uzerinden; disp yamalari dahil)
    {
        for (u32 ci = 0; ci < nPieces; ci++) {
            StreamPiece& ch = pcs[ci];
            u8 crc = 0;
            for (u32 i = 0; i < ch.len; i++) {
                crc ^= blob[ch.encOff + i];
                for (int b = 0; b < 8; b++)
                    crc = (u8)((crc & 0x80) ? ((crc << 1) ^ 0x07) : (crc << 1));
            }
            ch.crc = crc;
            u32 packed = ((u32)crc << 8) | ch.nSites;
            for (int i = 0; i < 4; i++) blob[blockTblOff + ci * 16 + 12 + i] = (u8)(packed >> (8 * i));
        }
    }
    // MZE3 header
    {
        auto wr32 = [&](u32 off, u32 v) { for (int i = 0; i < 4; i++) blob[off + i] = (u8)(v >> (8 * i)); };
        auto wr64 = [&](u32 off, u64 v) { for (int i = 0; i < 8; i++) blob[off + i] = (u8)(v >> (8 * i)); };
        wr32(0x00, nPieces);
        wr32(0x04, 0x33455A4D);            // 'MZE3'
        wr64(0x08, opt.key);
        wr32(0x10, rep.entryRva);
        wr32(0x14, opt.fnRva);
        wr32(0x18, opt.fnSize);
        wr32(0x1C, blockTblOff);
        wr32(0x20, 0u);                    // fallback decrypt-once flagi
        wr32(0x24, 0u);                    // encBytes (asagida)
        wr32(0x28, 0x1000);                // arenaSize (1 sayfa)
        wr32(0x2C, (u32)v4sites.size());
        wr32(0x30, sitesOff);
        wr32(0x34, pe.imgSz);
        wr64(0x48, 0ull);                  // jmpSlot (V4.2: S-8=0x48; yalniz fallback yazar)
        wr32(0x3C, edgeTblOff);
    }

    // ---- [15] DOGRULAMA ----
    {
        csh vh = c.dis.handle;
        // (a) stub + template linear sweep
        {
            u32 off = 0x50, end = templateOff + templateLen;
            while (off < end) {
                cs_insn* v0 = nullptr;
                size_t n = cs_disasm(vh, blob.data() + off, (std::min)((size_t)16, blob.size() - off), mazeRva + off, 1, &v0);
                if (!n) {
                    {   // DEBUG: blob'u dok (hata ayiklama)
                        FILE* f = fopen("v4fail_blob.bin", "wb");
                        if (f) { fwrite(blob.data(), 1, blob.size(), f); fclose(f); }
                    }
                    rep.err = "STREAM: stub/template cozulemedi (off 0x" + std::to_string(off) + ")"; return false;
                }
                off += v0[0].size; cs_free(v0, 1);
            }
        }
        // (b) parca span decode: govde + tail-E9 + pad tam kaplamali
        for (u32 ci = 0; ci < nPieces; ci++) {
            StreamPiece& ch = pcs[ci];
            std::vector<u8> tmp(blob.begin() + ch.encOff, blob.begin() + ch.encOff + ch.len);
            u32 off = 0;
            for (size_t k = 0; k < ch.n; k++) {
                MInsn& m = insns[ch.i0 + k];
                cs_insn* v0 = nullptr;
                size_t n = cs_disasm(vh, tmp.data() + off, (std::min)((size_t)16, tmp.size() - off), mazeRva + ch.encOff + off, 1, &v0);
                if (!n) { rep.err = "STREAM: parca komutu cozulemedi (blk " + std::to_string(ci) + ")"; return false; }
                bool ok = ((u32)v0[0].size == m.newSize) &&
                          (m.isRet ? (v0[0].bytes[0] == 0xE9) : (m.mn == v0[0].mnemonic));
                cs_free(v0, 1);
                if (!ok) { rep.err = std::string("STREAM dogrulama: '") + m.mn + "' yeniden cozulemedi (blk " +
                                  std::to_string(ci) + ")"; return false; }
                off += m.newSize;
            }
            bool expectTail = true;
            { MInsn& m = insns[ch.i0 + ch.n - 1]; expectTail = !m.isRet; }
            if (expectTail) {
                if (off + 5 > ch.len || tmp[off] != 0xE9) { rep.err = "STREAM: tail-E9 yok (blk " + std::to_string(ci) + ")"; return false; }
                off += 5;
            }
            while (off < ch.len) {
                if (tmp[off] != 0x90) { rep.err = "STREAM: pad beklendi (blk " + std::to_string(ci) + ")"; return false; }
                off++;
            }
        }
        // (c) SIMULASYON: slot = blobBase + SIM; her site disp -= (SIM - encOff)
        {
            const i64 SIM = 0x40000000;
            std::vector<u8> sim = blob;
            for (auto& s : v4sites) {
                i32 delta = (i32)SIM;   // slot = parcanin kendi konumu + SIM varsayimi (encOff cancel olur)
                i32 dv; memcpy(&dv, &sim[s.fieldAbs], 4);
                dv -= delta;
                memcpy(&sim[s.fieldAbs], &dv, 4);
            }
            auto checkOne = [&](u32 insnAbs, i64 expectRvaAbs, const char* what) -> bool {
                u64 simVA = (u64)mem.base + mazeRva + (u64)SIM + insnAbs;
                cs_insn* v0 = nullptr;
                size_t n = cs_disasm(vh, &sim[insnAbs], (std::min)((size_t)16, sim.size() - insnAbs), simVA, 1, &v0);
                if (!n) { rep.err = std::string("STREAM sim: komut cozulemedi (") + what + ")"; return false; }
                bool ok = false;
                cs_detail* d = v0[0].detail;
                if (d && d->x86.op_count > 0 && d->x86.operands[0].type == X86_OP_IMM)
                    ok = ((u64)d->x86.operands[0].imm == (u64)expectRvaAbs);
                else if (d) for (int i = 0; i < d->x86.op_count && !ok; i++) {
                    auto& o = d->x86.operands[i];
                    if (o.type == X86_OP_MEM && o.mem.base == X86_REG_RIP)
                        ok = (((u64)simVA + v0[0].size + (u64)(i64)o.mem.disp) == (u64)expectRvaAbs);
                }
                if (!ok) {
                    char dbg[256];
                    snprintf(dbg, sizeof(dbg),
                        "[sim-dbg] %s: insnAbs=%u size=%u simVA=0x%llX expect=0x%llX asm='%s %s'\n",
                        what, insnAbs, (unsigned)v0[0].size,
                        (unsigned long long)simVA, (unsigned long long)expectRvaAbs,
                        v0[0].mnemonic, v0[0].op_str);
                    fputs(dbg, stderr);
                    FILE* f = fopen("v4fail_sim.bin", "wb");
                    if (f) { fwrite(sim.data(), 1, sim.size(), f); fclose(f); }
                }
                cs_free(v0, 1);
                if (!ok) { rep.err = std::string("STREAM sim: hedef tutmadi (") + what + ")"; return false; }
                return true;
            };
            for (auto& lc : v4locals) {
                i64 expect = (i64)mem.base + insns[lc.targetInsn].newRva + SIM;   // ayni-parca: slot-uzayinda
                if (!checkOne(lc.insnAbs, expect, "local")) return false;
            }
            for (auto& s : v4sites) {
                i64 expect = 0;
                if (s.kind == 0) expect = (i64)mem.base + s.value;
                else if (s.kind == 2) expect = (i64)mem.base + s.value;
                else {
                    u32 thunkIdx = (s.value < 0xF0) ? s.value : (nPieces + (0xFE - s.value));
                    expect = (i64)mem.base + mazeRva + edgeTblOff + (i64)thunkIdx * 12;
                }
                if (!checkOne(s.insnAbs, expect, s.kind == 1 ? "thunk" : (s.kind == 0 ? "ext" : "rip"))) return false;
            }
        }
    }

    // ---- [16] SIFRELEME (span'ler + decoy blob'lari) ----
    u32 encBytes = 0;
    {
        u8 kb[8]; memcpy(kb, &opt.key, 8);
        for (auto& ch : pcs) {
            for (u32 i = 0; i < ch.len; i++) blob[ch.encOff + i] ^= kb[i & 7];
            encBytes += ch.len;
        }
        if (hardened && decoyTblOff) {
            for (int di = 0; di < 4; di++) {
                u32 off, len;
                memcpy(&off, &blob[decoyTblOff + di * 8], 4);
                memcpy(&len, &blob[decoyTblOff + di * 8 + 4], 4);
                for (u32 i = 0; i < len; i++) blob[off + i] ^= kb[i & 7];
                encBytes += len;
            }
        }
    }

    // ---- [17] BELLEGE YAZ + TRAMBOLIN ----
    memcpy(mem.data.data() + mazeRva, blob.data(), blob.size());
    {
        u32 jmpTargetRva = mazeRva + 0x50;   // stub (V4.2: header 0x50; blob+0x50'de)
        i64 rel = (i64)jmpTargetRva - ((i64)opt.fnRva + 5);
        if (rel < -2147483648LL || rel > 2147483647LL) { rep.err = "Trambolin rel32 tasmadi"; return false; }
        // V4.1: son komut fnSize'i astiginda (tail-jmp) CC doldurmayi komut sonuna uzat
        u32 bodyEnd = insns.back().rva + insns.back().size - opt.fnRva;
        if (bodyEnd < opt.fnSize) bodyEnd = opt.fnSize;
        if (opt.fnRva + bodyEnd > mem.data.size()) { rep.err = "Trambolin yazim alani bellegin disinda"; return false; }
        u8* body = mem.data.data() + opt.fnRva;
        body[0] = 0xE9;
        for (int i = 0; i < 4; i++) body[1 + i] = (u8)(((u64)rel >> (8 * i)) & 0xFF);
        for (u32 i = 5; i < bodyEnd; i++) body[i] = 0xCC;
        if (mem.data[opt.fnRva] != 0xE9) { rep.err = "Trambolin yazilamadi"; return false; }
    }

    // ---- [18] DIS REFERANSLAR (ortaya gelenler reddedilir) ----
    {
        u64 fnStartVA = mem.base + opt.fnRva;
        u64 fnEndVA   = fnStartVA + opt.fnSize;
        for (auto& r : c.refs.refs) {
            if (r.dst < fnStartVA || r.dst >= fnEndVA) continue;
            if (r.src >= fnStartVA && r.src < fnEndVA) continue;
            u32 dstRva = (u32)(r.dst - mem.base);
            if (dstRva != opt.fnRva) {
                rep.err = "STREAM modu: fonksiyon ORTASINA gelen dis referans var (RVA 0x" + std::to_string(dstRva) +
                          ") - slot gecici; V3 arena modu kullanin";
                return false;
            }
            continue;   // girise gelenler tramboline carpar - yonlendirme gerekmez
        }
    }

    // ---- [19] RAPOR ----
    rep.ok = true;
    rep.mazeSize = pe.secs.back().rawSz;
    rep.blobBytes = (u32)blob.size();
    rep.chunkCount = nPieces;
    rep.streamActive = true;
    rep.streamBlocks = nPieces;
    rep.streamSites = (u32)v4sites.size();
    rep.streamThunks = nPieces + nCleanup;
    rep.slotSize = ((maxSpanLen + 15u) & ~15u);
    rep.maxPieceLen = maxSpanLen;
    rep.templateLen = templateLen;
    rep.edgeTblOff = edgeTblOff;
    rep.jmpSites.push_back(opt.fnRva);   // trambolin
    for (u32 pid = 0; pid < nPieces + nCleanup; pid++)
        rep.jmpSites.push_back(mazeRva + edgeTblOff + pid * 12);
    {
        char b[320];
        const char* convName = (convReg == 4) ? "r12" : (convReg == 5) ? "r13" :
                               (convReg == 6) ? "r14" : "r15";   // convReg = reg3 (4..7)
        snprintf(b, sizeof(b), "INFO mod=V4-STREAM hardened=%d slot=%uB maxPiece=%uB template=%uB conv=%s arena=4096B",
                 (int)hardened, rep.slotSize, maxSpanLen, templateLen, convName);
        rep.streamMap.push_back(b);
        for (u32 ci = 0; ci < nPieces; ci++) {
            StreamPiece& ch = pcs[ci];
            MInsn& f = insns[ch.i0];
            MInsn& l = insns[ch.i0 + ch.n - 1];
            snprintf(b, sizeof(b), "BLK %02u enc=0x%04X len=%2u ops=%2zu rva=0x%04X..0x%04X sites=%u crc=0x%02X",
                     ci, ch.encOff, ch.len, ch.n, f.rva, l.rva + l.size, ch.nSites, ch.crc);
            rep.streamMap.push_back(b);
        }
        for (auto& s : v4sites) {
            const char* kn = (s.kind == 0) ? "MODUL" : (s.kind == 1) ? "THUNK" : "RIP";
            snprintf(b, sizeof(b), "SITE blk=%02u +0x%02X kind=%s val=0x%X", s.piece, s.fieldAbs - pcs[s.piece].encOff, kn, s.value);
            rep.streamMap.push_back(b);
        }
        for (u32 pid = 0; pid < nPieces + nCleanup; pid++) {
            u32 effPid = (pid < nPieces) ? pid : 0xFE - (pid - nPieces);
            if (pid < nPieces) snprintf(b, sizeof(b), "EDGE thunk=0x%X mov r10d,%u -> parca%u", mazeRva + edgeTblOff + pid * 12, effPid, effPid);
            else               snprintf(b, sizeof(b), "EDGE thunk=0x%X mov r10d,0x%X -> cleanup", mazeRva + edgeTblOff + pid * 12, effPid);
            rep.streamMap.push_back(b);
        }
    }
    rep.warnings.push_back("V4 STREAM AKTIF: her cagride VirtualAlloc ile tek sayfa arena acilir, parcalar TEK TEK 32B'lik slot'a cozulur, WIPE-BEHIND oncekini siler; her an max 1 parca plaintext");
    if (hardened)
        rep.warnings.push_back("G1 slot her cagride rastgele adrese duser; G2 CRC-8 parca butunlugunu denetler; G3 %25 decoy enjeksiyonu");
    rep.warnings.push_back("ARENA-V3 kurali gecerli: ayni fonksiyonu ayni anda coklu thread'te cagirmayin (fallback yolu decrypt-once flagi kullanir); VirtualAlloc basarisizsa otomatik YERINDE stream'a duser (crash yok)");
    return true;
}

static bool FixFileChecksum(const std::wstring& path, std::string& err) {
    HANDLE hF = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hF == INVALID_HANDLE_VALUE) { err = "checksum icin dosya acilamadi"; return false; }
    DWORD sz = GetFileSize(hF, nullptr);
    std::vector<u8> img((size_t)sz);
    DWORD rd = 0;
    ReadFile(hF, img.data(), sz, &rd, nullptr);
    if (rd != sz || sz < 0x100) { CloseHandle(hF); err = "checksum icin okuma kisa"; return false; }

    auto dos = (PIMAGE_DOS_HEADER)img.data();
    auto nt  = (PIMAGE_NT_HEADERS)(img.data() + dos->e_lfanew);
    // 1) Authenticode imzasi varsa temizle (artik gecersiz olur)
    auto& sec = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    bool hadSig = (sec.VirtualAddress && sec.Size);
    if (hadSig) { sec.VirtualAddress = 0; sec.Size = 0; }
    // 2) MS checksum: sozcuk sozcuk topla, eldeleri katla, checksum alanini 0 say
    u32* pSum = (u32*)(void*)&nt->OptionalHeader.CheckSum;
    u64 sumOff = (u64)((u8*)pSum - img.data());
    u32 sum = 0;
    size_t n = img.size();
    for (size_t i = 0; i + 1 < n; i += 2) {
        u32 v = 0;
        if (!(i == sumOff || i + 1 == sumOff)) v = img[i] | ((u32)img[i + 1] << 8);
        sum += v;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (n & 1) { sum += img[n - 1]; sum = (sum & 0xFFFF) + (sum >> 16); }
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum += (u32)n;                         // dosya uzunlugu
    sum = (sum & 0xFFFF) + (sum >> 16);    // son fold (MS algoritmasi)
    u32 finalSum = sum;
    *pSum = finalSum;

    SetFilePointer(hF, 0, nullptr, FILE_BEGIN);
    DWORD wr = 0;
    WriteFile(hF, img.data(), sz, &wr, nullptr);
    CloseHandle(hF);
    if (wr != sz) { err = "checksum yazilamadi"; return false; }
    return hadSig; // true donerse imza temizlendi (hata degil)
}

// ============================================================================
//  ANA KURULUM
//  Core c: yuklu PE (pe+mem+dis+refs). Kod bellekte (mem) degisir;
//  kaydetme isini cagiran taraf yapar (pe.Save) -> benikoru.exe
// ============================================================================

#include "Motor_V4.2_X86.h"   // V4.2: PE32 (x86) STREAM emitter'i

inline bool Build(Core& c, const Options& optIn, Report& rep) {
    if (optIn.stream) return c.pe.is64 ? BuildStream(c, optIn, rep) : BuildStreamX86(c, optIn, rep);   // V4.2: x64 + x86
    Options opt = optIn;
    auto& pe  = c.pe;
    auto& mem = c.mem;
    rep.fnRva = opt.fnRva; rep.fnSize = opt.fnSize;  // trim sonrasi guncellenecek

    // ---- [1] TEMEL DOGRULAMA ---------------------------------------------
    if (!pe.valid || mem.data.empty())          { rep.err = "PE yuklu degil"; return false; }
    if (!pe.is64)                               { rep.err = "Sadece x64 (PE32+) destekleniyor"; return false; }
    if (opt.fnSize < 5)                         { rep.err = "Fonksiyon cok kucuk (en az 5 bayt gerekli, trambolin icin)"; return false; }
    if (opt.fnRva == 0 || opt.fnRva >= pe.imgSz){ rep.err = "RVA goruntu disinda"; return false; }
    if (opt.fnRva + opt.fnSize > pe.imgSz)      { rep.err = "Fonksiyon araligi SizeOfImage'i asiyor"; return false; }
    if (opt.chunkMax < 8)  opt.chunkMax = 8;
    if (opt.chunkMax > 64) opt.chunkMax = 64;
    if (opt.decoyChance < 0)   opt.decoyChance = 0;
    if (opt.decoyChance > 100) opt.decoyChance = 100;

    // fonksiyon CALISTIRILABILIR bir section'da olmali
    bool inExec = false;
    for (auto& s : pe.secs)
        if (opt.fnRva >= s.va && opt.fnRva + opt.fnSize <= s.va + (std::max)(s.vSz, s.rawSz))
            { inExec = (s.chars & IMAGE_SCN_MEM_EXECUTE) != 0; break; }
    if (!inExec) { rep.err = "Fonksiyon calistirilabilir (X) bir section'da degil"; return false; }

    // ---- [1.5] MUTLAK ADRES (RELOC) KONTROLÜ ------------------------------
    // Fonksiyon govdesinde imm64/disp32 mutlak adres varsa (reloc kayitli), komut
    // .maze'ye tasininca loader artik dogru yeri yamalayamaz -> ASLR altinda crash.
    // Bu durumda fonksiyonu reddet (guvenli taraf).
    for (auto& r : pe.relocs) {
        if (r.rva + 8 > opt.fnRva && r.rva < opt.fnRva + opt.fnSize) {
            if (!opt.allowRelocBody) {
                char eb[192]; snprintf(eb, sizeof(eb),
                    "Fonksiyon govdesinde mutlak adres var (reloc RVA 0x%X) - tasima sonrasi ASLR altinda bozulur, bu fonksiyon labirentlenemez (cozum: encoder V4.5 ASLR kapali cikis)", r.rva);
                rep.err = eb;
                return false;
            }
            char wb[160]; snprintf(wb, sizeof(wb),
                "Govdede mutlak adres (reloc RVA 0x%X): cikista ASLR KAPALI (DYNAMICBASE temizlendi), mutlak adresler tercih-edilen base'de gecerli", r.rva);
            rep.warnings.push_back(wb);
            break;
        }
    }

    // ---- [1.6] ARENA MODU KARARI (v3) --------------------------------------
    // Sartlar: IAT'de kernel32!VirtualAlloc + VirtualFree var, son komut ret.
    // Sart saglanmazsa sessizce YERINDE moda duser (non-breaking, crash yok).
    bool arena = opt.arena;
    u32 iatVaRva = 0, iatVfRva = 0;
    if (arena) {
        bool va = FindIatRva(c, "VirtualAlloc", iatVaRva);
        bool vf = FindIatRva(c, "VirtualFree", iatVfRva);
        if (!va || !vf) {
            rep.warnings.push_back("ARENA modu istendi ama IAT'de kernel32!VirtualAlloc/VirtualFree yok -> YERINDE mod kullanilacak");
            arena = false;
        }
    }

    // ---- [2] DISREFERENCES TARA (diger kodun bu fonksiyona atlari) --------
    if (!c.refs.built) {
        rep.warnings.push_back("Goruntu referanslari taraniyor (diger fonksiyonlardan gelen call/jmp icin)...");
        c.BuildRefs();
    }

    // ---- [3] KOMUT KOMUT COZ (komut sinirlari kesinlikle korunur) --------
    u64 startVA = mem.base + opt.fnRva;
    u64 endVA   = startVA + opt.fnSize;
    std::vector<MInsn> insns;
    {
        u64 a = startVA;
        while (a < endVA) {
            const u8* p = &mem.data[(size_t)(a - mem.base)];
            size_t rm = (size_t)(mem.data.size() - (a - mem.base));
            cs_insn* i0 = nullptr;
            size_t n = cs_disasm(c.dis.handle, p, (std::min)(rm, (size_t)16), a, 1, &i0);
            if (!n) { rep.err = "Cozulamayan bayt: RVA 0x" + std::to_string(a - mem.base) +
                               " (fonksiyon boyutu yanlis olabilir)"; return false; }
            MInsn m;
            m.rva  = (u32)(a - mem.base);
            m.size = (u8)i0[0].size;
            memcpy(m.bytes, i0[0].bytes, (m.size <= 16) ? m.size : 16);
            m.mn = i0[0].mnemonic;
            cs_detail* d = i0[0].detail;
            u8 op0 = m.bytes[0];
            u8 op1 = (m.size >= 2) ? m.bytes[1] : 0;
            bool grpJmp = false, grpCall = false, grpRet = false;
            if (d) for (u8 g = 0; g < d->groups_count; g++) {
                if (d->groups[g] == CS_GRP_JUMP) grpJmp = true;
                if (d->groups[g] == CS_GRP_CALL) grpCall = true;
                if (d->groups[g] == CS_GRP_RET)  grpRet  = true;
            }
            m.isRet = grpRet;

            if (op0 >= 0xE0 && op0 <= 0xE3) { // loop/loope/loopne/jcxz/jrcxz
                cs_free(i0, 1);
                rep.err = "loop/jcxz komutu tespit edildi (RVA 0x" + std::to_string(m.rva) +
                          ") - bu fonksiyon labirentlenemez (rel32 karsiligi yok)";
                return false;
            }
            // dallanma hedefi (ilk IMM)
            u64 immTarget = 0; bool hasImm = false;
            if (d) for (int i = 0; i < d->x86.op_count; i++)
                if (d->x86.operands[i].type == X86_OP_IMM) { hasImm = true; immTarget = (u64)d->x86.operands[i].imm; break; }

            if (grpCall && op0 == 0xE8) {
                m.kind = K_BR; m.targetRva = (u32)(immTarget - mem.base);
            } else if (grpJmp && m.mn == "jmp") {
                if (op0 == 0xE9)      { m.kind = K_BR; m.targetRva = (u32)(immTarget - mem.base); }
                else if (op0 == 0xEB) { m.kind = K_EXPJMP; m.targetRva = (u32)(immTarget - mem.base); }
                else if (hasImm)      { cs_free(i0, 1); rep.err = "Far/segment jmp desteklenmiyor (RVA 0x" + std::to_string(m.rva) + ")"; return false; }
                // dolayli jmp (jmp rax/[..]) -> K_NONE, bayt aynen tasinir
            } else if (grpJmp) { // kosullu jcc
                if (op0 >= 0x70 && op0 <= 0x7F)                 { m.kind = K_EXPJCC; m.targetRva = (u32)(immTarget - mem.base); }
                else if (op0 == 0x0F && op1 >= 0x80 && op1 <= 0x8F) { m.kind = K_JCC;  m.targetRva = (u32)(immTarget - mem.base); }
                else { cs_free(i0, 1); rep.err = "Bilinmeyen dallanma formu (RVA 0x" + std::to_string(m.rva) + ")"; return false; }
            } // else: dolayli call / diger komutlar K_NONE

            if ((m.kind == K_BR || m.kind == K_JCC || m.kind == K_EXPJMP || m.kind == K_EXPJCC)) {
                if (m.targetRva >= pe.imgSz) { cs_free(i0, 1); rep.err = "Dallanma goruntu disina cikiyor (RVA 0x" + std::to_string(m.rva) + ")"; return false; }
            }

            // RIP-relatif veri erisimi ("address belirten rva'lar" burada korunur)
            if (d) for (int i = 0; i < d->x86.op_count; i++) {
                auto& o = d->x86.operands[i];
                if (o.type == X86_OP_MEM && o.mem.base == X86_REG_RIP) {
                    if (m.hasRip) { cs_free(i0, 1); rep.err = "Coklu RIP-relatif operand desteklenmiyor (RVA 0x" + std::to_string(m.rva) + ")"; return false; }
                    m.hasRip  = true;
                    m.ripDisp = (i32)o.mem.disp;
                    i64 t = (i64)m.rva + m.size + (i64)o.mem.disp;
                    if (t < 0 || t >= (i64)pe.imgSz) { cs_free(i0, 1); rep.err = "RIP-relatif hedef goruntu disinda (RVA 0x" + std::to_string(m.rva) + ")"; return false; }
                    m.ripTargetRva = (u32)t;
                    if (t >= (i64)opt.fnRva && t < (i64)(opt.fnRva + opt.fnSize)) {
                        cs_free(i0, 1);
                        rep.err = "Fonksiyon KENDI icindeki veriye isaret ediyor (jump table?) RVA 0x" + std::to_string(m.rva) + " - desteklenmiyor";
                        return false;
                    }
                    int off = CalcRipDispOff(m.bytes, m.size, &d->x86);
                    if (off < 0) { cs_free(i0, 1); rep.err = "RIP-relatif disp konumu bulunamadi (RVA 0x" + std::to_string(m.rva) + ")"; return false; }
                    m.ripOff = (u32)off;
                }
            }
            cs_free(i0, 1);
            insns.push_back(m);
            a += m.size;
        }
    }
    if (insns.empty()) { rep.err = "Hic komut cozulamadi"; return false; }

    // sondaki INT3/NOP dolgusunu temizle (kullanici boyutu fazla girdiyse)
    while (insns.size() >= 2) {
        MInsn& last = insns.back();
        if (last.size == 1 && (last.bytes[0] == 0xCC || last.bytes[0] == 0x90)) {
            MInsn& prev = insns[insns.size() - 2];
            if (prev.isRet || (prev.kind == K_BR && prev.mn == "jmp")) {
                insns.pop_back();
                opt.fnSize -= 1;
                rep.warnings.push_back("Sondaki INT3/NOP dolgusu temizlendi (fonksiyon sonu: RVA 0x" + std::to_string(prev.rva + prev.size) + ")");
                continue;
            }
        }
        break;
    }
    rep.fnSize = opt.fnSize;
    {
        MInsn& last = insns.back();
        if (!last.isRet && !(last.kind == K_BR && last.mn == "jmp")) {
            rep.err = "Son komut ret/jmp degil ('" + last.mn + "' RVA 0x" + std::to_string(last.rva) +
                      ") - fonksiyon boyutu yanlis olabilir (ortadan kesilmis)";
            return false;
        }
        // ARENA: cikis ret olmak ZORUNDA (tail jmp'te cleanup calismaz -> arena leak ->
        // dongude tekrar tekrar cagrilirsa bellek biter). Guvenli taraf: yerinde mod.
        if (arena && !last.isRet) {
            rep.warnings.push_back("ARENA modu istendi ama fonksiyon tail-jmp ile bitiyor (ret yok) -> YERINDE mod kullanilacak");
            arena = false;
        }
    }
    rep.insnCount = (u32)insns.size();

    // ---- [4] PARCALAMA (chunk) --------------------------------------------
    std::vector<Chunk> chunks;
    {
        size_t i = 0;
        while (i < insns.size()) {
            Chunk ch; ch.i0 = i; u32 len = 0;
            while (i < insns.size()) {
                u32 isz = NewSizeOf(insns[i]);
                if (len > 0 && len + isz > opt.chunkMax) break;
                len += isz; i++;
            }
            ch.n = i - ch.i0;
            chunks.push_back(ch);
        }
    }
    rep.chunkCount = (u32)chunks.size();
    size_t lastInsnIdx = insns.size() - 1;

    // cikista tekrar sifreleme: DECRYPT-ONCE FLAGI ile cakisir -> artik her zaman kapali
    // (eski davranis 2. cagrida XOR'u geri sifreleyip crash yaratirdi; flag modu coklu
    //  cagri/rekursyon/thread guvenli tek dogru mod)
    bool reencrypt = false; u8 retOp = 0xC3; u16 retImm = 0;
    if (opt.encrypt && opt.reencryptOnExit)
        rep.warnings.push_back("'Cikista tekrar sifreleme' devre disi: decrypt-once flagi kullaniliyor (coklu cagri guvenligi)");
    rep.reencrypt = reencrypt;

    // ---- [5] ANAHTAR / TOHUM ----------------------------------------------
    Rng rng(opt.seed ? opt.seed : (opt.fnRva ^ 0x5A17A5A5u));
    if (!opt.key) {
        u64 t = (u64)GetTickCount64();
        t ^= (u64)(uintptr_t)&c << 32;
        t ^= (u64)opt.fnRva * 0x9E3779B97F4A7C15ull;
        t ^= t >> 29; t *= 0xBF58476D1CE4E5B9ull; t ^= t >> 32;
        opt.key = t ? t : 0x0123456789ABCDEFull;
    }
    rep.keyUsed = opt.key;

    // ---- [6] BLOB INSASI ---------------------------------------------------
    std::vector<u8> blob;
    std::vector<Patch> patches;
    bool enc = opt.encrypt;
    if (arena && !enc) {
        rep.warnings.push_back("ARENA modu sifreleme ile anlamli (plain parcalar zaten gorunur) -> YERINDE mod kullanilacak");
        arena = false;
    }

    // sifrelenecek/arena'ya kopyalanacak span listesi (chunk govde+connector+dolgu
    // ve arena modunda cleanup bloklari) - v2'de chunk'larin kendisi
    std::vector<std::pair<u32,u32>> encSpans;
    // calisma aninda delta-duzeltilecek disp'ler + dogrulama bilgisi
    struct ArenaSite { u32 fieldOff; u32 insnOff; u8 kind; u64 expectRva; u32 extra; }; // kind: 0=BR 1=RIP 3=FAREWELLJMP(extra=blob off)
    std::vector<ArenaSite> arenaSiteInfo;
    std::vector<std::pair<u32,u32>> mazeOnlySpans;   // farewell: sifrelenir, arena'ya kopyalanmaz
    struct FarewellSite { u32 fieldOff, insnOff, farewellOff; };
    std::vector<FarewellSite> farewellSites;         // {fieldOff, insnOff, farewellOff}
    u32 arenaStubEnd = 0;

    if (enc && !arena) {
        // header (0x30 bayt): alanlar EmitXorStub'in varsirimlariyla uyumlu
        // 0x28: decrypt-once flagi (stub 1. cagride cozer, bayragi kurar;
        //       2. cagride atlar - coklu cagri/rekursyon guvenli)
        blob.resize(0x30, 0);
        // stub
        EmitXorStub(blob, true, patches); // P_STUBJ ekler
    } else if (enc && arena) {
        // ARENA header (0x40 bayt):
        //  0x00 nRegions | 0x04 'MZE2' | 0x08 anahtar | 0x10 entryRva | 0x14 fnRva
        //  0x18 fnSize   | 0x1C tableOff | 0x20 decryptFlag(fallback) | 0x24 encBytes
        //  0x28 arenaSize | 0x2C nSites | 0x30 sitesOff | 0x34 imgSize | 0x38 jmpSlot(u64, runtime)
        blob.resize(0x40, 0);
        arenaStubEnd = EmitArenaStub(blob, patches, iatVaRva); // P_ARENA_IMM/VA ekler
    }

    // fiziksel sirayi karistir (mantiksal akis JMP'lerle bagli - labirent etkisi)
    std::vector<u32> order(chunks.size());
    for (u32 i = 0; i < (u32)order.size(); i++) order[i] = i;
    for (size_t i = order.size() - 1; i > 0; i--) std::swap(order[i], order[rng.Next((u32)(i + 1))]);

    bool firstPhys = true;
    for (u32 ci : order) {
        Chunk& ch = chunks[ci];
        bool isLast = (ci == (u32)chunks.size() - 1);

        if (!firstPhys) {
            u32 nf = rng.Next(3);
            for (u32 k = 0; k < nf; k++) blob.push_back(0x90);
            if ((int)rng.Next(100) < opt.decoyChance) EmitDecoy(blob, rng, rep.decoyCount);
        }
        firstPhys = false;

        ch.blobOff = (u32)blob.size();
        ch.spanOff = ch.blobOff;
        for (size_t k = 0; k < ch.n; k++) {
            size_t ii = ch.i0 + k;
            MInsn& m = insns[ii];
            m.blobOff = (u32)blob.size();
            bool termSwap = (reencrypt && ii == lastInsnIdx);
            // ARENA: her ret -> JMP cleanup bloku (cikista arena serbest birakilir).
            // ret encoding'i saklanir; cleanup bloklari chunk'lardan sonra uretilir.
            bool arenaRet = (arena && enc && m.isRet);
            // komutu yeni formuyla uret
            if (termSwap || arenaRet) {
                // KRITIK: ret'in baytlari YAZILMAZ - sadece JMP cleanup yazilir
                // (ret once yazilsaydi fonksiyon cleanup'a hic ulasmadan donerdi)
                m.newSize = 5;
            } else switch (m.kind) {
            case K_BR: case K_JCC: {
                for (int b = 0; b < m.size; b++) blob.push_back(m.bytes[b]);
                m.newSize = (u32)m.size;
                Patch p; p.kind = Patch::P_BR; p.insnIdx = (u32)ii;
                p.dispOff = (m.kind == K_BR) ? 1 : 2;
                p.targetInsn = Patch::NO_TARGET;
                patches.push_back(p);
                break;
            }
            case K_EXPJMP: {
                blob.push_back(0xE9); blob.resize(blob.size() + 4, 0);
                m.newSize = 5;
                Patch p; p.kind = Patch::P_BR; p.insnIdx = (u32)ii; p.dispOff = 1;
                p.targetInsn = Patch::NO_TARGET;
                patches.push_back(p);
                break;
            }
            case K_EXPJCC: {
                blob.push_back(0x0F); blob.push_back((u8)(0x80 | (m.bytes[0] - 0x70)));
                blob.resize(blob.size() + 4, 0);
                m.newSize = 6;
                Patch p; p.kind = Patch::P_BR; p.insnIdx = (u32)ii; p.dispOff = 2;
                p.targetInsn = Patch::NO_TARGET;
                patches.push_back(p);
                break;
            }
            default: { // K_NONE
                for (int b = 0; b < m.size; b++) blob.push_back(m.bytes[b]);
                m.newSize = (u32)m.size;
                break;
            }
            }
            // dallanma hedefi: fonksiyon icindeyse YENI konuma, disaridaysa ayni RVA
            // (K_JCC DAHIL OLMALI - 0F8x jcc'lerin hedefi yoksa ESKI govdeye atlar!)
            if (m.kind == K_BR || m.kind == K_JCC || m.kind == K_EXPJMP || m.kind == K_EXPJCC) {
                bool foundT = false;
                for (size_t j = 0; j < insns.size(); j++)
                    if (insns[j].rva == m.targetRva) {
                        patches.back().targetInsn = (u32)j; foundT = true; break;
                    }
                // bulunamadi -> dis hedef, targetRva oldugu gibi kullanilacak
                // AMA hedef fonksiyonun KENDI araliginda ise bu CATI (komut siniri
                // disina atlama) - eski govde CC dolgusuna dusar -> INT3/crash:
                if (!foundT && m.targetRva >= opt.fnRva && m.targetRva < opt.fnRva + opt.fnSize) {
                    rep.err = "Ic dallanma hedefi komut sinirinda degil (RVA 0x" + std::to_string(m.targetRva) +
                              ") - fonksiyon guvenli labirentlenemez (yanlis boyut / ortaya atlama)";
                    return false;
                }
            }
            if (m.hasRip) {
                Patch p; p.kind = Patch::P_RIP; p.insnIdx = (u32)ii;
                patches.push_back(p);
            }
            if (termSwap) {
                blob.push_back(0xE9); blob.resize(blob.size() + 4, 0);
                Patch p; p.kind = Patch::P_CC; p.siteOff = (u32)blob.size() - 4;
                patches.push_back(p);
            } else if (arenaRet) {
                blob.push_back(0xE9); blob.resize(blob.size() + 4, 0);
                Patch p; p.kind = Patch::P_ARENA_RET; p.siteOff = (u32)blob.size() - 4;
                p.targetInsn = 0; // cleanup blob ofseti [7]'de doldurulur
                p.immValue = (u32)m.bytes[0] | ((u32)((m.size >= 3) ? (m.bytes[1] | ((u32)m.bytes[2] << 8)) : 0) << 8);
                patches.push_back(p);
            }
        }
        if (!isLast) {
            // connector: JMP sonraki mantiksal chunk'in ilk komutuna
            blob.push_back(0xE9); blob.resize(blob.size() + 4, 0);
            Patch p; p.kind = Patch::P_CONN; p.siteOff = (u32)blob.size() - 4; p.chunkIdx = ci + 1;
            patches.push_back(p);
        }
        // sifrelenecek span'i 8'in katina NOP ile tamamla
        while ((blob.size() - ch.spanOff) % 8) blob.push_back(0x90);
        ch.spanLen = (u32)(blob.size() - ch.spanOff);
        encSpans.push_back({ ch.spanOff, ch.spanLen });
        rep.encBytes += enc ? ch.spanLen : 0;
    }

    // ---- [7] BOLGE TABLOSU + CLEANUP STUB ---------------------------------
    u32 tableOff = 0, cleanupOff = 0, sitesOff = 0, arenaSize = 0;
    if (enc && !arena) {
        tableOff = (u32)blob.size();
        for (auto& ch : chunks) {
            u32 o = ch.spanOff, l = ch.spanLen;
            for (int i = 0; i < 4; i++) blob.push_back((u8)(o >> (8 * i)));
            for (int i = 0; i < 4; i++) blob.push_back((u8)(l >> (8 * i)));
        }
        if (reencrypt) cleanupOff = EmitXorStub(blob, false, patches, retOp, retImm);
    } else if (enc && arena) {
        // her benzersiz ret encoding'i icin cleanup (arena'da yasar) + farewell
        // (maze'de yasar, VirtualFree'i ORADAN yapar -> freed-fetch crash imkansiz)
        // DIKKAT: EmitArena* patches'i realloc eder -> INDEX ile gez, referans tasima!
        std::map<u32, u32> cleanupMap;            // key (op | imm<<8) -> cleanup blob off
        std::map<u32, u32> farewellMap;           // key -> farewell blob off
        std::vector<ArenaJmpSite> jmpSites;       // cleanup->farewell jmp yamalari
        size_t nRet = 0;
        for (size_t pi = 0; pi < patches.size(); pi++)
            if (patches[pi].kind == Patch::P_ARENA_RET) nRet++;
        size_t processed = 0;
        for (size_t pi = 0; pi < patches.size() && processed < nRet; pi++) {
            if (patches[pi].kind != Patch::P_ARENA_RET) continue;
            processed++;
            u32 key = patches[pi].immValue;
            auto it = cleanupMap.find(key);
            if (it == cleanupMap.end()) {
                u32 off = EmitArenaCleanup(blob, patches, jmpSites, key);
                while ((blob.size() - off) % 8) blob.push_back(0x90);   // span 8'in kati
                it = cleanupMap.emplace(key, off).first;
                encSpans.push_back({ off, (u32)blob.size() - off });
                rep.encBytes += (u32)blob.size() - off;
            }
            patches[pi].targetInsn = it->second;  // realloc SONRASI index ile yaz (ret-site E9 -> cleanup)
        }
        for (auto& kv : cleanupMap) {
            u8 op = (u8)(kv.first & 0xFF);
            u16 iw = (u16)((kv.first >> 8) & 0xFFFF);
            u32 off = EmitArenaFarewell(blob, patches, op, iw, iatVfRva);
            while ((blob.size() - off) % 8) blob.push_back(0x90);
            farewellMap[kv.first] = off;
            // FAREWELL SADECE MAZE'DE YASAR: region tablosuna GIRMEZ (arena'ya
            // kopyalanmaz). PLAINTEXT kalir (sifrelenmez - hicbir zaman cozulmeyecek
            // ve hicbir korunan kod icermiyor: sadece VirtualFree + ret).
            rep.encBytes += 0;
        }
        for (auto& js : jmpSites)
            Poke32(blob, js.siteOff, (i32)((i64)farewellMap[js.key] - ((i64)js.siteOff + 4)));   // disp sonu = siteOff+4
        // cleanup->farewell jmp'leri ARENA'DAN calisir -> delta-fix SITE'leri
        for (auto& js : jmpSites)
            farewellSites.push_back({ js.siteOff, js.siteOff - 1, farewellMap[js.key] });   // E9 insn basi = disp-1
        rep.arenaCleanup = (u32)cleanupMap.size();
        // bolge tablosu (tum encSpans: chunk'lar + cleanup + farewell bloklari)
        tableOff = (u32)blob.size();
        for (auto& sp : encSpans) {
            for (int i = 0; i < 4; i++) blob.push_back((u8)(sp.first >> (8 * i)));
            for (int i = 0; i < 4; i++) blob.push_back((u8)(sp.second >> (8 * i)));
        }
        // calisma aninda delta-fix uygulanacak disp ofsetleri:
        // dis dallanmalar + RIP-relatif + cleanup->farewell jmp'leri
        // (farewell VirtualFree'i MAZE'den calisir - disp maze-static)
        for (auto& p : patches) {
            if (p.kind == Patch::P_BR) {
                MInsn& s = insns[p.insnIdx];
                if (p.targetInsn == Patch::NO_TARGET || p.targetInsn >= insns.size())
                    arenaSiteInfo.push_back({ s.blobOff + p.dispOff, s.blobOff, 0, (u64)s.targetRva, 0 });
            } else if (p.kind == Patch::P_RIP) {
                MInsn& s = insns[p.insnIdx];
                arenaSiteInfo.push_back({ s.blobOff + s.ripOff, s.blobOff, 1, (u64)s.ripTargetRva, 0 });
            }
        }
        for (auto& fs : farewellSites)
            arenaSiteInfo.push_back({ fs.fieldOff, fs.insnOff, 3, 0, fs.farewellOff });   // expectRva [11.5]'te mazeRva+extra
        sitesOff = (u32)blob.size();
        for (auto& st : arenaSiteInfo)
            for (int i = 0; i < 4; i++) blob.push_back((u8)(st.fieldOff >> (8 * i)));
        arenaSize = (u32)blob.size();   // VirtualAlloc boyutu (tum blob; span'ler ayni offsetlere kopyalanir)
    }

    // ---- [8] .maze SECTION EKLE / MEVCUT OLANA EKLE ------------------------
    // Ayni dosyada birden fazla fonksiyon korunurken 16 section limiti dolmasin:
    // ".maze" section'i zaten varsa blob'u SONUNA ekler (VirtualSize/SizeOfRawData/
    // SizeOfImage buyutulur). Yoksa yeni RWX .maze section'i eklenir.
    u32 chars = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE; // RWX: in-place decrypt icin
    u32 mazeRva = 0;
    {
        SecInfo* exist = nullptr;
        for (auto& s : pe.secs) if (!strncmp(s.name, ".maze", 8)) { exist = &s; break; }
        bool reuse = (exist != nullptr);
        if (exist) {
            // 1) once TUM olculeri SecInfo'dan hesapla (raw pointer'larina dokunmadan)
            u32 offInSec = ((std::max)(exist->vSz, exist->rawSz) + 15u) & ~15u;   // section icindeki yazim ofseti (16 hizali)
            u32 needVSz  = offInSec + (u32)blob.size();
            u32 newFileEnd = (size_t)exist->raw + ((needVSz + 0xFFFF) & ~0xFFFFu);
            u32 newImgSz  = exist->va + ((needVSz + 0xFFF) & ~0xFFFu);
            // 2) raw'i BUYUT (resize pointer'lari kirar - bu yuzden alttan yeniden turetilecek)
            if (newFileEnd > pe.raw.size()) pe.raw.resize(newFileEnd, 0xCC);
            if (mem.data.size() < pe.imgSz) {} // asagida imgSz guncellenince tekrar bakilacak
            // 3) header pointer'larini RESIZE SONRASI yeniden al
            auto dos = (PIMAGE_DOS_HEADER)pe.raw.data();
            auto nt = (PIMAGE_NT_HEADERS)(pe.raw.data() + dos->e_lfanew);
            u32 secAlign, fileAlign;
            if (pe.is64) { secAlign = ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.SectionAlignment; fileAlign = ((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.FileAlignment; }
            else         { secAlign = ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.SectionAlignment; fileAlign = ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.FileAlignment; }
            auto sh = IMAGE_FIRST_SECTION(nt);
            IMAGE_SECTION_HEADER* hh = nullptr;
            for (u16 i = 0; i < nt->FileHeader.NumberOfSections; i++)
                if (!strncmp((const char*)sh[i].Name, ".maze", 8)) { hh = &sh[i]; break; }
            if (hh) {
                u32 newVSz   = ((needVSz + secAlign - 1) / secAlign) * secAlign;
                u32 newRawSz = ((needVSz + fileAlign - 1) / fileAlign) * fileAlign;
                hh->Misc.VirtualSize = newVSz; hh->SizeOfRawData = newRawSz;
                exist->vSz = newVSz; exist->rawSz = newRawSz;
                if (pe.is64)((PIMAGE_NT_HEADERS64)nt)->OptionalHeader.SizeOfImage = newImgSz;
                else ((PIMAGE_NT_HEADERS32)nt)->OptionalHeader.SizeOfImage = newImgSz;
                pe.imgSz = newImgSz;
                if (mem.data.size() < pe.imgSz) mem.data.resize(pe.imgSz, 0);
                mazeRva = exist->va + offInSec;   // blob tabani (section basi + dolu kisim)
            } else reuse = false;
        }
        if (!reuse) {
            ByteInjector bij;
            u32 addSz = (u32)blob.size() + (enc ? 8 : 0);
            if (!bij.AddSection(pe, mem, ".maze", addSz, chars)) {
                rep.err = ".maze section eklenemedi (PE header'da yer yok - 16 section siniri / header bos alani dolu)";
                return false;
            }
            mazeRva = pe.secs.back().va;
        }
    }
    rep.mazeRva = mazeRva;

    // ---- [9] YENI KONUMLAR + YAMALAR ---------------------------------------
    for (auto& m : insns) m.newRva = mazeRva + m.blobOff;
    rep.entryRva = insns[chunks[0].i0].newRva;

    // rel32 semantigi: hedef = komutSonu + disp  ->  disp = hedefRVA - (mazeRva + komutSonu)
    // fieldOff = disp alaninin blob konumu; deltaToEnd = komutSonu - fieldOff (rel32 icin 4)
    auto applyRel32 = [&](u64 fieldOff, u64 deltaToEnd, i64 targetRva, const char* what) -> bool {
        i64 disp = targetRva - ((i64)mazeRva + (i64)fieldOff + (i64)deltaToEnd);
        if (disp < -2147483648LL || disp > 2147483647LL) {
            rep.err = std::string("rel32 tasmasi: ") + what;
            return false;
        }
        Poke32(blob, (size_t)fieldOff, (i32)disp);
        rep.fixupCount++;
        return true;
    };

    for (auto& p : patches) {
        switch (p.kind) {
        case Patch::P_BR: {
            MInsn& s = insns[p.insnIdx];
            i64 target = (p.targetInsn != Patch::NO_TARGET && p.targetInsn < insns.size())
                       ? (i64)insns[p.targetInsn].newRva     // ic hedef -> yeni konum
                       : (i64)s.targetRva;                   // dis hedef -> yerinde
            if (!applyRel32(s.blobOff + p.dispOff, s.newSize - p.dispOff, target, "ic dallanma")) return false;
            rep.jmpSites.push_back(s.newRva);
            break;
        }
        case Patch::P_RIP: {
            MInsn& s = insns[p.insnIdx];
            if (!applyRel32(s.blobOff + s.ripOff, s.size - s.ripOff, (i64)s.ripTargetRva, "RIP-relatif")) return false;
            break;
        }
        case Patch::P_CONN: {
            MInsn& t = insns[chunks[p.chunkIdx].i0];
            if (!applyRel32(p.siteOff, 4, (i64)t.newRva, "connector")) return false;
            rep.jmpSites.push_back(mazeRva + p.siteOff - 1); // E9 byte'i
            break;
        }
        case Patch::P_CC: {
            if (!cleanupOff) { rep.err = "cleanup stub yok"; return false; }
            i64 disp = (i64)cleanupOff - ((i64)p.siteOff + 4); // blob-icinde, mazeRva kisir
            Poke32(blob, p.siteOff, (i32)disp);
            rep.fixupCount++;
            break;
        }
        case Patch::P_STUBJ: {
            if (!applyRel32(p.siteOff, 4, (i64)rep.entryRva, "stub giris jmp")) return false;
            rep.jmpSites.push_back(mazeRva + p.siteOff - 1);
            break;
        }
        case Patch::P_TBL: {
            Poke32(blob, p.siteOff, (i32)tableOff);
            break;
        }
        case Patch::P_ARENA_RET: {
            // ret yerine yazilan E9 -> cleanup blok (blob-ici, yer-bagimsiz)
            i64 disp = (i64)p.targetInsn - ((i64)p.siteOff + 4);
            Poke32(blob, p.siteOff, (i32)disp);
            rep.fixupCount++;
            rep.jmpSites.push_back(mazeRva + p.siteOff - 1);
            break;
        }
        case Patch::P_ARENA_IMM: {
            u32 v = 0;
            switch (p.immWhich) {
            case 0: v = pe.imgSz; break;      // final SizeOfImage ([8] sonrasi)
            case 1: v = tableOff; break;
            case 2: v = sitesOff; break;
            case 3: v = arenaSize; break;
            case 4: v = mazeRva; break;       // blobRva
            case 5: v = rep.entryRva - mazeRva; break; // ilk parcanin blob ofseti
            }
            Poke32(blob, p.siteOff, (i32)v);
            break;
        }
        case Patch::P_ARENA_VA: case Patch::P_ARENA_VF: {
            // call qword [rip+d]: disp = IAT slot RVA - (mazeRva + siteEnd)
            i64 disp = (i64)p.immValue - ((i64)mazeRva + (i64)p.siteOff + 4);
            Poke32(blob, p.siteOff, (i32)disp);
            rep.fixupCount++;
            break;
        }
        }
    }
    rep.blobBytes = (u32)blob.size();

    // ---- [10] HEADER ALANLARINI DOLDUR -------------------------------------
    if (enc && !arena) {
        auto wr32 = [&](u32 off, u32 v) { for (int i = 0; i < 4; i++) blob[off + i] = (u8)(v >> (8 * i)); };
        auto wr64 = [&](u32 off, u64 v) { for (int i = 0; i < 8; i++) blob[off + i] = (u8)(v >> (8 * i)); };
        wr32(0x00, (u32)chunks.size());            // nRegions
        wr32(0x04, 0x31455A4D);                    // magic 'MZE1'
        wr64(0x08, opt.key);                       // anahtar
        wr32(0x10, rep.entryRva);                  // giris chunk RVA (bilgi)
        wr32(0x14, opt.fnRva);
        wr32(0x18, opt.fnSize);
        wr32(0x1C, tableOff);
        wr32(0x20, reencrypt ? 1u : 0u);
        wr32(0x24, rep.encBytes);
    } else if (enc && arena) {
        auto wr32 = [&](u32 off, u32 v) { for (int i = 0; i < 4; i++) blob[off + i] = (u8)(v >> (8 * i)); };
        auto wr64 = [&](u32 off, u64 v) { for (int i = 0; i < 8; i++) blob[off + i] = (u8)(v >> (8 * i)); };
        wr32(0x00, (u32)encSpans.size());          // nRegions (chunk'lar + cleanup bloklari)
        wr32(0x04, 0x32455A4D);                    // magic 'MZE2' (arena)
        wr64(0x08, opt.key);
        wr32(0x10, rep.entryRva);
        wr32(0x14, opt.fnRva);
        wr32(0x18, opt.fnSize);
        wr32(0x1C, tableOff);
        wr32(0x20, 0u);                            // decrypt-once flagi (yalniz fallback yolu kullanir)
        wr32(0x24, rep.encBytes);
        wr32(0x28, arenaSize);
        wr32(0x2C, (u32)arenaSiteInfo.size());     // nSites
        wr32(0x30, sitesOff);
        wr32(0x34, pe.imgSz);                      // bilgi (stub P_IMM ile de alir)
        wr64(0x38, 0ull);                          // jmpSlot (runtime yazar)
    }

    // ---- [11] DOGRULAMA (sifrelemeden ONCE, duz metin kopyasinda) ---------
    {
        csh vh = c.dis.handle;
        for (auto& ch : chunks) {
            for (size_t k = 0; k < ch.n; k++) {
                size_t ii = ch.i0 + k;
                MInsn& m = insns[ii];
                if (reencrypt && ii == lastInsnIdx) continue; // ret -> JMP swap dogrulanamaz
                if (arena && m.isRet) continue;               // arena ret -> JMP cleanup dogrulamasi [11.5]'te
                cs_insn* v0 = nullptr;
                size_t n = cs_disasm(vh, blob.data() + m.blobOff, (std::min)((size_t)m.newSize + 2, blob.size() - m.blobOff),
                                     mazeRva + m.blobOff, 1, &v0);
                if (!n) { rep.err = "Dogrulama: komut cozulemedi (blob off 0x" + std::to_string(m.blobOff) + ")"; return false; }
                bool ok = ((u32)v0[0].size == m.newSize) && (m.mn == v0[0].mnemonic);
                cs_free(v0, 1);
                if (!ok) { rep.err = std::string("Dogrulama hatasi: '") + m.mn + "' -> yeniden cozulen komut farkli (blob off 0x" + std::to_string(m.blobOff) + ")"; return false; }
            }
        }
    }

    // ---- [11.5] ARENA DOGRULAMASI (simulasyon + bayt denetimi) -------------
    // (a) stub + tum span'ler komut sinirlarinda TAMAMEN cozulebilmeli
    // (b) SIMULASYON: arenaBase = mazeRva + 0x40000000 varsay; her site disp -= delta;
    //     cozulen komutun MUTLAK hedefi maze-durumundakiyle ayni kalmali
    //     (delta isaret hatasi / tasma burada yakalanir - dosya hic bozulmadan once)
    if (arena) {
        const i64 SIM_DELTA = 0x40000000;
        csh vh = c.dis.handle;
        // (a1) stub
        {
            u32 off = 0x40;
            while (off < arenaStubEnd) {
                cs_insn* v0 = nullptr;
                size_t n = cs_disasm(vh, blob.data() + off, (std::min)((size_t)16, blob.size() - off), mazeRva + off, 1, &v0);
                if (!n) { rep.err = "ARENA stub cozulemedi (off 0x" + std::to_string(off) + ")"; return false; }
                off += v0[0].size; cs_free(v0, 1);
            }
            if (off != arenaStubEnd) { rep.err = "ARENA stub uzunlugu beklenmedik"; return false; }
        }
        // (a2) tum span'ler (chunk + cleanup + farewell) basindan sonuna kadar
        for (auto& sp : encSpans) {
            u32 o = sp.first, end = sp.first + sp.second;
            while (o < end) {
                cs_insn* v0 = nullptr;
                size_t n = cs_disasm(vh, blob.data() + o, (std::min)((size_t)16, blob.size() - o), mazeRva + o, 1, &v0);
                if (!n) { rep.err = "ARENA span cozulemedi (off 0x" + std::to_string(o) + ")"; return false; }
                o += v0[0].size; cs_free(v0, 1);
            }
        }
        for (auto& sp : mazeOnlySpans) {
            u32 o = sp.first, end = sp.first + sp.second;
            while (o < end) {
                cs_insn* v0 = nullptr;
                size_t n = cs_disasm(vh, blob.data() + o, (std::min)((size_t)16, blob.size() - o), mazeRva + o, 1, &v0);
                if (!n) { rep.err = "ARENA farewell cozulemedi (off 0x" + std::to_string(o) + ")"; return false; }
                o += v0[0].size; cs_free(v0, 1);
            }
        }
        // (b) delta simülasyonu
        {
            std::vector<u8> sim = blob;
            for (auto& st : arenaSiteInfo) {
                i32 dv; memcpy(&dv, &sim[st.fieldOff], 4);
                dv -= (i32)SIM_DELTA;
                memcpy(&sim[st.fieldOff], &dv, 4);
            }
            int __si = 0;
            for (auto& st : arenaSiteInfo) {
                // gercek arena yerlesimi: blobBase_runtime = imgBase + mazeRva; arenaBase = blobBase + delta
                u64 simVA = (u64)mem.base + (u64)mazeRva + (u64)SIM_DELTA + st.insnOff;
                u64 expectVA = (st.kind == 3) ? ((u64)mem.base + (u64)mazeRva + st.extra)
                                              : ((u64)mem.base + st.expectRva);
                cs_insn* v0 = nullptr;
                size_t n = cs_disasm(vh, &sim[st.insnOff], (std::min)((size_t)16, sim.size() - st.insnOff), simVA, 1, &v0);
                if (!n) { rep.err = "ARENA sim: site komutu cozulemedi (off 0x" + std::to_string(st.insnOff) + ")"; return false; }
                bool ok = false;
                cs_detail* d = v0[0].detail;
                if (st.kind == 0 || st.kind == 3) {   // BR ve farewell jmp: E9 rel32 -> IMM hedef
                    ok = d && d->x86.op_count > 0 && d->x86.operands[0].type == X86_OP_IMM &&
                         (u64)d->x86.operands[0].imm == expectVA;
                } else {
                    if (d) for (int i = 0; i < d->x86.op_count && !ok; i++) {
                        auto& o = d->x86.operands[i];
                        if (o.type == X86_OP_MEM && o.mem.base == X86_REG_RIP)
                            ok = ((u64)((i64)simVA + v0[0].size + o.mem.disp) == expectVA);
                    }
                }
                cs_free(v0, 1);
                if (!ok) { char _b[256]; snprintf(_b, sizeof(_b), "ARENA sim: bozuk idx=%d kind=%d insn=0x%X field=0x%X exp=%016llX", __si, (int)st.kind, st.insnOff, st.fieldOff, (unsigned long long)expectVA); rep.err = _b; return false; }
            }
        }
        rep.arenaSites = (u32)arenaSiteInfo.size();
        rep.arenaSize = arenaSize;
        rep.arenaActive = true;
    }

    // ---- [12] ONIZLEME (duz metin - "IDA ne gorurdu") ----------------------
    {
        u64 va = mem.base + mazeRva + insns[chunks[0].i0].blobOff;
        u64 off = insns[chunks[0].i0].blobOff;
        int lines = 0;
        while (off < blob.size() && lines < 40) {
            cs_insn* v0 = nullptr;
            size_t n = cs_disasm(c.dis.handle, blob.data() + off, (std::min)((size_t)16, (size_t)(blob.size() - off)), va, 1, &v0);
            char b1[64] = {}; int q = 0;
            if (n) {
                for (int i = 0; i < v0[0].size && i < 16; i++) q += sprintf(b1 + q, "%02X", v0[0].bytes[i]);
                char line[256];
                sprintf(line, "  %016llX  %-18s  %-7s %s", (unsigned long long)va, b1, v0[0].mnemonic, v0[0].op_str);
                rep.preview.push_back(line);
                va += v0[0].size; off += v0[0].size; lines++;
                cs_free(v0, 1);
            } else {
                sprintf(b1, "%02X", blob[off]);
                char line[256];
                sprintf(line, "  %016llX  %-18s  db      0x%s", (unsigned long long)va, b1, b1);
                rep.preview.push_back(line);
                va++; off++; lines++;
            }
        }
    }

    // ---- [13] SIFRELEME (en son - yamalar duz metinde yapildi) ------------
    if (enc) {
        u8 kb[8]; memcpy(kb, &opt.key, 8);
        for (auto& sp : encSpans)
            for (u32 i = 0; i < sp.second; i++)
                blob[sp.first + i] ^= kb[i & 7];
        for (auto& sp : mazeOnlySpans)
            for (u32 i = 0; i < sp.second; i++)
                blob[sp.first + i] ^= kb[i & 7];
    }

    // ---- [14] BLOB'U BELLEGE YAZ + TRAMBOLIN -------------------------------
    memcpy(mem.data.data() + mazeRva, blob.data(), blob.size());
    {
        // orijinal govde -> JMP (mod2/arena: stub'a, mod1: giris parcasina)
        // DIKKAT: mem.Write8 VA bekler - RVA dogrudan data[]'ya yazilir (dogrulanir)
        u32 hdrSize = (enc && arena) ? 0x40u : 0x30u;
        u32 jmpTargetRva = enc ? (mazeRva + hdrSize) : rep.entryRva; // stub header'in hemen sonrasi
        i64 rel = (i64)jmpTargetRva - ((i64)opt.fnRva + 5);
        if (rel < -2147483648LL || rel > 2147483647LL) { rep.err = "Trambolin rel32 tasmadi (olanaksiz)"; return false; }
        if (opt.fnRva + opt.fnSize > mem.data.size()) { rep.err = "Trambolin yazim alani bellegin disinda"; return false; }
        u8* body = mem.data.data() + opt.fnRva;
        body[0] = 0xE9;
        for (int i = 0; i < 4; i++) body[1 + i] = (u8)(((u64)rel >> (8 * i)) & 0xFF);
        for (u32 i = 5; i < opt.fnSize; i++) body[i] = 0xCC;
        // YAZMA DOGRULAMASI (sessiz basarisizlik olmasin)
        if (mem.data[opt.fnRva] != 0xE9) { rep.err = "Trambolin yazilamadi (RVA 0x" + std::to_string(opt.fnRva) + ")"; return false; }
    }

    // ---- [15] DIS REFERANSLARI YONLENDIR -----------------------------------
    // Diger fonksiyonlardan bu fonksiyona gelen call/jmp'ler artik labirentin
    // girisine bakmali. (Girise gelenler zaten tramboline carpar - dogru;
    // ORTAYA gelenler yeni konuma tasiniyor.)
    {
        // DIKKAT: RefEngine src/dst ALANLARINI (VA) tutar - RVA'ye cevrilir
        u64 fnStartVA = mem.base + opt.fnRva;
        u64 fnEndVA   = fnStartVA + opt.fnSize;
        for (auto& r : c.refs.refs) {
            if (r.dst < fnStartVA || r.dst >= fnEndVA) continue;
            if (r.src >= fnStartVA && r.src < fnEndVA) continue; // ic dallanma - labirent halletti
            u32 dstRva = (u32)(r.dst - mem.base);
            // ARENA: ortaya gelen dis ref arena'da KARARLI adrese sahip degil
            // (her cagride yeni arena) -> bu fonksiyon arena'lanamaz, guvenli reddet
            if (arena && dstRva != opt.fnRva) {
                rep.err = "ARENA modu: fonksiyon ORTASINA gelen dis referans var (RVA 0x" + std::to_string(dstRva) +
                          ") - arena'da kararli adres yok; bu fonksiyonu YERINDE modda koru";
                return false;
            }
            // SIFRELI modda GIRISE gelen refs YONLENDIRILMEZ: trambolin -> stub -> decrypt
            // zinciri islesin. Dogrudan chunk'a yonlendirirsek stub atlanir ve SIFRELI
            // baytlar calistirilir -> crash. (Duz modda direkt yonlendirme guvenli.)
            if (enc && dstRva == opt.fnRva) continue;
            auto it = std::find_if(insns.begin(), insns.end(), [&](const MInsn& m) { return m.rva == dstRva; });
            if (it == insns.end()) {
                rep.warnings.push_back("Dis ref VA 0x" + std::to_string(r.src) + " -> fonksiyon ORTASI (RVA 0x" + std::to_string(dstRva) +
                                       "): hedef komut siniri tam degil, yonlendirilemedi - KONTROL ET");
                continue;
            }
            u32 newDst = it->newRva;
            u64 srcVA = r.src; // DIKKAT: RefEngine src/dst ZATEN VA tutar - base bir daha EKLENMEZ
                               // (eski kod mem.base + r.src yapip disp'i tasiyordu -> sessiz atlanma)
            const u8* p = &mem.data[(size_t)(r.src - mem.base)];
            size_t rm = (std::min)((size_t)16, mem.data.size() - (size_t)(r.src - mem.base));
            cs_insn* i0 = nullptr;
            size_t n = cs_disasm(c.dis.handle, p, rm, srcVA, 1, &i0);
            if (!n) continue;
            u8 op0 = i0[0].bytes[0]; u8 op1 = (i0[0].size >= 2) ? i0[0].bytes[1] : 0;
            int sz = i0[0].size;
            cs_free(i0, 1);
            // GUVENLIK: site hala gercekten bu fonksiyonu mu gosteiyor?
            // (aradaki Build'ler orijinal govdeyi tramboline cevirmis olabilir -
            //  o zaman bu kayit STALE'dir, dokunma! yoksa trambolin bozulur)
            {
                i64 cur = -1;
                const u8* sp = &mem.data[(size_t)(r.src - mem.base)];
                if ((op0 == 0xE8 || op0 == 0xE9) && sz == 5 && rm >= 5) {
                    i32 dv; memcpy(&dv, sp + 1, 4);
                    cur = (i64)r.src + 5 + dv;
                } else if (op0 == 0x0F && op1 >= 0x80 && op1 <= 0x8F && sz == 6 && rm >= 6) {
                    i32 dv; memcpy(&dv, sp + 2, 4);
                    cur = (i64)r.src + 6 + dv;
                }
                if (cur >= 0 && cur != (i64)r.dst) continue; // stale ref
            }
            bool patched = false;
            if ((op0 == 0xE8 || op0 == 0xE9) && sz == 5) {
                i64 disp = (i64)(mem.base + newDst) - (srcVA + 5);
                if (disp >= -2147483648LL && disp <= 2147483647LL) {
                    mem.Write8(r.src + 1, (u8)((u64)disp & 0xFF));
                    mem.Write8(r.src + 2, (u8)(((u64)disp >> 8) & 0xFF));
                    mem.Write8(r.src + 3, (u8)(((u64)disp >> 16) & 0xFF));
                    mem.Write8(r.src + 4, (u8)(((u64)disp >> 24) & 0xFF));
                    patched = true;
                }
            } else if (op0 == 0x0F && op1 >= 0x80 && op1 <= 0x8F && sz == 6) {
                i64 disp = (i64)(mem.base + newDst) - (srcVA + 6);
                if (disp >= -2147483648LL && disp <= 2147483647LL) {
                    mem.Write8(r.src + 2, (u8)((u64)disp & 0xFF));
                    mem.Write8(r.src + 3, (u8)(((u64)disp >> 8) & 0xFF));
                    mem.Write8(r.src + 4, (u8)(((u64)disp >> 16) & 0xFF));
                    mem.Write8(r.src + 5, (u8)(((u64)disp >> 24) & 0xFF));
                    patched = true;
                }
            } else if ((op0 == 0xEB || (op0 >= 0x70 && op0 <= 0x7F)) && sz == 2) {
                rep.warnings.push_back("Dis KISA dallanma (RVA 0x" + std::to_string(r.src) +
                                       ") labirente ulasamiyor (rel8) - genisletilemedi, manuel kontrol et");
            } else if (op0 == 0x68 && sz == 5) { // push imm32 (fonksiyon adresi)
                i64 d64 = (i64)(mem.base + newDst);
                if (d64 >= 0 && d64 <= 0x7FFFFFFF) {
                    for (int i = 0; i < 4; i++) mem.Write8(r.src + 1 + i, (u8)(((u64)d64 >> (8 * i)) & 0xFF));
                    patched = true;
                }
            }
            if (patched) rep.extFixCount++;
        }
    }

    // ---- [16] RAPOR ---------------------------------------------------------
    rep.ok = true;
    rep.mazeSize = pe.secs.back().rawSz;
    if (enc) {
        char kb[32]; sprintf(kb, "%016llX", (unsigned long long)opt.key);
        rep.warnings.push_back(std::string("XOR anahtari: 0x") + kb + " (ayni anahtar + ayni tohum = ayni labirent)");
    }
    rep.warnings.push_back("Fonksiyonun ORTASINA atlayan vtable/switch verisi varsa o girisler bozulur (giris noktasina gelenler sorunsuz)");
    if (reencrypt)
        rep.warnings.push_back("Cikista tekrar sifreleme ACIK: recursion veya coklu thread ile cagirilan fonksiyonlarda KULLANMA");
    if (rep.arenaActive) {
        rep.warnings.push_back("ARENA modu AKTIF: her cagride VirtualAlloc ile free-mem acilir, sifreli parcalar oraya cozulup oradan calisir, ret'te VirtualFree ile silinir; .maze'deki baytlar HICBIR ZAMAN cozulmez");
        rep.warnings.push_back("ARENA sinirlar: ayni fonksiyonu ayni anda coklu thread'te cagirmayin (stub jmpSlot yarisi); VirtualAlloc basarisizsa otomatik YERINDE moda duser (crash yok)");
    }
    return true;
}

// ---- KAYDETME: benikoru.exe + checksum -------------------------------------

inline std::wstring MakeBenikoruPath(const std::wstring& src) {
    std::wstring base = src;
    size_t dot = base.find_last_of(L'.');
    size_t slash = base.find_last_of(L"/\\");
    if (dot != std::wstring::npos && (slash == std::wstring::npos || dot > slash))
        base.insert(dot, L"_benikoru");
    else
        base += L"_benikoru.exe";
    return base;
}

inline bool SaveBenikoru(Core& c, const std::wstring& outPath, std::string& err, bool& signatureStripped) {
    signatureStripped = false;
    if (!c.pe.Save(outPath.c_str(), c.mem.data.data(), c.mem.base, c.mem.data.size())) {
        err = "PE kaydedilemedi"; return false;
    }
    std::string csErr;
    bool hadSig = FixFileChecksum(outPath, csErr);
    if (!csErr.empty()) { err = csErr; return false; }
    signatureStripped = hadSig;
    err.clear();
    return true;
}

} // namespace MazeProtect
