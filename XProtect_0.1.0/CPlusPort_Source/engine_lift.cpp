// ============================================================
// engine_lift.cpp — makine kodu -> VM bayt-kod lifter
// Akis: dogrusal cozum, temel akis haritasi, rel32 fixup'lari.
// ============================================================
#include "engine.hpp"

namespace {

struct Lift {
    std::vector<u8>& bc;
    std::vector<std::pair<u32, u32>>& fix;
    std::vector<u32>& str_refs;
    bool is64;
    u64 imagebase;
    u32 rdata_rva, rdata_size;

    void e(u8 x) { bc.push_back(x); }
    void e32(u32 v) { for (int k = 0; k < 4; k++) bc.push_back((u8)(v >> (8 * k))); }
    void e64(u64 v) { for (int k = 0; k < 8; k++) bc.push_back((u8)(v >> (8 * k))); }
    void ereg(int r) { e((u8)r); }

    // MEM operandini akisa yazar; .rdata referanslarini toplar
    void emem(const MemOp& m, const Insn& I) {
        if (m.riprel) {
            u32 tgt = I.pc + I.len + (u32)(long long)m.disp;
            e(MEMF_DISP); e32(tgt);
            if (tgt >= rdata_rva && tgt < rdata_rva + rdata_size) str_refs.push_back(tgt);
            return;
        }
        if (m.absimage) {
            u64 rva = m.absval - imagebase;
            if (rva >= 0x10000000ull) { /* image disi mutlak adres */ }
            // INDEX VARSA SAKLA! (eski kod idx'i atiyor -> [idx*4+tab] tablo
            // okumalari hep ilk elemani veriyordu)
            if (m.idx >= 0) {
                e(MEMF_SIB_IMG);
                e((u8)SIB_NOBASE);
                e((u8)m.idx);
                e((u8)m.scale);
                e32((u32)rva);
            } else {
                e(MEMF_DISP); e32((u32)rva);
            }
            if (rva >= rdata_rva && rva < rdata_rva + rdata_size) str_refs.push_back((u32)rva);
            return;
        }
        if (m.present && m.base >= 0) {
            u32 disp = (u32)(long long)m.disp;
            u8 form = MEMF_SIB;
            // x86: [reg + VA] bicimli erisimlerde disp image-RVA'ya cevrilir;
            // VM MEMF_SIB_IMG ile c->base'i ekler. (x64: disp zaten yigin/gosterici)
            if (!is64 && disp >= imagebase && disp < imagebase + 0x10000000ull) {
                disp -= (u32)imagebase;
                form = MEMF_SIB_IMG;
            }
            e(form);
            e((u8)m.base);
            e((u8)(m.idx >= 0 ? m.idx : SIB_NOBASE));
            e((u8)m.scale);
            e32(disp);
        } else {
            // tabansiz SIB / disp32: mutlak gibi ele al (rva'ya cevrilemediyse hatali)
            e(MEMF_SIB);
            e((u8)SIB_NOBASE);
            e((u8)(m.idx >= 0 ? m.idx : SIB_NOBASE));
            e((u8)m.scale);
            u64 rva = (m.absimage ? (m.absval - imagebase) : (u64)(long long)m.disp);
            e32((u32)rva);
        }
    }

    bool alu_common(const Insn& I, bool has_imm) {
        if (has_imm) {
            if (I.mem.present) { e(OP_ALU_MI); e((u8)I.alu); e((u8)I.sz); emem(I.mem, I); e32((u32)(long long)I.imm); }
            else { e(OP_ALU_RI); e((u8)I.alu); e((u8)I.sz); ereg(I.r1); e32((u32)(long long)I.imm); }
            return true;
        }
        if (I.mem.present) {
            // kaynak ya da hedef bellek: iki yon
            // disasm: "op r/m,r" -> r1=reg kaynak; "op r,r/m" -> r1=reg hedef
            // ayirt etmek icin: XP_ALU üretiminde mem.present + r2 yoksa yon belirsiz.
            // Lifte girmeden once lifter_in belirtir.
            return false;
        }
        e(OP_ALU_RR); e((u8)I.alu); e((u8)I.sz); ereg(I.r1); ereg(I.r2);
        return true;
    }
};

} // namespace

// yon bilgisi: disasm XP_ALU'da mem.present ise r1=reg, r2=-1 ve 'mem_is_src'
// ayirt edilemiyor -> lifter'a ham modrm yonunu tasiyacak sekilde
// Insn.r2 == -2 (mem<-reg) / -3 (reg<-mem) kuralini kullanacagiz.
// (engine_disasm.cpp'de set edilir.)

VFn lift_function(const u8* code, u32 rva, u32 size, bool is64,
                  u64 imagebase, u32 imagesize, bool allow_call,
                  u32 rdata_rva, u32 rdata_size, int junk_level, u32 junk_seed) {
    VFn F; F.rva = rva; F.size = size;

    Lift L{ F.plain, F.fix, F.str_refs, is64, imagebase, rdata_rva, rdata_size };

    // mutation junk ureteci (deterministik LCG)
    u32 rng = junk_seed ? junk_seed : 0x12345678u;
    auto rnd = [&rng]() { rng = rng * 1103515245u + 12345u; return (rng >> 16) & 0x7FFF; };
    auto emit_junk = [&]() {
        if (junk_level < 2) return;
        u32 roll = rnd() & 7;
        if (roll < 3) {
            int n = 1 + (int)(rnd() & 3);
            for (int k = 0; k < n; k++) L.e(OP_NOP);
        } else if (roll == 4) {
            // reg kaydet, junk it, ez, geri yukle (net sifir etki)
            // x64: R11(11) volatile; x86: ECX(1) volatile
            int r = is64 ? 11 : 1;
            L.e(OP_PUSH_R); L.e((u8)r);
            L.e(OP_PUSH_I); L.e32(rnd() | 1u);
            L.e(OP_POP_R);  L.e((u8)r);
            L.e(OP_POP_R);  L.e((u8)r);
        }
    };

    std::map<u32, u32> pc2ic;   // kaynak pc -> bc offset
    bool saw_ret = false;
    bool body_ended = false;    // ret sonrasi dolgu gorundu mu (govde bitti isareti)
    u32 retimm = 0xFFFFFFFF;
    u32 end = rva + size;

    u32 pc = rva;
    while (pc < end) {
        Insn I = disasm(code + (pc - rva), (int)(end - pc), is64, pc, imagebase, imagesize);
        if (I.op == XP_UNKNOWN || I.len == 0) {
            if (!saw_ret) { F.why = "pc=0x" + hex32(pc) + ": " + (I.text.empty() ? "cozulemedi" : I.text); return F; }
            break; // ret sonrasi padding/CC -> dur
        }
        if (I.op == XP_INT3) { if (saw_ret) break; F.why = "ret oncesi int3"; return F; }
        if (saw_ret) {
            // ret sonrasi POLITIKA:
            //  - dolgu (nop/int3) gorurse govde bitti sayar; dolgudan SONRA
            //    gercek talimat gelirse baska fonksiyona tasindik -> dur.
            //  - dolgu YOKKEN ret sonrasi kod gelirse AYNI fonksiyonun coklu
            //    cikis/yaln sonrasi blogudur (zig bunu uretir) -> taramaya devam.
            if (I.op == XP_NOP) { body_ended = true; pc += I.len; continue; }
            if (I.op == XP_INT3) break;
            if (body_ended) break;
        }

        if (!F.plain.empty() && I.op != XP_RET) emit_junk();
        pc2ic[pc] = (u32)F.plain.size();
        char buf[96];

        switch (I.op) {
        case XP_NOP: break;
        case XP_PUSH_R: L.e(OP_PUSH_R); L.ereg(I.r1);
            snprintf(buf, sizeof buf, "push %s", regname(is64, I.r1)); break;
        case XP_POP_R: L.e(OP_POP_R); L.ereg(I.r1);
            snprintf(buf, sizeof buf, "pop %s", regname(is64, I.r1)); break;
        case XP_PUSH_I: L.e(OP_PUSH_I); L.e32((u32)(long long)I.imm);
            snprintf(buf, sizeof buf, "push 0x%llx", (unsigned long long)I.imm); break;
        case XP_MOV_MR:
            if (!I.mem.present) {   // reg <- reg  (mov r/m,r mod3)
                L.e(OP_MOV_RR); L.e((u8)I.sz); L.ereg(I.r1); L.ereg(I.r2);
                snprintf(buf, sizeof buf, "mov %s, %s (sz%d)", regname(is64, I.r1), regname(is64, I.r2), I.sz);
            } else {
                L.e(OP_MOV_MR); L.e((u8)I.sz); L.emem(I.mem, I); L.ereg(I.r1);
                snprintf(buf, sizeof buf, "mov [mem], %s (sz%d)", regname(is64, I.r1), I.sz);
            }
            break;
        case XP_MOV_RM:
            if (!I.mem.present) {   // reg <- reg  (mov r,r/m mod3)
                L.e(OP_MOV_RR); L.e((u8)I.sz); L.ereg(I.r1); L.ereg(I.r2);
                snprintf(buf, sizeof buf, "mov %s, %s (sz%d)", regname(is64, I.r1), regname(is64, I.r2), I.sz);
            } else {
                L.e(OP_MOV_RM); L.e((u8)I.sz); L.ereg(I.r1); L.emem(I.mem, I);
                snprintf(buf, sizeof buf, "mov %s, [mem] (sz%d)", regname(is64, I.r1), I.sz);
            }
            break;
        case XP_MOV_MI: L.e(OP_MOV_MI); L.e((u8)I.sz); L.emem(I.mem, I); L.e32((u32)(long long)I.imm);
            snprintf(buf, sizeof buf, "mov [mem], imm%d=0x%llx", I.sz * 8, (unsigned long long)I.imm); break;
        case XP_MOV_RI: L.e(OP_MOV_RI); L.e((u8)I.sz); L.ereg(I.r1); L.e32((u32)(long long)I.imm);
            snprintf(buf, sizeof buf, "mov %s, imm=0x%llx", regname(is64, I.r1), (unsigned long long)I.imm); break;
        case XP_MOV_RI64: L.e(OP_MOV_RI64); L.ereg(I.r1); L.e64(I.imm);
            snprintf(buf, sizeof buf, "movabs %s, 0x%llx", regname(is64, I.r1), (unsigned long long)I.imm); break;
        case XP_LEA: L.e(OP_LEA_RM); L.ereg(I.r1); L.emem(I.mem, I);
            snprintf(buf, sizeof buf, "lea %s, [mem]", regname(is64, I.r1)); break;
        case XP_ALU: {
            // yon: engine_disasm XP_ALU üretiminde mem.present ise r2 == -2/-3 isareti
            if (I.immsz > 0) {
                if (I.mem.present) { L.e(OP_ALU_MI); L.e((u8)I.alu); L.e((u8)I.sz); L.emem(I.mem, I); L.e32((u32)(long long)I.imm); }
                else { L.e(OP_ALU_RI); L.e((u8)I.alu); L.e((u8)I.sz); L.ereg(I.r1); L.e32((u32)(long long)I.imm); }
            } else if (I.mem.present) {
                if (I.r2 == -2) { L.e(OP_ALU_MR); L.e((u8)I.alu); L.e((u8)I.sz); L.emem(I.mem, I); L.ereg(I.r1); }
                else { L.e(OP_ALU_RM); L.e((u8)I.alu); L.e((u8)I.sz); L.ereg(I.r1); L.emem(I.mem, I); }
            } else {
                L.e(OP_ALU_RR); L.e((u8)I.alu); L.e((u8)I.sz); L.ereg(I.r1); L.ereg(I.r2);
            }
            snprintf(buf, sizeof buf, "alu%d (sz%d)", I.alu, I.sz); break;
        }
        case XP_SHIFT: {
            if (I.mem.present) {
                if (I.immsz == -1) { L.e(OP_SHI_RM_CL); L.e((u8)I.shi); L.e((u8)I.sz); L.emem(I.mem, I); snprintf(buf, sizeof buf, "shift[mem]%%cl"); }
                else { L.e(OP_SHI_RM_RI); L.e((u8)I.shi); L.e((u8)I.sz); L.emem(I.mem, I); L.e((u8)I.imm); snprintf(buf, sizeof buf, "shift[mem] %d", (int)I.imm); }
                break;
            }
            if (I.immsz == -1) { L.e(OP_SHI_CL); L.e((u8)I.shi); L.e((u8)I.sz); L.ereg(I.r1); snprintf(buf, sizeof buf, "shift%%cl"); }
            else { L.e(OP_SHI_RI); L.e((u8)I.shi); L.e((u8)I.sz); L.ereg(I.r1); L.e((u8)I.imm); snprintf(buf, sizeof buf, "shift %d", (int)I.imm); }
            break;
        }
        case XP_IMUL_RRI:
            if (I.mem.present) {
                L.e(OP_IMUL_RMRI); L.e((u8)I.sz); L.ereg(I.r1); L.emem(I.mem, I); L.e32((u32)(long long)I.imm);
                snprintf(buf, sizeof buf, "imul %s, [mem], 0x%llx", regname(is64, I.r1), (unsigned long long)I.imm);
            } else {
                L.e(OP_IMUL_RRI); L.e((u8)I.sz); L.ereg(I.r1); L.ereg(I.r2); L.e32((u32)(long long)I.imm);
                snprintf(buf, sizeof buf, "imul %s, %s, 0x%llx", regname(is64, I.r1), regname(is64, I.r2), (unsigned long long)I.imm);
            }
            break;
        case XP_IMUL_RR: L.e(OP_IMUL_RR); L.e((u8)I.sz); L.ereg(I.r1); L.ereg(I.r2);
            snprintf(buf, sizeof buf, "imul %s, %s", regname(is64, I.r1), regname(is64, I.r2)); break;
        case XP_INCDEC_R: L.e(OP_INCDEC_R); L.e((u8)I.ud); L.e((u8)I.sz); L.ereg(I.r1);
            snprintf(buf, sizeof buf, "%s %s", I.ud ? "dec" : "inc", regname(is64, I.r1)); break;
        case XP_INCDEC_M: L.e(OP_INCDEC_M); L.e((u8)I.ud); L.e((u8)I.sz); L.emem(I.mem, I);
            snprintf(buf, sizeof buf, "%s [mem]", I.ud ? "dec" : "inc"); break;
        case XP_MOVZX: case XP_MOVSX: {
            L.e(I.op == XP_MOVZX ? OP_MOVZX : OP_MOVSX);
            L.e((u8)I.sz); L.e((u8)I.immsz); L.ereg(I.r1);
            if (I.mem.present) { L.e((u8)1); L.emem(I.mem, I); }
            else { L.e((u8)0); L.ereg(I.r2); }
            snprintf(buf, sizeof buf, "%s%d%s%d %s", I.op == XP_MOVZX ? "movzx" : "movsx",
                     I.sz * 8, "<-", I.immsz * 8, I.mem.present ? "[mem]" : regname(is64, I.r2)); break;
        }
        case XP_JMP: {
            if (I.target < rva || I.target >= end) {
                // disari dal -> KUYRUK CAGRI (fonksiyon sonu): ncall + ret.
                // (Bu nokta lifte gore fonksiyonun bitisidir; saw_ret isaretle.)
                if (!allow_call) { F.why = "disari jmp (call yok)"; return F; }
                L.e(OP_NCALL); L.e32(I.target);
                L.e(OP_RET);
                saw_ret = true;
                snprintf(buf, sizeof buf, "jmp disari -> ncall 0x%x (kuyruk)", I.target); break;
            }
            L.e(OP_JMP); u32 site = (u32)L.bc.size(); L.e32(0);
            F.fix.push_back({ site, I.target });
            snprintf(buf, sizeof buf, "jmp 0x%x", I.target); break;
        }
        case XP_JCC: {
            if (I.target < rva || I.target >= end) { F.why = "disari jcc"; return F; }
            L.e(OP_JCC); L.e((u8)I.cc); u32 site = (u32)L.bc.size(); L.e32(0);
            F.fix.push_back({ site, I.target });
            snprintf(buf, sizeof buf, "jcc%d 0x%x", I.cc, I.target); break;
        }
        case XP_CALL: {
            if (!allow_call) { F.why = "call desteklenmiyor (x86 yaprak modu)"; return F; }
            L.e(OP_NCALL); L.e32(I.target);
            snprintf(buf, sizeof buf, "call 0x%x (ncall)", I.target); break;
        }
        case XP_LEAVE: // mov rsp,rbp ; pop rbp
            L.e(OP_MOV_RR); L.e((u8)8); L.ereg(REG_RSP); L.ereg(REG_RBP);
            L.e(OP_POP_R);  L.ereg(REG_RBP);
            snprintf(buf, sizeof buf, "leave"); break;
        case XP_RET: L.e(OP_RET); saw_ret = true;
            snprintf(buf, sizeof buf, "ret"); break;
        case XP_RETI16: {
            u32 im = (u32)I.imm;
            if (retimm != 0xFFFFFFFF && retimm != im) { F.why = "farkli ret imm"; return F; }
            retimm = im; L.e(OP_RET); saw_ret = true;
            snprintf(buf, sizeof buf, "ret 0x%x", im); break;
        }
        case XP_SETCC: L.e(OP_SETCC); L.e((u8)I.cc); L.ereg(I.r1);
            snprintf(buf, sizeof buf, "setcc%d %s", I.cc, regname(is64, I.r1)); break;
        case XP_CMOV:
            L.e(OP_CMOV); L.e((u8)I.cc); L.e((u8)I.sz); L.ereg(I.r1);
            if (I.mem.present) { L.e((u8)1); L.emem(I.mem, I); }
            else { L.e((u8)0); L.ereg(I.r2); }
            snprintf(buf, sizeof buf, "cmov%d %s", I.cc, I.mem.present ? "[mem]" : regname(is64, I.r2));
            break;
        case XP_CWDE: { // x64: CDQE rax<-eax ; x86: CWDE eax<-ax
            L.e(OP_MOVSX); L.e((u8)(is64 ? 8 : 4)); L.e((u8)(is64 ? 4 : 2));
            L.ereg(REG_RAX); L.e((u8)0); L.ereg(REG_RAX);
            snprintf(buf, sizeof buf, "cwde/cdqe"); break; }
        case XP_CDQ: L.e(OP_CQO);
            snprintf(buf, sizeof buf, "cdq/cqo"); break;
        case XP_IDIV: L.e(OP_IDIV_R); L.e((u8)I.sz); L.ereg(I.r1);
            snprintf(buf, sizeof buf, "idiv %s", regname(is64, I.r1)); break;
        case XP_NEG:
            if (I.mem.present) { L.e(OP_NEG_M); L.e((u8)I.sz); L.emem(I.mem, I);
                snprintf(buf, sizeof buf, "neg [mem]"); }
            else { L.e(OP_NEG_R); L.e((u8)I.sz); L.ereg(I.r1);
                snprintf(buf, sizeof buf, "neg %s", regname(is64, I.r1)); }
            break;
        case XP_NOT:
            if (I.mem.present) { L.e(OP_NOT_M); L.e((u8)I.sz); L.emem(I.mem, I);
                snprintf(buf, sizeof buf, "not [mem]"); }
            else { L.e(OP_NOT_R); L.e((u8)I.sz); L.ereg(I.r1);
                snprintf(buf, sizeof buf, "not %s", regname(is64, I.r1)); }
            break;
        default:
            F.why = "lifter: bilinmeyen islem";
            return F;
        }
        F.notes.push_back(std::string("  ") + hex32(pc) + ": " + buf);
        pc += I.len;
    }

    if (!saw_ret) { F.why = "ret bulunamadi"; return F; }

    // fixup'lari uygula: rel32 = hedef_bc - (site + 4)
    for (auto& fx : F.fix) {
        auto it = pc2ic.find(fx.second);
        if (it == pc2ic.end()) { F.why = "fixup hedefi yok @0x" + hex32(fx.second); return F; }
        u32 site = fx.first;
        i64 rel = (i64)it->second - (i64)(site + 4);
        if (getenv("CPL_FIXDBG"))
            fprintf(stderr, "[fix] site=%u hedef_pc=0x%x hedef_ic=%u rel=%lld\n",
                    site, fx.second, it->second, (long long)rel);
        for (int k = 0; k < 4; k++)
            F.plain[site + k] = (u8)(((u64)rel >> (8 * k)) & 0xFF);
    }
    F.fix.clear();
    F.ok = true;
    return F;
}
