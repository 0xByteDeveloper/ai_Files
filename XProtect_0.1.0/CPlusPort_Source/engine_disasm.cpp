// ============================================================
// engine_disasm.cpp — x86/x64 kucuk-alt-kume cozucu (lifter icin)
// Yalnizca derleyici uretimine uygun talimatlar desteklenir;
// bilinmeyen olkus -> XP_UNKNOWN (lifter fonksiyonu red eder).
// ============================================================
#include "engine.hpp"

static int reg8enc(bool is64, bool rex, int r) {
    if (is64 && rex) return r;              // spl..dil / r8b..r15b
    if (r >= 4 && !rex && !is64) return 16 + (r - 4); // ah,ch,dh,bh (x86)
    if (r >= 4 && !rex && is64)  return 16 + (r - 4); // ah,ch,dh,bh (rex yok)
    return r;
}

Insn disasm(const u8* p, int maxlen, bool is64, u32 pc, u64 imagebase, u32 imagesize) {
    Insn I; I.pc = pc;
    int i = 0;
    bool rex = false, rexw = false, rexr = false, rexx = false, rexb = false;
    bool op66 = false;

    // --- on ekler ---
    while (i < maxlen) {
        u8 b = p[i];
        if (b == 0x66) { op66 = true; i++; continue; }
        if (b == 0x67 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65 || b == 0x67) { I.text = "desteklenmeyen onek"; return I; }
        if (is64 && b >= 0x40 && b <= 0x4F) {
            rex = true; rexw = (b >> 3) & 1; rexr = (b >> 2) & 1;
            rexx = (b >> 1) & 1; rexb = b & 1; i++; continue;
        }
        break;
    }
    if (i >= maxlen) return I;
    u8 op = p[i++];

    int sz = op66 ? 2 : (is64 && rexw ? 8 : 4);

    // --- ModRM okuyucu ---
    auto read_modrm = [&](int opsz, int& regf, MemOp& m, bool memok, bool is8=false)->bool {
        if (i >= maxlen) return false;
        u8 mrm = p[i++];
        int mod = mrm >> 6, rg = (mrm >> 3) & 7, rm = mrm & 7;
        regf = rg + (rexr ? 8 : 0);
        if (mod == 3) {
            m.present = false;
            int rr = rm + (rexb ? 8 : 0);
            m.base = is8 ? reg8enc(is64, rexb, rr) : rr;
            return true;
        }
        if (!memok) return false;
        m.present = true;
        if (rm == 4 && !(is64 && mod == 0 && false)) {
            // SIB (x86 rm=4; x64 rm=4)
            if (i >= maxlen) return false;
            u8 sib = p[i++];
            int sc = sib >> 6, ix = (sib >> 3) & 7, bs = sib & 7;
            m.scale = sc;
            m.idx = (ix == 4) ? -1 : ix + (rexx ? 8 : 0);
            if (bs == 5 && mod == 0) {
                m.base = -1;
                if (i + 4 > maxlen) return false;
                long long d = 0; for (int k = 0; k < 4; k++) d |= ((long long)p[i + k]) << (8 * k);
                i += 4;
                if (is64) { m.riprel = false; m.absimage = true; m.absval = (u64)d; }
                else      { m.absimage = true; m.absval = (u64)d; }
                m.disp = 0;
            } else {
                m.base = bs + (rexb ? 8 : 0);
                if (mod == 1) { if (i >= maxlen) return false;
                    m.disp = (signed char)p[i++]; }
                else if (mod == 2) { if (i + 4 > maxlen) return false;
                    long long d = 0; for (int k = 0; k < 4; k++) d |= ((long long)p[i + k]) << (8 * k);
                    i += 4; m.disp = d; }
            }
        } else if (rm == 5 && mod == 0) {
            m.base = -1;
            if (i + 4 > maxlen) return false;
            long long d = 0; for (int k = 0; k < 4; k++) d |= ((long long)p[i + k]) << (8 * k);
            i += 4;
            if (is64) { m.riprel = true; m.disp = d; }   // rip-rel: hedef = pc+len+disp
            else      { m.absimage = true; m.absval = (u64)d; }
        } else {
            m.base = rm + (rexb ? 8 : 0);
            if (mod == 1) { if (i >= maxlen) return false;
                m.disp = (signed char)p[i++]; }
            else if (mod == 2) { if (i + 4 > maxlen) return false;
                long long d = 0; for (int k = 0; k < 4; k++) d |= ((long long)p[i + k]) << (8 * k);
                i += 4; m.disp = d; }
        }
        (void)opsz;
        return true;
    };

    auto read_imm = [&](int n)->u64 {
        u64 v = 0;
        for (int k = 0; k < n && i < maxlen; k++) v |= ((u64)p[i + k]) << (8 * k);
        i += n;
        return v;
    };

    auto sxt = [](u64 v, int n)->u64 {
        if (n == 1) return (u64)(long long)(signed char)(u8)v;
        if (n == 4) return (u64)(long long)(int)(u32)v;
        return v;
    };

    I.len = 0; // sonunda set edilecek
    int regf = -1;

    switch (op) {
    case 0x90: I.op = XP_NOP; break;
    case 0x9B: I.op = XP_NOP; break;
    case 0xCC: I.op = XP_INT3; break;
    case 0x0F: {
        if (i >= maxlen) return I;
        u8 op2 = p[i++];
        if (op2 == 0x1F) { I.op = XP_NOP; regf = 0; MemOp m; if (!read_modrm(4, regf, m, true)) return I; }
        else if (op2 >= 0x80 && op2 <= 0x8F) {
            I.op = XP_JCC; I.cc = op2 - 0x80; I.sz = 4;
            I.imm = read_imm(4); I.immsz = 4;
            I.target = pc + 6 + (u32)(int)I.imm;
        }
        else if (op2 >= 0x90 && op2 <= 0x9F) {
            I.op = XP_SETCC; I.cc = op2 - 0x90;
            if (i >= maxlen) return I;
            u8 mrm = p[i++]; int mod = mrm >> 6, rm = mrm & 7;
            if (mod != 3) { return I; }
            I.r1 = reg8enc(is64, rexb, rm + (rexb ? 8 : 0));
        }
        else if (op2 >= 0x40 && op2 <= 0x4F) { // CMOVcc r, r/m
            I.op = XP_CMOV; I.cc = op2 - 0x40; I.sz = sz;
            int rg; MemOp m;
            if (!read_modrm(sz, rg, m, true, sz == 1)) return I;
            I.r1 = rg; I.mem = m;
            if (!m.present) I.r2 = m.base;
        }
        else if (op2 == 0xAF) { // IMUL r, r/m
            I.op = XP_IMUL_RR;
            MemOp m;
            if (!read_modrm(sz, regf, m, true)) return I;
            I.r1 = regf;
            if (m.present) { I.text = "imul r,r/m destegi yok"; return I; }
            I.r2 = m.base;
        }
        else if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF) {
            I.op = (op2 == 0xB6 || op2 == 0xB7) ? XP_MOVZX : XP_MOVSX;
            I.sz = is64 && rexw ? 8 : 4;
            I.mem.present = false;
            int rg; MemOp m;
            if (!read_modrm(sz, rg, m, true, (op2 == 0xB6 || op2 == 0xBE))) return I;
            I.r1 = rg;
            I.mem = m;
            if (m.present) { /* kaynak bellek */ }
            else I.r2 = m.base;
            if (op2 == 0xB6 || op2 == 0xBE) I.immsz = 1; else I.immsz = 2; // kaynak boyut
        }
        else { I.text = "0F ikinci opcode desteklenmiyor"; return I; }
        break;
    }
    case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: {
        I.op = XP_PUSH_R; I.sz = is64 ? 8 : 4;
        I.r1 = op - 0x50 + (rexb ? 8 : 0);
        break;
    }
    case 0x68: { I.op = XP_PUSH_I; I.imm = read_imm(4); I.immsz = 4; break; }
    case 0x6A: { I.op = XP_PUSH_I; I.imm = read_imm(1);
                 I.imm = (u64)(long long)(signed char)(u8)I.imm; I.immsz = 4; break; }
    case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F: {
        I.op = XP_POP_R; I.sz = is64 ? 8 : 4;
        I.r1 = op - 0x58 + (rexb ? 8 : 0);
        break;
    }
    case 0x40: case 0x41: case 0x42: case 0x43:
    case 0x44: case 0x45: case 0x46: case 0x47:
        if (is64) { I.text = "rex tek basina"; return I; }
        I.op = XP_INCDEC_R; I.ud = 0; I.sz = 4; I.r1 = op - 0x40; break;
    case 0x48: case 0x49: case 0x4A: case 0x4B:
    case 0x4C: case 0x4D: case 0x4E: case 0x4F:
        if (is64) { I.text = "rex tek basina"; return I; }
        I.op = XP_INCDEC_R; I.ud = 1; I.sz = 4; I.r1 = op - 0x48; break;
    case 0x88: case 0x89: case 0x8A: case 0x8B: {
        // 88/89: MOV r/m, r  |  8A/8B: MOV r, r/m
        I.op = (op == 0x88 || op == 0x89) ? XP_MOV_MR : XP_MOV_RM;
        I.sz = (op == 0x88 || op == 0x8A) ? 1 : sz;
        int rg; MemOp m;
        if (!read_modrm(I.sz, rg, m, true)) return I;
        if (m.present) {
            if (op == 0x88 || op == 0x89) { I.mem = m; I.r1 = rg; }
            else { I.mem = m; I.r1 = rg; }
        } else {
            I.r1 = (op == 0x88 || op == 0x89) ? m.base : rg;
            I.r2 = (op == 0x88 || op == 0x89) ? rg : m.base;
        }
        // 8-bit yuksek bayt kaynak/hedef kontrolu
        if (I.sz == 1) {
            int src = (op == 0x88 || op == 0x89) ? I.r1 : I.r2;
            if (src >= 16 && !is64) { /* ah..bh ok (VM destekler) */ }
        }
        break;
    }
    case 0x8D: { // LEA r, m
        I.op = XP_LEA; I.sz = sz;
        int rg; MemOp m;
        if (!read_modrm(sz, rg, m, true)) return I;
        if (!m.present) { I.text = "lea reg,reg"; return I; }
        I.r1 = rg; I.mem = m;
        break;
    }
    case 0xC6: { // MOV r/m8, imm8
        I.op = XP_MOV_MI; I.sz = 1;
        int rg; MemOp m;
        if (!read_modrm(1, rg, m, true, true)) return I;
        if (!m.present) { I.r1 = m.base; I.text = "mov r8,imm"; return I; }
        I.mem = m; I.imm = read_imm(1); I.immsz = 1;
        break;
    }
    case 0xC7: { // MOV r/m, imm32
        I.op = XP_MOV_MI; I.sz = sz;
        int rg; MemOp m;
        if (!read_modrm(sz, rg, m, true)) return I;
        if (!m.present) {
            // mov r32, imm32
            I.op = XP_MOV_RI; I.r1 = m.base; I.r2 = -1;
            I.imm = read_imm(4); I.immsz = 4;
            break;
        }
        I.mem = m; I.imm = read_imm(4); I.immsz = 4;
        break;
    }
    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7:
        I.op = XP_MOV_RI; I.sz = 1;
        I.r1 = reg8enc(is64, rexb, (op - 0xB0) + (rexb ? 8 : 0));
        I.imm = read_imm(1); I.immsz = 1;
        break;
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF:
        I.r1 = op - 0xB8 + (rexb ? 8 : 0);
        if (is64 && rexw) { I.op = XP_MOV_RI64; I.imm = read_imm(8); I.immsz = 8; }
        else { I.op = XP_MOV_RI; I.sz = op66 ? 2 : 4; I.imm = read_imm(4); I.immsz = 4; }
        break;
    case 0x00: case 0x01: case 0x02: case 0x03:
    case 0x08: case 0x09: case 0x0A: case 0x0B:
    case 0x20: case 0x21: case 0x22: case 0x23:
    case 0x28: case 0x29: case 0x2A: case 0x2B:
    case 0x30: case 0x31: case 0x32: case 0x33:
    case 0x38: case 0x39: case 0x3A: case 0x3B: {
        int lo = op & 7;
        int alu = op >> 3; // 0=ADD 1=OR 4=AND 5=SUB 6=XOR 7=CMP
        static const int amap[8] = { ALU_ADD, -1, -1, -1, ALU_AND, ALU_SUB, ALU_XOR, ALU_CMP };
        // OR (1) ayri: asagida
        I.alu = (alu == 1) ? ALU_OR : amap[alu];
        if (I.alu < 0) { I.text = "alu destegi yok"; return I; }
        I.op = XP_ALU;
        I.sz = (lo < 4) ? ((lo & 1) ? sz : 1) : sz;
        int rg; MemOp m;
        if (!read_modrm(I.sz, rg, m, true, I.sz == 1)) return I;
        if (lo == 0 || lo == 1) { // op r/m, r  (mem = hedef)
            if (m.present) { I.mem = m; I.r1 = rg; I.r2 = -2; }
            else { I.r1 = m.base; I.r2 = rg; }
        } else {                  // op r, r/m  (mem = kaynak)
            if (m.present) { I.mem = m; I.r1 = rg; I.r2 = -3; }
            else { I.r1 = rg; I.r2 = m.base; }
        }
        break;
    }
    case 0x80: case 0x81: case 0x83: {
        static const int amap[8] = { ALU_ADD, ALU_OR, -1, -1, ALU_AND, ALU_SUB, ALU_XOR, ALU_CMP };
        int alu2 = -1;
        I.op = XP_ALU; I.sz = (op == 0x80) ? 1 : sz;
        int rg; MemOp m;
        if (!read_modrm(I.sz, rg, m, true, op == 0x80)) return I;
        alu2 = amap[rg & 7];
        if (alu2 < 0) { I.text = "grp1 adc/sbb"; return I; }
        I.alu = alu2;
        if (m.present) { I.mem = m; I.r1 = -1; }
        else { I.r1 = m.base; }
        // 0x83: imm8 ISIMLI genisletilir (add eax,-1 gibi). Sext YOKTU ->
        // -1 yerine +255 kodlaniyor, if-zincirleri (cmp+ja) yalnis dala giriyordu.
        I.imm = (op == 0x81) ? read_imm(4) : sxt(read_imm(1), 1);
        I.immsz = op == 0x81 ? 4 : 1;
        break;
    }
    case 0x04: case 0x05: case 0x0C: case 0x0D:
    case 0x24: case 0x25: case 0x2C: case 0x2D:
    case 0x34: case 0x35: case 0x3C: case 0x3D: {
        // ALU acc-form: op AL,imm8 | op eAX,imm32 (ADC/SBB yok: 0x14/15/1C/1D)
        int hi = op >> 3;
        static const int amap2[8] = { ALU_ADD, ALU_OR, -1, -1, ALU_AND, ALU_SUB, ALU_XOR, ALU_CMP };
        int alu2 = amap2[hi & 7];
        if (alu2 < 0) { I.text = "acc adc/sbb"; return I; }
        I.op = XP_ALU; I.alu = alu2;
        // x86 acc-form: AL-form op&7==4 (imm8), eAX-form op&7==5 (imm32).
        // ESKI TEST "op & 4" YANLISTI: 0x05 (add eax,imm32) de op&4=4 oldugu
        // icin AL,imm8 saniliyor, 1 bayt okuyup tum akis kayiyordu!
        if ((op & 7) == 4) { // x04/x0C/x24/x2C/x34/x3C: AL, imm8
            I.sz = 1; I.r1 = 0;
            I.imm = read_imm(1); I.immsz = 1;
        } else {      // x05/x0D/x25/x2D/x35/x3D: eAX, imm32 (REX.W -> 64)
            I.sz = op66 ? 2 : (is64 && rexw ? 8 : 4); I.r1 = 0;
            I.imm = read_imm(4); I.immsz = 4;
        }
        break;
    }
    case 0x84: case 0x85: { // TEST r/m, r
        I.op = XP_ALU; I.alu = ALU_TEST; I.sz = (op == 0x84) ? 1 : sz;
        int rg; MemOp m;
        if (!read_modrm(I.sz, rg, m, true, I.sz == 1)) return I;
        if (m.present) { I.mem = m; I.r1 = rg; I.r2 = -2; }
        else { I.r1 = m.base; I.r2 = rg; }
        break;
    }
    case 0xA8: case 0xA9: { // TEST r, imm
        I.op = XP_ALU; I.alu = ALU_TEST; I.sz = (op == 0xA8) ? 1 : sz;
        I.r1 = 0; I.imm = read_imm(op == 0xA8 ? 1 : 4); I.immsz = op == 0xA8 ? 1 : 4;
        break;
    }
    case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3: {
        I.op = XP_SHIFT; I.sz = (op == 0xC0) ? 1 : sz;
        int rg; MemOp m;
        if (!read_modrm(I.sz, rg, m, true, op == 0xC0)) return I;
        int sh = rg & 7;
        if (sh < 4)  { I.text = "rol/ror/rcl/rcr"; return I; }
        // 4=SHL 5=SHR 6=SAL(=SHL) 7=SAR
        I.shi = (sh == 5) ? SHI_SHR : (sh == 7 ? SHI_SAR : SHI_SHL);
        if (m.present) { I.mem = m; I.r1 = -1; }
        else I.r1 = m.base;
        if (op == 0xC0 || op == 0xC1) { I.imm = read_imm(1); I.immsz = 1; }
        else if (op == 0xD2 || op == 0xD3) I.immsz = -1; // CL
        else { I.imm = 1; I.immsz = 1; }
        break;
    }
    case 0x69: case 0x6B: { // IMUL r, r/m, imm
        I.op = XP_IMUL_RRI; I.sz = sz;
        int rg; MemOp m;
        if (!read_modrm(sz, rg, m, true)) return I;
        I.r1 = rg; I.mem = m;
        if (!m.present) I.r2 = m.base;
        // 0x6B: imm8 ISIMLI genisletilir (imul r,r/m,-N yaygin)
        I.imm = (op == 0x69) ? read_imm(4) : sxt(read_imm(1), 1);
        I.immsz = op == 0x69 ? 4 : 1;
        break;
    }
    case 0xF6: case 0xF7: { // GRP3
        I.sz = (op == 0xF6) ? 1 : sz;
        int rg; MemOp m;
        if (!read_modrm(I.sz, rg, m, true, op == 0xF6)) return I;
        int sub = rg & 7;
        if (sub == 0) { // TEST r/m, imm
            I.op = XP_ALU; I.alu = ALU_TEST;
            if (m.present) { I.mem = m; I.r1 = -1; }
            else I.r1 = m.base;
            I.imm = read_imm(I.sz == 1 ? 1 : 4); I.immsz = I.sz == 1 ? 1 : 4;
        } else if (sub == 7) { // IDIV r/m
            I.op = XP_IDIV;
            if (m.present) { I.text = "idiv bellek"; return I; }
            I.r1 = m.base;
        } else if (sub == 2) { // NOT r/m (bayrak etkisi YOK)
            I.op = XP_NOT; I.r1 = -1; I.mem = m;
            if (!m.present) I.r1 = m.base;
        } else if (sub == 3) { // NEG r/m (CF=x!=0, ZF/SF/OF)
            I.op = XP_NEG; I.r1 = -1; I.mem = m;
            if (!m.present) I.r1 = m.base;
        } else { I.text = "grp3 mul/div"; return I; }
        break;
    }
    case 0xFE: { // GRP4: INC/DEC r/m8
        int rg; MemOp m;
        if (!read_modrm(1, rg, m, true, true)) return I;
        int sub = rg & 7;
        I.sz = 1;
        if (m.present) { I.op = XP_INCDEC_M; I.ud = (sub == 0) ? 0 : 1; I.mem = m; }
        else { I.op = XP_INCDEC_R; I.ud = (sub == 0) ? 0 : 1; I.r1 = reg8enc(is64, rexb, m.base); }
        break;
    }
    case 0xFF: { // GRP5
        int rg; MemOp m;
        if (!read_modrm(sz, rg, m, true)) return I;
        int sub = rg & 7;
        if (sub == 0 || sub == 1) {
            I.sz = sz;
            if (m.present) { I.op = XP_INCDEC_M; I.ud = (sub == 0) ? 0 : 1; I.mem = m; }
            else { I.op = XP_INCDEC_R; I.ud = (sub == 0) ? 0 : 1; I.r1 = m.base; }
        } else { I.text = "grp5 call/jmp/push ind"; return I; }
        break;
    }
    case 0xE8: { I.op = XP_CALL; I.imm = read_imm(4); I.immsz = 4;
                 I.target = pc + 5 + (u32)(int)I.imm; break; }
    case 0xE9: { I.op = XP_JMP; I.imm = read_imm(4); I.immsz = 4;
                 I.target = pc + 5 + (u32)(int)I.imm; break; }
    case 0xEB: { I.op = XP_JMP; I.imm = read_imm(1); I.immsz = 1;
                 I.target = pc + 2 + (u32)(long long)(signed char)(u8)I.imm; break; }
    case 0xC2: { I.op = XP_RETI16; I.imm = read_imm(2); I.immsz = 2; break; }
    case 0xC3: { I.op = XP_RET; break; }
    case 0xC9: { I.op = XP_LEAVE; break; }
    case 0x70: case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
    case 0x76: case 0x77: case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
        I.op = XP_JCC; I.cc = op - 0x70; I.sz = 4;
        I.imm = read_imm(1); I.immsz = 1;
        I.target = pc + 2 + (u64)(long long)(signed char)(u8)I.imm;
        break;
    }
    case 0xA0: case 0xA1: case 0xA2: case 0xA3: {
        // mov AL/eAX <-> moffs32 (x86 mutlak statik erisim)
        I.op = (op == 0xA0 || op == 0xA1) ? XP_MOV_RM : XP_MOV_MR;
        I.sz = (op == 0xA0 || op == 0xA2) ? 1 : (op66 ? 2 : (is64 && rexw ? 8 : 4));
        I.r1 = 0;  // AL/AX/EAX/RAX
        MemOp m; m.present = true; m.absimage = true;
        u64 v = read_imm(4);
        m.absval = v;
        I.mem = m;
        if (is64 && !rexw && (op == 0xA1 || op == 0xA3)) { /* 32-bit moffs isaret genisletme: nadir, kabul */ }
        break;
    }
    case 0x98: { I.op = XP_CWDE; break; }
    case 0x99: { I.op = XP_CDQ; break; }
    case 0x63: { if (!is64) { I.text = "arpl"; return I; }
                 I.op = XP_MOVSX; I.sz = sz; I.immsz = 4;
                 int rg; MemOp m;
                 if (!read_modrm(sz, rg, m, true)) return I;
                 if (m.present) { I.mem = m; I.r1 = rg; } else { I.r1 = rg; I.r2 = m.base; }
                 break; }
    default:
        I.text = "opcode desteklenmiyor";
        return I;
    }

    I.len = (u32)i;
    if (I.op == XP_UNKNOWN) return I;
    return I;
}
