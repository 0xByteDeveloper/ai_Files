// ============================================================
// engine_main.cpp — koruma orkestrasyonu
// Akis: PE yukle -> fonksiyonlari bul (export+COFF, PDB YOK) ->
//       sec -> lift (+mutation junk) -> STRDEC/state planla ->
//       sifrele -> .vmp0 kur (blob+bc+stub+state) -> .text yamala ->
//       secenekler (antidebug/strenc/memprot) -> checksum -> kaydet
// ============================================================
#include "engine.hpp"
#include <algorithm>
#include <cstdio>

struct RStr { u32 rva, len; };

// Fonksiyonun GERCEK sonunu tara: ret + dolgu (int3/nop) -> dur.
// COFF sembolu olmayan son fonksiyonlarda 0xCC firtinasi onlenir.
static u32 est_func_size(const u8* p, u32 max, bool is64, u64 ib, u32 isz) {
    u32 pc = 0; bool sawret = false;
    while (pc < max) {
        Insn I = disasm(p + pc, (int)(max - pc), is64, pc, ib, isz);
        if (I.op == XP_UNKNOWN || I.len == 0 || I.op == XP_INT3)
            return sawret ? pc : max;
        if (I.op == XP_NOP && sawret) return pc;
        if (I.op == XP_NOP && !sawret) { pc += I.len; continue; }
        pc += I.len;
        if (I.op == XP_RET || I.op == XP_RETI16) sawret = true;
    }
    return pc;
}

// .pdata (x64): RUNTIME_FUNCTION tablosundan fonksiyonun KESIN sonunu bul.
// Donus: fonksiyon sonu RVA'si (bulunamazsa 0).
static u32 pdata_func_end(const PEFile& pe, u32 rva) {
    const Section* pd = pe.secbyname_c(".pdata");
    if (!pd || pd->vsz < 12) return 0;
    bool ok; u32 raw = pe.rva2raw(pd->va, &ok);
    if (!ok) return 0;
    u32 n = pd->vsz / 12;
    // RUNTIME_FUNCTION dizisi BeginAddress'e gore siralidir -> ikili arama
    u32 lo = 0, hi = n;
    while (lo < hi) {
        u32 mid = (lo + hi) / 2;
        u32 o = raw + mid * 12;
        if (o + 12 > pe.buf.size()) return 0;
        u32 beg; memcpy(&beg, &pe.buf[o], 4);
        if (beg == rva) {
            u32 end; memcpy(&end, &pe.buf[o + 4], 4);
            return (end > beg) ? end : 0;
        }
        if (beg < rva) lo = mid + 1; else hi = mid;
    }
    return 0;
}

static void scan_strings(const PEFile& pe, std::vector<RStr>& out) {
    const Section* rd = pe.secbyname_c(".rdata");
    if (!rd) return;
    bool ok; u32 raw = pe.rva2raw(rd->va, &ok);
    if (!ok) return;
    u32 run = 0;
    for (u32 i = 0; i < rd->vsz && raw + i < pe.buf.size(); i++) {
        u8 c = pe.buf[raw + i];
        if (c >= 0x20 && c < 0x7F) { run++; continue; }
        if (run >= 4 && c == 0) out.push_back({ rd->va + i - run, run });
        run = 0;
    }
}

int protect(const std::string& in, const std::string& out, const Options& opt,
            std::vector<std::string>& log) {
    auto L = [&](const std::string& s) { log.push_back(s); };
    char b[300];

    PEFile pe; std::string err;
    if (!pe.load(in, err)) { L("[HATA] " + err); return 1; }
    snprintf(b, sizeof b, "[PE] %s | Machine=0x%04X | %s | ImageBase=0x%llX | GirisRVA=0x%X",
             in.c_str(), pe.machine, pe.is64 ? "PE32+(x64)" : "PE32(x86)",
             (unsigned long long)pe.ib64, pe.entry_rva);
    L(b);
    for (auto& s : pe.secs) {
        snprintf(b, sizeof b, "  sec %-8s RVA=0x%06X VSz=0x%06X Raw=0x%06X Chars=0x%08X",
                 s.name, s.va, s.vsz, s.rawoff, s.chars);
        L(b);
    }

    // --- fonksiyon kesfi: export + COFF sembolleri (PDB GEREKMEZ) ---
    std::map<u32, std::string> fnames;
    std::vector<std::pair<std::string, u32>> ex, cs;
    pe.exports(ex);
    pe.coff_symbols(cs);
    for (auto& e : ex) fnames[e.second] = e.first;
    for (auto& c : cs) if (!fnames.count(c.second)) fnames[c.second] = c.first;
    L("[KESIF] export=" + std::to_string(ex.size()) + " coff-fonksiyon=" + std::to_string(cs.size()) + " (PDB kullanilmadi)");

    std::vector<FnInfo> fns;
    {
        Section* text0 = pe.secbyname(".text");
        u32 textend = text0 ? text0->va + text0->vsz : 0;
        std::vector<u32> rv;
        for (auto& kv : fnames) rv.push_back(kv.first);
        std::sort(rv.begin(), rv.end());
        for (size_t i = 0; i < rv.size(); i++) {
            u32 r = rv[i];
            if (!text0 || r < text0->va || r >= textend) continue;
            u32 next_bound = (i + 1 < rv.size() ? rv[i + 1] : textend);
            u32 sz = next_bound - r;
            if (sz > 0x8000) sz = 0x8000;
            // x64: .pdata'daki RUNTIME_FUNCTION KESIN siniri verir —
            // (BU, onceki surumdeki "est+16 tasma -> sonraki fonksiyonu
            //  int3 ile ezip acilista crash" hatasini kokten engeller)
            if (pe.is64) {
                u32 pend = pdata_func_end(pe, r);
                if (pend > r && pend <= next_bound) sz = pend - r;
            }
            // sembol araligi zenginse guven; genis aralikta gercek kod sonunu tara
            {
                bool okraw; u32 raw = pe.rva2raw(r, &okraw);
                if (okraw && raw + sz <= pe.buf.size() && sz > 16) {
                    u32 est = est_func_size(&pe.buf[raw], sz, pe.is64, pe.imagebase, pe.sizeofimage);
                    if (est + 64 < sz) sz = est + 16;   // tarayici daha erken bitirdi
                }
            }
            // KESIN GUVENLIK: sonraki sembolun icine asla tasma (x86 + pdata'siz durumlar)
            if (r + sz > next_bound) sz = next_bound - r;
            if (sz < 8) continue;
            FnInfo f; f.rva = r; f.size = sz; f.name = fnames[r];
            f.exported = std::any_of(ex.begin(), ex.end(), [&](auto& e) { return e.second == r; });
            fns.push_back(f);
        }
    }
    snprintf(b, sizeof b, "[FONKSIYON] %zu aday (.text)", fns.size());
    L(b);

    // --- secim ---
    for (auto& f : fns) {
        if (opt.all || opt.funcs.empty()) { f.selected = (f.size >= 24 && f.size <= 8192); continue; }
        for (auto& want : opt.funcs) {
            if (want == f.name) { f.selected = true; break; }
            u32 rv = (u32)strtoul(want.c_str(), nullptr, 16);
            if (rv && rv == f.rva) { f.selected = true; break; }
        }
    }

    Section* text = pe.secbyname(".text");
    Section* rdata = pe.secbyname(".rdata");
    u32 rdata_rva = rdata ? rdata->va : 0;
    u32 rdata_sz  = rdata ? rdata->vsz : 0;
    std::vector<RStr> strings;
    if (opt.strenc) {
        scan_strings(pe, strings);
        snprintf(b, sizeof b, "[STRENC] .rdata'da %zu string tespit", strings.size());
        L(b);
    }

    // --- lift ---
    struct Compiled {
        FnInfo* f; VFn v; std::vector<u8> plain, enc;
        u64 key = 0; u32 bc_rva = 0, stub_rva = 0;
        bool tramp = false;
        std::vector<u32> state_sites;         // plain icinde state rva u32 pozisyonlari
        std::vector<u32> state_strva;         // sirasiyla string rva'lari
    };
    std::vector<Compiled> comps;
    for (auto& f : fns) {
        if (!f.selected) continue;
        bool okraw; u32 raw = pe.rva2raw(f.rva, &okraw);
        if (!okraw || raw + f.size > pe.buf.size()) { f.note = "ham veri yok"; continue; }
        VFn v = lift_function(&pe.buf[raw], f.rva, f.size, pe.is64,
                              pe.imagebase, pe.sizeofimage,
                              pe.is64 /* x86: call iceren red */,
                              rdata_rva, rdata_sz,
                              opt.level >= 2 ? 2 : 0, f.rva ^ 0x9E3779B9u);
        if (!v.ok) { f.note = "RED: " + v.why; continue; }
        Compiled c; c.f = &f; c.v = v;
        comps.push_back(c);
    }
    snprintf(b, sizeof b, "[LIFT] %zu/%zu fonksiyon bayt-koda cevrildi", comps.size(), fns.size());
    L(b);
    for (auto& f : fns) {
        if (f.selected && !f.virtualized && !f.note.empty() && f.note.rfind("RED", 0) == 0)
            L("[RED] " + f.name + " @0x" + hex32(f.rva) + ": " + f.note);
    }

    // --- plain olustur: STRDEC + ANTIDBG + govde ---
    const u8* blob; int blob_len;
    if (pe.is64) { blob = VM_BLOB64; blob_len = VM_BLOB64_LEN; }
    else         { blob = VM_BLOBX86; blob_len = VM_BLOBX86_LEN; }

    u32 newva_guess = 0;
    {
        u32 lastva = 0, lastvsz = 0;
        for (auto& s : pe.secs) if (s.va + s.vsz > lastva + lastvsz) { lastva = s.va; lastvsz = s.vsz; }
        newva_guess = (lastva + lastvsz + pe.secalign - 1) & ~(pe.secalign - 1);
    }

    for (auto& c : comps) {
        std::vector<u8> plain;
        if (opt.strenc) {
            std::vector<RStr> used;
            for (u32 ref : c.v.str_refs)
                for (auto& s : strings)
                    if (ref >= s.rva && ref < s.rva + s.len)
                        if (std::find_if(used.begin(), used.end(), [&](RStr& r) { return r.rva == s.rva; }) == used.end())
                            used.push_back(s);
            for (auto& s : used) {
                plain.push_back(OP_STRDEC);
                for (int k = 0; k < 4; k++) plain.push_back((u8)(s.rva >> (8 * k)));
                c.state_sites.push_back((u32)plain.size());
                for (int k = 0; k < 4; k++) plain.push_back(0);   // state rva placeholder
                c.state_strva.push_back(s.rva);
                u32 k2 = (s.rva * 2654435761u) | 1u;
                c.v.notes.push_back("  [STRDEC] str=0x" + hex32(s.rva) + " len=" + std::to_string(s.len) + " key=0x" + hex32(k2));
            }
        }
        if (opt.antidebug) plain.push_back(OP_ANTIDBG);
        plain.insert(plain.end(), c.v.plain.begin(), c.v.plain.end());
        c.plain = plain;
    }

    // --- section icinde RVAlari planla ---
    u32 cur = (u32)blob_len;
    for (auto& c : comps) {
        cur = (cur + 7) & ~7u;
        c.bc_rva = newva_guess + cur;
        cur += (u32)c.plain.size();
    }
    u32 vent_guess = newva_guess + (pe.is64 ? VM_BLOB64_ENTRY_OFF : VM_BLOBX86_ENTRY_OFF);
    for (auto& c : comps) {
        cur = (cur + 15) & ~15u;
        c.stub_rva = newva_guess + cur;
        std::vector<u8> st;
        if (pe.is64) st = build_stub_x64(c.stub_rva, vent_guess, c.key, c.bc_rva, (u32)c.plain.size());
        else         st = build_stub_x86(c.stub_rva, vent_guess, c.key, c.bc_rva, (u32)c.plain.size(), c.v.retimm);
        c.tramp = st.size() > c.f->size;
        cur += (u32)st.size();
    }
    u32 state_off = cur;
    u32 nstate = 0;
    for (auto& c : comps) nstate += (u32)c.state_sites.size();

    // --- state RVA'larini plain'e yaz ---
    u32 state_idx = 0;
    for (auto& c : comps) {
        for (size_t i = 0; i < c.state_sites.size(); i++) {
            u32 stva = newva_guess + state_off + state_idx;
            u32 at = c.state_sites[i];
            for (int k = 0; k < 4; k++) c.plain[at + k] = (u8)(stva >> (8 * k));
            state_idx++;
        }
    }

    // --- sifrele ---
    for (auto& c : comps) {
        u64 key = 0;
        if (opt.vmenc) {
            key = ((u64)(u32)(c.f->rva * 2654435761u + 0x9E3779B9u) << 32)
                | (u32)((u32)c.plain.size() * 0x2545F491u + 1u) | 1ull;
        }
        c.key = key;
        c.enc.resize(c.plain.size());
        for (size_t i = 0; i < c.plain.size(); i++)
            c.enc[i] = c.plain[i] ^ VM_KS(key, i);   /* pozisyon-bazli */
    }

    // --- section goruntusunu kur ---
    std::vector<u8> secimg;
    secimg.insert(secimg.end(), blob, blob + blob_len);
    while (secimg.size() < (size_t)state_off - (nstate ? 0 : 0)) secimg.push_back(0);
    secimg.resize(state_off + nstate, 0);
    for (auto& c : comps) {
        u32 o = c.bc_rva - newva_guess;
        memcpy(&secimg[o], c.enc.data(), c.enc.size());
        u32 so = c.stub_rva - newva_guess;
        u32 vent = vent_guess;
        std::vector<u8> st;
        if (pe.is64) st = build_stub_x64(c.stub_rva, vent, c.key, c.bc_rva, (u32)c.plain.size());
        else         st = build_stub_x86(c.stub_rva, vent, c.key, c.bc_rva, (u32)c.plain.size(), c.v.retimm);
        memcpy(&secimg[so], st.data(), st.size());
    }
    // state baytlari 0 (VM ilk calismada 1 yapar)

    u32 vmp_rva = 0;
    u32 chars = 0xE0000060u;   // CNT_CODE|MEM_EXEC|MEM_READ|MEM_WRITE
    if (!pe.add_section(".vmp0", secimg, chars, vmp_rva)) { L("[HATA] section eklenemedi"); return 1; }
    snprintf(b, sizeof b, "[SECTION] .vmp0 RVA=0x%06X boyut=0x%06X | VM blob %dB | vm_entry RVA=0x%06X",
             vmp_rva, (u32)secimg.size(), blob_len, vmp_rva + (pe.is64 ? VM_BLOB64_ENTRY_OFF : VM_BLOBX86_ENTRY_OFF));
    L(b);
    if (vmp_rva != newva_guess) L("[UYARI] section RVA beklentiyle farkli!");

    // --- .text yamalama ---
    for (auto& c : comps) {
        FnInfo& f = *c.f;
        bool okraw; u32 raw = pe.rva2raw(f.rva, &okraw);
        if (!okraw) { f.note += " | yama raw yok"; continue; }
        if (c.tramp) {
            i32 rel = (i32)(c.stub_rva - (f.rva + 5));
            u8 j[5] = { 0xE9, (u8)(u32)rel, (u8)((u32)rel >> 8), (u8)((u32)rel >> 16), (u8)((u32)rel >> 24) };
            memcpy(&pe.buf[raw], j, 5);
            for (u32 i = 5; i < f.size; i++) pe.buf[raw + i] = 0xCC;
        } else {
            // YERINDE stub: stub_rva = fonksiyonun kendi RVA'si olacak sekilde uret
            u32 vent = vmp_rva + (pe.is64 ? VM_BLOB64_ENTRY_OFF : VM_BLOBX86_ENTRY_OFF);
            std::vector<u8> st;
            if (pe.is64) st = build_stub_x64(f.rva, vent, c.key, c.bc_rva, (u32)c.plain.size());
            else         st = build_stub_x86(f.rva, vent, c.key, c.bc_rva, (u32)c.plain.size(), c.v.retimm);
            memcpy(&pe.buf[raw], st.data(), st.size());
            for (u32 i = (u32)st.size(); i < f.size; i++) pe.buf[raw + i] = 0xCC;
        }
        f.virtualized = true;
        snprintf(b, sizeof b, "[YAMA] %s @RVA=0x%06X boyut=0x%X | bc=%uB key=0x%llX | stubRVA=0x%06X %s",
                 f.name.c_str(), f.rva, f.size, (u32)c.enc.size(),
                 (unsigned long long)c.key, c.stub_rva, c.tramp ? "(trampoline)" : "(yerinde)");
        L(b);
        for (auto& n : c.v.notes) L(n);
    }

    // --- BUGFIX #13: ezilen bolgelerin eski reloc girdilerini temizle ---
    // Yerinde stub + trampoline .text yamasi fonksiyonun TUM govdesini
    // eziyor (stub + int3). Orijinal koda ait HIGHLOW girdileri bu
    // baytlarin uzerinde kalirsa gercek Windows ASLR (DYNAMICBASE) loader
    // tarafindan +delta ile yamalanir -> stub immediateleri (VM anahtari!)
    // ve E9 rel32 bozulur -> ilk VM cagrisinda cokme. Wine preferred-base
    // yukledigi icin (delta=0) bu hata wine'da gorunmezdi.
    {
        std::vector<std::pair<u32,u32>> ranges;
        for (auto& c : comps)
            if (c.f->virtualized) ranges.push_back({ c.f->rva, c.f->size });
        u32 removed = 0; std::string rnote;
        if (pe.filter_relocs(ranges, removed, rnote)) L("[RELOC] " + rnote);
        else L("[HATA] reloc filtreleme: " + rnote);
    }

    // --- secenek bayraklari ---
    if ((opt.memprot && text) || (opt.strenc && rdata)) {
        u32 fh = pe.e_lfanew + 4;
        u16 optsize = 0; memcpy(&optsize, &pe.buf[fh + 16], 2);
        u32 sh = fh + 20 + optsize;
        for (u32 i = 0; i < pe.secs.size(); i++) {
            u32 o = sh + i * 40;
            char nm[9]; memcpy(nm, &pe.buf[o], 8); nm[8] = 0;
            if (opt.memprot && strcmp(nm, ".text") == 0) {
                u32 ch = text->chars & ~0x80000000u;   // WRITE kaldir -> EXECUTE_READ
                memcpy(&pe.buf[o + 36], &ch, 4);
                snprintf(b, sizeof b, "[MEMPROT] .text Chars=0x%08X (yazilamaz)", ch);
                L(b);
            }
            if (opt.strenc && strcmp(nm, ".rdata") == 0) {
                u32 ch = rdata->chars | 0x80000000u;   // cozum icin yazma
                memcpy(&pe.buf[o + 36], &ch, 4);
                snprintf(b, sizeof b, "[STRENC] .rdata Chars=0x%08X (yazilabilir)", ch);
                L(b);
            }
        }
    }

    pe.fix_checksum();
    if (!pe.save(out)) { L("[HATA] kaydedilemedi: " + out); return 1; }
    snprintf(b, sizeof b, "[KAYIT] %s (%zu bayt)", out.c_str(), pe.buf.size());
    L(b);
    L("[OZET] level=" + std::to_string(opt.level) + (opt.level >= 2 ? " (UltraVirt+Mutation)" : " (Virt)")
      + " | antidebug=" + (opt.antidebug ? "ACIK" : "kapali")
      + " | strenc=" + (opt.strenc ? "ACIK" : "kapali")
      + " | memprot=" + (opt.memprot ? "ACIK" : "kapali")
      + " | vmenc=" + (opt.vmenc ? "ACIK" : "KAPALI"));
    return 0;
}
