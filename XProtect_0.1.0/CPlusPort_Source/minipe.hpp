// minipe.hpp — lifcmp icin minimal PE okuyucu (export tablosu + section'lar)
#pragma once
#include "engine.hpp"
#include <string>

struct MiniPE {
    std::vector<u8> buf;
    bool is64 = false;
    u32 imagebase = 0, sizeofimage = 0x10000000;
    struct Exp { std::string name; u32 rva; };
    std::vector<Exp> exps;

    bool load(const std::string& path, std::string& err) {
        FILE* f = fopen(path.c_str(), "rb");
        if (!f) { err = "acilamadi"; return false; }
        fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
        buf.resize(n);
        if (fread(buf.data(), 1, n, f) != (size_t)n) { fclose(f); err = "okuma"; return false; }
        fclose(f);
        u32 e_lfanew; memcpy(&e_lfanew, &buf[0x3C], 4);
        u16 machine; memcpy(&machine, &buf[e_lfanew + 4], 2);
        u16 optsize; memcpy(&optsize, &buf[e_lfanew + 16], 2);
        u32 opt = e_lfanew + 20;
        u16 magic; memcpy(&magic, &buf[opt], 2);
        is64 = (magic == 0x20B);
        if (is64) imagebase = (u32)((u64)buf[opt+24] | ((u64)buf[opt+25]<<8) | ((u64)buf[opt+26]<<16) | ((u64)buf[opt+27]<<24));
        else      memcpy(&imagebase, &buf[opt + 28], 4);
        u32 sh = opt + optsize;
        u16 nsec; memcpy(&nsec, &buf[e_lfanew + 6], 2);
        // export dizini
        u32 expdir_rva = 0;
        u32 ddoff = opt + (is64 ? 112 : 96);
        memcpy(&expdir_rva, &buf[ddoff], 4);
        if (expdir_rva) {
            bool ok; u32 eoff = rva2off(expdir_rva, &ok);
            if (ok) {
                u32 nfun, nnames, fn_rva, names_rva;
                memcpy(&nfun, &buf[eoff + 20], 4);
                memcpy(&nnames, &buf[eoff + 24], 4);
                memcpy(&fn_rva, &buf[eoff + 28], 4);
                memcpy(&names_rva, &buf[eoff + 32], 4);
                bool o2; u32 noff = rva2off(names_rva, &o2);
                u32 foff = rva2off(fn_rva, &o2);
                for (u32 k = 0; k < nnames && o2; k++) {
                    u32 nameRva; memcpy(&nameRva, &buf[noff + k*4], 4);
                    bool o3; u32 nstr = rva2off(nameRva, &o3);
                    if (!o3) break;
                    std::string name((char*)&buf[nstr]);
                    u32 funRva; memcpy(&funRva, &buf[foff + k*4], 4);
                    exps.push_back({ name, funRva });
                }
                (void)foff;
            }
        }
        (void)sh; (void)nsec; (void)machine;
        return true;
    }
    u32 rva2off(u32 rva, bool* ok = nullptr) {
        // section tablosunu her seferinde tara (basit)
        u32 e_lfanew; memcpy(&e_lfanew, &buf[0x3C], 4);
        u16 optsize; memcpy(&optsize, &buf[e_lfanew + 16], 2);
        u32 sh = e_lfanew + 20 + optsize;
        u16 nsec; memcpy(&nsec, &buf[e_lfanew + 6], 2);
        for (u16 i = 0; i < nsec; i++) {
            u32 o = sh + i * 40;
            u32 va, vsz, raw, rawsz;
            memcpy(&va, &buf[o + 12], 4);
            memcpy(&vsz, &buf[o + 8], 4);
            memcpy(&raw, &buf[o + 20], 4);
            memcpy(&rawsz, &buf[o + 16], 4);
            if (rva >= va && rva < va + (vsz ? vsz : rawsz)) {
                if (ok) *ok = (raw + (rva - va) + 1) <= buf.size() && rawsz > 0;
                return raw + (rva - va);
            }
        }
        if (ok) *ok = false;
        return 0;
    }
    u32 export_rva(const char* name) {
        for (auto& e : exps) if (e.name == name) return e.rva;
        return 0;
    }
    u32 next_export_rva(u32 rva) {
        u32 best = 0;
        for (auto& e : exps) if (e.rva > rva && (!best || e.rva < best)) best = e.rva;
        return best;
    }
};
