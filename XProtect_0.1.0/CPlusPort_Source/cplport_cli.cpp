// ============================================================
// cplport_cli.cpp — CPlusPort komut satiri arayuzu
// Ayni motoru GUI ile paylasir. Kullanim:
//   cplport_cli --in Test64.exe --out Test64_vmp.exe
//              --funcs GameTick,MovePlayer --level 2
//              --opt antidebug,strenc,memprot,vmenc
//              --log CPlusPort_debug.log
//   cplport_cli --list --in Test64.exe
// ============================================================
#include "engine.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>

static std::vector<std::string> splitc(const std::string& s, char c) {
    std::vector<std::string> out; std::string cur;
    for (char ch : s) {
        if (ch == c) { if (!cur.empty()) out.push_back(cur); cur.clear(); }
        else cur += ch;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

static int list_mode(const std::string& in) {
    PEFile pe; std::string err;
    if (!pe.load(in, err)) { printf("[HATA] %s\n", err.c_str()); return 1; }
    std::map<u32, std::string> fnames;
    std::vector<std::pair<std::string, u32>> ex, cs;
    pe.exports(ex);
    pe.coff_symbols(cs);
    for (auto& e : ex) fnames[e.second] = e.first;
    for (auto& c : cs) if (!fnames.count(c.second)) fnames[c.second] = c.first;
    Section* text = pe.secbyname(".text");
    u32 textend = text ? text->va + text->vsz : 0;
    std::vector<u32> rv;
    for (auto& kv : fnames) rv.push_back(kv.first);
    std::sort(rv.begin(), rv.end());
    printf("PE: %s | %s | ImageBase=0x%llX\n", in.c_str(), pe.is64 ? "x64" : "x86", (unsigned long long)pe.ib64);
    printf("%-10s %-8s %-6s %s\n", "RVA", "BOYUT", "EXPORT", "ISIM");
    for (size_t i = 0; i < rv.size(); i++) {
        u32 r = rv[i];
        if (!text || r < text->va || r >= textend) continue;
        u32 sz = ((i + 1 < rv.size() ? rv[i + 1] : textend) - r);
        bool isex = std::any_of(ex.begin(), ex.end(), [&](auto& e) { return e.second == r; });
        printf("0x%08X %-8u %-6s %s\n", r, sz, isex ? "EVET" : "-", fnames[r].c_str());
    }
    return 0;
}

int main(int argc, char** argv) {
    std::string in, out, logpath = "CPlusPort_debug.log";
    Options opt;
    bool list = false;
    std::vector<std::string> optlist;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto nx = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : std::string(); };
        if (a == "--in") in = nx();
        else if (a == "--out") out = nx();
        else if (a == "--funcs") opt.funcs = splitc(nx(), ',');
        else if (a == "--level") opt.level = atoi(nx().c_str());
        else if (a == "--opt") optlist = splitc(nx(), ',');
        else if (a == "--log") logpath = nx();
        else if (a == "--list") list = true;
        else if (a == "--all") opt.all = true;
        else if (a == "--help" || a == "-h") {
            printf("CPlusPort CLI — VMProtect tarzi sanallastirici (MiniVM)\n"
                   "  --in F            giris PE (x64/x86)\n"
                   "  --out F           cikis (varsayilan: <in>_vmp.exe)\n"
                   "  --funcs a,b       fonksiyon isimleri ya da RVA (hex)\n"
                   "  --all             tum uygun fonksiyonlar\n"
                   "  --level N         1=Virt  2=UltraVirt+Mutation\n"
                   "  --opt a,b,c       antidebug, strenc, memprot, vmenc\n"
                   "  --log F           hata ayiklama gunlugu\n"
                   "  --list            fonksiyonlari listele (PDB'siz)\n");
            return 0;
        }
    }
    if (in.empty()) { printf("Giris dosyasi gerekli. --help\n"); return 1; }
    if (list) return list_mode(in);
    if (out.empty()) { out = in.substr(0, in.rfind('.')) + "_vmp.exe"; }

    for (auto& o : optlist) {
        if (o == "antidebug") opt.antidebug = true;
        else if (o == "strenc") opt.strenc = true;
        else if (o == "memprot") opt.memprot = true;
        else if (o == "vmenc") opt.vmenc = true;
        else if (o == "novmenc") opt.vmenc = false;
        else if (o == "all") opt.all = true;
    }
    if (opt.level >= 2 && optlist.empty()) { /* mutation zaten liftte */ }

    std::vector<std::string> log;
    log.push_back("=== CPlusPort v1.0 (MiniVM) — debug gunlugu ===");
    log.push_back("Mod: CLI | Tarih-parametreleri: level=" + std::to_string(opt.level));
    int rc = protect(in, out, opt, log);

    FILE* f = fopen(logpath.c_str(), "ab");
    if (f) {
        fprintf(f, "\n---- oturum ----\n");
        for (auto& s : log) fprintf(f, "%s\n", s.c_str());
        fclose(f);
    }
    for (auto& s : log) printf("%s\n", s.c_str());
    printf("\nGunluk: %s\n", logpath.c_str());
    return rc;
}
