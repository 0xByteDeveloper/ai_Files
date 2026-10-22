// ============================================================
// cplport_gui.cpp — CPlusPort GUI (Win32 API, PDB'siz calisir)
// Akis: dosya sec -> fonksiyon listesi (export+COFF taramasi) ->
//       secim + seviye (1=Virt 2=UltraVirt+Mutation) + genel
//       secenekler -> Koru -> <ad>_vmp.exe + CPlusPort_debug.log
// ============================================================
#include "engine.hpp"
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#define IDC_OPEN     1001
#define IDC_LIST     1002
#define IDC_PROTECT  1003
#define IDC_LBLFILE  1004
#define IDC_LBLLOG   1005
#define IDC_EDLOG    1006
#define IDC_RADIO_L1 1010
#define IDC_RADIO_L2 1011
#define IDC_CHK_AD   1020
#define IDC_CHK_SE   1021
#define IDC_CHK_MP   1022
#define IDC_CHK_VM   1023

static HWND g_hMain, g_hList, g_hLog, g_hLblFile;
static std::string g_inPath;
static std::vector<FnInfo> g_fns;

static void AppendLog(const std::string& s) {
    int len = GetWindowTextLength(g_hLog);
    SendMessage(g_hLog, EM_SETSEL, len, len);
    std::string line = s + "\r\n";
    SendMessage(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)line.c_str());
}

static bool ListFile(const std::string& path) {
    PEFile pe; std::string err;
    if (!pe.load(path, err)) { AppendLog("[HATA] " + err); return false; }
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
    g_fns.clear();
    ListView_DeleteAllItems(g_hList);
    char b[300];
    for (size_t i = 0; i < rv.size(); i++) {
        u32 r = rv[i];
        if (!text || r < text->va || r >= textend) continue;
        u32 sz = ((i + 1 < rv.size() ? rv[i + 1] : textend) - r);
        if (sz > 0x8000) sz = 0x8000;
        if (sz < 8) continue;
        FnInfo f; f.rva = r; f.size = sz; f.name = fnames[r];
        f.exported = std::any_of(ex.begin(), ex.end(), [&](auto& e) { return e.second == r; });
        g_fns.push_back(f);
    }
    snprintf(b, sizeof b, "[LISTE] %s | %s | %zu fonksiyon (PDB kullanilmadi)",
             path.c_str(), pe.is64 ? "x64" : "x86", g_fns.size());
    AppendLog(b);
    // en cok export edilenleri isaretle
    for (size_t i = 0; i < g_fns.size(); i++) {
        char sub[128];
        snprintf(sub, sizeof sub, "0x%06X  %5uB  %s", g_fns[i].rva, g_fns[i].size,
                 g_fns[i].exported ? "[export]" : "");
        LVITEMA it = {};
        it.mask = LVIF_TEXT | LVIF_PARAM;
        it.iItem = (int)i;
        it.pszText = (LPSTR)g_fns[i].name.c_str();
        it.lParam = (LPARAM)i;
        int idx = SendMessage(g_hList, LVM_INSERTITEMA, 0, (LPARAM)&it);
        it.iSubItem = 1; it.pszText = sub;
        SendMessage(g_hList, LVM_SETITEMA, idx, (LPARAM)&it);
    }
    return true;
}

static void DoProtect(HWND h) {
    if (g_inPath.empty()) { MessageBoxA(h, "Once bir PE dosyasi sec.", "CPlusPort", MB_ICONWARNING); return; }
    Options opt;
    opt.level = (SendMessage(GetDlgItem(h, IDC_RADIO_L2), BM_GETCHECK, 0, 0) & BST_CHECKED) ? 2 : 1;
    opt.antidebug = (SendMessage(GetDlgItem(h, IDC_CHK_AD), BM_GETCHECK, 0, 0) & BST_CHECKED) != 0;
    opt.strenc    = (SendMessage(GetDlgItem(h, IDC_CHK_SE), BM_GETCHECK, 0, 0) & BST_CHECKED) != 0;
    opt.memprot   = (SendMessage(GetDlgItem(h, IDC_CHK_MP), BM_GETCHECK, 0, 0) & BST_CHECKED) != 0;
    opt.vmenc     = (SendMessage(GetDlgItem(h, IDC_CHK_VM), BM_GETCHECK, 0, 0) & BST_CHECKED) != 0;
    int n = ListView_GetItemCount(g_hList);
    LVITEMA it = {};
    it.mask = LVIF_PARAM | LVIF_STATE;
    it.stateMask = LVIS_SELECTED;
    for (int i = 0; i < n; i++) {
        it.iItem = i;
        SendMessage(g_hList, LVM_GETITEMA, 0, (LPARAM)&it);
        if (it.state & LVIS_SELECTED) opt.funcs.push_back(g_fns[it.lParam].name);
    }
    if (opt.funcs.empty()) { MessageBoxA(h, "Listeden en az bir fonksiyon sec (Ctrl ile coklu).", "CPlusPort", MB_ICONWARNING); return; }

    std::string out = g_inPath.substr(0, g_inPath.rfind('.')) + "_vmp.exe";
    AppendLog("=== KORUMA BASLIYOR (level " + std::to_string(opt.level) + ") ===");
    std::vector<std::string> log;
    int rc = protect(g_inPath, out, opt, log);
    for (auto& s : log) AppendLog(s);
    AppendLog(rc == 0 ? "=== BITTI: " + out + " ===" : "=== HATA ile bitti ===");
    // ayrica dosyaya yaz
    std::string lp = g_inPath.substr(0, g_inPath.rfind('\\') + 1) + "CPlusPort_debug.log";
    FILE* f = fopen(lp.c_str(), "ab");
    if (f) { fprintf(f, "\n---- GUI oturumu ----\n");
             for (auto& s : log) fprintf(f, "%s\n", s.c_str()); fclose(f); }
    MessageBoxA(h, rc == 0 ? ("Cikti: " + out + "\nGunluk: " + lp).c_str() : "Koruma basarisiz (gunluge bak).",
                "CPlusPort", MB_ICONINFORMATION);
}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_CREATE: {
        CreateWindowA("BUTTON", "PE dosyasi sec...", WS_CHILD | WS_VISIBLE,
                      10, 10, 140, 28, h, (HMENU)IDC_OPEN, nullptr, nullptr);
        g_hLblFile = CreateWindowA("STATIC", "(dosya secilmedi)",
                      WS_CHILD | WS_VISIBLE, 160, 16, 500, 20, h, (HMENU)IDC_LBLFILE, nullptr, nullptr);
        CreateWindowA("STATIC", "Fonksiyonlar (RVA | boyut | isim) — secmek icin tikla, Ctrl=coklu:",
                      WS_CHILD | WS_VISIBLE, 10, 46, 500, 18, h, nullptr, nullptr, nullptr);
        g_hList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, nullptr,
                      WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SHOWSELALWAYS,
                      10, 66, 640, 260, h, (HMENU)IDC_LIST, nullptr, nullptr);
        LVCOLUMNA col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = (LPSTR)"Fonksiyon"; col.cx = 300;
        SendMessage(g_hList, LVM_INSERTCOLUMN, 0, (LPARAM)&col);
        col.pszText = (LPSTR)"RVA / boyut"; col.cx = 330;
        SendMessage(g_hList, LVM_INSERTCOLUMN, 1, (LPARAM)&col);

        CreateWindowA("BUTTON", "Seviye 1: Virt", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
                      10, 336, 150, 20, h, (HMENU)IDC_RADIO_L1, nullptr, nullptr);
        CreateWindowA("BUTTON", "Seviye 2: UltraVirt+Mutation", WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
                      10, 358, 220, 20, h, (HMENU)IDC_RADIO_L2, nullptr, nullptr);
        CheckRadioButton(h, IDC_RADIO_L1, IDC_RADIO_L2, IDC_RADIO_L2);

        CreateWindowA("BUTTON", "Anti-Debug (PEB)", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                      240, 336, 170, 20, h, (HMENU)IDC_CHK_AD, nullptr, nullptr);
        CheckDlgButton(h, IDC_CHK_AD, BST_CHECKED);
        CreateWindowA("BUTTON", "String Sifreleme", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                      240, 358, 170, 20, h, (HMENU)IDC_CHK_SE, nullptr, nullptr);
        CreateWindowA("BUTTON", "Memory Protection (.text RO)", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                      420, 336, 230, 20, h, (HMENU)IDC_CHK_MP, nullptr, nullptr);
        CreateWindowA("BUTTON", "VM Bayt-Kod Sifreleme", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                      420, 358, 230, 20, h, (HMENU)IDC_CHK_VM, nullptr, nullptr);
        CheckDlgButton(h, IDC_CHK_VM, BST_CHECKED);

        CreateWindowA("BUTTON", "KORU ve Kaydet (_vmp.exe)", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                      10, 390, 220, 34, h, (HMENU)IDC_PROTECT, nullptr, nullptr);
        g_hLog = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", nullptr,
                      WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
                      10, 432, 640, 220, h, (HMENU)IDC_EDLOG, nullptr, nullptr);
        AppendLog("CPlusPort v1.0 — VMProtect tarzi sanallastirici (MiniVM)");
        AppendLog("1) PE sec  2) fonksiyon sec  3) Koru. Detaylar CPlusPort_debug.log'a yazilir.");
        break;
    }
    case WM_COMMAND:
        if (LOWORD(w) == IDC_OPEN) {
            char file[MAX_PATH] = {};
            OPENFILENAMEA of = {};
            of.lStructSize = sizeof of; of.hwndOwner = h;
            of.lpstrFilter = "PE dosyalari\0*.exe;*.dll\0Tumu\0*.*\0";
            of.lpstrFile = file; of.nMaxFile = MAX_PATH;
            of.Flags = OFN_FILEMUSTEXIST;
            if (GetOpenFileNameA(&of)) {
                g_inPath = file;
                SetWindowTextA(g_hLblFile, file);
                ListFile(g_inPath);
            }
        } else if (LOWORD(w) == IDC_PROTECT) {
            DoProtect(h);
        }
        break;
    case WM_DESTROY: PostQuitMessage(0); break;
    default: return DefWindowProcA(h, m, w, l);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hI, HINSTANCE, LPSTR, int nCmd) {
    WNDCLASSA wc = {};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hI;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = "CPlusPortWnd";
    RegisterClassA(&wc);
    INITCOMMONCONTROLSEX icc = { sizeof icc, ICC_LISTVIEW_CLASSES };
    InitCommonControlsEx(&icc);
    g_hMain = CreateWindowExA(0, "CPlusPortWnd", "CPlusPort — VMProtect tarzi Sanallastirici v1.0",
              WS_OVERLAPPEDWINDOW, 60, 60, 680, 700, nullptr, nullptr, hI, nullptr);
    ShowWindow(g_hMain, nCmd);
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    return 0;
}
