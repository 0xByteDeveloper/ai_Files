// shims.cpp - Windows.h shim implementasyonu (yalnizca Linux driver derlemesi icin)
#include "Windows.h"
#include <string>
#include <time.h>

static std::string W2U8(const WCHAR* w) {
    std::string s;
    for (const WCHAR* p = w; *p; ++p) s.push_back((char)*p); // ASCII yeterli (test yollari)
    return s;
}

HANDLE CreateFileW(const WCHAR* name, DWORD access, DWORD share, void* sa, DWORD creation, DWORD flags, HANDLE tmpl) {
    (void)share; (void)sa; (void)flags; (void)tmpl;
    const char* mode = (access & GENERIC_WRITE) ? "r+b" : "rb";
    if (creation == CREATE_ALWAYS) mode = "w+b";
    FILE* f = fopen(W2U8(name).c_str(), mode);
    if (!f) return INVALID_HANDLE_VALUE;
    return (HANDLE)f;
}

DWORD GetFileSize(HANDLE h, DWORD* hi) {
    if (hi) *hi = 0;
    FILE* f = (FILE*)h;
    long cur = ftell(f);
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, cur, SEEK_SET);
    return (DWORD)sz;
}

BOOL ReadFile(HANDLE h, void* buf, DWORD n, DWORD* read, void* ov) {
    (void)ov;
    DWORD r = (DWORD)fread(buf, 1, n, (FILE*)h);
    if (read) *read = r;
    return r == n;
}

BOOL WriteFile(HANDLE h, const void* buf, DWORD n, DWORD* written, void* ov) {
    (void)ov;
    DWORD w = (DWORD)fwrite(buf, 1, n, (FILE*)h);
    if (written) *written = w;
    return w == n;
}

DWORD SetFilePointer(HANDLE h, LONG dist, LONG* hi, DWORD method) {
    (void)hi;
    fseek((FILE*)h, dist, method == FILE_BEGIN ? SEEK_SET : method == 1 ? SEEK_CUR : SEEK_END);
    return (DWORD)ftell((FILE*)h);
}

BOOL CloseHandle(HANDLE h) {
    if (h == INVALID_HANDLE_VALUE) return 0;
    fclose((FILE*)h);
    return 1;
}

ULONGLONG GetTickCount64() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ULONGLONG)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
