#pragma once
#include "globals.h"
#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <map>
#include <psapi.h>

enum class InstanceType { File, Process };

struct InstanceInfo {
    std::string id;           // i1, i2, i3...
    std::string name;         // Display name: dosya1.exe veya pid:1234
    std::string shortName;    // Kýsa isim: dosya1
    std::wstring filePath;
    DWORD pid = 0;
    InstanceType type = InstanceType::File;
    HANDLE hProcess = nullptr; // Process handle (Process modunda)

    // Core components - her instance kendi PE/Memory'sine sahip
    PEFile pe;
    MemImage mem;
    Disasm dis;
    Assembler asmb;
    RefEngine refs;
    SymTable syms;
    UndoSys undo;

    // State
    u64 viewAddr = 0;
    u64 selAddr = 0;
    u64 hexAddr = 0;
    bool loaded = false;
    bool refsBuilt = false;
    bool is64bit = false;

    // String storage per instance
    StringStorage stringStorage;

    // Process-specific
    u64 processBaseAddr = 0;      // Ana modülün gerçek base adresi
    u32 processImageSize = 0;     // Ana modülün boyutu

    // Process-specific: enumerate loaded modules
    struct ProcessModule {
        std::string moduleName;       // e.g. "kernel32.dll"
        std::wstring modulePath;      // Full path
        u64 baseAddr = 0;            // Base address in target process
        u32 moduleSize = 0;
        std::vector<ImpDll> imports;  // Parsed imports for this module
    };
    std::vector<ProcessModule> processModules;
    bool processModulesEnumerated = false;

    // Process memory buffer (for disasm/hex display)
    std::vector<u8> processMemoryCache;
    u64 processCacheBase = 0;
    u64 processCacheSize = 0;

    ~InstanceInfo() {
        if (hProcess) {
            CloseHandle(hProcess);
            hProcess = nullptr;
        }
    }

    // Process belleðinden oku (cache'li)
    bool ReadFromProcess(u64 addr, u8* buf, size_t size) {
        if (type != InstanceType::Process || !hProcess) return false;
        SIZE_T bytesRead = 0;
        return ReadProcessMemory(hProcess, (LPCVOID)addr, buf, size, &bytesRead) && bytesRead > 0;
    }

    // Process belleðine yaz
    bool WriteToProcess(u64 addr, const u8* buf, size_t size) {
        if (type != InstanceType::Process || !hProcess) return false;

        // Önce write eriþimi al
        DWORD oldProtect = 0;
        if (!VirtualProtectEx(hProcess, (LPVOID)addr, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            // Koruma deðiþtirilemezse direkt dene
        }

        SIZE_T bytesWritten = 0;
        BOOL result = WriteProcessMemory(hProcess, (LPVOID)addr, buf, size, &bytesWritten);

        // Eski korumayý geri yükle
        if (oldProtect) {
            DWORD temp;
            VirtualProtectEx(hProcess, (LPVOID)addr, size, oldProtect, &temp);
        }

        return result && bytesWritten > 0;
    }

    // Belirli adresteki byte'ý oku (process veya file)
    u8 ReadByte(u64 addr) {
        if (type == InstanceType::Process && hProcess) {
            u8 b = 0;
            ReadFromProcess(addr, &b, 1);
            return b;
        }
        else if (mem.InRange(addr)) {
            return mem.Read8(addr);
        }
        return 0;
    }

    // Belirli adrese byte yaz (process veya file)
    bool WriteByte(u64 addr, u8 val) {
        if (type == InstanceType::Process && hProcess) {
            return WriteToProcess(addr, &val, 1);
        }
        else if (mem.InRange(addr)) {
            mem.Write8(addr, val);
            return true;
        }
        return false;
    }

    // Adres geçerli mi?
    bool IsAddressValid(u64 addr) {
        if (type == InstanceType::Process) {
            return addr >= processBaseAddr && addr < processBaseAddr + processImageSize;
        }
        return mem.InRange(addr);
    }

    // Base address
    u64 GetBaseAddress() {
        if (type == InstanceType::Process) {
            return processBaseAddr;
        }
        return mem.base;
    }

    // Image size
    u64 GetImageSize() {
        if (type == InstanceType::Process) {
            return processImageSize;
        }
        return mem.data.size();
    }
};

class InstanceManager {
public:
    static InstanceManager& I() { static InstanceManager m; return m; }

    // === Instance Creation/Removal ===
    std::string CreateFileInstance(const std::wstring& path) {
        auto inst = std::make_unique<InstanceInfo>();
        inst->id = GenerateId();
        inst->type = InstanceType::File;
        inst->filePath = path;

        // Extract filename
        size_t ls = path.find_last_of(L"\\/");
        std::wstring fn = (ls != std::wstring::npos) ? path.substr(ls + 1) : path;
        inst->name.clear();
        for (wchar_t wc : fn) inst->name += (wc < 128) ? (char)wc : '?';

        // Short name without extension
        inst->shortName = inst->name;
        size_t dp = inst->shortName.find_last_of('.');
        if (dp != std::string::npos) inst->shortName = inst->shortName.substr(0, dp);

        // Load file
        if (!inst->pe.Load(path.c_str()) || !inst->mem.Create(inst->pe) || !inst->dis.Init(inst->pe.is64)) {
            return "";
        }

        inst->asmb.is64 = inst->pe.is64;
        inst->is64bit = inst->pe.is64;
        inst->syms.Build(inst->pe.imps, inst->pe.imgBase);
        SetupAssemblerCallbacks(inst.get());

        if (inst->pe.dllCharacteristics & 0x40) inst->pe.DisableASLR();

        inst->viewAddr = inst->pe.imgBase + inst->pe.ep;
        inst->selAddr = inst->viewAddr;
        inst->hexAddr = inst->pe.imgBase;
        inst->loaded = true;

        inst->stringStorage.ScanExistingStrings(inst->pe, inst->mem);

        std::string id = inst->id;
        m_instances.push_back(std::move(inst));

        if (m_activeId.empty()) m_activeId = id;
        if (OnInstanceCreated) OnInstanceCreated(id);

        return id;
    }

    std::string CreateProcessInstance(DWORD pid) {
        auto inst = std::make_unique<InstanceInfo>();
        inst->id = GenerateId();
        inst->type = InstanceType::Process;
        inst->pid = pid;

        char buf[64];
        sprintf(buf, "pid:%lu", pid);
        inst->name = buf;
        inst->shortName = inst->name;

        // === Open process with FULL access for read/write ===
        HANDLE hProc = OpenProcess(
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
            PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE, pid);

        if (!hProc) {
            // Try with read-only access
            hProc = OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE, pid);
        }

        if (!hProc) {
            hProc = OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE, pid);
        }

        if (!hProc) {
            inst->loaded = false;
            std::string id = inst->id;
            m_instances.push_back(std::move(inst));
            if (m_activeId.empty()) m_activeId = id;
            if (OnInstanceCreated) OnInstanceCreated(id);
            return id;
        }

        inst->hProcess = hProc;

        // === Enumerate process modules ===
        HMODULE hMods[1024];
        DWORD cbNeeded = 0;
        DWORD modCount = 0;

        // Try different enumeration methods
        if (EnumProcessModulesEx(hProc, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
            modCount = cbNeeded / sizeof(HMODULE);
        }
        else if (EnumProcessModulesEx(hProc, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_32BIT)) {
            modCount = cbNeeded / sizeof(HMODULE);
        }
        else if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
            modCount = cbNeeded / sizeof(HMODULE);
        }

        if (modCount == 0) {
            inst->loaded = false;
            std::string id = inst->id;
            m_instances.push_back(std::move(inst));
            if (m_activeId.empty()) m_activeId = id;
            if (OnInstanceCreated) OnInstanceCreated(id);
            return id;
        }

        // === Ana modül bilgilerini al ===
        MODULEINFO mainModInfo = {};
        if (GetModuleInformation(hProc, hMods[0], &mainModInfo, sizeof(mainModInfo))) {
            inst->processBaseAddr = (u64)mainModInfo.lpBaseOfDll;
            inst->processImageSize = mainModInfo.SizeOfImage;
        }
        else {
            inst->processBaseAddr = (u64)hMods[0];
            inst->processImageSize = 0x100000; // Default 1MB
        }

        // === Detect 32/64 bit ===
        BOOL isWow64 = FALSE;
        IsWow64Process(hProc, &isWow64);
        inst->is64bit = !isWow64;

        // Initialize disassembler
        inst->dis.Init(inst->is64bit);

        // === Parse each module ===
        for (DWORD mi = 0; mi < modCount && mi < 1024; mi++) {
            InstanceInfo::ProcessModule pmod;

            pmod.baseAddr = (u64)hMods[mi];

            MODULEINFO modInfo = {};
            if (GetModuleInformation(hProc, hMods[mi], &modInfo, sizeof(modInfo))) {
                pmod.moduleSize = modInfo.SizeOfImage;
            }

            wchar_t modPath[MAX_PATH] = { 0 };
            if (GetModuleFileNameExW(hProc, hMods[mi], modPath, MAX_PATH)) {
                pmod.modulePath = modPath;

                std::wstring wfn = modPath;
                size_t lslash = wfn.find_last_of(L"\\/");
                if (lslash != std::wstring::npos) wfn = wfn.substr(lslash + 1);
                for (wchar_t wc : wfn) pmod.moduleName += (wc < 128) ? (char)wc : '?';
            }
            else {
                char mname[32];
                sprintf(mname, "mod_%llX", pmod.baseAddr);
                pmod.moduleName = mname;
            }

            // === Read PE headers from process memory for import parsing ===
            ParseModuleImports(hProc, pmod, inst->is64bit);

            inst->processModules.push_back(std::move(pmod));
        }

        inst->processModulesEnumerated = true;

        // === Ana modül bilgilerini güncelle ===
        if (!inst->processModules.empty()) {
            auto& mainMod = inst->processModules[0];

            inst->shortName = mainMod.moduleName;
            size_t dp = inst->shortName.find_last_of('.');
            if (dp != std::string::npos) inst->shortName = inst->shortName.substr(0, dp);

            inst->name = inst->shortName + " (pid:" + std::to_string(pid) + ")";
            inst->filePath = mainMod.modulePath;

            // Entry point'i process belleðinden oku
            u64 entryPoint = 0;
            std::vector<u8> headerBuf(0x1000, 0);
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(hProc, (LPCVOID)inst->processBaseAddr,
                headerBuf.data(), 0x1000, &bytesRead) && bytesRead >= 64) {

                auto dos = (PIMAGE_DOS_HEADER)headerBuf.data();
                if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
                    auto nt = (PIMAGE_NT_HEADERS)(headerBuf.data() + dos->e_lfanew);
                    if (nt->Signature == IMAGE_NT_SIGNATURE) {
                        if (inst->is64bit) {
                            auto n64 = (PIMAGE_NT_HEADERS64)nt;
                            entryPoint = inst->processBaseAddr + n64->OptionalHeader.AddressOfEntryPoint;
                        }
                        else {
                            auto n32 = (PIMAGE_NT_HEADERS32)nt;
                            entryPoint = inst->processBaseAddr + n32->OptionalHeader.AddressOfEntryPoint;
                        }
                    }
                }
            }

            inst->viewAddr = entryPoint ? entryPoint : inst->processBaseAddr;
            inst->selAddr = inst->viewAddr;
            inst->hexAddr = inst->processBaseAddr;
            inst->loaded = true;

            // Symbol table oluþtur (tüm modüllerden)
            BuildProcessSymbols(inst.get());
        }

        std::string id = inst->id;
        m_instances.push_back(std::move(inst));
        if (m_activeId.empty()) m_activeId = id;
        if (OnInstanceCreated) OnInstanceCreated(id);
        return id;
    }

    // === Process belleðinden okuma ===
    bool ReadProcessMemoryAt(const std::string& id, u64 addr, u8* buf, size_t size) {
        InstanceInfo* inst = GetInstance(id);
        if (!inst || inst->type != InstanceType::Process || !inst->hProcess) return false;
        return inst->ReadFromProcess(addr, buf, size);
    }

    // === Process belleðine yazma ===
    bool WriteProcessMemoryAt(const std::string& id, u64 addr, const u8* buf, size_t size) {
        InstanceInfo* inst = GetInstance(id);
        if (!inst || inst->type != InstanceType::Process || !inst->hProcess) return false;
        return inst->WriteToProcess(addr, buf, size);
    }

    // === Refresh process memory (modül listesini yenile) ===
    bool RefreshProcessMemory(const std::string& id) {
        InstanceInfo* inst = GetInstance(id);
        if (!inst || inst->type != InstanceType::Process || !inst->hProcess) return false;

        // Modül listesini yeniden oku
        inst->processModules.clear();
        inst->processModulesEnumerated = false;

        HMODULE hMods[1024];
        DWORD cbNeeded = 0;

        if (EnumProcessModulesEx(inst->hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
            DWORD modCount = cbNeeded / sizeof(HMODULE);

            for (DWORD mi = 0; mi < modCount && mi < 1024; mi++) {
                InstanceInfo::ProcessModule pmod;
                pmod.baseAddr = (u64)hMods[mi];

                MODULEINFO modInfo = {};
                if (GetModuleInformation(inst->hProcess, hMods[mi], &modInfo, sizeof(modInfo))) {
                    pmod.moduleSize = modInfo.SizeOfImage;
                }

                wchar_t modPath[MAX_PATH] = { 0 };
                if (GetModuleFileNameExW(inst->hProcess, hMods[mi], modPath, MAX_PATH)) {
                    pmod.modulePath = modPath;
                    std::wstring wfn = modPath;
                    size_t lslash = wfn.find_last_of(L"\\/");
                    if (lslash != std::wstring::npos) wfn = wfn.substr(lslash + 1);
                    for (wchar_t wc : wfn) pmod.moduleName += (wc < 128) ? (char)wc : '?';
                }

                ParseModuleImports(inst->hProcess, pmod, inst->is64bit);
                inst->processModules.push_back(std::move(pmod));
            }
            inst->processModulesEnumerated = true;
        }

        return true;
    }

    // === Diðer mevcut fonksiyonlar ===
    bool RemoveInstance(const std::string& id) {
        for (auto it = m_instances.begin(); it != m_instances.end(); ++it) {
            if ((*it)->id == id) {
                if (OnInstanceRemoved) OnInstanceRemoved(id);
                m_instances.erase(it);

                if (m_activeId == id) {
                    m_activeId = m_instances.empty() ? "" : m_instances.back()->id;
                    if (OnActiveInstanceChanged) OnActiveInstanceChanged(m_activeId);
                }
                return true;
            }
        }
        return false;
    }

    void RemoveLastInstance() {
        if (!m_instances.empty()) {
            std::string id = m_instances.back()->id;
            RemoveInstance(id);
        }
    }

    InstanceInfo* GetInstance(const std::string& id) {
        for (auto& inst : m_instances) {
            if (inst->id == id) return inst.get();
        }
        return nullptr;
    }

    InstanceInfo* GetActiveInstance() {
        return GetInstance(m_activeId);
    }

    InstanceInfo* GetFirstInstance() {
        return m_instances.empty() ? nullptr : m_instances[0].get();
    }

    std::vector<std::string> GetInstanceIds() const {
        std::vector<std::string> ids;
        for (auto& inst : m_instances) ids.push_back(inst->id);
        return ids;
    }

    std::vector<InstanceInfo*> GetAllInstances() {
        std::vector<InstanceInfo*> result;
        for (auto& inst : m_instances) result.push_back(inst.get());
        return result;
    }

    size_t GetInstanceCount() const { return m_instances.size(); }

    void SetActiveInstance(const std::string& id) {
        if (GetInstance(id)) {
            m_activeId = id;
            if (OnActiveInstanceChanged) OnActiveInstanceChanged(id);
        }
    }

    std::string GetActiveInstanceId() const { return m_activeId; }

    // === Save - Sadece File instance için ===
    bool SaveInstance(const std::string& id, const wchar_t* path) {
        InstanceInfo* inst = GetInstance(id);
        if (!inst || !inst->loaded) return false;

        // Process için save desteklenmiyor
        if (inst->type == InstanceType::Process) {
            return false;
        }

        return inst->pe.Save(path, inst->mem.data.data(), inst->mem.base, inst->mem.data.size());
    }

    bool CanSaveInstance(const std::string& id) {
        InstanceInfo* inst = GetInstance(id);
        if (!inst || !inst->loaded) return false;
        return inst->type == InstanceType::File;
    }

    std::string GetDisplayName(const std::string& id) {
        InstanceInfo* inst = GetInstance(id);
        if (!inst) return id;
        return inst->name;
    }

    std::string GetShortName(const std::string& id) {
        InstanceInfo* inst = GetInstance(id);
        if (!inst) return id;
        return inst->shortName;
    }

    // === Callbacks ===
    std::function<void(const std::string&)> OnInstanceCreated;
    std::function<void(const std::string&)> OnInstanceRemoved;
    std::function<void(const std::string&)> OnActiveInstanceChanged;

    // === Session Save/Load ===
    void SaveSession(std::ofstream& f) {
        f << "\n[Instances]\n";
        f << "count=" << m_instances.size() << "\n";
        f << "active=" << m_activeId << "\n";
        f << "nextId=" << m_nextId << "\n";

        for (size_t i = 0; i < m_instances.size(); i++) {
            auto& inst = m_instances[i];
            std::string prefix = "inst" + std::to_string(i) + "_";
            f << prefix << "id=" << inst->id << "\n";
            f << prefix << "type=" << (int)inst->type << "\n";
            f << prefix << "name=" << inst->name << "\n";

            if (inst->type == InstanceType::File) {
                std::string pathStr;
                for (wchar_t wc : inst->filePath) {
                    if (wc < 128) pathStr += (char)wc;
                    else pathStr += '?';
                }
                f << prefix << "path=" << pathStr << "\n";
            }
            else {
                f << prefix << "pid=" << inst->pid << "\n";
            }

            f << prefix << "viewAddr=" << inst->viewAddr << "\n";
            f << prefix << "selAddr=" << inst->selAddr << "\n";
            f << prefix << "hexAddr=" << inst->hexAddr << "\n";
        }
    }

    void LoadSession(std::map<std::string, std::string>& cfg) {
        try {
            if (!cfg.count("count")) return;

            int count = std::stoi(cfg["count"]);
            if (cfg.count("nextId")) m_nextId = std::stoi(cfg["nextId"]);

            for (int i = 0; i < count; i++) {
                std::string prefix = "inst" + std::to_string(i) + "_";

                if (!cfg.count(prefix + "id")) continue;

                std::string id = cfg[prefix + "id"];
                int type = cfg.count(prefix + "type") ? std::stoi(cfg[prefix + "type"]) : 0;

                if (type == 0 && cfg.count(prefix + "path")) {
                    std::string pathStr = cfg[prefix + "path"];
                    std::wstring path;
                    for (char c : pathStr) path += (wchar_t)c;

                    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
                        std::string newId = CreateFileInstance(path);
                        if (!newId.empty()) {
                            InstanceInfo* inst = GetInstance(newId);
                            if (inst) {
                                inst->id = id;
                                if (cfg.count(prefix + "viewAddr")) inst->viewAddr = std::stoull(cfg[prefix + "viewAddr"]);
                                if (cfg.count(prefix + "selAddr")) inst->selAddr = std::stoull(cfg[prefix + "selAddr"]);
                                if (cfg.count(prefix + "hexAddr")) inst->hexAddr = std::stoull(cfg[prefix + "hexAddr"]);
                            }
                        }
                    }
                }
                // Process session restore - PID deðiþmiþ olabilir, restore etme
            }

            if (cfg.count("active")) {
                std::string activeId = cfg["active"];
                if (GetInstance(activeId)) m_activeId = activeId;
            }
        }
        catch (...) {}
    }

    void Clear() {
        m_instances.clear();
        m_activeId.clear();
        m_nextId = 1;
    }

private:
    InstanceManager() = default;

    std::vector<std::unique_ptr<InstanceInfo>> m_instances;
    std::string m_activeId;
    int m_nextId = 1;

    std::string GenerateId() {
        char buf[16];
        sprintf(buf, "i%d", m_nextId++);
        return buf;
    }

    void ParseModuleImports(HANDLE hProc, InstanceInfo::ProcessModule& pmod, bool is64) {
        if (!pmod.baseAddr || !pmod.moduleSize) return;

        std::vector<u8> headerBuf(0x1000, 0);
        SIZE_T bytesRead = 0;

        if (!ReadProcessMemory(hProc, (LPCVOID)pmod.baseAddr, headerBuf.data(), 0x1000, &bytesRead) || bytesRead < 64) {
            return;
        }

        auto dos = (PIMAGE_DOS_HEADER)headerBuf.data();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

        auto nt = (PIMAGE_NT_HEADERS)(headerBuf.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;

        u32 impRva = 0, impSize = 0;

        if (is64) {
            auto n64 = (PIMAGE_NT_HEADERS64)nt;
            impRva = n64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            impSize = n64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }
        else {
            auto n32 = (PIMAGE_NT_HEADERS32)nt;
            impRva = n32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            impSize = n32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        }

        if (!impRva || !impSize) return;

        std::vector<u8> impBuf(impSize + 256, 0);
        SIZE_T impRead = 0;
        u64 impAddr = pmod.baseAddr + impRva;

        if (!ReadProcessMemory(hProc, (LPCVOID)impAddr, impBuf.data(), impSize + 256, &impRead)) {
            return;
        }

        auto desc = (PIMAGE_IMPORT_DESCRIPTOR)impBuf.data();

        while (desc->Name && (u8*)desc < impBuf.data() + impBuf.size() - sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
            u64 nameAddr = pmod.baseAddr + desc->Name;
            char dllNameBuf[256] = { 0 };
            ReadProcessMemory(hProc, (LPCVOID)nameAddr, dllNameBuf, 255, nullptr);

            ImpDll dll;
            dll.name = dllNameBuf;

            u32 thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            u64 thunkAddr = pmod.baseAddr + thunkRva;
            u64 iatRva = desc->FirstThunk;
            u64 iatEntryAddr = pmod.baseAddr + iatRva;

            std::vector<u8> thunkBuf(0x1000, 0);
            SIZE_T thunkRead = 0;
            ReadProcessMemory(hProc, (LPCVOID)thunkAddr, thunkBuf.data(), 0x1000, &thunkRead);

            u8* tp = thunkBuf.data();
            u8* tpEnd = thunkBuf.data() + thunkRead;

            while (tp < tpEnd) {
                ImpFunc func;
                func.iatAddr = iatEntryAddr;

                if (is64) {
                    auto th64 = (PIMAGE_THUNK_DATA64)tp;
                    if (!th64->u1.AddressOfData) break;

                    if (IMAGE_SNAP_BY_ORDINAL64(th64->u1.Ordinal)) {
                        func.ord = (u16)IMAGE_ORDINAL64(th64->u1.Ordinal);
                        func.name = "Ord_" + std::to_string(func.ord);
                    }
                    else {
                        u64 hintAddr = pmod.baseAddr + (u32)th64->u1.AddressOfData;
                        u8 hintBuf[256] = { 0 };
                        SIZE_T hintRead = 0;
                        if (ReadProcessMemory(hProc, (LPCVOID)hintAddr, hintBuf, 255, &hintRead) && hintRead > 2) {
                            func.name = (char*)(hintBuf + 2);
                        }
                        else {
                            func.name = "func_" + std::to_string((u32)th64->u1.AddressOfData);
                        }
                    }
                    tp += 8;
                    iatEntryAddr += 8;
                }
                else {
                    auto th32 = (PIMAGE_THUNK_DATA32)tp;
                    if (!th32->u1.AddressOfData) break;

                    if (IMAGE_SNAP_BY_ORDINAL32(th32->u1.Ordinal)) {
                        func.ord = (u16)IMAGE_ORDINAL32(th32->u1.Ordinal);
                        func.name = "Ord_" + std::to_string(func.ord);
                    }
                    else {
                        u64 hintAddr = pmod.baseAddr + th32->u1.AddressOfData;
                        u8 hintBuf[256] = { 0 };
                        SIZE_T hintRead = 0;
                        if (ReadProcessMemory(hProc, (LPCVOID)hintAddr, hintBuf, 255, &hintRead) && hintRead > 2) {
                            func.name = (char*)(hintBuf + 2);
                        }
                        else {
                            func.name = "func_" + std::to_string(th32->u1.AddressOfData);
                        }
                    }
                    tp += 4;
                    iatEntryAddr += 4;
                }

                if (!func.name.empty()) {
                    dll.funcs.push_back(func);
                }
            }

            if (!dll.funcs.empty()) {
                pmod.imports.push_back(dll);
            }

            desc++;
        }
    }

    void BuildProcessSymbols(InstanceInfo* inst) {
        inst->syms.addr2name.clear();
        inst->syms.name2addr.clear();

        for (auto& mod : inst->processModules) {
            for (auto& imp : mod.imports) {
                for (auto& func : imp.funcs) {
                    std::string fullName = imp.name + "." + func.name;
                    inst->syms.addr2name[func.iatAddr] = fullName;
                    inst->syms.name2addr[fullName] = func.iatAddr;

                    // Kýsa isim de ekle
                    std::string shortDll = imp.name;
                    size_t dot = shortDll.find_last_of('.');
                    if (dot != std::string::npos) shortDll = shortDll.substr(0, dot);
                    std::string shortName = shortDll + "." + func.name;
                    inst->syms.name2addr[shortName] = func.iatAddr;
                    inst->syms.name2addr[func.name] = func.iatAddr;
                }
            }
        }
    }

    void SetupAssemblerCallbacks(InstanceInfo* inst) {
        inst->asmb.symbolLookup = [inst](const std::string& n)->u64 {
            return inst->syms.Lookup(n);
        };

        inst->asmb.iatLookup = [inst](const std::string& n)->u64 {
            std::string ln = n;
            for (auto& c : ln) c = tolower(c);
            for (auto& d : inst->pe.imps) {
                std::string dl = d.name;
                for (auto& c : dl) c = tolower(c);
                std::string dn = dl;
                if (dn.size() > 4 && dn.substr(dn.size() - 4) == ".dll")
                    dn = dn.substr(0, dn.size() - 4);
                for (auto& f : d.funcs) {
                    std::string fl = f.name;
                    for (auto& c : fl) c = tolower(c);
                    if (fl == ln || dn + "." + fl == ln || dl + "." + fl == ln)
                        return f.iatAddr;
                }
            }
            return 0;
        };

        inst->asmb.readMemory = [inst](u64 a)->u64 {
            if (inst->type == InstanceType::Process && inst->hProcess) {
                u64 val = 0;
                inst->ReadFromProcess(a, (u8*)&val, inst->is64bit ? 8 : 4);
                return val;
            }
            return inst->mem.InRange(a) ?
                (inst->pe.is64 ? inst->mem.Read64(a) : inst->mem.Read32(a)) : 0;
        };

        inst->asmb.addRelocation = [inst](u64 a, u16 t) {
            if (inst->type == InstanceType::File) {
                if (a >= inst->mem.base && a < inst->mem.base + inst->mem.data.size())
                    inst->pe.AddRelocation((u32)(a - inst->mem.base), t);
            }
        };

        inst->asmb.allocateString = [inst](const std::string& c)->u64 {
            if (inst->type == InstanceType::File) {
                return inst->stringStorage.AllocateString(inst->pe, inst->mem, c);
            }
            return 0; // Process için string allocation desteklenmiyor
        };
    }
};

#define InstMgr InstanceManager::I()