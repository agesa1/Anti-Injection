#pragma once
#include <windows.h>
#include <psapi.h>
#include <winternl.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cstring>
#include <thread>
#include <chrono>
#include <memory>
#include <atomic>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <random>
#include <TlHelp32.h>
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

namespace AdvancedIntegrityCheck {
    std::atomic<bool> monitoring_active{ false };
    std::atomic<bool> threat_detected{ false };

    // Random intervals 
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(50, 200);

    struct MemoryRegion {
        uintptr_t start;
        size_t size;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        std::string name;
        DWORD protection;
    };

    struct APIHookInfo {
        const char* module;
        const char* function;
        BYTE originalBytes[16];
        FARPROC address;
        bool initialized;
    };

    std::vector<MemoryRegion> protected_regions;
    std::vector<APIHookInfo> monitored_apis;
    std::unordered_set<uintptr_t> legitimate_modules;
    std::unordered_map<uintptr_t, size_t> private_exec_regions;

    // Critical APIs to monitor for hooks 
    // WARNING! EDIT THIS PART FOR YOUR APPLICATION
    const char* critical_apis[][2] = {
        {"ntdll.dll", "NtCreateThread"},
        {"ntdll.dll", "NtCreateThreadEx"},
        {"ntdll.dll", "NtWriteVirtualMemory"},
        {"ntdll.dll", "NtProtectVirtualMemory"},
        {"ntdll.dll", "NtAllocateVirtualMemory"},
        {"ntdll.dll", "NtMapViewOfSection"},
        {"ntdll.dll", "NtUnmapViewOfSection"},
        {"ntdll.dll", "LdrLoadDll"},
        {"kernel32.dll", "CreateThread"},
        {"kernel32.dll", "WriteProcessMemory"},
        {"kernel32.dll", "VirtualProtect"},
        {"kernel32.dll", "VirtualAlloc"},
        {"kernel32.dll", "LoadLibraryA"},
        {"kernel32.dll", "LoadLibraryW"},
        {"kernel32.dll", "GetProcAddress"},
        {nullptr, nullptr}
    };

    inline bool GetModuleInfo(HMODULE hModule, uintptr_t& base, size_t& size) {
        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
            return false;
        }
        base = (uintptr_t)modInfo.lpBaseOfDll;
        size = modInfo.SizeOfImage;
        return true;
    }

    inline bool GetTextSegmentRange(HMODULE hModule, uintptr_t& start, size_t& size) {
        if (!hModule) hModule = GetModuleHandle(NULL);
        if (!hModule) return false;

        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

        auto section = IMAGE_FIRST_SECTION(ntHeaders);
        WORD numberOfSections = ntHeaders->FileHeader.NumberOfSections;

        for (WORD i = 0; i < numberOfSections; i++, section++) {
            if (strncmp((char*)section->Name, ".text", 5) == 0) {
                start = (uintptr_t)hModule + section->VirtualAddress;
                size = section->Misc.VirtualSize;
                return true;
            }
        }
        return false;
    }

    inline bool CalculateSHA256(const BYTE* data, size_t size, unsigned char* outHash) {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return false;

        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx_ptr(ctx, EVP_MD_CTX_free);

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) return false;
        if (EVP_DigestUpdate(ctx, data, size) != 1) return false;

        unsigned int hashLen = 0;
        if (EVP_DigestFinal_ex(ctx, outHash, &hashLen) != 1) return false;

        return hashLen == SHA256_DIGEST_LENGTH;
    }

    inline bool CompareHashes(const unsigned char* h1, const unsigned char* h2, size_t len) {
        return std::memcmp(h1, h2, len) == 0;
    }

    inline void InitializeAPIMonitoring() {
        monitored_apis.clear();

        for (int i = 0; critical_apis[i][0] != nullptr; i++) {
            HMODULE hMod = GetModuleHandleA(critical_apis[i][0]);
            if (!hMod) continue;

            FARPROC proc = GetProcAddress(hMod, critical_apis[i][1]);
            if (!proc) continue;

            APIHookInfo hookInfo = {};
            hookInfo.module = critical_apis[i][0];
            hookInfo.function = critical_apis[i][1];
            hookInfo.address = proc;
            hookInfo.initialized = false;

            __try {
                memcpy(hookInfo.originalBytes, proc, 16);
                hookInfo.initialized = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }

            monitored_apis.push_back(hookInfo);
        }
    }

    inline bool DetectAPIHooks() {
        for (auto& api : monitored_apis) {
            if (!api.initialized) continue;

            __try {
                BYTE currentBytes[16];
                memcpy(currentBytes, api.address, 16);

                if (memcmp(api.originalBytes, currentBytes, 16) != 0) {
                    return true; // Hook detected
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return true; 
            }
        }
        return false;
    }

    inline bool IsModuleInPEB(LPVOID baseAddress) {
        HMODULE hModules[1024];
        DWORD cbNeeded;

        if (!EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &cbNeeded)) {
            return false;
        }

        DWORD moduleCount = cbNeeded / sizeof(HMODULE);
        for (DWORD i = 0; i < moduleCount; i++) {
            if (hModules[i] == baseAddress) {
                return true;
            }
        }
        return false;
    }

    inline bool DetectManualMappedDLLs() {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t address = 0x10000; 

        while (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi))) {
            if ((mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
                mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {

                __try {
                    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(mbi.BaseAddress);
                    if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
                        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
                            (BYTE*)mbi.BaseAddress + dosHeader->e_lfanew);

                        if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                            if (!IsModuleInPEB(mbi.BaseAddress)) {
                                return true; 
                            }
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                }
            }

            address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            if (address < (uintptr_t)mbi.BaseAddress) break; 
        }
        return false;
    }

    inline bool CheckMemoryRegionsAdvanced() {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t address = 0;
        size_t totalPrivateExec = 0;
        int suspiciousRegions = 0;

        while (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi))) {
            if ((mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) &&
                mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {

                totalPrivateExec += mbi.RegionSize;
                suspiciousRegions++;

                if (totalPrivateExec > 100 * 1024 * 1024) { // 100MB threshold
                    return true;
                }

                if (suspiciousRegions > 50) { // Too many private exec regions
                    return true;
                }

                __try {
                    BYTE* mem = (BYTE*)mbi.BaseAddress;
                    size_t scanSize = min(mbi.RegionSize, 2048ULL);

                    for (size_t i = 0; i < scanSize - 8; i++) {
                        // Common shellcode patterns
                        // GetProcAddress hash resolution: mov esi, [fs:0x30]
                        if (mem[i] == 0x64 && mem[i + 1] == 0x8B && mem[i + 2] == 0x35 &&
                            mem[i + 3] == 0x30 && mem[i + 4] == 0x00 && mem[i + 5] == 0x00 && mem[i + 6] == 0x00) {
                            return true;
                        }

                        // Common API resolution pattern
                        if (mem[i] == 0x8B && mem[i + 1] == 0x45 && mem[i + 2] == 0x3C) {
                            return true;
                        }

                        // Suspicious jmp table
                        if (mem[i] == 0xFF && mem[i + 1] == 0x25) {
                            return true;
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                }
            }

            address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            if (address < (uintptr_t)mbi.BaseAddress) break;
        }

        return false;
    }

    inline bool DetectProcessHollowing() {
        HMODULE hMain = GetModuleHandle(NULL);
        if (!hMain) return false;

        // Get expected base address from PE header
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hMain);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE*)hMain + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

        uintptr_t expectedBase = ntHeaders->OptionalHeader.ImageBase;
        uintptr_t actualBase = (uintptr_t)hMain;

        if (expectedBase != actualBase) {
            // Additional checks for process hollowing
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(hMain, &mbi, sizeof(mbi))) {
                if (mbi.Type != MEM_IMAGE) {
                    return true; 
                }
            }
        }

        return false;
    }

   
    inline void AdvancedIntegrityMonitor() {
        HMODULE hModule = GetModuleHandle(NULL);
        uintptr_t textStart = 0;
        size_t textSize = 0;

        if (!GetTextSegmentRange(hModule, textStart, textSize)) {
            return;
        }

        MemoryRegion mainRegion;
        mainRegion.start = textStart;
        mainRegion.size = textSize;
        mainRegion.name = "Main .text";

        if (!CalculateSHA256((BYTE*)textStart, textSize, mainRegion.hash)) {
            return;
        }

        protected_regions.push_back(mainRegion);

        InitializeAPIMonitoring();

        monitoring_active = true;

        while (monitoring_active && !threat_detected) {
            // Code integrity check
            for (auto& region : protected_regions) {
                unsigned char currentHash[SHA256_DIGEST_LENGTH];

                if (CalculateSHA256((BYTE*)region.start, region.size, currentHash)) {
                    if (!CompareHashes(region.hash, currentHash, SHA256_DIGEST_LENGTH)) {
                        threat_detected = true;
                        break;
                    }
                }
            }

            if (threat_detected) break;

            if (DetectManualMappedDLLs()) {
                threat_detected = true;
                break;
            }

            if (DetectAPIHooks()) {
                threat_detected = true;
                break;
            }

            if (CheckMemoryRegionsAdvanced()) {
                threat_detected = true;
                break;
            }

            if (DetectProcessHollowing()) {
                threat_detected = true;
                break;
            }

            int wait_time = dis(gen);
            std::this_thread::sleep_for(std::chrono::milliseconds(wait_time));
        }

        if (threat_detected) {
            TerminateProcess(GetCurrentProcess(), 0xDEAD);
        }
    }

    inline void StartAdvancedMonitoring() {
        std::thread monitor_thread(AdvancedIntegrityMonitor);
        monitor_thread.detach();
    }

    inline void StopMonitoring() {
        monitoring_active = false;
    }

    inline void RunProtectedApplication() {
        StartAdvancedMonitoring();

        while (!threat_detected) {
            std::this_thread::sleep_for(std::chrono::seconds(1));

            static int counter = 0;
            counter++;
        }
    }

    inline bool PerformComprehensiveCheck() {
        InitializeAPIMonitoring();

        if (DetectManualMappedDLLs()) {
            return false;
        }

        if (DetectAPIHooks()) {
            return false;
        }

        if (CheckMemoryRegionsAdvanced()) {
            return false;
        }

        if (DetectProcessHollowing()) {
            return false;
        }

    }
}