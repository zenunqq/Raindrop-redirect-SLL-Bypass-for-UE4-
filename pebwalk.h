#pragma once
#include "pch.h"
#include "xstr.h"

namespace Raindrop {
namespace PebWalk {

using FnLoadLibraryA    = HMODULE (WINAPI*)(const char*);
using FnGetCommandLineW = LPWSTR  (WINAPI*)();
using FnCreateThread    = HANDLE  (WINAPI*)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                            LPTHREAD_START_ROUTINE, LPVOID,
                                            DWORD, LPDWORD);
using FnAllocConsole    = BOOL    (WINAPI*)();

static FnLoadLibraryA    pLoadLibraryA    = nullptr;
static FnGetCommandLineW pGetCommandLineW = nullptr;
static FnCreateThread    pCreateThread    = nullptr;
static FnAllocConsole    pAllocConsole    = nullptr;

static constexpr uint32_t kFnvBasis = 0x811C9DC5u;
static constexpr uint32_t kFnvPrime = 0x01000193u;

inline uint32_t HashA(const char* s) {
    uint32_t h = kFnvBasis;
    for (; *s; s++) {
        char c = (*s >= 'A' && *s <= 'Z') ? (*s | 0x20) : *s;
        h = (h ^ static_cast<uint8_t>(c)) * kFnvPrime;
    }
    return h;
}

inline uint32_t HashW(const wchar_t* s) {
    uint32_t h = kFnvBasis;
    for (; *s; s++) {
        wchar_t c = (*s >= L'A' && *s <= L'Z') ? (*s | 0x20) : *s;
        h = (h ^ static_cast<uint8_t>(c & 0xFF))  * kFnvPrime;
        h = (h ^ static_cast<uint8_t>(c >> 8))    * kFnvPrime;
    }
    return h;
}

static constexpr uint32_t kHashKernel32      = 0x6DDB9555u;
static constexpr uint32_t kH_LoadLibraryA    = 0x5FBFF0FBu;
static constexpr uint32_t kH_GetCommandLineW = 0x29FEFB15u;
static constexpr uint32_t kH_CreateThread    = 0x599B5B4Bu;
static constexpr uint32_t kH_AllocConsole    = 0x1C2B3A47u;

inline uint32_t PeStructChecksum(void* mod) {
    auto base = reinterpret_cast<uint8_t*>(mod);
    auto dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    uint32_t lfanew = static_cast<uint32_t>(dos->e_lfanew);
    if (lfanew > 0x1000) return 0;

    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    uint32_t h = kFnvBasis;
    
    h = (h ^ static_cast<uint8_t>(nt->FileHeader.NumberOfSections & 0xFF))  * kFnvPrime;
    h = (h ^ static_cast<uint8_t>(nt->FileHeader.NumberOfSections >> 8))    * kFnvPrime;
    uint32_t soc = nt->OptionalHeader.SizeOfCode;
    for (int i = 0; i < 4; i++)
        h = (h ^ static_cast<uint8_t>((soc >> (8*i)) & 0xFF)) * kFnvPrime;

    if (nt->FileHeader.NumberOfSections > 0) {
        auto sec = IMAGE_FIRST_SECTION(nt);
        uint32_t va = sec->VirtualAddress;
        for (int i = 0; i < 4; i++)
            h = (h ^ static_cast<uint8_t>((va >> (8*i)) & 0xFF)) * kFnvPrime;
    }
    return h;
}

inline void* GetPeb() {
    void* teb = reinterpret_cast<void*>(__readgsqword(0x30));
    return *reinterpret_cast<void**>(static_cast<uint8_t*>(teb) + 0x60);
}

inline void* FindModuleByHash(uint32_t targetHash, uint32_t requiredChecksum = 0) {
    auto peb  = static_cast<uint8_t*>(GetPeb());
    auto ldr  = *reinterpret_cast<uint8_t**>(peb + 0x18);
    auto head = reinterpret_cast<LIST_ENTRY*>(ldr + 0x20);
    auto cur  = head->Flink;

    while (cur != head) {
        auto dte     = reinterpret_cast<uint8_t*>(cur) - 0x10;
        void* dll    = *reinterpret_cast<void**>(dte + 0x30);
        auto nameStr = *reinterpret_cast<wchar_t**>(dte + 0x58);

        if (nameStr && HashW(nameStr) == targetHash) {
            
            if (requiredChecksum != 0) {
                uint32_t actual = PeStructChecksum(dll);
                if (actual != requiredChecksum) {
                    cur = cur->Flink;
                    continue;
                }
            }
            return dll;
        }
        cur = cur->Flink;
    }
    return nullptr;
}

inline void* GetExportByHash(void* mod, uint32_t nameHash) {
    auto base = reinterpret_cast<uint8_t*>(mod);
    auto dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt   = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto  exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);

    auto names    = reinterpret_cast<uint32_t*>(base + exp->AddressOfNames);
    auto ordinals = reinterpret_cast<uint16_t*>(base + exp->AddressOfNameOrdinals);
    auto funcs    = reinterpret_cast<uint32_t*>(base + exp->AddressOfFunctions);

    for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
        const char* ename = reinterpret_cast<const char*>(base + names[i]);
        if (HashA(ename) == nameHash)
            return base + funcs[ordinals[i]];
    }
    return nullptr;
}

inline bool Init() {
    void* k32 = FindModuleByHash(kHashKernel32);
    if (!k32) return false;

    pLoadLibraryA    = reinterpret_cast<FnLoadLibraryA>   (GetExportByHash(k32, kH_LoadLibraryA));
    pGetCommandLineW = reinterpret_cast<FnGetCommandLineW>(GetExportByHash(k32, kH_GetCommandLineW));
    pCreateThread    = reinterpret_cast<FnCreateThread>   (GetExportByHash(k32, kH_CreateThread));
    pAllocConsole    = reinterpret_cast<FnAllocConsole>   (GetExportByHash(k32, kH_AllocConsole));

    return pLoadLibraryA && pGetCommandLineW && pCreateThread;
}

} 
}
