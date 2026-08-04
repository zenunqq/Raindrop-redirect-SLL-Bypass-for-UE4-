#pragma once
#include "pch.h"

// ---------------------------------------------------------------
// Direct syscall dispatch — zero imported symbols, no stack stubs.
//
// Trampoline page layout (heap-allocated, RX after init):
//
//   [0..N-1]   Variable-length NOP sled (length = g_SledLen, 0–15 bytes).
//              Sled length is derived from RDTSC at init time, so the
//              functional entry point lands at a different page offset
//              each process lifetime.  A scan for the mov r10,rcx
//              prologue at page offset 0 will not find it.
//
//   [N+0]  4C 8B D1           mov r10, rcx
//   [N+3]  B8 xx xx xx xx     mov eax, <ssn>
//   [N+8]  0F 05              syscall  (written as separate byte vars)
//   [N+10] C3                 ret
//
// g_Entry points into the page at [N], not at [0].
// ---------------------------------------------------------------

namespace Raindrop {
namespace Syscall {

static uint8_t* g_Page     = nullptr;   // base of heap allocation
static uint8_t* g_Entry    = nullptr;   // functional entry (page + sled)
static uint32_t g_SsnProtect = static_cast<uint32_t>(-1);
static uint8_t  g_SledLen  = 0;
static bool     g_Ready    = false;

// -----------------------------------------------
// TEB → PEB (gs:[0x30] = TEB self-pointer)
// -----------------------------------------------
inline void* ReadTeb() {
    return reinterpret_cast<void*>(__readgsqword(0x30));
}

inline void* TebToPeb(void* teb) {
    return *reinterpret_cast<void**>(static_cast<uint8_t*>(teb) + 0x60);
}

inline void* FindNtdll() {
    void* teb = ReadTeb();
    auto  peb = static_cast<uint8_t*>(TebToPeb(teb));
    auto  ldr = *reinterpret_cast<uint8_t**>(peb + 0x18);
    auto  head = reinterpret_cast<LIST_ENTRY*>(ldr + 0x20);
    auto  entry = head->Flink->Flink;
    auto  dte   = reinterpret_cast<uint8_t*>(entry) - 0x10;
    return *reinterpret_cast<void**>(dte + 0x30);
}

// FNV-1a
static constexpr uint32_t kFnvBasis = 0x811C9DC5u;
static constexpr uint32_t kFnvPrime = 0x01000193u;

inline uint32_t FnvStr(const char* s) {
    uint32_t h = kFnvBasis;
    for (; *s; ++s) h = (h ^ static_cast<uint8_t>(*s)) * kFnvPrime;
    return h;
}

static constexpr uint32_t kHash_NtProtect = 0x3B3B43E8u;

inline void* GetExportByHash(void* mod, uint32_t want) {
    auto base = static_cast<uint8_t*>(mod);
    auto dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt   = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto  exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);

    auto names    = reinterpret_cast<uint32_t*>(base + exp->AddressOfNames);
    auto ordinals = reinterpret_cast<uint16_t*>(base + exp->AddressOfNameOrdinals);
    auto funcs    = reinterpret_cast<uint32_t*>(base + exp->AddressOfFunctions);

    for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
        const char* ename = reinterpret_cast<const char*>(base + names[i]);
        if (FnvStr(ename) == want)
            return base + funcs[ordinals[i]];
    }
    return nullptr;
}

// -----------------------------------------------
// SSN resolution with Halo's Gate neighbor scan
// -----------------------------------------------
inline uint32_t SsnFromCleanStub(void* stub) {
    auto b = static_cast<uint8_t*>(stub);
    if (b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8) {
        uint32_t v; memcpy(&v, b + 4, 4); return v;
    }
    for (int i = 1; i < 32; i++) {
        if (b[i] == 0xB8 && b[i+2] == 0 && b[i+3] == 0 && b[i+4] == 0) {
            uint32_t v; memcpy(&v, b + i + 1, 4); return v;
        }
    }
    return static_cast<uint32_t>(-1);
}

inline uint32_t ResolveViaSortedNeighbor(void* ntdll, uint32_t targetHash) {
    auto base = static_cast<uint8_t*>(ntdll);
    auto dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    auto nt   = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto  exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);

    auto names    = reinterpret_cast<uint32_t*>(base + exp->AddressOfNames);
    auto ordinals = reinterpret_cast<uint16_t*>(base + exp->AddressOfNameOrdinals);
    auto funcs    = reinterpret_cast<uint32_t*>(base + exp->AddressOfFunctions);

    int32_t targetIdx = -1;
    for (uint32_t i = 0; i < exp->NumberOfNames; i++) {
        const char* en = reinterpret_cast<const char*>(base + names[i]);
        if (FnvStr(en) == targetHash) { targetIdx = static_cast<int32_t>(i); break; }
    }
    if (targetIdx < 0) return static_cast<uint32_t>(-1);

    {
        void* s = base + funcs[ordinals[targetIdx]];
        uint32_t ssn = SsnFromCleanStub(s);
        if (ssn != static_cast<uint32_t>(-1)) return ssn;
    }

    for (int32_t delta = 1; delta <= 8; delta++) {
        for (int32_t sign : {-1, 1}) {
            int32_t idx = targetIdx + sign * delta;
            if (idx < 0 || idx >= static_cast<int32_t>(exp->NumberOfNames)) continue;
            void* s = base + funcs[ordinals[idx]];
            uint32_t ssn = SsnFromCleanStub(s);
            if (ssn != static_cast<uint32_t>(-1))
                return static_cast<uint32_t>(static_cast<int32_t>(ssn) - sign * delta);
        }
    }
    return static_cast<uint32_t>(-1);
}

// -----------------------------------------------
// RDTSC-derived sled length (0–15).
// Mixes low bits of TSC with constant fold to
// produce different offsets per process lifetime.
// -----------------------------------------------
inline uint8_t DeriveSledLen() {
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    // XOR fold: mix lo and hi, take low nibble (0–15)
    uint32_t mixed = (lo ^ (hi << 13) ^ (lo >> 7));
    return static_cast<uint8_t>(mixed & 0x0F);
}

// -----------------------------------------------
// Build the trampoline page with randomized NOP sled.
// -----------------------------------------------
inline bool BuildTrampoline(void* ntdllStub, uint32_t ssn) {
    g_SledLen = DeriveSledLen();

    // HeapAlloc: less flagged than VirtualAlloc for small RX pages
    HANDLE heap  = GetProcessHeap();
    size_t total = 64 + static_cast<size_t>(g_SledLen);
    g_Page = static_cast<uint8_t*>(HeapAlloc(heap, HEAP_ZERO_MEMORY, total));
    if (!g_Page) return false;

    // Fill sled with 0x90 (NOP) — innocuous, commonly produced by compilers
    for (uint8_t i = 0; i < g_SledLen; i++)
        g_Page[i] = 0x90;

    // Functional entry follows the sled
    g_Entry = g_Page + g_SledLen;

    // mov r10, rcx
    g_Entry[0] = 0x4C;
    g_Entry[1] = 0x8B;
    g_Entry[2] = 0xD1;
    // mov eax, ssn
    g_Entry[3] = 0xB8;
    memcpy(g_Entry + 4, &ssn, 4);
    // syscall bytes — two isolated byte writes, never a pair in .text
    uint8_t sc_lo = 0x0F;
    uint8_t sc_hi = 0x05;
    g_Entry[8]  = sc_lo;
    g_Entry[9]  = sc_hi;
    // ret
    g_Entry[10] = 0xC3;

    // Bootstrap RX via raw ntdll stub (one call only, then abandoned)
    using RawFn = NTSTATUS(__fastcall*)(HANDLE, void**, SIZE_T*, ULONG, ULONG*);
    auto raw = reinterpret_cast<RawFn>(ntdllStub);

    void*  addr = g_Page;
    SIZE_T sz   = total;
    ULONG  prev = 0;
    NTSTATUS st = raw(reinterpret_cast<HANDLE>(-1), &addr, &sz, 0x20 /*PAGE_EXECUTE_READ*/, &prev);
    return st == 0;
}

// -----------------------------------------------
// One-time init
// -----------------------------------------------
inline bool EnsureReady() {
    if (g_Ready) return true;

    void* ntdll = FindNtdll();
    if (!ntdll) return false;

    g_SsnProtect = ResolveViaSortedNeighbor(ntdll, kHash_NtProtect);
    if (g_SsnProtect == static_cast<uint32_t>(-1)) return false;

    void* rawStub = GetExportByHash(ntdll, kHash_NtProtect);
    if (!rawStub) return false;

    if (!BuildTrampoline(rawStub, g_SsnProtect)) return false;

    g_Ready = true;
    return true;
}

// -----------------------------------------------
// Public API — replaces VirtualProtect
// Calls via g_Entry (post-sled), not g_Page base.
// -----------------------------------------------
inline NTSTATUS NtProtect(
    void*   base,
    size_t  size,
    ULONG   newProt,
    ULONG*  oldProt)
{
    if (!EnsureReady()) return static_cast<NTSTATUS>(-1);

    using Fn = NTSTATUS(__fastcall*)(HANDLE, void**, SIZE_T*, ULONG, ULONG*);
    auto fn = reinterpret_cast<Fn>(g_Entry);

    void*  addr = base;
    SIZE_T sz   = size;
    return fn(reinterpret_cast<HANDLE>(-1), &addr, &sz, newProt, oldProt);
}

} // namespace Syscall
} // namespace Raindrop
