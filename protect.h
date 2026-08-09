#pragma once
#include "pch.h"
#include "syscall.h"

namespace Raindrop {
namespace Protect {

template<typename Fn>
inline void WithWrite(void* addr, size_t sz, Fn fn) {
    ULONG prev = 0;
    Syscall::NtProtect(addr, sz, PAGE_EXECUTE_READWRITE, &prev);
    fn();
    Syscall::NtProtect(addr, sz, prev, &prev);
}

inline void PokeBytes(void* dst, const void* src, size_t n) {
    WithWrite(dst, n, [&] { memcpy(dst, src, n); });
}

template<typename T>
inline void PokeVal(void* dst, T val) {
    PokeBytes(dst, &val, sizeof(T));
}

inline void SwapSlot(void** slot, void* replacement, void** saved = nullptr) {
    WithWrite(slot, sizeof(void*), [&] {
        if (saved) *saved = *slot;
        *slot = replacement;
    });
}

template<typename Fn>
inline void SwapSlot(void** slot, Fn replacement, void** saved = nullptr) {
    SwapSlot(slot, reinterpret_cast<void*>(replacement), saved);
}

inline void GuardedWrite(void* dst, const void* src, size_t n) {
    ULONG prev = 0;
    Syscall::NtProtect(dst, n, PAGE_EXECUTE_READWRITE, &prev);
    memcpy(dst, src, n);
    Syscall::NtProtect(dst, n, PAGE_EXECUTE_READ, &prev);
}

} 
}
