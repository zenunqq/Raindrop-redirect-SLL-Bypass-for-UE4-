#pragma once
#include "pch.h"

namespace Raindrop {
namespace Locate {

struct Sig {
    uint8_t Val;
    bool    Any;
    constexpr Sig(uint8_t v) : Val(v), Any(false) {}
    constexpr bool Hit(uint8_t b) const { return Any || b == Val; }
};

inline constexpr Sig Wild() { Sig s(0); s.Any = true; return s; }
#define RD_WC Raindrop::Locate::Wild()

static constexpr uint32_t kFnvBasis = 0x811C9DC5u;
static constexpr uint32_t kFnvPrime = 0x01000193u;

inline uint32_t FnvByte(uint32_t h, uint8_t b) {
    return (h ^ b) * kFnvPrime;
}

struct BloomFilter {
    uint64_t W[4] = {};

    void Insert(uint8_t b) {
        uint32_t h = FnvByte(kFnvBasis, b);
        for (int i = 0; i < 4; i++) {
            uint32_t bit = (FnvByte(h, static_cast<uint8_t>(i))) & 255u;
            W[bit >> 6] |= 1ull << (bit & 63u);
            h = FnvByte(h, b ^ static_cast<uint8_t>(i + 1));
        }
    }

    bool MayContain(uint8_t b) const {
        uint32_t h = FnvByte(kFnvBasis, b);
        for (int i = 0; i < 4; i++) {
            uint32_t bit = (FnvByte(h, static_cast<uint8_t>(i))) & 255u;
            if (!(W[bit >> 6] & (1ull << (bit & 63u)))) return false;
            h = FnvByte(h, b ^ static_cast<uint8_t>(i + 1));
        }
        return true;
    }

    static BloomFilter Build(const Sig* pat, size_t patLen) {
        BloomFilter f;
        for (size_t i = 0; i < patLen; i++)
            if (!pat[i].Any) f.Insert(pat[i].Val);
        return f;
    }
};

inline uint8_t* FindLast(void* base, size_t size, const Sig* pat, size_t patLen) {
    if (patLen == 0 || size < patLen) return nullptr;
    auto mem = reinterpret_cast<uint8_t*>(base);

    
    BloomFilter bf = BloomFilter::Build(pat, patLen);

    for (size_t i = size - patLen; ; i--) {
        
        if (!pat[0].Any && !bf.MayContain(mem[i])) {
            if (i == 0) break;
            i--;
            
            while (i > 0 && !pat[0].Any && !bf.MayContain(mem[i])) i--;
        }
        bool hit = true;
        for (size_t j = 0; j < patLen; j++) {
            if (!pat[j].Hit(mem[i + j])) { hit = false; break; }
        }
        if (hit) return mem + i;
        if (i == 0) break;
    }
    return nullptr;
}

template<typename Cb>
inline void FindEach(void* base, size_t size, const Sig* pat, size_t patLen, Cb cb) {
    if (patLen == 0 || size < patLen) return;
    auto   mem = reinterpret_cast<uint8_t*>(base);
    BloomFilter bf = BloomFilter::Build(pat, patLen);
    size_t i = 0;
    while (i + patLen <= size) {
        if (!pat[0].Any && !bf.MayContain(mem[i])) { i++; continue; }
        bool hit = true;
        for (size_t j = 0; j < patLen; j++) {
            if (!pat[j].Hit(mem[i + j])) { hit = false; break; }
        }
        if (hit) {
            if (!cb(mem + i)) return;
            i += patLen;
        } else {
            i++;
        }
    }
}

inline uint8_t* FindFirst(void* base, size_t size, const Sig* pat, size_t patLen) {
    uint8_t* result = nullptr;
    FindEach(base, size, pat, patLen, [&](uint8_t* p) -> bool {
        result = p;
        return false;
    });
    return result;
}

inline void** LocatePointer(void* base, size_t size, void* needle) {
    auto     slots  = reinterpret_cast<uintptr_t*>(base);
    size_t   count  = size / sizeof(uintptr_t);
    uintptr_t target = reinterpret_cast<uintptr_t>(needle);

    for (size_t i = count; i-- > 0; ) {
        if (slots[i] == target)
            return reinterpret_cast<void**>(&slots[i]);
    }
    return nullptr;
}

inline void** LocateAnyPointer(void* base, size_t size,
                                void* const* needles, size_t needleCount) {
    auto     slots  = reinterpret_cast<uintptr_t*>(base);
    size_t   count  = size / sizeof(uintptr_t);

    for (size_t i = count; i-- > 0; ) {
        for (size_t n = 0; n < needleCount; n++) {
            if (slots[i] == reinterpret_cast<uintptr_t>(needles[n]))
                return reinterpret_cast<void**>(&slots[i]);
        }
    }
    return nullptr;
}

inline void* RipResolve(void* instr, int dispOff = 3, int instrLen = 7) {
    auto ip = reinterpret_cast<uint8_t*>(instr);
    int32_t disp;
    memcpy(&disp, ip + dispOff, 4);
    return ip + instrLen + disp;
}

inline void* BacktrackPrologue(void* hit, size_t radius = 2048) {
    auto p = reinterpret_cast<uint8_t*>(hit);

    for (size_t i = 0; i < radius; i++) {
        uint8_t* c = p - i;

        
        if (c[0] == 0x4C && c[1] == 0x8B && c[2] == 0xDC) return c;

        
        if (c[0] == 0x48 && c[1] == 0x8B && c[2] == 0xC4) return c;

        
        if (c[0] == 0x48 && c[1] == 0x89 && c[2] == 0x5C && c[3] == 0x24) return c;

        
        if (c[0] == 0x48 && c[1] == 0x89 && c[2] == 0x74 && c[3] == 0x24) return c;

        
        if (c[0] == 0x48 && c[1] == 0x89 && c[2] == 0x7C && c[3] == 0x24) return c;

        
        if (c[0] == 0x53 && i > 0 &&
            (c[-1] == 0xCC || c[-1] == 0x90 || c[-1] == 0xC3)) return c;

        
        if (c[0] == 0x55 && i > 0 &&
            (c[-1] == 0xCC || c[-1] == 0x90 || c[-1] == 0xC3)) return c;

        
        if (c[0] == 0x57 && i > 0 && c[-1] == 0xCC) return c;

        
        if ((c[0] == 0x48 && c[1] == 0x81 && c[2] == 0xEC) ||
            (c[0] == 0x48 && c[1] == 0x83 && c[2] == 0xEC)) {
            for (size_t x = 1; x < 64 && x <= i; x++) {
                uint8_t* c2 = c - x;
                if ((c2[0] == 0x4C && c2[1] == 0x8B && c2[2] == 0xDC) ||
                    (c2[0] == 0x48 && c2[1] == 0x8B && c2[2] == 0xC4) ||
                    (c2[0] == 0x48 && c2[1] == 0x89 && c2[2] == 0x5C) ||
                    (c2[0] == 0x48 && c2[1] == 0x89 && c2[2] == 0x74) ||
                    (c2[0] == 0x48 && c2[1] == 0x89 && c2[2] == 0x7C) ||
                     c2[0] == 0x40)
                    return c2;
            }
        }
    }
    return nullptr;
}

inline void EraseRtti(void* dataBase, size_t dataSz) {
    auto mem = reinterpret_cast<uint8_t*>(dataBase);
    
    static const uint8_t sigs[][4] = {
        { '.', '?', 'A', 'V' },
        { '.', '?', 'A', 'U' },
        { '.', '?', 'A', 'W' },
    };
    for (size_t i = 0; i + 8 <= dataSz; i++) {
        for (auto& sig : sigs) {
            if (mem[i]   == sig[0] && mem[i+1] == sig[1] &&
                mem[i+2] == sig[2] && mem[i+3] == sig[3]) {
                
                size_t lim = i + 128 < dataSz ? i + 128 : dataSz;
                for (size_t j = i; j < lim; j++) {
                    mem[j] = 0x00;
                    if (j > i && mem[j] == 0x00) break;
                }
                break;
            }
        }
    }
}

} 
}
