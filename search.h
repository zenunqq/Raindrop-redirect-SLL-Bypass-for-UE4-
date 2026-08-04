#pragma once
#include "pch.h"
#include "xstr.h"
#include "locate.h"
#include "intercept.h"

// ---------------------------------------------------------------
// Anchor matching — uses AES-CTR decoded wide strings.
// Adjusted for new xstr.h layout: blob = IV(16) || CT(n).
// ---------------------------------------------------------------

namespace Raindrop {
namespace Search {

struct Corpus {
    void*  CodeBase;   size_t CodeSz;
    void*  DataBase;   size_t DataSz;
    void*  EosCode;    size_t EosCodeSz;
    void*  EosData;    size_t EosDataSz;
    bool   HasEos;
};

static bool TargetIsAnchor(void* instr, void* dataBase, size_t dataSz) {
    void* target = Locate::RipResolve(instr, 3, 7);
    auto  t  = reinterpret_cast<uintptr_t>(target);
    auto  d0 = reinterpret_cast<uintptr_t>(dataBase);
    if (t < d0 || t >= d0 + dataSz) return false;

    auto candidate = reinterpret_cast<const wchar_t*>(target);

    {
        constexpr size_t ct = sizeof(kEnc_ANCHOR1) - 16;
        wchar_t buf[ct / 2 + 1] = {};
        XStr::WideInto(kEnc_ANCHOR1, ct, buf);
        bool hit = (wcscmp(candidate, buf) == 0);
        memset(buf, 0, sizeof(buf));
        if (hit) return true;
    }

    {
        constexpr size_t ct = sizeof(kEnc_ANCHOR2) - 16;
        wchar_t buf[ct / 2 + 1] = {};
        XStr::WideInto(kEnc_ANCHOR2, ct, buf);
        bool hit = (wcscmp(candidate, buf) == 0);
        memset(buf, 0, sizeof(buf));
        if (hit) return true;
    }

    return false;
}

static bool TryHook(void* codeHit, void* dataBase, size_t dataSz, bool isEos) {
    void* fn = Locate::BacktrackPrologue(codeHit);
    if (!fn) return false;

    void** slot = Locate::LocatePointer(dataBase, dataSz, fn);
    if (!slot) return false;

    if (isEos) Intercept::AttachEos(slot);
    else        Intercept::AttachGame(slot);

    return true;
}

static void Run(const Corpus& c) {
    {
        bool done = false;
        auto code = reinterpret_cast<uint8_t*>(c.CodeBase);
        size_t n  = c.CodeSz;
        for (size_t i = 0; i + 7 <= n && !done; i++) {
            uint8_t b0 = code[i];
            if ((b0 & 0xFB) == 0x48 && code[i + 1] == 0x8D)
                if (TargetIsAnchor(code + i, c.DataBase, c.DataSz))
                    done = TryHook(code + i, c.DataBase, c.DataSz, false);
        }
    }

    if (c.HasEos && c.EosCode && c.EosData) {
        bool done = false;
        auto code = reinterpret_cast<uint8_t*>(c.EosCode);
        size_t n  = c.EosCodeSz;
        for (size_t i = 0; i + 7 <= n && !done; i++) {
            uint8_t b0 = code[i];
            if ((b0 & 0xFB) == 0x48 && code[i + 1] == 0x8D)
                if (TargetIsAnchor(code + i, c.EosData, c.EosDataSz))
                    done = TryHook(code + i, c.EosData, c.EosDataSz, true);
        }
    }
}

} // namespace Search
} // namespace Raindrop
