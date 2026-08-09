#pragma once
#include "pch.h"
#include "xstr.h"

namespace Raindrop {
namespace Image {

struct Region {
    void*  Base  = nullptr;
    size_t Bytes = 0;
    bool   Ok    = false;
};

inline Region FindSection(void* mod, const uint8_t* encBlob, size_t ct_len) {
    char sname[16] = {};
    XStr::NarrowInto(encBlob, ct_len, sname);

    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(mod);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { memset(sname,0,sizeof(sname)); return {}; }

    auto nt  = reinterpret_cast<IMAGE_NT_HEADERS64*>(
        reinterpret_cast<uint8_t*>(mod) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { memset(sname,0,sizeof(sname)); return {}; }

    auto sec   = IMAGE_FIRST_SECTION(nt);
    WORD count = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < count; i++, sec++) {
        if (strncmp(reinterpret_cast<const char*>(sec->Name),
                    sname, IMAGE_SIZEOF_SHORT_NAME) == 0) {
            void* va = reinterpret_cast<uint8_t*>(mod) + sec->VirtualAddress;
            memset(sname, 0, sizeof(sname));
            return { va, sec->Misc.VirtualSize, true };
        }
    }

    memset(sname, 0, sizeof(sname));
    return {};
}

} 
}
