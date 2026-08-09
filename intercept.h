#pragma once
#include "pch.h"
#include "fstr.h"
#include "url.h"
#include "route.h"
#include "protect.h"
#include "config.h"

namespace Raindrop {
namespace Intercept {

struct CurlRequest {
    void** VT;
};

static wchar_t g_Destination[512] = RD_ORIGIN;

static uintptr_t g_Cookie         = 0;
static uintptr_t g_GameOrigXor    = 0;
static uintptr_t g_EosOrigXor     = 0;

static inline void  StoreOrig(uintptr_t& slot, void* fn) {
    slot = reinterpret_cast<uintptr_t>(fn) ^ g_Cookie;
}
static inline void* LoadOrig(uintptr_t slot) {
    return reinterpret_cast<void*>(slot ^ g_Cookie);
}

static int64_t g_SetUrlSlot = 0;
static void**  g_AnchorSlot = nullptr;

static void InitCookie() {
    uintptr_t stack_addr;
    
    __asm__ volatile("mov %%rsp, %0" : "=r"(stack_addr));
    uint32_t tsc_lo;
    __asm__ volatile("rdtsc" : "=a"(tsc_lo) : : "edx");
    g_Cookie = stack_addr ^ (static_cast<uintptr_t>(tsc_lo) << 32) ^ 0xDEADC0DE13370000ULL;
}

static void ResolveSetUrl(CurlRequest* req) {
    if (g_SetUrlSlot != 0) return;

    void* getUrlFn = req->VT[0];
    uint32_t urlOff = 0;
    for (int i = 0; i < 160; i++) {
        auto b = reinterpret_cast<uint8_t*>(getUrlFn) + i;
        if (b[0] == 0x48 && b[1] == 0x8D && b[2] == 0x91) {
            memcpy(&urlOff, b + 3, 4);
            break;
        }
    }

    if (urlOff == 0) { g_SetUrlSlot = 10; return; }

    int64_t limit = g_AnchorSlot
        ? (reinterpret_cast<int64_t>(g_AnchorSlot) -
           reinterpret_cast<int64_t>(req->VT)) / 8
        : 32;

    for (int64_t i = limit - 1; i >= 1; i--) {
        void* fn = req->VT[i];
        for (int j = 0; j < 0x40; j++) {
            auto b = reinterpret_cast<uint8_t*>(fn) + j;
            if (b[0] == 0x48 && b[1] == 0x81 && b[2] == 0xC1) {
                uint32_t addend;
                memcpy(&addend, b + 3, 4);
                if (addend == urlOff) { g_SetUrlSlot = i; return; }
            }
        }
    }

    g_SetUrlSlot = 10;
}

static FStr ReadUrl(CurlRequest* req) {
    FStr out{};
    reinterpret_cast<void(*)(CurlRequest*, FStr*)>(req->VT[0])(req, &out);
    return out;
}

static void WriteUrl(CurlRequest* req, FStr& url, bool forEos) {
    int64_t idx = forEos ? 10 : g_SetUrlSlot;
    reinterpret_cast<void(*)(CurlRequest*, FStr*)>(req->VT[idx])(req, &url);
}

static bool Forward(CurlRequest* req, uintptr_t origXor, bool isEos) {
    auto orig = reinterpret_cast<bool(*)(CurlRequest*)>(LoadOrig(origXor));

    ResolveSetUrl(req);

    FStr raw = ReadUrl(req);
    if (!raw.Ptr) return orig(req);

    Url u = Url::From(raw.Ptr);

    if (Route::ShouldForward(u)) {
        u.SwapOrigin(g_Destination);
        FStr rebuilt = u.Assemble();
        WriteUrl(req, rebuilt, isEos);
        rebuilt.Release();
    }

    u.DropAll();
    return orig(req);
}

static bool GameDetour(CurlRequest* req) { return Forward(req, g_GameOrigXor, false); }
static bool EosDetour (CurlRequest* req) { return Forward(req, g_EosOrigXor,  true ); }

static void AttachGame(void** slot) {
    if (g_Cookie == 0) InitCookie();
    g_AnchorSlot = slot;
    void* prev = nullptr;
    Protect::SwapSlot(slot, GameDetour, &prev);
    StoreOrig(g_GameOrigXor, prev);
}

static void AttachEos(void** slot) {
    if (g_Cookie == 0) InitCookie();
    void* prev = nullptr;
    Protect::SwapSlot(slot, EosDetour, &prev);
    StoreOrig(g_EosOrigXor, prev);
}

} 
}
