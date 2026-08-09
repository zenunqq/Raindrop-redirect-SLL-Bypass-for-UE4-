#pragma once
#include "url.h"
#include "config.h"

namespace Raindrop {
namespace Route {

static constexpr uint32_t kFnvBasis = 0x811C9DC5u;
static constexpr uint32_t kFnvPrime = 0x01000193u;

inline uint32_t HashW(const wchar_t* s) {
    uint32_t h = kFnvBasis;
    for (; *s; s++) {
        wchar_t c = (*s >= L'A' && *s <= L'Z') ? (*s | 0x20) : *s;
        h = (h ^ static_cast<uint8_t>(c & 0xFF))  * kFnvPrime;
        h = (h ^ static_cast<uint8_t>(c >> 8))    * kFnvPrime;
    }
    return h;
}

static const uint32_t kDomainHashes[] = {
    HashW(L"ol.epicgames.com"),
    HashW(L"ol.epicgames.net"),
    HashW(L"on.epicgames.com"),
    HashW(L"game-social.epicgames.com"),
    HashW(L"ak.epicgames.com"),
    HashW(L"epicgames.dev"),
};
static constexpr size_t kDomainCount = sizeof(kDomainHashes) / sizeof(kDomainHashes[0]);

static constexpr const wchar_t* kHybridPaths[] = {
    L"/fortnite/api/v2/versioncheck/",
    L"/fortnite/api/game/v2/profile/",
    L"/content/api/pages/",
    L"/affiliate/api/public/affiliates/slug",
    L"/socialban/api/public/v1",
    L"/fortnite/api/cloudstorage/system",
    L"/fortnite/api/matchmaking/session",
};
static constexpr size_t kHybridPathCount = sizeof(kHybridPaths) / sizeof(kHybridPaths[0]);

static constexpr const wchar_t* kDevPaths[] = {
    L"/fortnite/api/game/v2/profile/",
    L"/affiliate/api/public/affiliates/slug",
    L"/content/api/pages/",
};
static constexpr size_t kDevPathCount = sizeof(kDevPaths) / sizeof(kDevPaths[0]);

inline bool HostIsEpic(const FStr& host) {
    if (!host.Ptr) return false;
    const wchar_t* p = host.Ptr;
    size_t         n = host.CharLen();
    for (size_t start = 0; start <= n; start++) {
        if (start > 0 && host.Ptr[start - 1] != L'.') continue;
        uint32_t h = HashW(p + start);
        for (size_t d = 0; d < kDomainCount; d++) {
            if (kDomainHashes[d] == h) return true;
        }
    }
    return false;
}

inline bool ShouldForward(const Url& u) {
    switch (URLSet) {
    case All:
        return true;

    case Hybrid:
        for (size_t i = 0; i < kHybridPathCount; i++)
            if (u.Path.HasPrefix(kHybridPaths[i])) return true;
        return false;

    case Dev:
        for (size_t i = 0; i < kDevPathCount; i++)
            if (u.Path.HasPrefix(kDevPaths[i])) return true;
        return false;

    case Default:
    default:
        return HostIsEpic(u.Host);
    }
}

} 
}
