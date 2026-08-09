#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwchar>

namespace Raindrop {

struct FStr {
    wchar_t* Ptr = nullptr;
    int32_t  Num = 0;
    int32_t  Cap = 0;

    static constexpr size_t kNone = static_cast<size_t>(-1);

    FStr() = default;

    explicit FStr(size_t reserve) {
        Cap  = static_cast<int32_t>(reserve + 1);
        Ptr  = static_cast<wchar_t*>(malloc(Cap * sizeof(wchar_t)));
        Num  = 1;
        if (Ptr) Ptr[0] = L'\0';
    }

    explicit FStr(const wchar_t* src) {
        if (!src) return;
        size_t len = wcslen(src);
        Num = Cap = static_cast<int32_t>(len + 1);
        Ptr = static_cast<wchar_t*>(malloc(Num * sizeof(wchar_t)));
        if (Ptr) memcpy(Ptr, src, Num * sizeof(wchar_t));
    }

    
    static FStr Borrow(wchar_t* raw) {
        FStr s;
        s.Ptr = raw;
        s.Num = raw ? static_cast<int32_t>(wcslen(raw) + 1) : 0;
        s.Cap = s.Num;
        return s;
    }

    void Release() {
        free(Ptr);
        Ptr = nullptr;
        Num = Cap = 0;
    }

    size_t CharLen() const {
        return Num > 0 ? static_cast<size_t>(Num - 1) : 0;
    }

    bool Empty() const { return CharLen() == 0; }

    
    FStr Slice(size_t off, size_t len = kNone) const {
        size_t total = CharLen();
        if (off >= total) return FStr{};
        size_t take = (len == kNone || off + len > total) ? total - off : len;
        FStr out;
        out.Num = out.Cap = static_cast<int32_t>(take + 1);
        out.Ptr = static_cast<wchar_t*>(malloc(out.Num * sizeof(wchar_t)));
        if (out.Ptr) {
            memcpy(out.Ptr, Ptr + off, take * sizeof(wchar_t));
            out.Ptr[take] = L'\0';
        }
        return out;
    }

    size_t IndexOf(wchar_t ch) const {
        for (size_t i = 0, n = CharLen(); i < n; i++)
            if (Ptr[i] == ch) return i;
        return kNone;
    }

    size_t IndexOf(const wchar_t* sub) const {
        if (!sub || !Ptr) return kNone;
        size_t slen = wcslen(sub);
        size_t n    = CharLen();
        for (size_t i = 0; i + slen <= n; i++)
            if (wcsncmp(Ptr + i, sub, slen) == 0) return i;
        return kNone;
    }

    bool HasPrefix(const wchar_t* pre) const {
        if (!pre || !Ptr) return false;
        size_t plen = wcslen(pre);
        return CharLen() >= plen && wcsncmp(Ptr, pre, plen) == 0;
    }

    bool HasSuffix(const wchar_t* suf) const {
        if (!suf || !Ptr) return false;
        size_t slen = wcslen(suf);
        size_t mylen = CharLen();
        return mylen >= slen && wcscmp(Ptr + mylen - slen, suf) == 0;
    }

    operator wchar_t*() const { return Ptr; }
};

}
