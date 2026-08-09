#pragma once
#include "fstr.h"

namespace Raindrop {

struct Url {
    FStr Proto;   
    FStr Glue;    
    FStr Host;    
    FStr PortStr; 
    FStr Path;    
    FStr Query;   

    
    
    
    static Url From(const wchar_t* raw) {
        Url u;
        if (!raw) return u;

        FStr full(raw);
        size_t colon = full.IndexOf(L':');
        if (colon == FStr::kNone) { full.Release(); return u; }

        
        u.Proto = full.Slice(0, colon);

        bool dbl = full.Ptr[colon + 1] == L'/' && full.Ptr[colon + 2] == L'/';
        size_t glueLen = dbl ? 3u : 1u;
        u.Glue = full.Slice(colon, glueLen);

        FStr after = full.Slice(colon + glueLen);
        full.Release();

        
        size_t slash = after.IndexOf(L'/');
        FStr authority = after.Slice(0, slash);
        FStr pathq     = (slash != FStr::kNone)
                         ? after.Slice(slash)
                         : FStr(L"");
        after.Release();

        size_t pcolon = authority.IndexOf(L':');
        u.Host    = authority.Slice(0, pcolon);
        if (pcolon != FStr::kNone)
            u.PortStr = authority.Slice(pcolon);
        authority.Release();

        size_t qmark = pathq.IndexOf(L'?');
        u.Path  = pathq.Slice(0, qmark);
        if (qmark != FStr::kNone)
            u.Query = pathq.Slice(qmark);
        pathq.Release();

        return u;
    }

    
    void SwapOrigin(const wchar_t* backend) {
        Url b = From(backend);
        Proto.Release();   Proto   = b.Proto;
        Glue.Release();    Glue    = b.Glue;
        Host.Release();    Host    = b.Host;
        PortStr.Release(); PortStr = b.PortStr;
        b.Path.Release();
        b.Query.Release();
    }

    
    FStr Assemble() const {
        size_t total = Proto.CharLen() + Glue.CharLen() + Host.CharLen()
                     + PortStr.CharLen() + Path.CharLen() + Query.CharLen();
        FStr out(total);
        if (!out.Ptr) return out;

        wchar_t* w = out.Ptr;
        auto Paste = [&](const FStr& f) {
            if (f.Ptr && f.CharLen()) {
                memcpy(w, f.Ptr, f.CharLen() * sizeof(wchar_t));
                w += f.CharLen();
            }
        };
        Paste(Proto); Paste(Glue); Paste(Host);
        Paste(PortStr); Paste(Path); Paste(Query);
        *w = L'\0';
        out.Num = static_cast<int32_t>(total + 1);
        return out;
    }

    void DropAll() {
        Proto.Release(); Glue.Release(); Host.Release();
        PortStr.Release(); Path.Release(); Query.Release();
    }
};

}
