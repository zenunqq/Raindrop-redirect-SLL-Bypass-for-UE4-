#pragma once

enum RaindropURLSet {
    Default,
    Hybrid,
    Dev,
    All,
};

constexpr RaindropfallURLSet URLSet = Default;

#define RD_ORIGIN L"http://127.0.0.1:3551"

#define RD_CMDLINE_ORIGIN 0

#define RD_VERBOSE 0

#define RD_DIRECT_ENTRY 0
