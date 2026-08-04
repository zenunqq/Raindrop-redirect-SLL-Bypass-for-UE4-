#pragma once

// -----------------------------------------------
//  Raindrop - redirect layer for UE4 HTTP traffic
// -----------------------------------------------

// Routing mode — mirrors Starfall's URLSet enum names
// so configs are interchangeable between projects.
//
//   Default  - Epic/EOS host suffix match (ol.epicgames.com etc.)
//   Hybrid   - Specific API path prefixes only
//   Dev      - Minimal path set (profile + affiliate + content)
//   All      - Forward every request unconditionally
enum StarfallURLSet {
    Default,
    Hybrid,
    Dev,
    All,
};

// Active routing mode
constexpr StarfallURLSet URLSet = Default;

// Target backend URL
#define RD_ORIGIN L"http://127.0.0.1:3551"

// Parse origin from -origin=<url> on startup command line
#define RD_CMDLINE_ORIGIN 0

// Attach a debug console
#define RD_VERBOSE 0

// Skip DllMain thread, call entry directly (for manual map injection)
#define RD_DIRECT_ENTRY 0
