#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwchar>

// ---------------------------------------------------------------
// Runtime string deobfuscation — AES-128-CTR replace for rolling XOR.
//
// Rolling XOR (key[i] = key[i-1] + C) is a tier-1 AV/BE heuristic:
// the incrementing-key pattern is directly fingerprinted in
// disassembly by both static engines and behavioral emulators.
//
// Replacement: AES-128-CTR using the x64 AES-NI instruction set.
// AES-NI is used legitimately by every TLS stack on the machine;
// its presence is not an IOC.  We require AES-NI (guaranteed on
// any BE-protected game platform shipped since ~2014).
//
// Layout:
//   Each encoded blob is:  IV (16 bytes) || ciphertext
//   Key is a 128-bit compile-time constant embedded as four
//   separate uint32_t words (no contiguous 16-byte key block
//   in .rdata).
//
// CTR mode:   keystream[i] = AES_ENC(key, IV ^ counter(i))
//             plaintext[i] = ciphertext[i] ^ keystream[i]
//
// Decoded buffers are stack-allocated and zeroed after use.
// ---------------------------------------------------------------

#include <wmmintrin.h>   // _mm_aesenc_si128, _mm_aesenclast_si128
#include <emmintrin.h>   // __m128i

namespace Raindrop {
namespace XStr {

// -----------------------------------------------
// AES-128 key schedule (10 rounds).
// Key is four separate words — no 16-byte literal.
// -----------------------------------------------
static constexpr uint32_t kK0 = 0xDEAD9173u;
static constexpr uint32_t kK1 = 0x4F2C81A0u;
static constexpr uint32_t kK2 = 0xB35E0CF7u;
static constexpr uint32_t kK3 = 0x920A6B4Eu;

// AES-128 key expansion helper (single round)
inline __m128i KeyExpand(__m128i key, __m128i kg) {
    kg = _mm_shuffle_epi32(kg, 0xFF);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, kg);
}

// Expand the 128-bit key into 11 round keys
inline void ExpandKey(__m128i rk[11]) {
    // Assemble key from four separate words — avoids contiguous key in .rdata
    alignas(16) uint32_t kw[4] = { kK0, kK1, kK2, kK3 };
    rk[0] = _mm_loadu_si128(reinterpret_cast<const __m128i*>(kw));
    memset(kw, 0, sizeof(kw));

    #define RD(i, rc) rk[i] = KeyExpand(rk[i-1], _mm_aeskeygenassist_si128(rk[i-1], rc))
    RD(1,  0x01); RD(2,  0x02); RD(3,  0x04); RD(4,  0x08);
    RD(5,  0x10); RD(6,  0x20); RD(7,  0x40); RD(8,  0x80);
    RD(9,  0x1B); RD(10, 0x36);
    #undef RD
}

// Encrypt one 128-bit block (CTR keystream generation)
inline __m128i AesEncBlock(__m128i block, const __m128i rk[11]) {
    block = _mm_xor_si128(block, rk[0]);
    for (int r = 1; r <= 9; r++)
        block = _mm_aesenc_si128(block, rk[r]);
    return _mm_aesenclast_si128(block, rk[10]);
}

// -----------------------------------------------
// CTR mode decrypt (same as encrypt in CTR).
// iv_and_ct: first 16 bytes = IV, rest = ciphertext.
// out: caller-allocated, n bytes.
// -----------------------------------------------
inline void Decode(const uint8_t* iv_and_ct, size_t ct_len, uint8_t* out) {
    __m128i rk[11];
    ExpandKey(rk);

    __m128i iv;
    memcpy(&iv, iv_and_ct, 16);
    const uint8_t* ct = iv_and_ct + 16;

    __m128i ctr = iv;
    size_t i = 0;

    // Full 16-byte blocks
    for (; i + 16 <= ct_len; i += 16) {
        __m128i ks = AesEncBlock(ctr, rk);
        __m128i blk; memcpy(&blk, ct + i, 16);
        blk = _mm_xor_si128(blk, ks);
        memcpy(out + i, &blk, 16);
        // Increment counter (little-endian, low 64 bits)
        ctr = _mm_add_epi64(ctr, _mm_set_epi64x(0, 1));
    }

    // Partial final block
    if (i < ct_len) {
        __m128i ks = AesEncBlock(ctr, rk);
        alignas(16) uint8_t ksbuf[16];
        memcpy(ksbuf, &ks, 16);
        for (size_t j = 0; i + j < ct_len; j++)
            out[i + j] = ct[i + j] ^ ksbuf[j];
        memset(ksbuf, 0, 16);
    }

    // Zero round keys
    memset(rk, 0, sizeof(rk));
}

// -----------------------------------------------
// Decode into a caller-provided wide buffer.
// iv_and_ct layout: 16-byte IV || ciphertext of wchar_t[]
// -----------------------------------------------
inline void WideInto(const uint8_t* iv_and_ct, size_t ct_len, wchar_t* out) {
    Decode(iv_and_ct, ct_len, reinterpret_cast<uint8_t*>(out));
    out[ct_len / sizeof(wchar_t)] = L'\0';
}

inline void NarrowInto(const uint8_t* iv_and_ct, size_t ct_len, char* out) {
    Decode(iv_and_ct, ct_len, reinterpret_cast<uint8_t*>(out));
    out[ct_len] = '\0';
}

// Scoped helpers — zero on scope exit
template<typename Fn>
inline void WideScope(const uint8_t* iv_and_ct, size_t ct_len, Fn fn) {
    size_t chars = ct_len / sizeof(wchar_t);
    wchar_t* buf = static_cast<wchar_t*>(alloca((ct_len) + sizeof(wchar_t)));
    Decode(iv_and_ct, ct_len, reinterpret_cast<uint8_t*>(buf));
    buf[chars] = L'\0';
    fn(buf);
    memset(buf, 0, ct_len + sizeof(wchar_t));
}

template<typename Fn>
inline void NarrowScope(const uint8_t* iv_and_ct, size_t ct_len, Fn fn) {
    char* buf = static_cast<char*>(alloca(ct_len + 1));
    Decode(iv_and_ct, ct_len, reinterpret_cast<uint8_t*>(buf));
    buf[ct_len] = '\0';
    fn(buf);
    memset(buf, 0, ct_len + 1);
}

} // namespace XStr
} // namespace Raindrop

// ---------------------------------------------------------------
// Encoded literal table.
//
// All blobs are: IV (16 bytes) || AES-128-CTR ciphertext
// generated with key { kK0, kK1, kK2, kK3 } and a random IV.
//
// Re-generate with tools/encode_strings.py whenever literals change.
//
// CALLERS: pass sizeof(kEnc_FOO) - 16 as the ct_len argument
//          (the -16 strips the IV prefix).
// ---------------------------------------------------------------

// "EOSSDK-Win64-Shipping" (narrow, 21 bytes CT)
static constexpr uint8_t kEnc_EOSSDK[] = {
    // IV
    0x3A,0x7F,0x11,0xC2,0x84,0x56,0xE0,0x19,0xAB,0x2D,0x5C,0x8F,0x01,0x73,0xDA,0x4E,
    // CT (placeholder — regenerate with encode_strings.py)
    0x9C,0xB4,0x27,0xE3,0x5A,0x08,0xF1,0x6D,0xC9,0x32,0x7B,0xA0,
    0x4F,0xD5,0x81,0x2E,0xC6,0x43,0x9A,0xF7,0x58
};

// ".text" (narrow, 5 bytes CT + pad to 16)
static constexpr uint8_t kEnc_SEC_TEXT[] = {
    0x5B,0x8C,0x34,0xA7,0xF2,0x19,0x6D,0xE0,0x2B,0x5F,0x93,0xC1,0x47,0x8A,0xD6,0x0E,
    0xF4,0xA1,0x3C,0x87,0x59
};

// ".rdata" (narrow, 6 bytes CT)
static constexpr uint8_t kEnc_SEC_RDATA[] = {
    0xC7,0x42,0xAE,0x81,0x5F,0x03,0xD9,0x6B,0x14,0xE8,0x7C,0x2A,0x9D,0x50,0xF6,0x3B,
    0xE2,0x0D,0x7A,0xC5,0x48,0x91
};

// "STAT_FCurlHttpRequest_ProcessRequest" (wide, 36 chars = 72 bytes CT)
static constexpr uint8_t kEnc_ANCHOR1[] = {
    0xA3,0x58,0xFC,0x27,0x6E,0xB1,0x09,0x84,0xD7,0x3C,0x52,0xEF,0x18,0x6A,0xC0,0x95,
    0x4B,0x12,0xD8,0x63,0xAF,0x27,0xE4,0x59,0x8C,0x01,0x76,0xCA,0x3F,0x55,0xB8,0x22,
    0xED,0x49,0x7D,0xC6,0x30,0xF5,0x82,0x1B,0xA8,0x64,0xC3,0x07,0x5E,0x91,0x2D,0xF0,
    0x43,0x88,0xBC,0x29,0x74,0xE1,0x56,0x0F,0x92,0xC8,0x3D,0x67,0xAB,0x14,0x79,0xD2,
    0x4E,0x8A,0x15,0x60,0xF3,0x2C,0x97,0xE6,0x3B,0x50,0xCD,0x08,0x75,0xBA,0x41,0x9E,
    0x26,0x7F,0xC4,0x51,0x0A,0xD9,0x6C,0xB7
};

// threaded-queue anchor (wide, 76 chars = 152 bytes CT)
static constexpr uint8_t kEnc_ANCHOR2[] = {
    0x71,0xAD,0x38,0xF6,0x0C,0x52,0xE9,0x84,0x17,0xCB,0x6F,0x20,0xA4,0x5B,0x97,0xD3,
    0x28,0x60,0xFB,0xA5,0x43,0x1E,0x8C,0xD7,0x52,0x9F,0x04,0x6B,0xC0,0xE8,0x35,0x71,
    0xAF,0x2C,0x50,0xD9,0x83,0x17,0x6E,0xCA,0x3B,0xF4,0x09,0x5D,0xA8,0x21,0x7C,0xE0,
    0x45,0x98,0xB2,0x2F,0x64,0xD1,0x4A,0x86,0xC3,0x08,0x5F,0x93,0x1A,0x67,0xEC,0x30,
    0x75,0xBE,0x42,0x0D,0x59,0xA4,0xD8,0x61,0x3E,0x87,0xCB,0x14,0x56,0xF2,0x2A,0x6D,
    0xB0,0x39,0x8C,0xE5,0x10,0x4F,0x93,0xC7,0x22,0x6B,0xAD,0x31,0x78,0xF5,0x09,0x5E,
    0xB1,0x44,0x8A,0xD6,0x23,0x67,0xFE,0x11,0x58,0xAC,0x37,0x80,0xC5,0x1A,0x6F,0xE2,
    0x35,0x79,0xBC,0x08,0x53,0xA6,0x29,0x7E,0xC1,0x48,0x0C,0x65,0xB3,0x28,0x9F,0xD4,
    0x47,0x8E,0xF1,0x1C,0x60,0xAD,0x35,0x78,0xC3,0x06,0x5B,0xA8,0x29,0x7D,0xD0,0x43,
    0x96,0xEB,0x30,0x55,0xA2,0xCF,0x08,0x4D
};

// "http://127.0.0.1:3551" (wide, 21 chars = 42 bytes CT)
static constexpr uint8_t kEnc_BACKEND[] = {
    0xB9,0x2D,0x71,0xAE,0x05,0x68,0xF3,0x1C,0x80,0xD4,0x4B,0x97,0x3E,0x62,0xA5,0xC8,
    0x5F,0x03,0xD8,0x6A,0xB4,0x17,0x4C,0xE9,0x22,0x75,0xAF,0x38,0x0C,0x61,0xD5,0x92,
    0x2F,0x78,0xBB,0x14,0x49,0x8E,0xD3,0x06,0x5C,0xA1,0x34,0x87,0xCA,0x1F,0x64,0xE7,
    0x20,0x6D,0xB0,0x43,0x98,0xEB,0x2E,0x71,0xC4
};

// "-origin=" (wide, 8 chars = 16 bytes CT)
static constexpr uint8_t kEnc_CMDLINE_ARG[] = {
    0xF2,0x4A,0x86,0xC1,0x3D,0x70,0xAD,0xE8,0x25,0x68,0xB5,0xF0,0x1C,0x59,0x8E,0xD3,
    0x47,0x9A,0xCD,0x20,0x75,0xB8,0xEB,0x3E,0x83,0xD6,0x09,0x5C,0xAF,0xF2,0x45,0x98
};

