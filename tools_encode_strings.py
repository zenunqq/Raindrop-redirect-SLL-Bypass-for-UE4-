#!/usr/bin/env python3
"""
tools/encode_strings.py — AES-128-CTR string encoder for Raindrop xstr.h

Matches the key and CTR implementation in xstr.h exactly.
Output format: 16-byte IV || ciphertext, as a C constexpr uint8_t[].

Usage:
    python encode_strings.py

Edit the STRINGS dict below, then paste the output into xstr.h.

Key: { kK0=0xDEAD9173, kK1=0x4F2C81A0, kK2=0xB35E0CF7, kK3=0x920A6B4E }

IV entropy: os.urandom(16) XOR'd with RDTSC-derived bytes for additional
mixing on platforms where the OS CSPRNG may be seeded predictably.
"""

import struct, os, time, hashlib
from Crypto.Cipher import AES

KEY = struct.pack('<IIII', 0xDEAD9173, 0x4F2C81A0, 0xB35E0CF7, 0x920A6B4E)


def make_iv() -> bytes:
    """
    Produce a 16-byte IV with mixed entropy sources:
      - os.urandom(16)    : OS CSPRNG
      - time.perf_counter_ns() : high-resolution process timer
      - os.getpid()       : process identity
      - hash of argv[0]   : interpreter path
    All sources are SHA-256'd together and the first 16 bytes taken.
    This ensures that even if one source is weak, the combination is strong.
    """
    h = hashlib.sha256()
    h.update(os.urandom(16))
    h.update(struct.pack('<Q', time.perf_counter_ns()))
    h.update(struct.pack('<I', os.getpid()))
    h.update(os.path.abspath(__file__).encode())
    return h.digest()[:16]


def encrypt_ctr(plaintext: bytes) -> bytes:
    iv = make_iv()
    cipher = AES.new(KEY, AES.MODE_CTR, nonce=b'', initial_value=int.from_bytes(iv, 'little'))
    ct = cipher.encrypt(plaintext)
    return iv + ct


def fmt_c_array(name: str, data: bytes) -> str:
    iv   = data[:16]
    rest = data[16:]
    lines = []
    lines.append('    // IV')
    lines.append('    ' + ','.join(f'0x{b:02X}' for b in iv) + ',')
    lines.append('    // CT')
    for i in range(0, len(rest), 12):
        chunk = rest[i:i+12]
        lines.append('    ' + ','.join(f'0x{b:02X}' for b in chunk) + ',')
    body = '\n'.join(lines).rstrip(',')
    return f'static constexpr uint8_t {name}[] = {{\n{body}\n}};'


STRINGS = {
    'kEnc_EOSSDK':       ('EOSSDK-Win64-Shipping', 'narrow'),
    'kEnc_SEC_TEXT':     ('.text',  'narrow'),
    'kEnc_SEC_RDATA':    ('.rdata', 'narrow'),
    'kEnc_ANCHOR1':      ('STAT_FCurlHttpRequest_ProcessRequest', 'wide'),
    'kEnc_ANCHOR2':      ('%p: request (easy handle:%p) has been added to threaded queue for processing', 'wide'),
    'kEnc_BACKEND':      ('http://127.0.0.1:3551', 'wide'),
    'kEnc_CMDLINE_ARG':  ('-origin=', 'wide'),
}


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Encode strings for Raindrop xstr.h')
    parser.add_argument('--backend', metavar='URL',
                        help='Override the BACKEND URL (e.g. http://192.168.1.10:3551)')
    args = parser.parse_args()

    strings = dict(STRINGS)
    if args.backend:
        strings['kEnc_BACKEND'] = (args.backend, 'wide')

    for var, (s, enc) in strings.items():
        if enc == 'wide':
            raw = s.encode('utf-16-le')
        else:
            raw = s.encode('ascii')
        blob = encrypt_ctr(raw)
        ct_len = len(blob) - 16
        comment = f'// "{s}" ({enc}, {ct_len} bytes CT)'
        print(comment)
        print(fmt_c_array(var, blob))
        print()

    print('// Reminder: pass sizeof(kEnc_FOO) - 16 as ct_len to XStr functions.')
