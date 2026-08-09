#!/usr/bin/env python3
import struct, os, time, hashlib
from Crypto.Cipher import AES

KEY = struct.pack('<IIII', 0xDEAD9173, 0x4F2C81A0, 0xB35E0CF7, 0x920A6B4E)

def make_iv() -> bytes:
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
    lines.append('    ' + ','.join(f'0x{b:02X}' for b in iv) + ',')
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
        print(fmt_c_array(var, blob))
        print()
