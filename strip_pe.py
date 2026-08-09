#!/usr/bin/env python3

import sys, os, struct, random, ctypes

def u8(data, off):  return struct.unpack_from('B',  data, off)[0]
def u16(data, off): return struct.unpack_from('<H', data, off)[0]
def u32(data, off): return struct.unpack_from('<I', data, off)[0]
def u64(data, off): return struct.unpack_from('<Q', data, off)[0]
def p8(data, off, v):  struct.pack_into('B',  data, off, v)
def p16(data, off, v): struct.pack_into('<H', data, off, v)
def p32(data, off, v): struct.pack_into('<I', data, off, v)

def pe_checksum(data: bytearray, checksum_field_offset: int) -> int:

    checksum = 0

    view = memoryview(data)
    length = len(data)
    i = 0
    while i < length:
        if i == checksum_field_offset or i == checksum_field_offset + 1 or \
           i == checksum_field_offset + 2 or i == checksum_field_offset + 3:
            i += 1
            continue
        if i + 1 < length:
            word = u16(data, i)
        else:
            word = u8(data, i)
        checksum = (checksum & 0xFFFF) + word + (checksum >> 16)
        if checksum > 0xFFFF:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        i += 2
    checksum = (checksum & 0xFFFF) + (checksum >> 16)
    checksum += length
    return checksum & 0xFFFFFFFF

SECTION_NAME_MAP = {
    b'.text':   b'.t0',
    b'.rdata':  b'.r0',
    b'.data':   b'.d0',
    b'.pdata':  b'.p0',
    b'.rsrc':   b'.s0',
    b'.reloc':  b'.l0',
    b'.idata':  b'.i0',
    b'.edata':  b'.e0',
    b'.tls':    b'.q0',
    b'.CRT':    b'.c0',
    b'.bss':    b'.b0',
}

def strip(path):
    with open(path, 'rb') as f:
        raw = bytearray(f.read())

    if raw[0:2] != b'MZ':
        print(f"[!] Not a valid PE: {path}")
        return False

    e_lfanew = u32(raw, 0x3C)

    rich_end = e_lfanew
    found_rich = False
    for i in range(rich_end - 4, 0x40, -1):
        if raw[i:i+4] == b'Rich':
            xor_key = u32(raw, i + 4)
            dans = struct.pack('<I', xor_key ^ 0x536E6144)
            start = raw.find(dans, 0x40)
            if start != -1 and start < rich_end:
                for j in range(start, rich_end):
                    raw[j] = 0x00
                print(f"[+] Rich header wiped ({rich_end - start} bytes)")
            found_rich = True
            break
    if not found_rich:
        print("[~] No Rich header found")

    if raw[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
        print("[!] PE signature not found")
        return False

    coff_off = e_lfanew + 4

    ts_off = coff_off + 4
    old_ts = u32(raw, ts_off)
    p32(raw, ts_off, 0)
    print(f"[+] TimeDateStamp wiped (was 0x{old_ts:08X})")

    opt_off = coff_off + 20
    magic = u16(raw, opt_off)
    if magic != 0x020B:
        print("[!] Not PE32+. Aborting optional header processing.")
        return False

    linker_major_off = opt_off + 2
    linker_minor_off = opt_off + 3
    p8(raw, linker_major_off, random.randint(10, 14))
    p8(raw, linker_minor_off, random.randint(0, 40))
    print("[+] LinkerVersion randomized")

    num_sections    = u16(raw, coff_off + 2)
    size_opt_hdr    = u16(raw, coff_off + 16)
    sec_table_off   = opt_off + size_opt_hdr

    last_section_end = 0

    used_names = set()
    generic_idx = 0

    for s in range(num_sections):
        soff = sec_table_off + s * 40

        raw_ptr  = u32(raw, soff + 20)
        raw_sz   = u32(raw, soff + 16)
        if raw_ptr and raw_sz:
            end = raw_ptr + raw_sz
            if end > last_section_end:
                last_section_end = end

        name_bytes = bytes(raw[soff:soff+8]).rstrip(b'\x00')

        new_name = None
        for canonical, short_name in SECTION_NAME_MAP.items():
            if name_bytes == canonical:
                candidate = short_name

                while candidate in used_names:
                    candidate = candidate[:2] + str(len(used_names)).encode()[:5]
                new_name = candidate
                break

        if new_name is None:

            candidate = f".x{generic_idx:02d}".encode()
            while candidate in used_names:
                generic_idx += 1
                candidate = f".x{generic_idx:02d}".encode()
            new_name = candidate
            generic_idx += 1

        used_names.add(new_name)

        padded = new_name[:8].ljust(8, b'\x00')
        raw[soff:soff+8] = padded
        print(f"[+] Section {s}: '{name_bytes.decode(errors='replace')}' → '{new_name.decode()}'")

    dirs_off     = opt_off + 0x70
    dbg_rva_off  = dirs_off + 6 * 8
    dbg_size_off = dbg_rva_off + 4

    dbg_rva  = u32(raw, dbg_rva_off)
    dbg_size = u32(raw, dbg_size_off)

    if dbg_rva == 0:
        print("[~] No debug directory present")
    else:
        dbg_file_off = None
        for s in range(num_sections):
            soff = sec_table_off + s * 40
            sec_vaddr  = u32(raw, soff + 12)
            sec_vsz    = u32(raw, soff + 16)
            sec_rawoff = u32(raw, soff + 20)
            if sec_vaddr <= dbg_rva < sec_vaddr + sec_vsz:
                dbg_file_off = sec_rawoff + (dbg_rva - sec_vaddr)
                break

        if dbg_file_off:
            n_entries = dbg_size // 28
            for e in range(n_entries):
                entry_off    = dbg_file_off + e * 28
                raw_data_ptr = u32(raw, entry_off + 24)
                raw_data_sz  = u32(raw, entry_off + 20)
                for j in range(28):
                    raw[entry_off + j] = 0
                if raw_data_ptr and raw_data_sz and raw_data_ptr + raw_data_sz <= len(raw):
                    for j in range(raw_data_sz):
                        raw[raw_data_ptr + j] = 0
                print(f"[+] Debug directory entry {e} + data wiped")
            p32(raw, dbg_rva_off,  0)
            p32(raw, dbg_size_off, 0)
            print("[+] Debug data directory entry zeroed")
        else:
            print("[!] Could not locate debug directory in file")

    if last_section_end > 0 and last_section_end < len(raw):
        overlay_sz = len(raw) - last_section_end
        if overlay_sz > 0:
            raw[last_section_end:] = b'\x00' * overlay_sz
            print(f"[+] Overlay wiped ({overlay_sz} bytes after offset 0x{last_section_end:X})")
        else:
            print("[~] No overlay present")
    else:
        print("[~] No overlay present")

    checksum_field_off = opt_off + 0x40
    p32(raw, checksum_field_off, 0)
    new_checksum = pe_checksum(raw, checksum_field_off)
    p32(raw, checksum_field_off, new_checksum)
    print(f"[+] PE checksum recalculated: 0x{new_checksum:08X}")

    with open(path, 'wb') as f:
        f.write(raw)

    print(f"[+] Done: {path}")
    return True

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <dll>")
        sys.exit(1)
    ok = strip(sys.argv[1])
    sys.exit(0 if ok else 1)
