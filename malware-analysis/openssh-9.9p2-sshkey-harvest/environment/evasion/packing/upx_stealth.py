#!/usr/bin/env python3
"""
upx_stealth.py

Remove all UPX signatures from ELF binaries while preserving functionality,
and defeat one-command `upx -d` unpacking.

Usage:
    python upx_stealth.py input_packed output_stealthy [--no-deep]

Steps:
1. Replaces UPX! magic bytes (l_info.l_magic) with PKG!   — upx -d aborts
2. --deep (default): zeroes p_info.p_filesize/p_blocksize — upx -d needs
   these to rebuild the original file (Nozomi Networks documented the
   recovery; zeroing is the inverse)
3. --deep (default): renames the UPX0/UPX1/UPX2 section names in shstrtab
4. Obfuscates user-visible strings ($Info/$Id/URLs) version-agnostically
5. Verifies the result and exits non-zero if any UPX marker survived

The runtime stub locates its data positionally, so 1-3 do not affect
execution (confirmed by JPCERT/CC and Nozomi analyses of malware that
patches exactly these fields; recovery tools exist to UNDO them, which is
the point — `upx -d` and naive unpackers fail, restoring the fields is a
separate, conscious step).
"""

import argparse
import os
import re
import sys


def _zero_p_info(data: bytearray, magic_offsets: list, verbose: bool) -> int:
    """Zero p_info.{p_filesize,p_blocksize} after each UPX l_info header.

    Layout from the 'UPX!' magic (l_magic, the SECOND field of l_info):
        magic at pos:  [l_magic:4]
        pos+4:         [l_lsize:2][l_version:1][l_format:1]   (l_info tail)
        pos+8:         [p_progid:4]                            (p_info start)
        pos+12:        [p_filesize:4]
        pos+16:        [p_blocksize:4]
    The stub does not read p_filesize/p_blocksize at runtime (they describe
    the ORIGINAL file for the unpacker); `upx -d` however requires them.
    """
    patched = 0

    def u32(o):
        return int.from_bytes(data[o:o + 4], 'little')

    for pos in magic_offsets:
        filesize_off = pos + 12
        blocksize_off = pos + 16
        if blocksize_off + 4 > len(data):
            continue
        # sanity: sizes must be plausible (< file size x4) — otherwise this
        # is not really a p_info and we must not corrupt random bytes.
        if u32(blocksize_off) == 0:
            continue
        if u32(blocksize_off) > len(data) * 4 or u32(filesize_off) > len(data) * 4:
            continue
        data[filesize_off:filesize_off + 4] = b'\x00' * 4
        data[blocksize_off:blocksize_off + 4] = b'\x00' * 4
        patched += 1
    if patched and verbose:
        print(f"  - Zeroed p_info filesize/blocksize after {patched} l_info header(s)")
    return patched


def _rename_upx_sections(data: bytearray, verbose: bool) -> int:
    """Rename UPX0/UPX1/UPX2 in the section-name string table.

    Section names live in shstrtab as C strings; an equal-length in-place
    rewrite keeps every sh_name offset valid.
    """
    renamed = 0
    for old, new in ((b'UPX0', b'XP0.'), (b'UPX1', b'XP1.'), (b'UPX2', b'XP2.')):
        pos = 0
        while True:
            pos = data.find(old, pos)
            if pos == -1:
                break
            # only rewrite inside a plausible string-table context: the byte
            # after the name must be NUL (C string terminator)
            if pos + 4 < len(data) and data[pos + 4] == 0:
                data[pos:pos + 4] = new
                renamed += 1
            pos += 4
    if renamed and verbose:
        print(f"  - Renamed {renamed} UPX section name(s) (UPX0/1/2)")
    return renamed


def obfuscate_upx_strings(input_file: str, output_file: str, verbose: bool = True,
                          deep: bool = True) -> bool:
    """
    Obfuscate UPX strings while preserving functionality.

    Args:
        input_file: Path to UPX-packed binary
        output_file: Path for obfuscated output
        verbose: Print detailed progress
        deep: Also zero p_info and rename UPX sections (default True)

    Returns True if successful.
    """
    try:
        with open(input_file, 'rb') as f:
            data = bytearray(f.read())
    except OSError as e:
        print(f"[!] Error reading input: {e}")
        return False

    original_size = len(data)
    patches = 0

    if verbose:
        print("[*] Removing all UPX signatures...")

    # 1. Replace UPX! magic bytes; record offsets for the p_info pass.
    #    (The old code's separate 'UPX!P'/'UPX!u' passes could never match:
    #    their 'UPX!' prefix had already been rewritten by this pass.)
    magic_offsets = []
    pos = 0
    while True:
        pos = data.find(b'UPX!', pos)
        if pos == -1:
            break
        magic_offsets.append(pos)
        data[pos:pos+4] = b'PKG!'  # different magic, same length
        patches += 1
        pos += 4
    if magic_offsets and verbose:
        print(f"  - Replaced {len(magic_offsets)} UPX! magic bytes with PKG!")

    # 2-3. Deep stealth: break `upx -d`'s metadata requirements.
    if deep:
        patches += _zero_p_info(data, magic_offsets, verbose)
        patches += _rename_upx_sections(data, verbose)

    # 4. String obfuscation — version-agnostic. The old table pinned
    #    "UPX 3.96" and silently missed every other release's $Id line.
    bytes_modified = 0

    def pad_replace(pat_bytes, start):
        nul = data.find(b'\x00', start)
        end = nul if nul != -1 and nul - start <= 96 else start + 64
        span = end - start
        filler = b'\x00' * span
        data[start:start + span] = filler
        return span

    # exact, known strings first
    for pattern, replacement in [
        (b'$Info: This file is packed with the UPX executable packer http://upx.sf.net',
         b'$Info: Compressed binary.'),
        (b'http://upx.sf.net', b'\x00' * 17),
        (b'upx.sf.net', b'\x00' * 10),
        (b'the UPX Team', b'the DevTeam'),
        (b'UPX Team', b'DevTeam'),
    ]:
        pos = 0
        count = 0
        while True:
            pos = data.find(pattern, pos)
            if pos == -1:
                break
            padded = replacement[:len(pattern)] + b'\x00' * max(0, len(pattern) - len(replacement))
            data[pos:pos+len(pattern)] = padded
            count += 1
            patches += 1
            bytes_modified += len(pattern)
            pos += len(pattern)
        if count and verbose:
            print(f"  - Obfuscated {count}x: {pattern[:50]}...")

    # any "$Id: UPX <version> Copyright..." regardless of version numbers
    for m in re.finditer(rb'\$Id: UPX [0-9][^\x00]{0,80}', bytes(data)):
        span = pad_replace(data, m.start())
        patches += 1
        bytes_modified += span
    # any remaining "$Info: This file is packed with the UPX..." variants
    for m in re.finditer(rb'\$Info: This file is packed[^\x00]{0,80}', bytes(data)):
        span = pad_replace(data, m.start())
        patches += 1
        bytes_modified += span

    # 5. Remaining standalone "UPX " strings
    pos = 0
    string_patches = 0
    while pos < len(data) - 3:
        if data[pos:pos+4] == b'UPX ':
            if pos == 0 or data[pos-1] in (0, 0x20, 0x0a, 0x0d):
                data[pos:pos+4] = b'\x00\x00\x00\x00'
                string_patches += 1
                patches += 1
        pos += 1
    if string_patches and verbose:
        print(f"  - Cleaned {string_patches} additional UPX references")

    try:
        with open(output_file, 'wb') as f:
            f.write(data)
    except OSError as e:
        print(f"[!] Error writing output: {e}")
        return False

    # Preserve executable permissions
    try:
        st = os.stat(input_file)
        os.chmod(output_file, st.st_mode)
    except OSError:
        os.chmod(output_file, 0o755)

    if verbose:
        print(f"\n[+] Summary:")
        print(f"    Total patches: {patches}")
        print(f"    Bytes modified: {bytes_modified}")
        print(f"    Input size:  {original_size} bytes")
        print(f"    Output size: {len(data)} bytes")

    return True


# Markers that must NOT survive stealth processing. Generic "UPX" substrings
# are not included — the target program could legitimately embed them.
STEALTH_MUST_ABSENT = [
    b'UPX!',
    b'upx.sf.net',
    b'$Info: This file is packed',
    b'$Id: UPX ',
    b'UPX0', b'UPX1', b'UPX2',
]


def verify_obfuscation(file_path: str, verbose: bool = True) -> dict:
    """
    Verify the obfuscation results.
    Returns a dict with verification metrics; 'clean' is the gate.
    """
    result = {
        'upx_string_count': 0,
        'pkg_magic_count': 0,
        'survivors': [],
        'clean': True,
    }

    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except OSError:
        result['clean'] = False
        result['survivors'] = ['<unreadable>']
        return result

    result['upx_string_count'] = data.count(b'UPX')
    result['pkg_magic_count'] = data.count(b'PKG!')
    for marker in STEALTH_MUST_ABSENT:
        if marker in data:
            result['survivors'].append(marker.decode('latin-1'))
    result['clean'] = not result['survivors']

    if verbose:
        print("\n[+] Verification:")
        print(f"    Remaining 'UPX' substrings: {result['upx_string_count']}")
        print(f"    PKG! magic bytes (replacement): {result['pkg_magic_count']}")
        print(f"    Stealth markers remaining: {result['survivors'] or 'none'}")
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Remove all UPX packer signatures from ELF binaries.",
        epilog="Removes magic bytes and strings while preserving functionality."
    )
    parser.add_argument("input", help="Path to UPX-packed ELF binary")
    parser.add_argument("output", help="Path for obfuscated output binary")
    parser.add_argument("-q", "--quiet", action="store_true",
                       help="Suppress verbose output")
    parser.add_argument("--no-deep", action="store_true",
                       help="Skip deep stealth (p_info zeroing + UPX0/1/2 "
                            "section renaming). Deep mode is the default and "
                            "is what actually defeats `upx -d`.")
    args = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)

    verbose = not args.quiet

    if verbose:
        print("[*] UPX Stealth ELF - Remove all signatures")
        print(f"[*] Input:  {args.input}")
        print(f"[*] Output: {args.output}")
        print()

    success = obfuscate_upx_strings(args.input, args.output, verbose,
                                    deep=not args.no_deep)
    if not success:
        sys.exit(1)

    verdict = verify_obfuscation(args.output, verbose)
    if verbose:
        print(f"\n[+] Done: {args.output}")
    if not verdict['clean']:
        print(f"[!] STEALTH FAILED — markers survived: {verdict['survivors']}",
              file=sys.stderr)
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
