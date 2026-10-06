#!/usr/bin/env python3
"""
interlock_patch.py — post-compile patcher for the interlock guard network.

After the source emitted by interlock_gen.py is compiled, the `expected[]`
array in `struct _il_hdr` still holds placeholder zeros. This script reads each
guard section's bytes out of the finished ELF, CRC32s them (same algorithm as
the C runtime and common.crc32_bytes), and overwrites expected[] in place.

Convergence: expected[] lives in .data, NOT inside any g_* code section, so
patching it changes no byte that any guard checksums -> one compile + one patch
suffices (no second rebuild). This is how real integrity-protected builds embed
their checksums.

USAGE
  python3 interlock_patch.py --binary <elf> --manifest <emit>.ilmanifest.json
                             [--dump]
"""
import argparse
import json
import struct

# Single source of truth for the CRC32 (must match the emitted C il_crc32
# and interlock_gen.py's runtime bit-for-bit: reflected CRC32, poly
# 0xEDB88320, init/final 0xFFFFFFFF).
def crc32_bytes(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1) & 0xFFFFFFFF))
            crc &= 0xFFFFFFFF
    return crc ^ 0xFFFFFFFF


# ------------------------------------------------------------- ELF parsing ----

class ELF:
    """Minimal ELF reader: just enough to map section name -> file bytes."""

    def __init__(self, data):
        self.data = data
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        ei_class = data[4]   # 1=32-bit, 2=64-bit
        ei_data = data[5]    # 1=LE, 2=BE
        if ei_class not in (1, 2):
            raise ValueError("unknown ELF class")
        self.is64 = (ei_class == 2)
        self.endian = "<" if ei_data == 1 else ">"
        self._parse_sections()

    def _u(self, off, fmt):
        return struct.unpack_from(self.endian + fmt, self.data, off)

    def _parse_sections(self):
        e = self.endian
        if self.is64:
            # 64-bit: e_shoff at offset 0x28 (Q), e_shentsize 0x3a (H),
            # e_shnum 0x3c (H), e_shstrndx 0x3e (H)
            e_shoff = self._u(0x28, "Q")[0]
            e_shentsize = self._u(0x3a, "H")[0]
            e_shnum = self._u(0x3c, "H")[0]
            e_shstrndx = self._u(0x3e, "H")[0]
            sh_fmt = e + "IIQQQQIIQQ"  # name,type,flags,addr,offset,size,link,info,align,entsize
        else:
            e_shoff = self._u(0x20, "I")[0]
            e_shentsize = self._u(0x2e, "H")[0]
            e_shnum = self._u(0x30, "H")[0]
            e_shstrndx = self._u(0x32, "H")[0]
            sh_fmt = e + "IIIIIIIIII"

        raw = []
        for i in range(e_shnum):
            base = e_shoff + i * e_shentsize
            fields = struct.unpack_from(sh_fmt, self.data, base)
            raw.append({"name_off": fields[0], "offset": fields[4],
                        "size": fields[5]})

        # section-header string table
        strtab = raw[e_shstrndx]
        strblob = self.data[strtab["offset"]:strtab["offset"] + strtab["size"]]

        def name_at(off):
            end = strblob.find(b"\x00", off)
            return strblob[off:end].decode("latin-1")

        self.sections = {}
        for s in raw:
            nm = name_at(s["name_off"])
            # keep first occurrence by name
            if nm not in self.sections:
                self.sections[nm] = (s["offset"], s["size"])

    def section_bytes(self, name):
        if name not in self.sections:
            raise KeyError(f"section {name!r} not found in ELF")
        off, size = self.sections[name]
        return self.data[off:off + size]


# -------------------------------------------------------------- patch logic ---

def find_header(data, endian, expected_count):
    """Locate struct _il_hdr by its sentinel; return file offset of expected[]."""
    sentinel = {"<": 0xC1C0FFEED15EA5ED, ">": 0xC1C0FFEED15EA5ED}[endian]
    needle = struct.pack(endian + "Q", sentinel)
    magic = struct.pack(endian + "I", 0x494C0001)
    matches = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        # struct layout: sentinel(8) magic(4) count(4) expected[]
        if data[i + 8:i + 12] == magic:
            count = struct.unpack_from(endian + "I", data, i + 12)[0]
            if count == expected_count:
                matches.append(i)
        start = i + 1
    if not matches:
        raise RuntimeError(
            f"sentinel/magic/count header not found (expected count="
            f"{expected_count}); was interlock_gen.py run on this source?")
    if len(matches) > 1:
        raise RuntimeError(f"ambiguous header: {len(matches)} sentinel matches")
    return matches[0] + 16  # expected[] starts at offset 16 in the struct


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--binary", required=True, help="compiled ELF to patch in place")
    ap.add_argument("--manifest", required=True, help="*.ilmanifest.json from interlock_gen.py")
    ap.add_argument("--dump", action="store_true", help="print each section name/size/crc")
    args = ap.parse_args()

    with open(args.manifest) as f:
        manifest = json.load(f)
    with open(args.binary, "rb") as f:
        data = bytearray(f.read())

    elf = ELF(data)
    endian = elf.endian
    checks = manifest["checks"]

    # Compute the real CRC for each check's target section.
    crcs = []
    for c in checks:
        b = elf.section_bytes(c["target"])
        crcs.append(crc32_bytes(b))
        if args.dump:
            print(f"  [{c['index']:>2}] {c['guard']:>8} -> {c['target']:<10} "
                  f"size={len(b):>5}  crc=0x{crcs[-1]:08x}")

    expected_off = find_header(data, endian, len(checks))
    for i, crc in enumerate(crcs):
        struct.pack_into(endian + "I", data, expected_off + i * 4, crc & 0xFFFFFFFF)

    # verify round-trip
    readback = [struct.unpack_from(endian + "I", data, expected_off + i * 4)[0]
                for i in range(len(crcs))]
    if readback != crcs:
        raise RuntimeError("internal error: expected[] round-trip mismatch")

    with open(args.binary, "wb") as f:
        f.write(data)
    print(f"patched {args.binary}: {len(crcs)} checksum(s) embedded "
          f"at file offset 0x{expected_off:x}")


if __name__ == "__main__":
    main()
