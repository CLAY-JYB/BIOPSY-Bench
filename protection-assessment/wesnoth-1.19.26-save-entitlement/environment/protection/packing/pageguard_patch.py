#!/usr/bin/env python3
"""
pageguard_patch.py — page-granular on-demand decryption (binary stage).

Run AFTER compile (+ interlock_patch) and BEFORE any outer packer: it reads
the raw section layout. Pairs with pageguard.py (source stage).

What it does to the compiled ELF:
  1. locates the g_pg (protected code) and g_pg_rt (runtime) sections;
  2. key = crc32(g_pg_rt file bytes) — the self-key the runtime recomputes
     in memory at fault time (tamper the runtime and decryption breaks);
  3. XOR-encrypts the g_pg section bytes in the file with the same
     keystream the runtime uses:
         enc[i] = plain[i] ^ ((key >> ((i & 3) * 8)) ^ (uint8_t)i)
  4. flips pg_state from PLAIN to ENC so the constructor arms itself.

Idempotency/safety: refuses to run if pg_state is already ENC (a second
XOR would "decrypt"), and refuses if the g_pg section is missing (the
source stage did not run).

The on-disk binary now shows garbage for the whole license-check section;
the code materializes in memory one page at a time, on first execution.
Static tools (objdump/ghidra/angr) see encrypted bytes until the analyst
either replays the key derivation or lets it self-decrypt under a debugger
(which must pass SIGSEGV through to the handler — `handle sigsegv nostop
noprint pass` in gdb).
"""

import argparse
import struct
import sys

PG_PLAIN_MAGIC = 0x3147504C41494E   # '1GPLAIN'
PG_ENC_MAGIC = 0x3147454E435259     # '1GENCRY'
PG_ANCHOR0 = 0x3156645261556750     # 'PgUaRdV1' — precedes pg_state in .data
PG_ANCHOR1 = 0x3923655461547324     # '$sTaTe#9' — 16-byte pair defeats collisions


def crc32_bytes(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1) & 0xFFFFFFFF))
            crc &= 0xFFFFFFFF
    return crc ^ 0xFFFFFFFF


class ELF:
    """Minimal ELF section+symbol reader (same shape as interlock_patch.py,
    plus vaddr tracking and a symbol-table lookup)."""

    def __init__(self, data):
        self.data = data
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file")
        ei_class = data[4]
        ei_data = data[5]
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
            e_shoff = self._u(0x28, "Q")[0]
            e_shentsize = self._u(0x3a, "H")[0]
            e_shnum = self._u(0x3c, "H")[0]
            e_shstrndx = self._u(0x3e, "H")[0]
            sh_fmt = e + "IIQQQQIIQQ"
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
                        "size": fields[5], "addr": fields[3]})

        strtab = raw[e_shstrndx]
        strblob = self.data[strtab["offset"]:strtab["offset"] + strtab["size"]]

        def name_at(off):
            end = strblob.find(b"\x00", off)
            return strblob[off:end].decode("latin-1")

        self.sections = {}
        self._raw = raw
        for s in raw:
            nm = name_at(s["name_off"])
            if nm and nm not in self.sections:
                self.sections[nm] = s

    def section(self, name):
        if name not in self.sections:
            raise KeyError(f"section {name!r} not found in ELF")
        s = self.sections[name]
        return s["offset"], s["size"]

    def _vaddr_to_offset(self, vaddr):
        for s in self._raw:
            if s["addr"] != 0 and s["addr"] <= vaddr < s["addr"] + s["size"]:
                return s["offset"] + (vaddr - s["addr"])
        raise RuntimeError(f"no section maps vaddr 0x{vaddr:x}")

    def symbol_offset(self, name):
        """File offset of an object symbol via .symtab/.strtab.

        The patcher MUST run before `strip` — afterwards there is no symbol
        table and only the anchor scan fallback remains.
        """
        if ".symtab" not in self.sections:
            return None
        symtab = self.sections[".symtab"]
        strtab = self.sections.get(".strtab")
        if not strtab:
            return None
        strdata = self.data[strtab["offset"]:strtab["offset"] + strtab["size"]]

        ent = 24 if self.is64 else 16
        n = symtab["size"] // ent
        for i in range(n):
            base = symtab["offset"] + i * ent
            if self.is64:
                st_name, st_info, st_other, st_shndx, st_value, st_size = \
                    struct.unpack_from(self.endian + "IBBHQQ", self.data, base)
            else:
                st_name, st_value, st_size, st_info, st_other, st_shndx = \
                    struct.unpack_from(self.endian + "IIIBBH", self.data, base)
            if st_name >= len(strdata):
                continue
            end = strdata.find(b"\x00", st_name)
            nm = strdata[st_name:end].decode("latin-1")
            if nm == name and st_value != 0:
                return self._vaddr_to_offset(st_value)
        return None


def find_pg_state(elf, data, endian):
    """Locate pg_state: symbol table first (robust), then the PGUARDv1
    anchor immediately preceding it. Returns file offset."""
    off = elf.symbol_offset("pg_state")
    if off is not None:
        cur = struct.unpack_from(endian + "Q", data, off)[0]
        if cur == PG_ENC_MAGIC:
            raise RuntimeError("pg_state is already ENC — pageguard_patch has "
                               "already run (a second XOR would decrypt, not encrypt)")
        if cur != PG_PLAIN_MAGIC:
            raise RuntimeError(f"pg_state symbol found but magic is 0x{cur:x} "
                               f"(neither PLAIN nor ENC) — unexpected binary")
        return off

    # fallback: 16-byte anchor scan (stripped binaries)
    anchor = struct.pack(endian + "QQ", PG_ANCHOR0, PG_ANCHOR1)
    start = 0
    hits = []
    while True:
        i = data.find(anchor, start)
        if i < 0:
            break
        hits.append(i + 16)  # pg_state immediately follows the anchor pair
        start = i + 1
    if not hits:
        raise RuntimeError("pg_state not found (no symbol table, no anchor "
                           "pair) — did pageguard.py instrument the source, "
                           "and is this the right binary?")
    if len(hits) > 1:
        raise RuntimeError("ambiguous pg_state anchor")
    cur = struct.unpack_from(endian + "Q", data, hits[0])[0]
    if cur == PG_ENC_MAGIC:
        raise RuntimeError("pg_state is already ENC — refusing to XOR twice")
    if cur != PG_PLAIN_MAGIC:
        raise RuntimeError(f"anchor found but pg_state magic is 0x{cur:x}")
    return hits[0]


def main():
    ap = argparse.ArgumentParser(
        description="Encrypt the g_pg section for page-granular on-demand "
                    "decryption (binary stage; pair with pageguard.py)")
    ap.add_argument("--binary", required=True, help="compiled ELF to patch in place")
    ap.add_argument("--dump", action="store_true",
                    help="print section sizes/key and exit without patching")
    args = ap.parse_args()

    with open(args.binary, "rb") as f:
        data = bytearray(f.read())

    elf = ELF(data)
    endian = elf.endian

    pg_off, pg_size = elf.section("g_pg")
    rt_off, rt_size = elf.section("g_pg_rt")

    key = crc32_bytes(bytes(data[rt_off:rt_off + rt_size]))

    if args.dump:
        print(f"g_pg:   offset=0x{pg_off:x} size={pg_size}")
        print(f"g_pg_rt offset=0x{rt_off:x} size={rt_size}")
        print(f"self-key (crc32 of g_pg_rt) = 0x{key:08x}")
        return 0

    state_off = find_pg_state(elf, data, endian)

    original_first = data[pg_off]

    # XOR-encrypt g_pg with the runtime self-key (must match pg_fault's
    # keystream bit-for-bit: byte ^ ((key >> ((off & 3) * 8)) ^ off)).
    for i in range(pg_size):
        kb = ((key >> ((i & 3) * 8)) ^ (i & 0xFF)) & 0xFF
        data[pg_off + i] ^= kb

    if data[pg_off] == original_first:
        raise RuntimeError("encryption left the section unchanged — keystream "
                           "generated zero bytes; refusing to flip pg_state")

    struct.pack_into(endian + "Q", data, state_off, PG_ENC_MAGIC)

    with open(args.binary, "wb") as f:
        f.write(data)

    print(f"patched {args.binary}: g_pg ({pg_size} bytes) encrypted with "
          f"self-key 0x{key:08x} (crc32 of g_pg_rt, {rt_size} bytes); "
          f"pg_state -> ENC")
    return 0


if __name__ == "__main__":
    sys.exit(main())
