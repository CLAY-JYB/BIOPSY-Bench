#!/usr/bin/env python3
"""
elfmap.py — minimal pure-stdlib ELF reader: sections, symbols, function table.

Lifted from the family's hand-rolled parsers (interlock_patch.py class ELF +
pageguard_patch.py symbol lookup) and extended into a standalone module both
skill-authoring scripts and the shipped agent tools share verbatim. No
third-party imports: it must run on the bare host python3 (authoring side)
and inside the agent image alike.

Capabilities
  - section table (name -> {offset,size,addr}), 32/64-bit, both endians
  - vaddr <-> file offset mapping
  - symbol tables (.symtab with .strtab, .dynsym with .dynstr): defined
    STT_FUNC symbols -> function map [{name, offset, vaddr, size}]
  - section bytes extraction (e.g. .rodata for banner scans)
  - JSON dump CLI (the ground-truth function-map format used by both skills):
      python3 elfmap.py --json <binary>            # function table
      python3 elfmap.py --sections <binary>        # section table
      python3 elfmap.py --symbol <binary> <name>   # one symbol's file offset
"""

import argparse
import json
import struct
import sys

STT_FUNC = 2
SHN_UNDEF = 0

_MACHINE = {
    3: "x86", 62: "x86_64", 40: "arm", 183: "aarch64",
    8: "mips", 10: "mips", 20: "powerpc", 21: "powerpc64",
}


class ElfError(ValueError):
    pass


def _light_demangle(name):
    """Itanium-leftmost demangle: enough to recover the SOURCE-level
    name (a::b) of _Z... symbols so C++ family lists (which carry the
    hunk-header plain names) match the map. Full demangling is not
    needed -- only the identifier path."""
    if not name.startswith("_Z"):
        return None
    i = 3 if name.startswith("_ZN") else 2
    if i == 2 and i < len(name) and name[i] == "L":
        i += 1                     # internal-linkage marker
    parts = []
    while i < len(name):
        c = name[i]
        if c == "E":
            break
        if c.isdigit():
            j = i
            while j < len(name) and name[j].isdigit():
                j += 1
            ln = int(name[i:j])
            if j + ln > len(name):
                return None
            parts.append(name[j:j + ln])
            i = j + ln
        else:
            break
    if not parts:
        return None
    return "::".join(parts)


class ELF:
    """Minimal ELF reader: sections, symbols, function table."""

    def __init__(self, data):
        self.data = data
        if data[:4] != b"\x7fELF":
            raise ElfError("not an ELF file")
        ei_class = data[4]   # 1=32-bit, 2=64-bit
        ei_data = data[5]    # 1=LE, 2=BE
        if ei_class not in (1, 2):
            raise ElfError("unknown ELF class")
        self.is64 = (ei_class == 2)
        self.endian = "<" if ei_data == 1 else ">"
        self.e_type = self._u(0x10 if self.is64 else 0x10, "H")[0]
        self.e_machine = self._u(0x12 if self.is64 else 0x12, "H")[0]
        self.arch = _MACHINE.get(self.e_machine, "unknown-%d" % self.e_machine)
        self._parse_sections()

    # ------------------------------------------------------------ internals --

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
            raw.append({"name_off": fields[0], "type": fields[1],
                        "addr": fields[3], "offset": fields[4],
                        "size": fields[5], "link": fields[6]})

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

    # ------------------------------------------------------------- mapping --

    def vaddr_to_offset(self, vaddr):
        """Map a virtual address to a file offset via the section table."""
        for s in self._raw:
            if s["addr"] != 0 and s["addr"] <= vaddr < s["addr"] + s["size"]:
                return s["offset"] + (vaddr - s["addr"])
        raise ElfError("no section maps vaddr 0x%x" % vaddr)

    def section_bytes(self, name):
        if name not in self.sections:
            raise KeyError("section %r not found in ELF" % name)
        s = self.sections[name]
        return self.data[s["offset"]:s["offset"] + s["size"]]

    def has_symbols(self):
        return ".symtab" in self.sections


    def symbols(self):
        """Yield defined symbols from .symtab (full table) then .dynsym.

        Each item: {name, value(vaddr), size, type, defined}.
        Duplicate names (local + global) collapse to the first defined hit.
        """
        seen = set()
        for symtab_name, strtab_name in ((".symtab", ".strtab"),
                                         (".dynsym", ".dynstr")):
            symtab = self.sections.get(symtab_name)
            strtab = self.sections.get(strtab_name)
            if not symtab or not strtab:
                continue
            strdata = self.data[strtab["offset"]:strtab["offset"] + strtab["size"]]
            ent = 24 if self.is64 else 16
            for i in range(symtab["size"] // ent):
                base = symtab["offset"] + i * ent
                if self.is64:
                    st_name, st_info, _o, st_shndx, st_value, st_size = \
                        struct.unpack_from(self.endian + "IBBHQQ", self.data, base)
                else:
                    st_name, st_value, st_size, st_info, _o, st_shndx = \
                        struct.unpack_from(self.endian + "IIIBBH", self.data, base)
                if st_name >= len(strdata) or st_shndx == SHN_UNDEF:
                    continue
                end = strdata.find(b"\x00", st_name)
                nm = strdata[st_name:end].decode("latin-1")
                if not nm or nm in seen:
                    continue
                seen.add(nm)
                yield {"name": nm, "value": st_value, "size": st_size,
                       "type": st_info & 0xF, "defined": True}
                dm = _light_demangle(nm)
                if dm and dm not in seen:
                    seen.add(dm)
                    yield {"name": dm, "value": st_value, "size": st_size,
                           "type": st_info & 0xF, "defined": True}

    def function_map(self):
        """Defined STT_FUNC symbols as the shared function-map structure.

        Sorted by file offset; offsets resolved through the section table so
        the map stays valid after `strip` (stripping removes .symtab but
        never moves .text).
        """
        out = []
        for sym in self.symbols():
            if sym["type"] != STT_FUNC or sym["size"] == 0:
                continue
            try:
                off = self.vaddr_to_offset(sym["value"])
            except ElfError:
                continue
            out.append({"name": sym["name"], "offset": off,
                        "vaddr": sym["value"], "size": sym["size"]})
        out.sort(key=lambda f: (f["offset"], f["name"]))
        return out

    def dump(self):
        return {"arch": self.arch, "is64": self.is64,
                "endian": "little" if self.endian == "<" else "big",
                "has_symbols": self.has_symbols(),
                "functions": self.function_map()}


def load(path):
    with open(path, "rb") as f:
        return ELF(f.read())


def main():
    ap = argparse.ArgumentParser(
        description="minimal ELF section/symbol/function-table reader")
    ap.add_argument("binary")
    ap.add_argument("--json", action="store_true",
                    help="dump the function map as JSON")
    ap.add_argument("--sections", action="store_true",
                    help="dump the section table")
    ap.add_argument("--symbol", metavar="NAME",
                    help="print one symbol's file offset")
    args = ap.parse_args()

    elf = load(args.binary)
    if args.symbol:
        for sym in elf.symbols():
            if sym["name"] == args.symbol:
                print("0x%x" % elf.vaddr_to_offset(sym["value"]))
                return 0
        print("not-found", file=sys.stderr)
        return 1
    if args.sections:
        rows = [{"name": n, "offset": s["offset"], "size": s["size"],
                 "addr": s["addr"]}
                for n, s in sorted(elf.sections.items(),
                                   key=lambda kv: kv[1]["offset"])]
        print(json.dumps(rows, indent=2))
        return 0
    print(json.dumps(elf.dump(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
