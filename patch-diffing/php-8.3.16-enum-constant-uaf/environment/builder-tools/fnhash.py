#!/usr/bin/env python3
"""
fnhash.py — mnemonic-normalized per-function digests from objdump output.

Two digests per function, on purpose:
  seq  — ordered mnemonic + operand-SHAPE sequence. Precise change detector:
         register-identical rebuilds hash the same; any semantic edit moves it.
  bag  — sorted multiset of bare mnemonics. Coarse similarity anchor: survives
         register allocation and reordering (-O2 vs -Os), used for MATCHING
         functions across builds, never for declaring them unchanged.

The normalization strips everything a recompile legitimately perturbs:
absolute addresses, immediates and jump targets (-> L). Register names are
KEPT in `seq` (same-flags rebuilds are register-stable) and absent from `bag`.

Authoring-side only (funcevidence/audit_gen_patch import it to stamp the GT
function maps). It must NEVER be copied into the agent image — agent images
ship stock open-source tools only. Keep it stdlib-only and side-effect-free.
"""

import argparse
import hashlib
import json
import re
import subprocess
import sys

_FUNC_HEAD = re.compile(r"^([0-9a-f]+) <(.+)>:$")
_INSN = re.compile(r"^\s*([0-9a-f]+):\s*([a-z0-9.]+)\s*(.*)$")
_HEX = re.compile(r"\b0x[0-9a-f]+\b")
_BARE_HEX = re.compile(r"(?<![\w.$])0x?[0-9a-f]{4,}\b")
_REG = re.compile(r"\b%[a-z0-9]+\b")
_SYM = re.compile(r"<[^>]*>")


def disassemble(binary):
    res = subprocess.run(["objdump", "-d", "--no-show-raw-insn", binary],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if res.returncode != 0:
        raise RuntimeError("objdump failed on %s: %s"
                           % (binary, res.stderr.decode()[:300]))
    return res.stdout.decode("utf-8", "replace")


def parse_functions(disasm_text):
    """{name: [insn-line, ...]} in encounter order."""
    funcs = {}
    cur = None
    for line in disasm_text.splitlines():
        m = _FUNC_HEAD.match(line.strip())
        if m:
            cur = m.group(2)
            funcs.setdefault(cur, [])
            continue
        if cur is None:
            continue
        if _INSN.match(line):
            funcs[cur].append(line)
    return funcs


def normalize_insn(line):
    """`  401136:\tmov    eax,DWORD PTR [rbp-0x14]` -> `mov eax,DWORD PTR [rbp-#]`
    (address gone, hex immediates -> #, call/jump symbol targets -> <S>)"""
    m = _INSN.match(line)
    if not m:
        return None
    mnemonic, ops = m.group(2), m.group(3).strip()
    ops = _SYM.sub("<S>", ops)          # symbolic branch/call targets -> class
    ops = _HEX.sub("#", ops)            # hex immediates/displacements -> #
    ops = _BARE_HEX.sub("#", ops)
    return "%s %s" % (mnemonic, ops)


def _sha(items):
    return hashlib.sha256("\n".join(items).encode()).hexdigest()[:16]


def function_digests(binary):
    """{name: {"seq","bag","n_insns"}} for every disassembled function."""
    out = {}
    for name, lines in parse_functions(disassemble(binary)).items():
        seq = [n for n in (normalize_insn(l) for l in lines) if n]
        mnemonics = [s.split(" ", 1)[0] for s in seq]
        out[name] = {
            "seq": _sha(seq),
            "bag": _sha(sorted(mnemonics)),
            "n_insns": len(seq),
        }
    return out


def compare(a_binary, b_binary):
    """Diff two builds: changed / added / removed function sets.

    A matched function counts as changed when its `seq` digest or instruction
    count differs. `bag` is reported alongside for cross-opt inspection but
    never decides "unchanged" (that is the whole point of the two-digest rule).
    """
    da, db = function_digests(a_binary), function_digests(b_binary)
    names = sorted(set(da) & set(db))
    changed = [n for n in names
               if da[n]["seq"] != db[n]["seq"] or da[n]["n_insns"] != db[n]["n_insns"]]
    return {
        "changed": [{"name": n, "a": da[n], "b": db[n]} for n in changed],
        "added": sorted(set(db) - set(da)),
        "removed": sorted(set(da) - set(db)),
        "matched_unchanged": len(names) - len(changed),
    }


def main():
    ap = argparse.ArgumentParser(
        description="per-function normalized digests / pair compare")
    ap.add_argument("binary")
    ap.add_argument("--json", action="store_true", help="dump digests")
    ap.add_argument("--compare", metavar="B",
                    help="diff this binary against B (changed/added/removed)")
    args = ap.parse_args()
    if args.compare:
        print(json.dumps(compare(args.binary, args.compare), indent=2))
        return 0
    print(json.dumps(function_digests(args.binary), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
