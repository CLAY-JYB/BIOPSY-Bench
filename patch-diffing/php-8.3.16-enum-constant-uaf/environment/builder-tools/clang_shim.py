#!/usr/bin/env python3
"""clang_shim.py — build-train clang wrapper (builder stages only).

The xollvm -mllvm obf options (-obf-seed / -obf-deterministic) are only
registered when the pass plugin loads, which happens on C compilations.
Assembly compilations (.s/.S — OpenSSL's perlasm modules, any carrier
asm) never load the plugin, and clang HARD-errors on the unknown -mllvm
options. The wrapper strips the obf flag pairs (and the inert
-fpass-plugin) for assembler inputs and execs the real clang untouched
otherwise.

Invoked as: clang_shim.py <real-clang-path> <clang args...>
"""

import os
import sys


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: clang_shim.py <real-clang> <args...>\n")
        return 2
    real, args = sys.argv[1], sys.argv[2:]
    asm = any(a.rsplit(".", 1)[-1] in ("s", "S")
              for a in args if not a.startswith("-") and "." in a)
    if not asm:
        os.execv(real, ["clang"] + args)
    out, i = [], 0
    while i < len(args):
        a = args[i]
        if (a == "-mllvm" and i + 1 < len(args)
                and args[i + 1].startswith("-obf-")):
            i += 2
            continue
        if a.startswith("-fpass-plugin="):
            i += 1
            continue
        out.append(a)
        i += 1
    os.execv(real, ["clang"] + out)


if __name__ == "__main__":
    sys.exit(main())
