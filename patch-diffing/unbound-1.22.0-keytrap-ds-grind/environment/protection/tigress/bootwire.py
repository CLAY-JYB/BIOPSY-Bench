#!/usr/bin/env python3
"""tigress_bootwire.py, wire the renamed tigress stub mains into real
startup.

CIL moves non-constant global initializers (unbound's module function
blocks, which carry function pointers) into the TU's main. The armor
protocol appends a dummy `int main(void){return 0;}` so tigress accepts
the library TU, then renames it so the real main links -- which leaves
those relocated initializers DEAD (module table all NULL, the recorded
tigress contract pitfall 3). This tool declares each stub in the real
program TU and calls it as the first statement of real main.

Usage: tigress_bootwire.py FILE stub1 stub2 ...
"""

import re
import sys


def main():
    path, stubs = sys.argv[1], sys.argv[2:]
    src = open(path).read()
    if "tigress_stub_main_vu();" in src or "tigress_stub_main_vd();" in src:
        print("[+] %s: already wired" % path)
        return 0
    decls = "".join("int %s(void);\n" % s for s in stubs)
    calls = "".join("    %s();\n" % s for s in stubs)
    m = re.search(r"^([A-Za-z_][\w\s\*]*?)\bmain\s*\(", src, re.M)
    if not m:
        print("tigress_bootwire: main not found in %s" % path,
              file=sys.stderr)
        return 1
    # declaration block before the first function that includes main;
    # simplest: before main's return-type line
    start = m.start()
    src = src[:start] + decls + src[start:]
    # first statement of main's body
    b = src.find("{", src.find("main", start))
    src = src[:b + 1] + "\n" + calls + src[b + 1:]
    open(path, "w").write(src)
    print("[+] %s: wired boot calls %s" % (path, ",".join(stubs)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
