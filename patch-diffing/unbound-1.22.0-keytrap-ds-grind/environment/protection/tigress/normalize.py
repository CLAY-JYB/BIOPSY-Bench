#!/usr/bin/env python3
"""tigress_fixlnot.py, the Tigress LNot-on-pointer rewriter.

CIL's TreeCodeCIL2Tree chokes on `!ptr` for pointer operands
("vUnop.arithmeticVersionOf: char *" Internal Tigress error, the
recorded tigress contract pitfall 1). The semantics-preserving cure is
`ptr == NULL` (identical for integers too: !x is x==0).

This tool rewrites `!ident` to `(ident == NULL)` INSIDE the named
function bodies only, leaving the rest of the TU untouched. Idempotent.

Usage: tigress_fixlnot.py FILE fn1 fn2 ...
"""

import re
import sys


def top_level_functions(src):
    """Yield (name, body_start_line, body_end_line) for every top-level
    function definition. Tracks brace depth; a depth-0 line containing
    `name(` with the body opening within a few lines starts a function."""
    lines = src.split("\n")
    depth = 0
    out = []
    i = 0
    # the return type may sit on its own line (unbound style:
    # "int\nverify_dnskeys_with_ds_rr(...)"), so the type prefix is
    # optional and the captured name is the identifier before '('
    sig = re.compile(r"^(?:[A-Za-z_][\w\s\*]*\s+)?([A-Za-z_]\w*)\s*\(")
    while i < len(lines):
        if depth == 0:
            m = sig.match(lines[i])
            if m and not re.search(r"\)\s*;\s*$", lines[i]):
                # walk to paren balance, then the opening brace
                pd = 0
                seen = False
                j = i
                while j < len(lines) and j < i + 60:
                    pd += lines[j].count("(") - lines[j].count(")")
                    if "(" in lines[j]:
                        seen = True
                    if seen and pd <= 0:
                        break
                    j += 1
                k = j
                while k < len(lines) and k < j + 4:
                    if "{" in lines[k]:
                        break
                    k += 1
                if k < len(lines) and "{" in lines[k]:
                    bd = 0
                    e = k
                    while e < len(lines):
                        bd += lines[e].count("{") - lines[e].count("}")
                        if bd <= 0 and e >= k:
                            break
                        e += 1
                    out.append((m.group(1), k, e))
                    i = e + 1
                    continue
        depth += lines[i].count("{") - lines[i].count("}")
        i += 1
    return out


LNOT_D = re.compile(r"!\s*\*([A-Za-z_]\w*)\b(?!\s*[=(])")
LNOT_A = re.compile(r"!\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\b(?!\s*[=(])")
LNOT_M = re.compile(r"!\s*([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\b(?!\s*[=(])")
LNOT = re.compile(r"!\s*([A-Za-z_]\w*)(?!\w)(?!\s*\()(?!\s*->)(?!\s*\.)(?!\s*=)")


def rewrite(line):
    line, n1 = LNOT_D.subn(r"(*\1 == NULL)", line)
    line, n2 = LNOT_A.subn(r"(\1->\2 == NULL)", line)
    line, n3 = LNOT_M.subn(r"(\1.\2 == NULL)", line)
    line, n4 = LNOT.subn(r"(\1 == NULL)", line)
    return line, n1 + n2 + n3 + n4


def main():
    path, fns = sys.argv[1], sys.argv[2:]
    src = open(path).read()
    funcs = {n: (a, b) for n, a, b in top_level_functions(src)}
    lines = src.split("\n")
    changed = 0
    for fn in fns:
        if fn not in funcs:
            print("tigress_fixlnot: %s not found in %s" % (fn, path),
                  file=sys.stderr)
            return 1
        a, b = funcs[fn]
        for i in range(a, b + 1):
            new, n = rewrite(lines[i])
            if n:
                lines[i] = new
                changed += n
    open(path, "w").write("\n".join(lines))
    print("[+] %s: rewrote %d LNot(s) in %s" % (path, changed, ",".join(fns)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
