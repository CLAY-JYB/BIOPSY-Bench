#!/usr/bin/env python3
# Remove the throwaway `int main(...)` we appended so Tigress (a whole-program
# obfuscator) would accept a library TU (verification.c). Brace-matched delete.
import sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src).read()
i = s.rfind('int main(')
if i < 0:
    # some CIL renderings use "int main(void)" split; fall back
    i = s.rfind('main(')
    assert i >= 0, "no main() found in tigress output"
    i = s.rfind('\n', 0, i) + 1  # start of the return-type line
j = s.index('{', i)
depth = 0
k = j
while k < len(s):
    c = s[k]
    if c == '{': depth += 1
    elif c == '}':
        depth -= 1
        if depth == 0:
            k += 1
            break
    k += 1
out = s[:i] + s[k:]
assert 'validate_input' in out, "validate_input vanished after strip"
open(dst, 'w').write(out)
print(f"stripped main [{i}:{k}] ; wrote {dst} ({len(out)} bytes)")
