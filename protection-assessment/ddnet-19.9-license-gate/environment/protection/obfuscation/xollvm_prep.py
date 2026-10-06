#!/usr/bin/env python3
"""
xollvm Annotation Injector for C Files

xollvm (und3ath/xollvm) is annotation-driven: its obfuscation passes
(mba, substitution, bcf, flattening, shield, adec, vm, ...) only fire on
functions carrying an ``obf:`` annotation, e.g.::

    __attribute__((annotate("obf: mba,bcf,flattening,shield,adec")))
    int main(int argc, char **argv) { ... }

A command generator cannot assume the source is already annotated, so this
script idempotently injects the annotation immediately before the target
function definition. It is the xollvm analogue of tigress_prep.py: a
source-level, in-place editor run as the first step of the xollvm pipeline
(emitted by xollvm.py, executed as a Docker RUN).

Usage::

    ./xollvm_prep.py main.c "mba,bcf,flattening,shield,adec"
    ./xollvm_prep.py main.c "mba(prob=70),flattening" --function verify
    ./xollvm_prep.py main.c "obf: mba,bcf" --dry-run

The spec may be given with or without the leading ``obf: `` prefix.
"""

import argparse
import os
import re
import sys


def find_function_def(content: str, func_name: str):
    """Find a function DEFINITION (signature followed shortly by ``{``).

    Returns the 0-indexed line of the signature, or None. Skips prototypes /
    forward declarations (``type func(...);``) so it doesn't latch onto a
    declaration and inject the annotation in the wrong place.
    """
    lines = content.split('\n')
    func_pattern = re.compile(
        rf'^\s*([\w\s\*]+)?\b{re.escape(func_name)}\s*\('
    )
    for i, line in enumerate(lines):
        if not func_pattern.search(line):
            continue
        # Skip prototypes / forward declarations first.
        if re.search(r'\)\s*;\s*$', line):
            continue
        # Definition: an opening brace follows within a few lines.
        for j in range(i, min(i + 6, len(lines))):
            if '{' in lines[j]:
                return i
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Inject a xollvm __attribute__((annotate(\"obf: ...\"))) "
                    "before a function definition (idempotent)."
    )
    parser.add_argument("source", help="C source file to edit in place")
    parser.add_argument(
        "spec",
        help='Annotation passes, e.g. "mba,bcf,flattening,shield,adec". '
             'A leading "obf: " prefix is accepted and stripped.',
    )
    parser.add_argument("--function", default="main",
                        help="Function to annotate (default: main)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report the change without writing the file")
    args = parser.parse_args()

    if not os.path.isfile(args.source):
        print(f"Error: source file not found: {args.source}", file=sys.stderr)
        return 1

    obf = args.spec.strip()
    if obf.startswith("obf:"):
        obf = obf[4:].strip()
    if not obf:
        print("Error: empty annotation spec", file=sys.stderr)
        return 1

    annotation = f'__attribute__((annotate("obf: {obf}")))'

    with open(args.source, 'r') as f:
        content = f.read()

    # Idempotent: if this exact annotation is already present, do nothing.
    if annotation in content:
        print(f"[-] {args.source}: already annotated ({annotation})")
        return 0

    idx = find_function_def(content, args.function)
    if idx is None:
        print(f"Error: function '{args.function}' definition not found in "
              f"{args.source}; cannot inject annotation", file=sys.stderr)
        return 1

    lines = content.split('\n')
    lines.insert(idx, annotation)
    new_content = '\n'.join(lines)

    if args.dry_run:
        print(f"[dry-run] {args.source}: would insert before line {idx + 1}:")
        print(f"    {annotation}")
        return 0

    with open(args.source, 'w') as f:
        f.write(new_content)

    print(f"[+] {args.source}: injected {annotation} before {args.function}()")
    return 0


if __name__ == "__main__":
    sys.exit(main())
