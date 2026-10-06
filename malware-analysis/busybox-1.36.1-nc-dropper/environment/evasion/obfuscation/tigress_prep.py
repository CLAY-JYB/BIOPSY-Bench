#!/usr/bin/env python3
"""
Tigress Source Preparation Tool for C Files
Declares and wires up the init function that Tigress Init transforms instrument.

================================================================================
WHY THIS EXISTS
================================================================================
Tigress Init transforms (InitEntropy, InitOpaque, InitBranchFuns) instrument an
initialization function — ``init_tigress`` by default. For the obfuscated binary
to COMPILE and RUN correctly, the source must already contain:

  1. ``#include <stdlib.h>``  — InitEntropy calls malloc().
  2. A declared ``init_tigress()`` stub — Tigress rewrites the BODY of this
     function. If there is no such function, the Init options have nothing to
     instrument and the opaque-predicate / entropy infrastructure is left
     uninitialised.
  3. A CALL to ``init_tigress()`` at runtime (first statement of the target
     function, typically main) — the Init transforms populate entropy/opaque
     state inside the stub. If it is never called, that state is never set up
     and the protected binary crashes (segfault) or silently produces wrong
     output.

This script edits a .c file IN PLACE, idempotently, guaranteeing all three. It
is the Tigress analogue of anti-debug.py: both are source-level, in-place
editors run as a Docker RUN, before compilation and before the tigress pass
itself.

================================================================================
USAGE
================================================================================

  # Default init function 'init_tigress', caller 'main':
  ./tigress_prep.py main.c

  # Custom init function name and caller:
  ./tigress_prep.py shell.c --init-func tigress_init --target-function main

  # Dry run (report what would change, do not write):
  ./tigress_prep.py main.c --dry-run

================================================================================
"""

import argparse
import os
import re
import sys


STDLIB_INCLUDE = "#include <stdlib.h>"


def find_function_by_name(content: str, func_name: str):
    """Find a function definition by name.

    Returns (sig_line_index, brace_line_index) as 0-indexed line numbers, or
    (None, None) if not found. ``sig_line_index`` is the line of the function
    signature; ``brace_line_index`` is the line containing the opening brace of
    the body (which may be the same line or up to a few lines below).

    Matches a function DEFINITION (signature followed shortly by ``{``), not a
    bare prototype/forward declaration.
    """
    lines = content.split('\n')
    # Function signature: an optional return-type/qualifier prefix, then the
    # function name immediately followed by '('. E.g.:
    #   int main(int argc, char **argv) {
    #   static void *foo(void)
    func_pattern = re.compile(
        rf'^\s*([\w\s\*]+)?\b{re.escape(func_name)}\s*\('
    )

    for i, line in enumerate(lines):
        if not func_pattern.search(line):
            continue
        # Skip prototypes / forward declarations first: "type func(...);".
        # This MUST happen before scanning for a brace, otherwise a prototype
        # like "void init_tigress(void);" would latch onto the next function's
        # opening brace and be mistaken for a definition.
        if re.search(r'\)\s*;\s*$', line):
            continue
        # Definition: an opening brace follows within a few lines.
        for j in range(i, min(i + 6, len(lines))):
            if '{' in lines[j]:
                return (i, j)
    return (None, None)


def has_stdlib(content: str) -> bool:
    """True if <stdlib.h> is already included (angle or quote form)."""
    return bool(re.search(r'#\s*include\s*[<"]stdlib\.h[>"]', content))


def ensure_stdlib(content: str) -> tuple:
    """Insert #include <stdlib.h> after the last existing #include (or at top).

    Returns (new_content, changed_bool).
    """
    if has_stdlib(content):
        return content, False
    lines = content.split('\n')
    last_include = -1
    for i, line in enumerate(lines):
        if re.match(r'\s*#\s*include\b', line):
            last_include = i
    if last_include >= 0:
        lines.insert(last_include + 1, STDLIB_INCLUDE)
    else:
        lines.insert(0, STDLIB_INCLUDE)
    return '\n'.join(lines), True


def init_function_defined(content: str, init_func: str) -> bool:
    """True if init_func is defined as a function (has a body)."""
    sig, brace = find_function_by_name(content, init_func)
    return sig is not None


def ensure_init_stub(content: str, init_func: str, before_func: str = "main") -> tuple:
    """Insert an empty ``void init_func(void){}`` stub before ``before_func``.

    Idempotent: if init_func is already defined, does nothing. Falls back to
    inserting before the first function definition if ``before_func`` is absent,
    and ultimately to the top of the file.

    Returns (new_content, changed_bool).
    """
    if init_function_defined(content, init_func):
        return content, False

    stub_lines = [f"void {init_func}(void){{}}", "", ""]

    # Preferred anchor: the line of `before_func`'s definition.
    sig, _ = find_function_by_name(content, before_func)
    insert_at = sig

    # Fallback: first function definition in the file (any name(...) ... {).
    if insert_at is None:
        lines = content.split('\n')
        any_func = re.compile(r'^\s*([\w\s\*]+)?\b\w+\s*\([^;]*\)\s*$')
        for i, line in enumerate(lines):
            if any_func.search(line):
                for j in range(i, min(i + 6, len(lines))):
                    if '{' in lines[j]:
                        insert_at = i
                        break
                if insert_at is not None:
                    break

    if insert_at is None:
        # Ultimate fallback: top of the file.
        lines = content.split('\n')
        lines = stub_lines + lines
        return '\n'.join(lines), True

    lines = content.split('\n')
    for offset, stub_line in enumerate(stub_lines):
        lines.insert(insert_at + offset, stub_line)
    return '\n'.join(lines), True


def init_function_called(content: str, init_func: str, target_function: str) -> bool:
    """True if init_func() is called inside target_function's body."""
    sig, brace = find_function_by_name(content, target_function)
    if sig is None:
        return False
    lines = content.split('\n')
    # Scan from the opening brace until the matching close (depth-based).
    depth = 0
    call_pattern = re.compile(r'\b' + re.escape(init_func) + r'\s*\(')
    started = False
    for i in range(brace, len(lines)):
        depth += lines[i].count('{')
        depth -= lines[i].count('}')
        if '{' in lines[i]:
            started = True
        if started and call_pattern.search(lines[i]):
            return True
        if started and depth == 0:
            break
    return False


def ensure_init_call(content: str, init_func: str, target_function: str) -> tuple:
    """Insert ``init_func();`` as the first statement of target_function.

    Idempotent: if init_func is already called inside the target, does nothing.
    Returns (new_content, changed_bool). Returns (content, False) unchanged if
    the target function cannot be located.
    """
    if init_function_called(content, init_func, target_function):
        return content, False

    sig, brace = find_function_by_name(content, target_function)
    if sig is None:
        return content, False

    lines = content.split('\n')
    call_line = f"    {init_func}();"
    # Insert immediately AFTER the line holding the opening brace, so the call
    # is the first statement in the body.
    lines.insert(brace + 1, call_line)
    return '\n'.join(lines), True


def prepare_source(content: str, init_func: str = "init_tigress",
                   target_function: str = "main") -> tuple:
    """Apply all three preparations. Returns (new_content, [change_descriptions])."""
    changes = []

    content, changed = ensure_stdlib(content)
    if changed:
        changes.append(f"added #include <stdlib.h> (InitEntropy uses malloc)")

    content, changed = ensure_init_stub(content, init_func, target_function)
    if changed:
        changes.append(f"declared empty {init_func}() stub (target of Init transforms)")

    content, changed = ensure_init_call(content, init_func, target_function)
    if changed:
        changes.append(
            f"added {init_func}() call at start of {target_function}() "
            f"(must run to initialise opaque/entropy state)"
        )

    return content, changes


def main():
    parser = argparse.ArgumentParser(
        description="Prepare a C source file for Tigress Init transforms: "
                    "declare and wire up the init function (init_tigress by default)."
    )
    parser.add_argument("source", help="C source file to edit in place")
    parser.add_argument("--init-func", default="init_tigress",
                        help="Init function name (default: init_tigress)")
    parser.add_argument("--target-function", default="main",
                        help="Function that should call init_func at runtime (default: main)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report changes without writing the file")
    args = parser.parse_args()

    if not os.path.isfile(args.source):
        print(f"Error: source file not found: {args.source}", file=sys.stderr)
        return 1

    with open(args.source, 'r') as f:
        content = f.read()

    new_content, changes = prepare_source(content, args.init_func, args.target_function)

    if not changes:
        print(f"[-] {args.source}: already prepared (stdlib + {args.init_func} stub + call present)")
        return 0

    if args.dry_run:
        print(f"[dry-run] {args.source} would change:")
        for c in changes:
            print(f"    + {c}")
        return 0

    with open(args.source, 'w') as f:
        f.write(new_content)

    print(f"[+] {args.source}: prepared for Tigress ({len(changes)} change(s))")
    for c in changes:
        print(f"    + {c}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
