#!/usr/bin/env python3
"""
interlock_gen.py — standalone reimplementation of the interdependency (mutual /
circular) protection layer.

A self-contained source-to-source transform that injects a *real* guard network
into a C source file, plus a manifest that interlock_patch.py consumes to embed
the true expected checksums after compile.

LEVEL = cumulative difficulty. Each level adds one more mutual-protection pattern
on top of the Aucsmith ring (Pattern 1) + Chang-Atallah topology (Pattern 2) and
the integrity canary:

  level 1 (Ring)         ring topology + POISON response (Pattern 7, fixed mask)
  level 2 (Network)      + overlap edges + SELF-KEY (Pattern 6, mask = CRC of a
                         guard section's own bytes)
  level 3 (All-to-All)   all-to-all topology + ANTI-DEBUG<->CHECKSUM (Pattern 5)
                         using the REAL protection/anti-debug adbg library: the
                         whole adbg detection code is placed in section g_adbg
                         (CRC'd by a guard) AND a probe calling it runs on the
                         integrity path (debugger -> taint). Both routes.

Patterns from the design notes:
  1 Aucsmith IVK ring      — guard_i runtime-CRCs guard_{i+1}'s section, cyclic
  2 Chang-Atallah guard net— multi-guard mutual checking, region overlap (scales
                            with level: ring -> +overlap -> all-to-all)
  7 tamper response (poison)— on mismatch, set _integrity_taint (NEVER trap); the
                            license-check call site is wrapped so a tainted run
                            corrupts the key -> the check fails -> "Invalid key"
  6 self-key from own bytes— (L2+) the corruption mask is the CRC of a guard
                            section, i.e. deterministic from the protected bytes
  5 anti-debug <-> checksum— (L3) real protection/anti-debug adbg in g_adbg,
                            covered by a guard's CRC AND called on the integrity
                            path; changing/removing it trips both routes
  4 integrity<->obfuscation— approximated: the guard code is single-file,
                            self-contained, obfuscator-friendly (run it through
                            tigress/xollvm to realize the VM/obfuscation layer)
Pattern 3 (environmentally-keyed packer) is intentionally NOT implemented.

USAGE
  python3 interlock_gen.py --input src.c --emit src_il.c [--num-guards 4]
                           [--level 1|2|3] [--seed N] [--wrap validate_input]
  # writes src_il.c (instrumented) + src_il.ilmanifest.json (for the patcher)
  # at level 3 also copies protection/anti-debug/{adbg.c,adbg.h} next to src_il.c
"""
import argparse
import json
import os
import re
import shutil
import sys

# Must match interlock_patch.py::crc32_bytes and the emitted C il_crc32 EXACTLY.
CRC_POLY = 0xEDB88320

# Header marker the patcher locates (struct _il_hdr in the emitted C).
SENTINEL = 0xC1C0FFEE_D15EA5ED  # uint64
MAGIC2   = 0x494C0001           # uint32  ('IL' + version)


# ---------------------------------------------------------------- topology ----

def build_nodes(num_guards, functions):
    """Section tags of all guard nodes (synthetic + any user-named extras)."""
    nodes = [f"g_s{i}" for i in range(num_guards)]
    for fn in functions:
        tag = "g_" + re.sub(r"[^A-Za-z0-9_]", "_", fn)
        if tag not in nodes:
            nodes.append(tag)
    return nodes


def build_edges(nodes, level, seed):
    """Ordered list of CRC edges (guard_tag -> target_tag). Each edge = one
    expected[] entry; the index in this list is the index into expected[]."""
    n = len(nodes)
    edges = []

    # Pattern 1: ring  guard_i -> guard_{i+1}  (all levels)
    for i in range(n):
        edges.append((nodes[i], nodes[(i + 1) % n]))

    # Integrity canary: a pure-DATA region (no code lives here). Always present.
    # Tampering it is detected cleanly by guard_0 (its own bytes are never
    # executed) -> deterministic clean rejection at every level.
    edges.append((nodes[0], "g_canary"))

    if level >= 2:
        # Pattern 2: extra overlap edges guard_i -> guard_{i+2}
        for i in range(n):
            edges.append((nodes[i], nodes[(i + 2) % n]))

    if level >= 3:
        # Pattern 2 (extreme): all-to-all among guard nodes
        for g in nodes:
            for t in nodes:
                if g != t:
                    edges.append((g, t))
        # Pattern 5: a guard covers the real anti-debug section (g_adbg).
        edges.append((nodes[0], "g_adbg"))

    # de-dup preserving order
    seen, uniq = set(), []
    for e in edges:
        if e not in seen:
            seen.add(e)
            uniq.append(e)
    return uniq


def fixed_mask(seed):
    """Deterministic nonzero mask for the level-1 (fixed-mask) poison response."""
    m = (0x12345678 ^ ((seed & 0xFFFFFFFF) * 0x9E3779B9)) & 0xFFFFFFFF
    return m if m != 0 else 0xDEADBEEF


# ----------------------------------------------------------------- C emit -----

C_PRELUDE = r"""/* ===== BEGIN interlock guard network (auto-generated by interlock_gen.py) =====
 * Level {LEVEL}: {LEVELDESC}
 * Patterns: 1 Aucsmith ring | 2 Chang-Atallah guard net | 7 poison tamper response
 *           (+6 self-key L2+) (+5 anti-debug<->checksum L3, real protection/anti-debug)
 * Do not hand-edit. Expected checksums are embedded post-compile by interlock_patch.py.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CRC32 — must match common.crc32_bytes bit-for-bit. */
static uint32_t il_crc32(const uint8_t *p, size_t n) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc ^= p[i];
        for (int k = 0; k < 8; k++)
            crc = (crc >> 1) ^ ((crc & 1u) ? 0xEDB88320u : 0u);
    }
    return crc ^ 0xFFFFFFFFu;
}

/* Pattern 7: tamper response is a poison flag, NEVER a trap. */
volatile uint32_t _integrity_taint = 0u;

/* Header located + rewritten by interlock_patch.py:
 *   u64 sentinel | u32 magic | u32 count | u32 expected[count]
 * Living in .data (non-const) so the patcher can overwrite expected[] in place. */
#define IL_NCHECK @@NCHECK@@
struct _il_header {
    uint64_t sentinel;
    uint32_t magic;
    uint32_t count;
    uint32_t expected[IL_NCHECK];
};
struct _il_header _il_hdr = {
    0xC1C0FFEED15EA5EDull, 0x494C0001u, IL_NCHECK, {0}
};
"""

# Pattern 5 (level 3): the REAL anti-debug library (protection/anti-debug)
# amalgamated into this TU and placed wholesale in section g_adbg, so a guard
# CRCs the actual detection code. ADBG_SECTION_NAME is the opt-in hook that
# adbg.c's ADBG_SECTION_ATTR macro reads (undefined = normal .text).
C_ADBG = r"""
#define ADBG_SECTION_NAME "g_adbg"
#include "adbg.c"
/* Probe wrapper: reuses the real adbg detection. ADBG_CHECK_ADVANCED = all
 * checks EXCEPT ptrace (ptrace self-traces the process via PTRACE_TRACEME,
 * destructive on repeat calls / external tracers). adbg_check_mask only RETURNS,
 * never exits in-process. */
__attribute__((noinline, used, section("g_adbg")))
static uint32_t il_adbg_probe(void) {
    return adbg_check_mask(ADBG_CHECK_ADVANCED) ? 0xDB6AD06Bu : 0u;
}
"""


def canary_bytes(seed, n=64):
    import random
    rng = random.Random(seed ^ 0x5A5A5A5A)
    return [rng.randrange(256) for _ in range(n)]


def emit_extern_decls(tags):
    """Top-level extern decls for the ld-provided section boundary symbols."""
    lines = ["/* section boundary symbols auto-provided by ld */"]
    for t in tags:
        lines.append(f"extern uint8_t __start_{t}[], __stop_{t}[];")
    return "\n".join(lines)


def emit_mask_block(level, seed, s0_tag):
    """Emit the mask helper whose definition depends on level:
       L1 = fixed-mask poison (Pattern 7 only); L2+ = self-key (Pattern 6)."""
    if level >= 2:
        return (
            "/* Pattern 6 (level 2+): self-key — corruption mask = CRC of guard\n"
            f" * section {s0_tag}'s own bytes (deterministic from the protected code). */\n"
            f"static uint32_t il_derive_mask(void) {{\n"
            f"    extern uint8_t __start_{s0_tag}[], __stop_{s0_tag}[];\n"
            f"    return il_crc32(__start_{s0_tag}, "
            f"(size_t)(__stop_{s0_tag} - __start_{s0_tag}));\n"
            "}\n"
            "static uint32_t il_mask(void) { return il_derive_mask(); }\n"
        )
    m = fixed_mask(seed)
    return (
        "/* Pattern 7 (level 1): fixed-mask poison (no self-key yet). */\n"
        f"static uint32_t il_mask(void) {{ return 0x{m:08X}u; }}\n"
    )


def emit_guard(i, tag, my_edges, edge_index, debug):
    """One guard function in section <tag>; performs its CRC edges."""
    body = []
    body.append(f"/* guard {i}: section {tag}, {len(my_edges)} CRC check(s) */")
    for (g, t), idx in my_edges:
        body.append("{")
        body.append(f"    extern uint8_t __start_{t}[], __stop_{t}[];")
        body.append(
            f"    uint32_t c = il_crc32(__start_{t}, "
            f"(size_t)(__stop_{t} - __start_{t}));"
        )
        body.append(
            f"    if (c != _il_hdr.expected[{idx}]) _integrity_taint |= 0x02u;"
        )
        if debug:
            body.append(
                f"    if (getenv(\"IL_DEBUG\")) fprintf(stderr, "
                f"\"[guard{idx}] {t}: got=0x%08x want=0x%08x len=%lu\\n\", "
                f"c, _il_hdr.expected[{idx}], "
                f"(unsigned long)(__stop_{t} - __start_{t}));"
            )
        body.append("}")
    return (
        f'__attribute__((noinline, used, section("{tag}")))\n'
        f"static void il_guard_{i}(void) {{\n"
        + "\n".join(body)
        + "\n}\n"
    )


LEVEL_DESC = {
    1: "ring + poison (fixed mask)",
    2: "ring + network + self-key",
    3: "all-to-all + self-key + real anti-debug<->checksum",
}


def emit_run_verify(level, calls, debug, verify_static, call_name):
    """Emit interlock_run() + interlock_verify(). interlock_run calls every guard
    and (L3) the adbg probe; interlock_verify corrupts the key with il_mask() on
    taint so the real license check rejects it. call_name is the wrapped
    license-entry function (gen_verification's `validate_input`; the historical
    `verify` is accepted for older trees)."""
    probe_call = "    if (il_adbg_probe() != 0u) _integrity_taint |= 0x01u;\n" if level >= 3 else ""
    run_debug = ('    if (getenv("IL_DEBUG")) fprintf(stderr, '
                 '"[interlock] taint=0x%08x\\n", _integrity_taint);') if debug else ""
    link = "static " if verify_static else ""
    # extern "C"-guarded: the block is prepended into the carrier TU, which
    # is C++ for some tasks (stk) -- a plain decl there would take C++
    # linkage and conflict with verification.h's extern "C" declaration
    verify_decl = (
        '#ifdef __cplusplus\nextern "C" {\n#endif\n'
        f'{link}int {call_name}(const char *);  '
        f'/* forward: the real license check (gen_verification); '
        f'linkage matches the source */\n'
        '#ifdef __cplusplus\n}\n#endif')
    return f"""
/* Run every guard{'+ the real adbg probe' if level >= 3 else ''}. */
void interlock_run(void) {{
{probe_call}{chr(10).join(calls)}
{run_debug}}}

/* Pattern 7 wrap: on taint, corrupt the key with il_mask() so the real license
 * check rejects it ("Invalid key"). Untainted -> the call passes through. */
{verify_decl}
static int interlock_{call_name}(const char *key) {{
    interlock_run();
    if (_integrity_taint) {{
        char buf[256];
        size_t n = 0;
        while (n + 1 < sizeof(buf) && key[n] != '\\0') {{ buf[n] = key[n]; n++; }}
        uint32_t m = il_mask();
        for (size_t i = 0; i < n; i++)
            buf[i] = (char)((uint8_t)buf[i] ^ (uint8_t)(m >> ((i % 4) * 8)));
        buf[n] = '\\0';
        return {call_name}(buf);
    }}
    return {call_name}(key);
}}
"""


def emit_interlock_block(nodes, edges, level, debug, seed, verify_static=False,
                         call_name="validate_input"):
    """Assemble the full injected C block.

    verify_static: whether the user's real license check is declared 'static'
    in the source. The forward declaration emitted here MUST match that
    linkage, or gcc rejects the file. gen_verification emits non-static; some
    hand-written sources use 'static' — detect and match both."""
    nchecks = len(edges)
    s0 = nodes[0]
    # extra CRC'd sections beyond the guard nodes: canary always; g_adbg at L3.
    extra_sections = ["g_canary"] + (["g_adbg"] if level >= 3 else [])

    out = []
    out.append(C_PRELUDE.replace("@@NCHECK@@", str(nchecks))
                        .replace("{LEVEL}", str(level))
                        .replace("{LEVELDESC}", LEVEL_DESC[level]))
    out.append(emit_extern_decls(list(nodes) + extra_sections))

    cb = canary_bytes(seed)
    cstr = ", ".join(f"0x{b:02x}u" for b in cb)
    out.append(
        "/* Integrity canary: pure-data region (no code). Tampering it is detected\n"
        " * cleanly by guard_0, with no chance of crashing the detecting guard. */\n"
        '__attribute__((used, section("g_canary")))\n'
        f"volatile uint8_t il_canary[{len(cb)}] = {{ {cstr} }};\n"
    )

    if level >= 3:
        out.append(C_ADBG)

    out.append(emit_mask_block(level, seed, s0))

    # index every edge
    edge_index = {e: i for i, e in enumerate(edges)}
    by_guard = {}
    for (g, t) in edges:
        by_guard.setdefault(g, []).append((g, t))

    calls = []
    gi = 0
    for tag in nodes:
        if tag in by_guard:
            my = [(e, edge_index[e]) for e in by_guard[tag]]
            out.append(emit_guard(gi, tag, my, edge_index, debug))
            calls.append(f"    il_guard_{gi}();")
            gi += 1

    out.append(emit_run_verify(level, calls, debug, verify_static, call_name))
    return "\n".join(out)


# --------------------------------------------------------------- wrapping -----

def wrap_verify_calls(src, call_name):
    """Replace CALL sites of <call_name>( with interlock_<call_name>(, leaving
    the definition and forward declarations untouched."""
    pat = re.compile(r"(?<![A-Za-z0-9_])(" + re.escape(call_name) + r")\s*\(")
    type_prefix = re.compile(
        r"\b(int|void|unsigned|static|const|char|size_t|uint32_t|long|short|float|double|bool)\b"
        r"(\s|\*)*$"
    )

    def repl(m):
        start = m.start()
        # inspect the 24 chars of source immediately before the match
        pre = src[max(0, start - 24):start]
        if type_prefix.search(pre):
            return m.group(0)  # looks like a definition / declaration -> skip
        return "interlock_" + m.group(1) + "("

    return pat.sub(repl, src)


def copy_adbg_libs(emit_path):
    """Level 3: copy protection/anti-debug/{adbg.c,adbg.h} next to the emitted
    source so `#include "adbg.c"` resolves at compile time. Works in both local
    and Docker (/protection) layouts (adbg sits at ../anti-debug/ relative to
    this script)."""
    here = os.path.dirname(os.path.abspath(__file__))
    adbg_dir = os.path.normpath(os.path.join(here, "..", "anti-debug"))
    dest_dir = os.path.dirname(os.path.abspath(emit_path))
    for name in ("adbg.c", "adbg.h"):
        src = os.path.join(adbg_dir, name)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(dest_dir, name))
        else:
            print(f"warning: {src} not found; level-3 adbg include will not "
                  f"resolve at compile time", file=sys.stderr)


# ------------------------------------------------------------------- main -----

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--input", required=True, help="input C source")
    ap.add_argument("--emit", required=True, help="output instrumented C source")
    ap.add_argument("--num-guards", type=int, default=4,
                    help="number of synthetic guard nodes (default 4)")
    ap.add_argument("--functions", default="",
                    help="comma-separated extra named guard nodes (informational; "
                         "adds named section nodes, does not modify your functions)")
    ap.add_argument("--level", type=int, default=2, choices=(1, 2, 3),
                    help="1=ring+poison, 2=+network+self-key, "
                         "3=+all-to-all+real-anti-debug (default 2)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--wrap", default="validate_input",
                    help="license-check call name to wrap (default "
                         "'validate_input', gen_verification's neutral carrier "
                         "name; older trees used 'verify')")
    ap.add_argument("--debug", action="store_true",
                    help="emit getenv(\"IL_DEBUG\")-gated stderr diagnostics in guards")
    args = ap.parse_args()

    with open(args.input) as f:
        src = f.read()

    # Detect the real license check's linkage so the forward declaration we
    # emit matches it (static vs extern) — a mismatch fails to compile.
    verify_static = bool(
        re.search(r"\bstatic\s+int\s+" + re.escape(args.wrap) + r"\s*\(", src)
    )

    functions = [x.strip() for x in args.functions.split(",") if x.strip()]
    nodes = build_nodes(args.num_guards, functions)
    edges = build_edges(nodes, args.level, args.seed)

    block = emit_interlock_block(nodes, edges, args.level, args.debug, args.seed,
                                 verify_static=verify_static,
                                 call_name=args.wrap)
    instrumented = wrap_verify_calls(src, args.wrap)
    if "interlock_" + args.wrap not in instrumented:
        print(f"warning: no {args.wrap}() call site found to wrap; guards will "
              f"compile but are not wired to the license path", file=sys.stderr)

    with open(args.emit, "w") as f:
        f.write(block)
        f.write("\n/* ===== original source (verify calls wrapped) ===== */\n")
        f.write(instrumented)
        f.write("\n/* ===== END interlock guard network ===== */\n")

    if args.level >= 3:
        copy_adbg_libs(args.emit)

    # manifest for interlock_patch.py: ordered target tags -> expected[] index
    extra_sections = ["g_canary"] + (["g_adbg"] if args.level >= 3 else [])
    manifest = {
        "sentinel": SENTINEL,
        "magic": MAGIC2,
        "header_struct": "struct _il_header { uint64_t sentinel; uint32_t magic; "
                         "uint32_t count; uint32_t expected[count]; }",
        "expected_offset_in_struct": 16,
        "checks": [{"index": i, "guard": g, "target": t} for i, (g, t) in enumerate(edges)],
        "nodes": nodes + extra_sections,
        "level": args.level,
        "seed": args.seed,
    }
    manifest_path = os.path.splitext(args.emit)[0] + ".ilmanifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    nsec = len(nodes) + len(extra_sections)
    print(f"wrote {args.emit}")
    print(f"wrote {manifest_path} ({len(edges)} CRC checks, {nsec} sections)")


if __name__ == "__main__":
    main()
