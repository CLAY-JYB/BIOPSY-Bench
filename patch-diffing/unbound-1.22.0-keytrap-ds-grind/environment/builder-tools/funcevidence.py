#!/usr/bin/env python3
"""
funcevidence.py — ground-truth changed-function maps from real builds.

Runs INSIDE the two Docker build stages (and in the host tests): it takes the
symbol-ful binary each stage just produced, dumps its function map via the
shared elfmap module, and stamps it to /gt. The verifier-side GT then merges
the two maps with the generator's role bookkeeping.

CLI (build-stage form):
    python3 funcevidence.py --binary <bin> --out /gt/function_map_vuln.json
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import elfmap  # noqa: E402
import fnhash  # noqa: E402


def stamp(binary, out_path, build_label):
    """Function map + normalized digests for one build."""
    elf = elfmap.load(binary)
    doc = {
        "build": build_label,
        "binary": os.path.basename(binary),
        "arch": elf.arch,
        "stripped": not elf.has_symbols(),
        "functions": elf.function_map(),
        "digests": fnhash.function_digests(binary),
    }
    with open(out_path, "w") as f:
        json.dump(doc, f, indent=2, sort_keys=True)
    return doc


def changed_between(map_a, map_b):
    """Changed/added/removed names from two stamped maps (name-matched)."""
    da = {f["name"]: f for f in map_a["functions"]}
    db = {f["name"]: f for f in map_b["functions"]}
    common = set(da) & set(db)
    changed = sorted(
        n for n in common
        if da[n]["size"] != db[n]["size"]
        or map_a["digests"].get(n, {}).get("seq") != map_b["digests"].get(n, {}).get("seq"))
    return {
        "changed": changed,
        "added": sorted(set(db) - set(da)),
        "removed": sorted(set(da) - set(db)),
    }


def main():
    ap = argparse.ArgumentParser(
        description="stamp a build's function map + digests as GT evidence")
    ap.add_argument("--binary", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", default="build")
    args = ap.parse_args()
    doc = stamp(args.binary, args.out, args.label)
    print("stamped %s: %d functions (%s)"
          % (args.out, len(doc["functions"]), args.label))
    return 0


if __name__ == "__main__":
    sys.exit(main())
