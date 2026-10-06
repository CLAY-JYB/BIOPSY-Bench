#!/usr/bin/env python3
"""pathway.py — build-time execution-pathway stamper (V2 verifier, 2026-09-18).

The pure-dynamic verifier scores an agent's trigger.bin against STAMPED
reference chains: for each stage probe (the real-gate adapter's probe
ladder, realgate.py) and the GT trigger, this tool single-steps the
just-built binary within the seeded
handler family's address ranges and records the ordered, deduplicated PC
chain plus the run's terminal observation (crash PC + signal, or exit
code). Chains are stamped into /gt BEFORE the verifier ever runs, so
verification-time cost is ONE traced run per binary (the agent's input).

Why single-step (not breakpoint scatter): the vm family EXPANDS the
handler into a per-function mega-body (verified empirically: 2289 unique
PCs, no hot interpreter loop), so PC-set membership is semantically rich
on every protection family. Failing records cost MORE steps than passing
ones (the walk-scan re-scans byte-by-byte) — bounded by STEP_CAP and the
outer timeout; the chain is whatever executed within the cap.

Usage (builder stage, post-strip):
  python3 pathway.py --binary /out/vuln_binary --map /gt/function_map_vuln.json \
      --family hook,seed_base,stage,+decoys,__vm_engine \
      --probes /builder-inputs/probes --argv '-c,@INPUT@' \
      --out /gt/pathway_vuln.json --timeout 90
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

# the gdb driver: BREAKPOINT SCATTER. Every instruction inside the
# family ranges (enumerated once via objdump) carries a breakpoint; the
# run proceeds at native speed and each hit records its own offset.
# This replaced the stepi walk (2026-09-29): under the virtual family a
# flattened dispatcher needs thousands of single-steps PER FUNCTION, and
# the tracer TIMEOUT truncated every probe's chain inside z_scan -- all
# probes stamped the same 247-PC prefix, the walk/check/store PCs never
# entered any chain, and every window past the scan level collapsed to
# empty (gzip/file agents covered the surviving scan windows at 100%
# and took the full 70-point ladder with tag-failing inputs).
_DRIVER = r'''
import gdb, re, subprocess, sys, time
RANGES = %r
LINKBASE = %d
BINPATH = %r
TIMEOUT = %d
gdb.execute("set confirm off")
gdb.execute("set pagination off")
gdb.execute("set disable-randomization on")
gdb.execute("set height 0")
gdb.execute("starti")
pid = gdb.selected_inferior().pid
base = None
for line in open("/proc/%%d/maps" %% pid):
    p = line.split(None, 5)
    if len(p) == 6 and p[5].strip().endswith(%r):
        base = int(p[0].split("-")[0], 16)
        break
if base is None:
    print("PDNOBASE")
    sys.exit(0)
lo = LINKBASE + min(a for a, b in RANGES)
hi = LINKBASE + max(b for a, b in RANGES)
out = subprocess.run(
    ["objdump", "-d", "--start-address=%%#x" %% lo,
     "--stop-address=%%#x" %% hi, BINPATH],
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout.decode(
        "utf-8", "replace")
ins = [int(m.group(1), 16) for m in re.finditer(r"^\s+([0-9a-f]+):",
                                                out, re.M)]
offs = sorted({v - LINKBASE for v in ins
               if any(a <= v - LINKBASE < b for a, b in RANGES)})
if not offs:
    print("PDNOBP")
    sys.exit(0)
hits = set()
class _Rec(gdb.Breakpoint):
    def __init__(self, addr, off):
        super().__init__("*%%#x" %% addr, gdb.BP_BREAKPOINT)
        self.off = off
        self.silent = True
    def stop(self):
        hits.add(self.off)
        return False
t0 = time.time()
for o in offs:
    try:
        _Rec(base + o, o)
    except gdb.error:
        pass
try:
    gdb.execute("continue", to_string=True)
except gdb.error:
    pass
print("PDCHAIN " + " ".join("%%x" %% p for p in sorted(hits)))
print("PDNBP %%d time %%.1fs" %% (len(offs), time.time() - t0),
      file=sys.stderr)
'''

# terminal observation: run to completion (no stepping) and capture the
# stop reason (signal + pc) or exit code. On a signal the stop frame is
# usually INSIDE libc (abort/assert paths): $pc there is layout-dependent
# arithmetic and register reads can fail wholesale. Walk up to the
# innermost frame still inside the binary's own mapping and anchor BOTH
# the fault pc and the register state there — deterministic for the same
# input, comparable across environments.
_TERM = r'''
import gdb, sys
gdb.execute("set confirm off")
gdb.execute("set pagination off")
gdb.execute("set disable-randomization on")
# scrub the inferior's execve env: the env block sits at the TOP of
# the initial stack, so a different env shifts every frame below it --
# a stack-overflow crash then lands on a different recursion frame
# with different registers between stamp time and replay time (the
# R2-sqlite B4 overlap 3/16 lesson)
gdb.execute("set exec-wrapper env -i " + %r)
gdb.execute("starti")
pid = gdb.selected_inferior().pid
try:
    r = gdb.execute("continue", to_string=True)
except gdb.error as e:
    pass
# CRASH-TIME MAPS: read the maps only AFTER the run has stopped. At
# starti under an exec-wrapper the loader has not necessarily exec'd
# the target yet, and the FIRST matching mapping's end (a read-only
# segment a few pages long) is not the binary's extent -- both made
# the build-side stamp record a nondeterministic huge pc while the
# identical replay in the verifier reproduced a stable offset (the
# R2-sqlite B1 lesson). Collect EVERY mapping of the target: base for
# offset math, and any-of-them as the in-binary test for the frame
# walk below.
base = None
bend = 0
stk_lo = stk_hi = 0
lib_lo = lib_hi = 0
try:
    seg_lo = []
    seg_hi = []
    for line in open("/proc/%%d/maps" %% pid):
        p = line.split(None, 5)
        name = p[5].strip() if len(p) == 6 else ""
        lo, hi = p[0].split("-")
        lo = int(lo, 16)
        hi = int(hi, 16)
        if len(p) == 6 and name.endswith(%r):
            seg_lo.append(lo)
            seg_hi.append(hi)
        if name == "[stack]":
            stk_lo, stk_hi = lo, hi
        if "libc.so.6" in name and not lib_lo:
            lib_lo, lib_hi = lo, hi
    if seg_lo:
        base = min(seg_lo)
        bend = max(seg_hi)
except (IOError, OSError):
    pass   # clean exit: the inferior is gone; only kind/code matter
# capture the raw stop state FIRST (deterministic under ASLR-off):
# anchor preference: innermost IN-BINARY frame (walk up); a smashed
# stack can make the walk fail, then fall back to the stop frame
stop_pc = None
stop_regs = []
try:
    stop_pc = int(gdb.parse_and_eval("$pc")) - base
except gdb.error:
    stop_pc = None
try:
    # info-registers text beats per-register parse_and_eval: at a fatal
    # signal stop the latter failed wholesale in the builder env (empty
    # regs), the former reads the same state without evaluation quirks
    _rt = gdb.execute(
        "info registers rax rbx rcx rdx rsi rdi rbp rsp "
        "r8 r9 r10 r11 r12 r13 r14 r15", to_string=True)
    for _l in _rt.splitlines():
        _p = _l.split()
        if len(_p) >= 2 and _p[1].startswith("0x"):
            # REGION-RELATIVE normalization (twin of pathway.py _TERM;
            # keep byte-identical): the stamp side runs where the build
            # container's seccomp blocks personality, so its ASLR stays
            # ON while this replay runs with randomization disabled --
            # raw pointer values can never match across the two worlds
            _v = int(_p[1], 16)
            if base and base <= _v < bend:
                stop_regs.append("T%%x" %% (_v - base))
            elif stk_lo and stk_lo <= _v < stk_hi:
                stop_regs.append("S%%x" %% (_v - stk_lo))
            elif lib_lo and lib_lo <= _v < lib_hi:
                stop_regs.append("L%%x" %% (_v - lib_lo))
            else:
                stop_regs.append(_p[1][2:])
except gdb.error:
    pass
found = None
for _ in range(60):
    try:
        pc = int(gdb.parse_and_eval("$pc"))
    except gdb.error:
        break
    if base <= pc < (bend or 0):
        found = pc - base
        break
    try:
        gdb.execute("up", to_string=True)
    except gdb.error:
        break
if stop_pc is None and found is None:
    print("PDTERM exit")
else:
    anchor = found if found is not None else stop_pc
    print("PDTERM sig pc=%%x regs=%%s" %% (anchor, ",".join(stop_regs)))
'''


def load_segments(binary):
    out = subprocess.run(["readelf", "-lW", binary],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL).stdout.decode(
                             "utf-8", "replace")
    segs = []
    for line in out.splitlines():
        m = re.match(r"\s*LOAD\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x[0-9a-f]+"
                     r"\s+0x([0-9a-f]+)", line)
        if m:
            segs.append((int(m.group(1), 16), int(m.group(2), 16),
                         int(m.group(3), 16)))
    return segs


def file_to_vaddr(binary, off):
    for fo, va, sz in load_segments(binary):
        if fo <= off < fo + sz:
            return va + (off - fo)
    return None


def run_gdb(binary, argv_rest, driver_text, timeout):
    fd, drv = tempfile.mkstemp(suffix=".pd.py")
    os.close(fd)
    try:
        with open(drv, "w") as f:
            f.write(driver_text)
        os.chmod(drv, 0o644)
        try:
            # gdb env: LSAN self-destructs under ptrace ("LeakSanitizer
            # does not work under ptrace" -- the inferior exits with
            # the LSAN error code before any breakpoint fires, and the
            # TRACER's chain comes back empty on every leak-carrying
            # carrier). The TERM twin re-scrubs its inferior through
            # the exec-wrapper, so its leak differential survives.
            r = subprocess.run(
                ["timeout", "-k", "5", str(timeout),
                 "env", "ASAN_OPTIONS=detect_leaks=0",
                 "gdb", "-nx", "-q",
                 "-batch", "-x", drv, "--args", binary] + list(argv_rest),
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=timeout + 15)
            return r.stdout.decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            return ""
    finally:
        try:
            os.unlink(drv)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--map", required=True,
                    help="funcevidence function map (name -> offset,size)")
    ap.add_argument("--family", required=True,
                    help="comma-separated family function names")
    ap.add_argument("--probes", required=True,
                    help="directory of <id>.bin probe inputs")
    ap.add_argument("--argv", required=True,
                    help="activation argv, comma-separated, @INPUT@")
    ap.add_argument("--out", required=True)
    ap.add_argument("--timeout", type=int, default=90)
    ap.add_argument("--step-cap", type=int, default=80000)
    ap.add_argument("--inferior-env", default="",
                    help="extra env assignments injected into the "
                         "scrubbed inferior environment (e.g. "
                         "USE_ZEND_ALLOC=0 -- the value rides the "
                         "exec-wrapper so stamp and replay match)")
    args = ap.parse_args()

    fmap = json.load(open(args.map))
    fns = fmap if isinstance(fmap, list) else fmap.get("functions", [])
    by_name = {f.get("name"): f for f in fns}
    family = [n for n in args.family.split(",") if n]
    # ranges over the family PLUS any unknown-but-adjacent seeded stages
    # (__vm_engine et al. ride the map too)
    names = list(family)
    for n in ("__vm_engine",):
        if n in by_name and n not in names:
            names.append(n)
    ranges = []
    entries = []
    missing = [n for n in names if n not in by_name]
    if missing and len(missing) == len(names):
        print("pathway: no family names found in map (%s...)" % names[:3],
              file=sys.stderr)
        return 1
    # runtime pc = load_base + (vaddr - link_base): link_base is the
    # ELF's own first PT_LOAD vaddr (readelf), NOT assumed equal to the
    # file offset -- thin-LTO layouts can shift segment alignment so
    # that vaddr - link_base != sh_offset (the first hard-draw: every
    # breakpoint landed one page below the family; chains stamped empty)
    link_base = None
    try:
        out = subprocess.run(["readelf", "-lW", args.binary],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL).stdout.decode()
        vas = [int(m.group(1), 16) for m in re.finditer(
            r"\s*LOAD\s+0x[0-9a-f]+\s+0x([0-9a-f]+)", out)]
        if vas:
            link_base = min(vas)
    except Exception:
        pass
    for n in names:
        f = by_name.get(n)
        if not f:
            continue
        va, size = f.get("vaddr", 0), f.get("size", 0)
        if link_base is not None and va:
            off = va - link_base
        else:
            off = f.get("offset", 0)
        ranges.append((off, off + size))
        entries.append(off)
    if not ranges:
        print("pathway: no resolvable family ranges", file=sys.stderr)
        return 1

    argv_tpl = [a for a in args.argv.split(",") if a]
    probes = sorted(f for f in os.listdir(args.probes) if f.endswith(".bin"))
    # REPLAY-PATH PARITY (R2 B4 law): the verifier's terminal replay
    # invokes /app/binaries/<vulnerable|patched> with the input staged
    # at /logs/artifacts/agent_output/trigger.bin. The argv and env
    # blocks sit at the TOP of the initial stack, so any length
    # difference shifts every frame below -- a crash whose registers
    # hold stack pointers (stack overflow, deep recursion) then shows
    # different GPR VALUES between stamp and replay and B4's overlap
    # collapses (3/16 on the R2 sqlite window-recursion case). Stage
    # the EXACT replay strings here: same binary path, same input path,
    # scrubbed env (the TERM twin's exec-wrapper). Python-side only --
    # the gdb driver strings stay byte-identical to the verifier twin.
    _bn = os.path.basename(args.binary)
    _side = "vulnerable" if "vuln" in _bn else "patched"
    try:
        os.makedirs("/app/binaries", exist_ok=True)
        _replay_bin = "/app/binaries/" + _side
        shutil.copyfile(args.binary, _replay_bin)
        os.chmod(_replay_bin, 0o755)
        os.makedirs("/logs/artifacts/agent_output", exist_ok=True)
        _stage = "/logs/artifacts/agent_output/trigger.bin"
        _parity_bin = _replay_bin
    except OSError:
        _parity_bin = args.binary   # host-side runs: unchanged behavior
        _stage = None
    chains = {}
    terminals = {}
    for pf in probes:
        pid = pf[:-4]
        path = os.path.join(args.probes, pf)
        if _stage:
            shutil.copyfile(path, _stage)
            path = _stage
        # substring semantics: the marker may ride INSIDE a token
        # (sqlite raw framing: ".read @INPUT@" is one argv element)
        argv_rest = [a.replace("@INPUT@", path) for a in argv_tpl]
        drv = (_DRIVER % (ranges, link_base or 0, _parity_bin,
                          args.timeout, os.path.basename(_parity_bin)))
        out = run_gdb(_parity_bin, argv_rest, drv, args.timeout)
        m = re.search(r"^PDCHAIN (.*)$", out, re.M)
        chain = [int(x, 16) for x in m.group(1).split()] if m else []
        chains[pid] = [hex(p) for p in chain]
        # terminal observation for every probe (crash pc / exit)
        tdrv = (_TERM % (args.inferior_env or "",
                     os.path.basename(_parity_bin)))
        tout = run_gdb(_parity_bin, argv_rest, tdrv, args.timeout)
        tm = re.search(r"^PDTERM sig pc=([0-9a-f]+) regs=([\da-zA-Z,]*)$", tout,
                       re.M)
        sm = re.search(r"(?:Program|Thread \d+ \"[^\"]*\") received signal (\w+)", tout)
        if tm and sm:
            terminals[pid] = {"kind": "signal", "sig": sm.group(1),
                              "pc": "0x%s" % tm.group(1),
                              "gprs": tm.group(2).split(",")}
        else:
            em = re.search(r"\[Inferior \d+ \(process \d+\) exited (\w+)\]",
                           tout)
            code = None
            if em:
                try:
                    code = int(em.group(1))
                except ValueError:
                    code = em.group(1)
            terminals[pid] = {"kind": "exit", "code": code}
        # plain-run output signature (exit code + normalized streams) for
        # the C3 comparison; the gdb wrapper must not perturb it
        try:
            pr = subprocess.run(
                ["timeout", "-k", "5", str(args.timeout),
                 _parity_bin] + argv_rest,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=args.timeout + 15)
            terminals[pid]["out"] = pr.stdout.decode("utf-8", "replace")[:4096]
            terminals[pid]["err"] = pr.stderr.decode("utf-8", "replace")[:4096]
            terminals[pid]["plain_rc"] = pr.returncode
        except subprocess.TimeoutExpired:
            terminals[pid]["out"] = ""
            terminals[pid]["err"] = ""
            terminals[pid]["plain_rc"] = None
        print("pathway: %s chain=%d term=%s" % (
            pid, len(chain), terminals[pid]["kind"]), file=sys.stderr)
    json.dump({"family": names,
               "ranges": [[hex(a), hex(b)] for a, b in ranges],
               "chains": chains,
               "terminals": terminals},
              open(args.out, "w"), indent=1)
    print("wrote %s (%d chains)" % (args.out, len(chains)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
