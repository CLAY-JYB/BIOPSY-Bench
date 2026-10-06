#!/usr/bin/env python3
"""
Anti-Debug Code Injection Tool for C Files
Automatically injects anti-debugging code into C source files with configurable detection methods

================================================================================
USAGE EXAMPLES
================================================================================

# Basic injection (all detection methods, exit on detection):
./anti-debug.py program.c

# Use specific detection methods:
./anti-debug.py program.c --checks ptrace tracer_pid
./anti-debug.py program.c -k parent gdb sigtrap

# Use predefined combinations:
./anti-debug.py program.c --checks stealth      # Stealth mode (no ptrace)
./anti-debug.py program.c --checks standard      # Standard protection
./anti-debug.py program.c --checks advanced     # All except ptrace

# Report only, don't exit on detection:
./anti-debug.py program.c --action none

# Silent mode (no debug output):
./anti-debug.py program.c --quiet

# Inject and copy library files:
./anti-debug.py program.c --copy-libs

# Only copy library files (no injection):
./anti-debug.py program.c --mode library

# Multiple files:
./anti-debug.py *.c --checks basic

# Compile the result (adbg.c is amalgamated into the source via #include,
# so the program's own build compiles it — no separate adbg.c on the link line):
gcc program.c -o program

================================================================================
DETECTION METHODS (10 Individual Methods)
================================================================================

INDIVIDUAL METHODS:
  ld_preload           LD_PRELOAD environment variable detection
  gdb                  GDB-specific fingerprints (env vars, file descriptors)
  parent               Parent process name check (gdb, ltrace, strace, valgrind, etc.)
  tracer_pid           TracerPid check via /proc/self/status
  sigtrap              SIGTRAP signal handling detection
  ptrace               ptrace syscall detection (direct syscall, not libc ptrace)
  proc_maps            /proc/self/maps injected library detection (frida, memfd, ...)
  breakpoint           Software breakpoint detection (INT3 instruction)
  timing               Timing-based detection (single-step detection)
  frida                Frida/dynamic instrumentation detection (maps, thread
                       names, default port 27042)

PREDEFINED COMBINATIONS:
  basic                ptrace + tracer_pid (fast, basic detection)
  advanced             All methods except ptrace (for when ptrace is hooked)
  stealth              tracer_pid + parent + sigtrap (no ptrace, stealthy)
  standard             ptrace + tracer_pid + parent + gdb (common debuggers)
  all                  All 10 detection methods (maximum protection)

================================================================================
INJECTION POINTS
================================================================================

  --target-function F  Insert the check as the first statement of F (default main)
  --insert-at-call FN  Insert the check immediately before the FIRST call site of
                       FN (e.g. verify) — the license-check path. This is the
                       most robust anchor for generated code: gen_verification
                       always injects a verify(...) call, while the verify-bearing
                       file may not contain main() at all (e.g. gameclient.cpp).
                       Falls back to --target-function when no call site exists
                       ONLY if --target-function also matches; otherwise exits 1.

  --harden             Also call adbg_apply_hardening() before the checks:
                       prctl(PR_SET_DUMPABLE, 0) + madvise(MADV_DONTDUMP) on
                       writable private mappings (anti-dump). No OSS packer
                       ships this; it is one syscall per region.

  --debug-blocker      Also start the self-ptrace DebugBlocker before the
                       checks: a forked child PTRACE_ATTACHes this process
                       and forwards every signal stop back, consuming the
                       one tracer slot so gdb/strace/frida can never attach.
                       Killing the child kills the program (PTRACE_O_EXITKILL).
                       Known limitation (kernel 5.4): a layout-sensitive
                       resume race can wedge programs that sleep immediately
                       after the blocker engages with buffered stdout; the
                       pipeline's stdin->verify->printf pattern is unaffected.

================================================================================
ACTIONS
================================================================================

  exit                 Exit with code 1 when debugger detected [default]
  abort                Call abort() when debugger detected
  none                 Report only, continue execution (for logging/testing)

================================================================================
MODES
================================================================================

  include              Inject #include "adbg.c" (amalgamation) + detection code [default]
  inline               Inject standalone detection code (no external files)
  library              Only copy adbg.h and adbg.c to target directory
"""

import argparse
import os
import re
import shutil
import sys
from pathlib import Path


# Detection method mappings
CHECK_FLAGS = {
    'ld_preload': 'ADBG_CHECK_LD_PRELOAD',
    'gdb': 'ADBG_CHECK_GDB',
    'parent': 'ADBG_CHECK_PARENT',
    'tracer_pid': 'ADBG_CHECK_TRACER_PID',
    'sigtrap': 'ADBG_CHECK_SIGTRAP',
    'ptrace': 'ADBG_CHECK_PTRACE',
    'proc_maps': 'ADBG_CHECK_PROC_MAPS',
    'breakpoint': 'ADBG_CHECK_BREAKPOINT',
    'timing': 'ADBG_CHECK_TIMING',
    'frida': 'ADBG_CHECK_FRIDA',
}

# Predefined combinations
CHECK_COMBOS = {
    'basic': 'ADBG_CHECK_BASIC',
    'advanced': 'ADBG_CHECK_ADVANCED',
    'stealth': 'ADBG_CHECK_STEALTH',
    'standard': 'ADBG_CHECK_STANDARD',
    'all': 'ADBG_CHECK_ALL',
}

# Action mappings
ACTION_FLAGS = {
    'exit': 'ADBG_ACTION_EXIT',
    'abort': 'ADBG_ACTION_ABORT',
    'none': 'ADBG_ACTION_NONE',
}


# Anti-debug include that will be added. We #include the IMPLEMENTATION
# (adbg.c), not the header, so the detection code is AMALGAMATED into the
# target translation unit. This means the program's own build system (make,
# cmake, ...) compiles it as part of the modified source — there is no need to
# add adbg.c to the build's source list or link line (which would require
# per-build-system Makefile patching and is impossible to do generically).
# adbg.c still #includes adbg.h (guarded), so --copy-libs must place both
# files next to the target. The result compiles with just: gcc target.c -o target
ADBG_INCLUDE = '#include "adbg.c"\n'

# Simple check code (for basic usage)
ADBG_CHECK_SIMPLE = """    // Anti-debug check
    if (adbg_check_all()) {
        fprintf(stderr, "Debugger detected! Exiting.\\n");
        return 1;
    }

"""

# Advanced check code with configuration
ADBG_CHECK_CONFIG = """    // Anti-debug check with configuration
    adbg_config_t config;
    adbg_init_config(&config, %s, %s);
    config.verbose = %d;
    adbg_detect(&config);

"""

# Full inline anti-debug code (for standalone mode)
INLINE_ADBG_CODE = """
// ===== Anti-Debug Detection Code (Inline) =====
#include <sys/ptrace.h>

#ifndef PTRACE_TRACEME
#define PTRACE_TRACEME          0
#endif

// Simple ptrace-based debugger detection
static int check_debugger(void) {
    if (ptrace((__ptrace_request)PTRACE_TRACEME, 0, NULL, NULL) < 0) {
        return 1;  // Debugger detected
    }
    return 0;  // No debugger
}
// ===== End Anti-Debug Code =====
"""


def find_main_function(content: str):
    """
    Find the main function and return (start_line, brace_line).
    Returns (None, None) if not found.
    """
    return find_function_by_name(content, 'main')


def find_function_by_name(content: str, func_name: str):
    """
    Find a function DEFINITION by name and return (start_line, brace_line)
    (1-indexed). Returns (None, None) if not found.

    Skips prototypes / forward declarations ("type func(...);") so a
    declaration earlier in the file cannot be mistaken for the definition —
    same rule as tigress_prep.py / xollvm_prep.py.
    """
    lines = content.split('\n')

    # Pattern for function declaration - handles various return types
    # Matches: type func_name(, type *func_name(, etc.
    func_pattern = re.compile(
        rf'^\s*([\w\s\*]+)?\b{re.escape(func_name)}\s*\(',
        re.MULTILINE
    )

    for i, line in enumerate(lines):
        if func_pattern.search(line):
            # Skip prototypes / forward declarations.
            if re.search(r'\)\s*;\s*$', line):
                continue
            # Found function declaration, now find the opening brace
            for j in range(i, min(i + 5, len(lines))):
                if '{' in lines[j]:
                    return (i + 1, j + 1)  # Convert to 1-indexed

    return (None, None)


def find_first_call_site(content: str, func_name: str):
    """
    Find the first CALL SITE of func_name(...) — a line that calls it, not a
    declaration/definition of it. Returns the 1-indexed line number, or None.

    A call site line matches "<name>(" but is NOT preceded by a type keyword
    (which would make it a declaration) and does not end with ';' on the same
    line as a standalone prototype. Good enough for generated code where the
    verify() call is injected on its own line.
    """
    lines = content.split('\n')
    call_pattern = re.compile(rf'(?<![A-Za-z0-9_]){re.escape(func_name)}\s*\(')
    type_prefix = re.compile(
        r"\b(int|void|unsigned|static|const|char|size_t|uint32_t|long|short|float|double|bool)\b"
        r"(\s|\*)*$"
    )
    for i, line in enumerate(lines):
        if not call_pattern.search(line):
            continue
        # A definition/declaration line starts (after whitespace) with a type
        # before the name — same heuristic as interlock_gen.wrap_verify_calls.
        prefix = line[:call_pattern.search(line).start()]
        if type_prefix.search(prefix):
            continue
        return i + 1
    return None


def insert_include(content: str) -> str:
    """Insert #include "adbg.c" (amalgamation) after other includes."""
    lines = content.split('\n')

    # Find the last #include line
    last_include = -1
    for i, line in enumerate(lines):
        if line.strip().startswith('#include'):
            last_include = i

    if last_include >= 0:
        # Insert after the last include
        lines.insert(last_include + 1, ADBG_INCLUDE.strip())
    else:
        # No includes found, insert at the beginning
        lines.insert(0, ADBG_INCLUDE.strip())

    return '\n'.join(lines)


def insert_check_in_main(content: str, check_code: str):
    """Insert anti-debug check at the start of main()."""
    return insert_check_in_function(content, check_code, 'main')


def insert_check_in_function(content: str, check_code: str, func_name: str):
    """Insert anti-debug check at the start of the specified function.

    Returns (new_content, inserted_bool) — inserted is False when the
    function cannot be located, so the caller can FAIL LOUDLY instead of
    silently shipping a binary whose anti-debug never runs.
    """
    lines = content.split('\n')
    func_start, func_brace = find_function_by_name(content, func_name)

    if func_start is None:
        return content, False

    # Insert after the opening brace of the function
    insert_pos = func_brace
    while insert_pos < len(lines) and '{' not in lines[insert_pos - 1]:
        insert_pos += 1

    if insert_pos < len(lines):
        lines.insert(insert_pos, check_code.rstrip())
        return '\n'.join(lines), True

    return content, False


def insert_check_before_call(content: str, check_code: str, call_name: str):
    """Insert anti-debug check immediately BEFORE the first call site of
    call_name() — the license-check path when call_name == verify.

    Handles the one-liner case where the call sits on the SAME line as the
    enclosing function's opening brace (e.g. ``int main(){ return verify(k); }``):
    naive "insert before the line" would place the statements at file scope.
    When a ``{`` precedes the call on that line, the check goes right after
    the brace instead.

    Returns (new_content, inserted_bool).
    """
    line_no = find_first_call_site(content, call_name)
    if line_no is None:
        return content, False
    lines = content.split('\n')
    call_line = lines[line_no - 1]
    indent = call_line[:len(call_line) - len(call_line.lstrip())]
    code = check_code.rstrip().lstrip()

    call_pattern = re.compile(rf'(?<![A-Za-z0-9_]){re.escape(call_name)}\s*\(')
    m = call_pattern.search(call_line)
    brace_idx = call_line.rfind('{', 0, m.start())
    if brace_idx != -1:
        # Call and opening brace share a line: split it open and put the
        # check as the first statement of the body.
        lines[line_no - 1] = (call_line[:brace_idx + 1]
                              + '\n' + indent + '    ' + code
                              + '\n' + indent + call_line[brace_idx + 1:].lstrip())
    else:
        lines.insert(line_no - 1, indent + code)
    return '\n'.join(lines), True


def resolve_checks(checks: list) -> tuple:
    """
    Resolve detection methods to flag combination.
    Returns (flag_expression, is_single_flag)
    """
    if not checks or 'all' in checks:
        return ('ADBG_CHECK_ALL', True)

    # Check if using predefined combo
    if len(checks) == 1 and checks[0] in CHECK_COMBOS:
        return (CHECK_COMBOS[checks[0]], True)

    # Build custom combination
    flags = []
    for check in checks:
        if check in CHECK_FLAGS:
            flags.append(CHECK_FLAGS[check])
        elif check in CHECK_COMBOS:
            flags.append(CHECK_COMBOS[check])

    if not flags:
        return ('ADBG_CHECK_ALL', True)

    if len(flags) == 1:
        return (flags[0], True)
    else:
        return (' | '.join(flags), False)


def resolve_action(action: str) -> str:
    """Resolve action to flag."""
    return ACTION_FLAGS.get(action, 'ADBG_ACTION_DEFAULT')


def inject_include_mode(target_file: Path, copy_libs: bool = False,
                       checks: list = None, action: str = 'exit',
                       verbose: bool = False, target_function: str = 'main',
                       insert_at_call: str = None, harden: bool = False,
                       debug_blocker: bool = False):
    """Inject include and check call into target file.

    Returns True on success. Failure to place the check (no anchor found)
    returns False — the pipeline treats that as a broken protection layer,
    NOT as a warning: a binary whose adbg code is amalgamated but never
    called has zero anti-debug while claiming D>0.
    """
    print(f"[*] Processing {target_file}...")

    # Read the target file
    with open(target_file, 'r') as f:
        content = f.read()

    # Check if already has the anti-debug amalgamation include
    if '#include "adbg.c"' in content:
        print(f"[-] {target_file} already includes adbg.c, skipping include insertion")
    else:
        content = insert_include(content)
        print(f"[+] Inserted #include \"adbg.c\" (amalgamates detection code into this TU)")

    # Check if already has anti-debug check
    if 'adbg_check' in content or 'adbg_detect' in content:
        print(f"[-] {target_file} already has anti-debug check, skipping")
        return True

    # Determine which check code to use
    if checks is None or (len(checks) == 1 and checks[0] == 'all'):
        # Use simple check for default
        check_code = ADBG_CHECK_SIMPLE
    else:
        # Use config-based check
        check_expr, is_single = resolve_checks(checks)
        action_expr = resolve_action(action)
        check_code = ADBG_CHECK_CONFIG % (check_expr, action_expr, 1 if verbose else 0)

    if harden:
        # Anti-dump hardening before any check runs (prctl + madvise).
        # Must run BEFORE the debug blocker: a non-dumpable process denies
        # the blocker child's PTRACE_ATTACH too.
        check_code = "    adbg_apply_hardening();\n" + check_code

    if debug_blocker:
        # Self-ptrace DebugBlocker: consume the tracer slot. Returns 1 only
        # when a debugger already holds it (-1 = environment denied ptrace,
        # benign). Start it before the adbg checks: the blocker is the
        # strongest lever, and adbg_check_ptrace skips itself while the
        # blocker is active (our own child must not be "detected").
        check_code = ("    if (adbg_debug_blocker_start() == 1) return 1;\n"
                      + check_code)

    inserted = False
    anchor_desc = None
    if insert_at_call:
        content, inserted = insert_check_before_call(content, check_code, insert_at_call)
        anchor_desc = f"before first {insert_at_call}() call"
    if not inserted:
        content, inserted = insert_check_in_function(content, check_code, target_function)
        anchor_desc = f"at start of {target_function}()"

    # Write back (even on failure: the include was added above and the
    # operator may want to place the call manually after inspecting)
    with open(target_file, 'w') as f:
        f.write(content)

    if not inserted:
        tried = (f"--insert-at-call {insert_at_call} and "
                 f"--target-function {target_function}") if insert_at_call \
            else f"--target-function {target_function}"
        print(f"[!] Error: no injection anchor found in {target_file} "
              f"(tried {tried}); anti-debug check NOT inserted", file=sys.stderr)
        return False

    print(f"[+] Inserted anti-debug check {anchor_desc}")
    print(f"[+] Successfully modified {target_file}")
    return True


def inject_inline_mode(target_file: Path):
    """Inject full anti-debug code inline."""
    print(f"[*] Processing {target_file} in inline mode...")

    with open(target_file, 'r') as f:
        content = f.read()

    lines = content.split('\n')

    # Find includes section and insert after
    insert_pos = 0
    for i, line in enumerate(lines):
        if line.strip().startswith('#include'):
            insert_pos = i + 1

    lines.insert(insert_pos, INLINE_ADBG_CODE.strip())

    # Add check in main
    main_start, main_brace = find_main_function('\n'.join(lines))
    if main_brace is None:
        with open(target_file, 'w') as f:
            f.write('\n'.join(lines))
        print(f"[!] Error: no main() found in {target_file}; inline anti-debug "
              f"check NOT inserted", file=sys.stderr)
        return False
    inline_check = """    // Anti-debug check
    if (check_debugger()) {
        fprintf(stderr, "Debugger detected! Exiting.\\n");
        return 1;
    }
"""
    lines.insert(main_brace + 1, inline_check.rstrip())

    with open(target_file, 'w') as f:
        f.write('\n'.join(lines))

    print(f"[+] Successfully injected inline anti-debug code to {target_file}")
    return True


def copy_library_files(target_dir: Path, source_dir: Path = None):
    """Copy adbg.h and adbg.c to target directory."""
    if source_dir is None:
        source_dir = Path(__file__).parent

    adbg_h = source_dir / 'adbg.h'
    adbg_c = source_dir / 'adbg.c'

    if not adbg_h.exists():
        print(f"[-] {adbg_h} not found, cannot copy")
        return False

    if not adbg_c.exists():
        print(f"[-] {adbg_c} not found, cannot copy")
        return False

    # Copy files
    dest_h = target_dir / 'adbg.h'
    dest_c = target_dir / 'adbg.c'

    shutil.copy2(adbg_h, dest_h)
    shutil.copy2(adbg_c, dest_c)

    print(f"[+] Copied adbg.h to {dest_h}")
    print(f"[+] Copied adbg.c to {dest_c}")

    return True


def process_file(target_file: Path, mode: str = 'include', copy_libs: bool = False,
                 checks: list = None, action: str = 'exit', verbose: bool = False,
                 target_function: str = 'main', insert_at_call: str = None,
                 harden: bool = False, debug_blocker: bool = False):
    """Process a single C file. Returns True on success."""
    if not target_file.exists():
        print(f"[-] Error: {target_file} does not exist")
        return False

    target_dir = target_file.parent

    if mode == 'library':
        return copy_library_files(target_dir)
    elif mode == 'include':
        if copy_libs:
            copy_library_files(target_dir)
        return inject_include_mode(target_file, copy_libs, checks, action, verbose,
                                   target_function, insert_at_call, harden,
                                   debug_blocker)
    elif mode == 'inline':
        return inject_inline_mode(target_file)
    else:
        print(f"[-] Unknown mode: {mode}")
        return False


def print_usage_example():
    """Print usage examples."""
    print("\n=== Usage Examples ===")
    print("\n1. Basic injection (all checks, exit on detection):")
    print("   python3 anti-debug.py target.c")
    print("\n2. Custom detection methods:")
    print("   python3 anti-debug.py target.c --checks ptrace tracer_pid")
    print("\n3. Use predefined combination:")
    print("   python3 anti-debug.py target.c --checks stealth")
    print("\n4. Report only, don't exit:")
    print("   python3 anti-debug.py target.c --action none")
    print("\n5. Silent mode:")
    print("   python3 anti-debug.py target.c --quiet")
    print("\n6. Inject with library copy:")
    print("   python3 anti-debug.py target.c --copy-libs")
    print("\n7. Only copy library files:")
    print("   python3 anti-debug.py target.c --mode library")
    print("\n8. Compile with anti-debug support (adbg.c amalgamated via #include):")
    print("   gcc target.c -o target")
    print("\n=== Available Detection Methods ===")
    print("Individual: " + ", ".join(CHECK_FLAGS.keys()))
    print("\nCombinations: " + ", ".join(CHECK_COMBOS.keys()))
    print("\n=== Available Actions ===")
    print("Actions: " + ", ".join(ACTION_FLAGS.keys()))
    print("=")


def main():
    parser = argparse.ArgumentParser(
        description='Inject anti-debug code into C files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument('target', nargs='*', help='Target C file(s) to process')
    parser.add_argument('--mode', '-m',
                       choices=['include', 'inline', 'library'],
                       default='include',
                       help='Injection mode (default: include)')
    parser.add_argument('--copy-libs', '-c',
                       action='store_true',
                       help='Copy adbg.h and adbg.c to target directory')
    parser.add_argument('--checks', '-k',
                       nargs='+',
                       choices=list(CHECK_FLAGS.keys()) + list(CHECK_COMBOS.keys()),
                       help='Detection methods to use (default: all)')
    parser.add_argument('--action', '-a',
                       choices=list(ACTION_FLAGS.keys()),
                       default='exit',
                       help='Action on detection (default: exit)')
    parser.add_argument('--verbose', '-V',
                       action='store_true',
                       help='Emit verbose runtime logging in the generated code (prints '
                            'which check fired AND "No debugger detected" on clean runs — '
                            'an oracle for the analyst; default: silent)')
    parser.add_argument('--quiet', '-q',
                       action='store_true',
                       help='(Deprecated no-op — silent is now the default; kept so '
                            'existing invocations keep working)')
    parser.add_argument('--target-function', '-f',
                       default='main',
                       help='Target function to inject anti-debug code (default: main)')
    parser.add_argument('--insert-at-call', '-C',
                       default=None,
                       metavar='FUNC',
                       help='Insert the check immediately before the FIRST call site of '
                            'FUNC (e.g. verify) — the license-check path. Preferred over '
                            '--target-function for generated code: the verify-bearing '
                            'file may not contain main() at all (e.g. gameclient.cpp)')
    parser.add_argument('--harden', '-H',
                       action='store_true',
                       help='Also call adbg_apply_hardening() before the checks: '
                            'prctl(PR_SET_DUMPABLE,0) + madvise(MADV_DONTDUMP) anti-dump')
    parser.add_argument('--debug-blocker', '-B',
                       action='store_true',
                       help='Also start the self-ptrace DebugBlocker: a forked child '
                            'traces this process and forwards signals, so no external '
                            'debugger can ever attach. See the docstring for the '
                            'kernel-5.4 sleep-race limitation')
    parser.add_argument('--example', '-e',
                       action='store_true',
                       help='Print usage examples')

    args = parser.parse_args()

    if args.example:
        print_usage_example()
        return

    if not args.target:
        print("[-] Error: No target files specified")
        print("Use --help for usage information or --example for examples")
        sys.exit(1)

    failed = []
    for target in args.target:
        target_file = Path(target).resolve()
        if not process_file(target_file, args.mode, args.copy_libs,
                            args.checks, args.action, args.verbose,
                            args.target_function, args.insert_at_call, args.harden,
                            args.debug_blocker):
            failed.append(target)

    if args.mode != 'library':
        print("\n[*] Done! Compile your target with (adbg.c is amalgamated via #include):")
        print("    gcc <target.c> -o <target>")

    if failed:
        print(f"[!] FAILED on {len(failed)} file(s): {', '.join(failed)}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
