#!/usr/bin/env python3
"""
pageguard.py — page-granular on-demand decryption (source stage).

Implements the OSS-blank technique the packing research identified: no
maintained open-source ELF protector ships page-granular self-decrypting
code (Kiteshield's ptrace engine is abandoned and has a published unpacker;
mprotect+SIGSEGV is the classic pattern nobody maintains). This is the
source half of a two-stage tool:

  Stage 1 (this script, SOURCE stage, in-place):
      instruments verification.c —
        1. every function definition gets __attribute__((section("g_pg"),
           noinline)) so the whole license-check algorithm lands in one
           named section (the FIRST one additionally aligned(4096) so the
           section owns its pages: PLT/.init must not share them);
        2. a small runtime is appended in its own page-aligned g_pg_rt
           section: a SIGSEGV handler + constructor that mprotect(PROT_NONE)s
           the g_pg pages after load. The first call into any of those pages
           faults, the handler XOR-decrypts just that page with a key
           derived from the runtime's own bytes (self-key), remaps it R+X
           and resumes. Code only ever exists in plaintext one page at a
           time, in memory, on demand.
        The handler uses RAW SYSCALLS ONLY (x86-64): any libc/PLT call from
        the handler would itself fault while the protected pages (which can
        share a page with .plt) are unmapped — that recursion is the
        classic way this technique crashes.

  Stage 2 (pageguard_patch.py, BINARY stage, after compile, before strip):
      XOR-encrypts the g_pg section bytes in the ELF with
      key = crc32(g_pg_rt) and flips pg_state from PLAIN to ENC.
      Until that runs, the constructor sees pg_state == PLAIN and leaves
      everything plaintext (safe no-op — this file alone never breaks a
      build).

Usage:
  python3 pageguard.py verification.c            # in-place, idempotent
  python3 pageguard.py verification.c --dry-run

PG_DEBUG=1 in the environment enables handler diagnostics over write(2).
"""

import argparse
import os
import re
import sys

MARKER = "PAGEGUARD_RUNTIME"

PG_PLAIN_MAGIC = "0x3147504C41494EULL"   # '1GPLAIN'
PG_ENC_MAGIC = "0x3147454E435259ULL"     # '1GENCRY'

RUNTIME = r"""
/* ===== BEGIN %s =====
 * Page-granular on-demand decryption runtime. The g_pg section holds the
 * license-check code; pageguard_patch.py encrypts it on disk (key derived
 * from these runtime bytes). At load time this constructor mprotects the
 * section to PROT_NONE; the SIGSEGV handler decrypts each faulting page
 * with the same self-derived key, remaps it R+X, and resumes.
 * Do not hand-edit; regenerate with pageguard.py.
 * ===== stages: pageguard.py (source) + pageguard_patch.py (binary) ===== */
#include <signal.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <stddef.h>

extern uint8_t __start_g_pg[], __stop_g_pg[];
extern uint8_t __start_g_pg_rt[], __stop_g_pg_rt[];

#define PG_PLAIN_MAGIC %s
#define PG_ENC_MAGIC   %s
#define PG_MAX_PAGES   512
#define PG_PAGE        4096UL   /* x86-64 challenge containers; the handler
                                 * cannot call sysconf (PLT) to ask */

/* pg_anchor0/1 + pg_state must stay adjacent (same TU, declaration order):
 * pageguard_patch.py locates pg_state via the ELF symbol table, falling
 * back to scanning for this 16-byte anchor. */
__attribute__((used)) volatile uint64_t pg_anchor0 = 0x3156645261556750ULL; /* 'PgUaRdV1' */
__attribute__((used)) volatile uint64_t pg_anchor1 = 0x3923655461547324ULL; /* '$sTaTe#9' */
__attribute__((used)) volatile uint64_t pg_state = PG_PLAIN_MAGIC;

static volatile sig_atomic_t pg_busy = 0;
static volatile unsigned char pg_done[PG_MAX_PAGES];
static volatile int pg_debug_on = 0;   /* cached in the constructor: getenv
                                        * itself is a PLT call */

/* Raw 3-arg syscall (x86-64). The handler MUST NOT enter the PLT: the PLT
 * can sit on a page this runtime has made PROT_NONE, and faulting inside
 * the fault handler recurses forever. */
__attribute__((section("g_pg_rt"), noinline, used))
static long pg_sys3(long n, long a, long b, long c)
{
    long ret;
    __asm__ volatile ("syscall"
                      : "=a"(ret)
                      : "a"(n), "D"(a), "S"(b), "d"(c)
                      : "rcx", "r11", "memory");
    return ret;
}

__attribute__((section("g_pg_rt"), noinline, used))
static void pg_dbg(const char *tag, unsigned long v1, unsigned long v2)
{
    char b[96];
    size_t n = 0;
    const char *p;
    const char hex[] = "0123456789abcdef";
    int i;
    if (!pg_debug_on)
        return;
    for (p = tag; *p && n < sizeof(b) - 40; p++)
        b[n++] = *p;
    b[n++] = ' ';
    for (i = 15; i >= 0 && n < sizeof(b) - 24; i--)
        b[n++] = hex[(v1 >> (i * 4)) & 0xF];
    b[n++] = ' ';
    for (i = 15; i >= 0 && n < sizeof(b) - 2; i--)
        b[n++] = hex[(v2 >> (i * 4)) & 0xF];
    b[n++] = '\n';
    pg_sys3(SYS_write, 2, (long)b, (long)n);
}

__attribute__((section("g_pg_rt"), noinline, used))
static uint32_t pg_self_key(void)
{
    /* crc32 (reflected, poly 0xEDB88320) of the runtime's own bytes —
     * the same computation pageguard_patch.py does on the file. Tamper
     * the runtime and the key no longer matches: decryption yields
     * garbage, which is the intended anti-tamper coupling. */
    const uint8_t *p = __start_g_pg_rt;
    size_t n = (size_t)(__stop_g_pg_rt - __start_g_pg_rt);
    uint32_t crc = 0xFFFFFFFFu;
    size_t i;
    int k;
    for (i = 0; i < n; i++) {
        crc ^= p[i];
        for (k = 0; k < 8; k++)
            crc = (crc >> 1) ^ ((crc & 1u) ? 0xEDB88320u : 0u);
    }
    return crc ^ 0xFFFFFFFFu;
}

/* aligned(4096) on the runtime functions is REQUIRED: the runtime section
 * must own its pages. g_pg and g_pg_rt are adjacent in the executable
 * segment, and the constructor mprotects whole PAGES to PROT_NONE — a
 * runtime sharing a page with g_pg would fault inside its own handler
 * the moment protection arms. */
__attribute__((section("g_pg_rt"), noinline, used, aligned(4096)))
static void pg_fault(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)uc;
    {
        uintptr_t ps = PG_PAGE;
        uintptr_t start = (uintptr_t)__start_g_pg;
        uintptr_t stop = (uintptr_t)__stop_g_pg;
        uintptr_t lo = start & ~(ps - 1);
        uintptr_t hi = (stop + ps - 1) & ~(ps - 1);
        uintptr_t page = (uintptr_t)si->si_addr & ~(ps - 1);

        if (page < lo || page >= hi) {
            /* Not our page: restore the default disposition and let the
             * fault redeliver — a genuine crash must stay a crash.
             * signal() is safe here: we are outside the protected range,
             * so the PLT is mapped. */
            pg_dbg("pg:foreign", (unsigned long)si->si_addr, (unsigned long)page);
            signal(SIGSEGV, SIG_DFL);
            return;
        }
        pg_dbg("pg:fault", (unsigned long)si->si_addr, (unsigned long)page);

        /* Per-page once-only under a signal-safe spinlock (two threads can
         * fault the same page concurrently; a double XOR would corrupt). */
        while (__sync_lock_test_and_set(&pg_busy, 1)) { /* spin */ }
        {
            size_t idx = (size_t)((page - lo) / ps);
            if (idx < PG_MAX_PAGES && !pg_done[idx]) {
                uintptr_t from = page < start ? start : page;
                uintptr_t to = (page + ps) < stop ? (page + ps) : stop;
                uint32_t key = pg_self_key();
                uintptr_t q;
                size_t off;
                long mp = pg_sys3(SYS_mprotect, (long)page, (long)ps,
                                  (long)(PROT_READ | PROT_WRITE));
                if (mp == 0) {
                    volatile uint8_t *mem = (volatile uint8_t *)from;
                    for (q = from, off = from - start; q < to; q++, off++)
                        mem[q - from] ^= (uint8_t)((key >> ((off & 3) * 8)) ^ (uint8_t)off);
                    pg_sys3(SYS_mprotect, (long)page, (long)ps,
                            (long)(PROT_READ | PROT_EXEC));
                }
                pg_dbg("pg:dec", key, (unsigned long)mp);
                if (idx < PG_MAX_PAGES)
                    pg_done[idx] = 1;
            }
        }
        __sync_lock_release(&pg_busy);
    }
}

__attribute__((constructor))
static void pg_init(void)
{
    uintptr_t ps = PG_PAGE;
    uintptr_t start, hi;

    /* Cache the debug flag while the PLT is still usable (pre-mprotect). */
    {
        extern char **environ;
        char **e;
        for (e = environ; e && *e; e++) {
            if (e[0][0] == 'P' && e[0][1] == 'G' && e[0][2] == '_'
                && e[0][3] == 'D' && e[0][4] == 'E' && e[0][5] == 'B'
                && e[0][6] == 'U' && e[0][7] == 'G' && e[0][8] == '='
                && e[0][9] == '1' && e[0][10] == '\0') {
                pg_debug_on = 1;
                break;
            }
        }
    }

    /* Until pageguard_patch.py has encrypted the section (pg_state flip),
     * protection stays off: a plaintext section that we made PROT_NONE
     * would be XOR-"decrypted" into garbage on first fault. */
    if (pg_state != PG_ENC_MAGIC)
        return;

    start = (uintptr_t)__start_g_pg & ~(ps - 1);
    hi = (((uintptr_t)__stop_g_pg) + ps - 1) & ~(ps - 1);
    if ((hi - start) / ps > PG_MAX_PAGES) {
        pg_state = PG_PLAIN_MAGIC;   /* too many pages: fail safe, stay plaintext */
        return;
    }

    {
        struct sigaction sa;
        sa.sa_sigaction = pg_fault;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_SIGINFO | SA_NODEFER;
        sigaction(SIGSEGV, &sa, NULL);
    }
    mprotect((void *)start, hi - start, PROT_NONE);
}
/* ===== END %s ===== */
""" % (MARKER, PG_PLAIN_MAGIC, PG_ENC_MAGIC, MARKER)

# One-line function DEFINITION start as emitted by gen_verification.py:
# "static uint32_t md5_f(uint32_t x, uint32_t y, uint32_t z){return ...}" or
# "int validate_input(const char* input) {". Signature starts at column 0,
# the name is followed by '(' on the same line, and it is not a preprocessor
# line, a comment, or a control statement. Name-agnostic on purpose: any
# column-0 definition in verification.c joins the g_pg section.
FUNC_DEF = re.compile(
    r'^(?:static\s+)?(?:[A-Za-z_][A-Za-z0-9_]*[\s\*]+)+'
    r'([A-Za-z_][A-Za-z0-9_]*)\s*\('
)
NON_FUNC = re.compile(
    r'^\s*#|^\s*(if|for|while|switch|return|else|sizeof)\b|^\s*//|^\s*/\*|^\s*\*'
)

ATTR = '__attribute__((section("g_pg"), noinline))'
# The FIRST function of the section additionally page-aligns the section
# start, so g_pg never shares a page with .plt/.init ahead of it.
ATTR_FIRST = '__attribute__((section("g_pg"), noinline, aligned(4096)))'


def instrument(src: str):
    """Mark every function definition for the g_pg section; returns
    (new_source, n_marked). The first marked function page-aligns the
    section (see ATTR_FIRST)."""
    out = []
    marked = 0
    for line in src.split('\n'):
        if (not line.startswith(' ') and not line.startswith('\t')
                and FUNC_DEF.match(line) and not NON_FUNC.match(line)
                and ATTR not in line
                and '(' in line and ')' in line):
            out.append(ATTR_FIRST if marked == 0 else ATTR)
            marked += 1
        out.append(line)
    return '\n'.join(out), marked


def main():
    ap = argparse.ArgumentParser(
        description="Instrument verification.c for page-granular on-demand "
                    "decryption (source stage; pair with pageguard_patch.py)")
    ap.add_argument("source", help="verification.c to edit in place")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would change without writing")
    args = ap.parse_args()

    if not os.path.isfile(args.source):
        print(f"Error: source file not found: {args.source}", file=sys.stderr)
        return 1

    with open(args.source) as f:
        src = f.read()

    if MARKER in src:
        print(f"[-] {args.source}: already instrumented ({MARKER} present)")
        return 0

    marked_src, marked = instrument(src)
    if marked == 0:
        print(f"Error: no function definitions found in {args.source} — is this "
              f"a gen_verification.py output?", file=sys.stderr)
        return 1

    result = marked_src.rstrip('\n') + '\n' + RUNTIME

    if args.dry_run:
        print(f"[dry-run] {args.source}: would mark {marked} function(s) for "
              f"g_pg + append the {MARKER} runtime")
        return 0

    with open(args.source, 'w') as f:
        f.write(result)
    print(f"[+] {args.source}: {marked} function(s) -> section g_pg "
          f"(first page-aligned); runtime appended (self-key page decryption)")
    print(f"[+] next: compile, then run pageguard_patch.py on the binary")
    return 0


if __name__ == "__main__":
    sys.exit(main())
