#include "adbg.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <stdarg.h>

#ifndef PTRACE_TRACEME
#define PTRACE_TRACEME          0
#endif

/* ptrace() portability + interposition hardening.
 *
 * adbg.c is amalgamated into BOTH C and C++ translation units (see
 * anti-debug.py), and must build against any glibc:
 *   - the `enum __ptrace_request` glibc used to require as arg 1 was
 *     REMOVED in glibc >= 2.38, so a cast to it breaks newer toolchains,
 *     while a plain int breaks strict C++ against older glibc;
 *   - calling the libc ptrace symbol lets an LD_PRELOAD hook fake it.
 * Going through syscall(2) sidesteps both problems. */
static long adbg_ptrace(long request, long pid, long addr, long data)
{
    return syscall(SYS_ptrace, request, pid, addr, data);
}

/* Opt-in section placement for the interlock guard network (interlock_gen.py
 * level 3). When ADBG_SECTION_NAME is defined (e.g. "g_adbg"), every detection
 * function below is placed in that ELF section so a guard can CRC the REAL
 * anti-debug code — the whole library becomes part of the integrity net.
 * Default (undefined, i.e. normal anti-debug.py / D-dimension builds): the macro
 * expands to nothing and adbg behaves exactly as before (normal .text). */
#ifdef ADBG_SECTION_NAME
#  define ADBG_SECTION_ATTR __attribute__((section(ADBG_SECTION_NAME)))
#else
#  define ADBG_SECTION_ATTR
#endif

#define NOT_DEBUGGED_TRACERPID  0
#define PROCNAME_MAX_SIZE       1024
#define CMDLINE_MAX_PATH        64
#define TRACER_LINE_MAX_SIZE    255
#define TRACERPID_FIELD_NAME    "TracerPid"
#define LD_PRELOAD_ENV          "LD_PRELOAD"
#define PROC_STATUS_PATH        "/proc/self/status"
#define CMDLINE_PATH_FORMAT     "/proc/%d/cmdline"

/* ============================================================
 * Global State
 * ============================================================ */

/* ============================================================
 * DebugBlocker (self-ptrace): the strongest Linux anti-debug lever.
 * Linux has no ScyllaHide equivalent, so consuming the one allowed
 * tracer slot ourselves defeats every external debugger attach.
 * ============================================================ */

#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER 0x59616d61
#endif

/* 1 while our own blocker child is the tracer: adbg_check_ptrace's
 * TRACEME probe would otherwise "detect" ourselves. */
static volatile int _blocker_active = 0;

/* Child side: attach to the parent and forward every signal stop back,
 * so signal handlers (ours, pageguard's SIGSEGV, ...) keep working.
 * Fork-safe: only ptrace/waitpid/read/_exit on this path.
 * Returns the result code on the pipe: 'Y' attached, 'D' debugger
 * already tracing the parent, 'E' environment denied ptrace. */
static void _blocker_child_main(pid_t parent, int grant_rd, int res_wr)
{
    char c;
    /* wait for the parent's PR_SET_PTRACER grant (avoids the attach racing
     * the prctl under yama ptrace_scope=1) */
    if (read(grant_rd, &c, 1) != 1)
        _exit(0);
    close(grant_rd);

    if (adbg_ptrace(PTRACE_ATTACH, parent, 0, 0) != 0) {
        /* Attach failed. Distinguish a real debugger from a locked-down
         * environment by reading the parent's TracerPid: under gdb/strace/
         * frida-ptrace it is nonzero; under seccomp-denied ptrace it is 0
         * and the blocker must degrade gracefully, not fail the program. */
        char path[64], line[256];
        int tracer = 0;
        snprintf(path, sizeof(path), "/proc/%d/status", (int)parent);
        FILE *fp = fopen(path, "r");
        if (fp) {
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "TracerPid:")) {
                    sscanf(line, "%*s %d", &tracer);
                    break;
                }
            }
            fclose(fp);
        }
        c = tracer ? 'D' : 'E';
        if (write(res_wr, &c, 1) == 1) { /* reported */ }
        close(res_wr);
        _exit(0);
    }

    /* Consume the attach-stop FIRST: PTRACE_SETOPTIONS is rejected (ESRCH)
     * unless the tracee is stopped. */
    {
        int st;
        if (waitpid(parent, &st, 0) != parent)
            _exit(0);
    }

    /* If WE die, the tracee (the program) is SIGKILLed: an analyst cannot
     * simply kill the blocker child and continue debugging. Detaching the
     * parent requires debugging THIS child (an ancestor of it — allowed
     * under yama scope 1) and issuing PTRACE_DETACH, which is the intended
     * solve path. */
    adbg_ptrace(PTRACE_SETOPTIONS, parent, 0, (long)PTRACE_O_EXITKILL);

    /* Report success BEFORE resuming the tracee: if PTRACE_CONT lands
     * first, the parent can wake from its verdict-read and race the
     * tracer's ptrace syscall teardown — a window in which the tracee's
     * next sleep never expires (reproduced deterministically per-binary).
     * Writing the verdict into the pipe buffer first means the parent only
     * proceeds once resumed, with the tracer fully out of ptrace. */
    c = 'Y';
    if (write(res_wr, &c, 1) == 1) { /* reported */ }
    close(res_wr);

    /* Resume the program (still inside the attach-stop). */
    adbg_ptrace(PTRACE_CONT, parent, 0, 0);

    {
        int st;
        for (;;) {
            if (waitpid(parent, &st, 0) != parent)
                _exit(0);                    /* parent exited */
            if (WIFSTOPPED(st)) {
                /* Distinguish signal-delivery-stop from group-stop (the
                 * official waitpid(2) recipe): PTRACE_GETSIGINFO fails
                 * with EINVAL only on group-stop. Forwarding a group-stop
                 * SIGSTOP would re-stop the tracee, ping-pong forever and
                 * wedge the program inside its next sleep — that is the
                 * classic self-tracer hang. Signal-delivery stops ARE
                 * forwarded so the program's own handlers keep working
                 * (SIGSEGV pageguard, SIGTRAP adbg probe, ...). */
                siginfo_t si;
                long sig = 0;
                if (adbg_ptrace(PTRACE_GETSIGINFO, parent, 0,
                                (long)(void *)&si) == 0)
                    sig = WSTOPSIG(st);
                adbg_ptrace(PTRACE_CONT, parent, 0, sig);
            } else {
                _exit(0);                    /* exited / signaled */
            }
        }
    }
}

/* Parent side: fork the tracer child and wait for its verdict.
 * Returns 0 = blocker engaged, 1 = a debugger was already tracing us,
 * -1 = environment denied ptrace (benign: run without the blocker). */
int ADBG_SECTION_ATTR adbg_debug_blocker_start(void)
{
    int grant[2], res[2];
    pid_t child;
    char c = 'E';
    ssize_t r;

    if (_blocker_active)
        return 0;

    /* Pre-fork warmup of the heap and stdio buffers. glibc allocates the
     * stdout buffer lazily on first use; performing that first allocation
     * from a tracee freshly resumed out of the attach-stop deadlocks it
     * (reproduced deterministically: buffered-stdout programs hang inside
     * their first post-blocker printf). Touch the arena and flush once
     * HERE so nothing allocates under trace. */
    {
        void *warm = malloc(8192);
        if (warm)
            free(warm);
        fflush(NULL);
    }

    if (pipe(grant) != 0 || pipe(res) != 0)
        return -1;

    child = fork();
    if (child < 0) {
        close(grant[0]); close(grant[1]);
        close(res[0]); close(res[1]);
        return -1;
    }
    if (child == 0) {
        close(grant[1]);
        close(res[0]);
        _blocker_child_main(getppid(), grant[0], res[1]);
        _exit(0);
    }
    /* parent: grant this exact child the right to trace us (works under
     * yama ptrace_scope=1, harmless where yama is disabled) */
    close(grant[0]);
    close(res[1]);
    prctl(PR_SET_PTRACER, (unsigned long)child, 0, 0, 0);
    c = 'G';
    if (write(grant[1], &c, 1) == 1) { /* granted */ }
    close(grant[1]);

    r = read(res[0], &c, 1);
    close(res[0]);
    if (r != 1) {
        int st;
        waitpid(child, &st, 0);
        return -1;
    }
    if (c == 'Y') {
        _blocker_active = 1;
        return 0;
    }
    if (c == 'D') {
        int st;
        waitpid(child, &st, 0);
        return 1;              /* debugger detected: it owns the tracer slot */
    }
    {
        int st;
        waitpid(child, &st, 0);
        return -1;             /* 'E': seccomp/sandbox denied ptrace */
    }
}

/* Positional initializers (no C99 designated-initializer syntax): this file
 * is #included into C++ translation units where designated initializers are
 * only valid from C++20 / as a GNU extension. Field order matches
 * adbg_config_t in adbg.h. */
static adbg_config_t _global_config = {
    ADBG_CHECK_ALL,
    ADBG_ACTION_DEFAULT,
    1,
    0,
    NULL,
    NULL
};

static int _auto_run_enabled = 0;
static volatile int _debugger_present = 0;

/* ============================================================
 * Utility Functions
 * ============================================================ */

static void _debug_log(const adbg_config_t *config, const char *format, ...)
{
    if (!config || !config->verbose) return;

    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

static char *get_procname_by_pid(int pid)
{
    char path[CMDLINE_MAX_PATH];
    snprintf(path, sizeof(path), CMDLINE_PATH_FORMAT, pid);

    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    char *name = (char *)calloc(PROCNAME_MAX_SIZE, 1);
    if (!name) {
        fclose(f);
        return NULL;
    }

    size_t size = fread(name, 1, PROCNAME_MAX_SIZE - 1, f);
    fclose(f);

    if (size == 0) {
        free(name);
        return NULL;
    }

    name[size] = '\0';
    return name;
}

static int is_debugger_name(const char *name)
{
    if (!name) return 0;

    return (
        strstr(name, "gdb")     ||
        strstr(name, "lldb")    ||
        strstr(name, "radare2") ||
        strstr(name, "r2")      ||
        strstr(name, "ltrace")  ||
        strstr(name, "strace")  ||
        strstr(name, "valgrind")||
        strstr(name, "edb")     ||
        strstr(name, "x64dbg")  ||
        strstr(name, "ida")
    );
}

/* ============================================================
 * Configuration Functions
 * ============================================================ */

void adbg_get_default_config(adbg_config_t *config)
{
    if (!config) return;

    config->enabled_checks = ADBG_CHECK_ALL;
    config->action_flags = ADBG_ACTION_DEFAULT;
    config->exit_code = 1;
    config->verbose = 1;
    config->on_detected = NULL;
    config->callback_user_data = NULL;
}

void adbg_init_config(adbg_config_t *config, int checks, int action)
{
    if (!config) return;

    config->enabled_checks = checks;
    config->action_flags = action;
    config->exit_code = 1;
    config->verbose = 1;
    config->on_detected = NULL;
    config->callback_user_data = NULL;
}

void adbg_set_auto_run(int enable, const adbg_config_t *config)
{
    _auto_run_enabled = enable;
    if (config) {
        _global_config = *config;
    }
}

/* ============================================================
 * Detection Functions (Public API)
 * ============================================================ */

int ADBG_SECTION_ATTR adbg_check_ldpreload(void)
{
    // Check if LD_PRELOAD is set
    if (getenv(LD_PRELOAD_ENV)) {
        return 1;
    }

    // Check for a custom getenv implementation
    putenv((char *)"LD_PRELOAD=test_anti_debug_12345");
    const char *val = getenv(LD_PRELOAD_ENV);

    if (!val || strcmp(val, "test_anti_debug_12345") != 0) {
        unsetenv(LD_PRELOAD_ENV);
        return 1;
    }

    unsetenv(LD_PRELOAD_ENV);
    return 0;
}

int ADBG_SECTION_ATTR adbg_check_gdb(void)
{
    char *s, path[1024];

    // Check for GDB path in _ environment variable
    if (getenv("_")) {
        strncpy(path, getenv("_"), sizeof(path) - 1);
        path[sizeof(path) - 1] = '\0';
        s = strrchr(path, '/');
        s = s ? s + 1 : path;

        if (strcmp(s, "gdb") == 0) {
            return 1;
        }
    }

    // GDB sets BOTH LINES and COLUMNS. Requiring both at once avoids the
    // false positive of an interactive shell that exported just one of them.
    if (getenv("LINES") && getenv("COLUMNS")) {
        return 1;
    }

    /* NOTE: the historical "gdb leaks 2 fds, so a fresh fopen('/') lands on
     * fd >= 5" probe is deliberately REMOVED. Any real program that has
     * already opened two files by the time the check runs (games, servers,
     * anything with audio/graphics/log handles) trips it: near-100% false
     * positives on actual targets. Proven live on DDNet: the check injected
     * at the OnInit-tail verify() call site fired on the engine's own fds
     * and silently exit(1)-ed the challenge binary. The two env probes
     * above are gdb-specific and false-positive-free. */

    return 0;
}

int ADBG_SECTION_ATTR adbg_check_parent(void)
{
    char buffer[64];
    char *s;
    FILE *fp;

    // Check parent name in /proc/${PID}/status
    snprintf(buffer, sizeof(buffer), "/proc/%i/status", getppid());

    if ((fp = fopen(buffer, "r"))) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            s = strrchr(buffer, '/');
            s = s ? s + 1 : buffer;

            if (is_debugger_name(s)) {
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);
    }

    // Check parent name in /proc/${PID}/cmdline
    snprintf(buffer, sizeof(buffer), "/proc/%i/cmdline", getppid());

    if ((fp = fopen(buffer, "r"))) {
        if (fgets(buffer, sizeof(buffer), fp)) {
            s = strrchr(buffer, '/');
            s = s ? s + 1 : buffer;

            if (is_debugger_name(s)) {
                fclose(fp);
                return 1;
            }
        }
        fclose(fp);
    }

    return 0;
}

int ADBG_SECTION_ATTR adbg_check_tracer_pid(void)
{
    FILE *fptr;
    char line[TRACER_LINE_MAX_SIZE];
    int tracerPid = -1;

    fptr = fopen(PROC_STATUS_PATH, "r");
    if (!fptr) return 0;

    while (fgets(line, TRACER_LINE_MAX_SIZE, fptr)) {
        if (strstr(line, TRACERPID_FIELD_NAME)) {
            sscanf(line, "%*s %d", &tracerPid);
            break;
        }
    }
    fclose(fptr);

    if (tracerPid > 0) {
        char *procName = get_procname_by_pid(tracerPid);
        int is_debugger = is_debugger_name(procName);

        if (procName) free(procName);
        return is_debugger;
    }

    return 0;
}

static void _sigtrap_handler(int sig)
{
    if (sig == SIGTRAP)
        _debugger_present = 0;
}

int ADBG_SECTION_ATTR adbg_check_sigtrap(void)
{
    _debugger_present = 1;
    signal(SIGTRAP, _sigtrap_handler);

    if (!raise(SIGTRAP) && _debugger_present) {
        signal(SIGTRAP, SIG_DFL);
        return 1;
    }

    signal(SIGTRAP, SIG_DFL);
    return 0;
}

int ADBG_SECTION_ATTR adbg_check_ptrace(void)
{
    // When the DebugBlocker child is already tracing us, TRACEME fails by
    // design — that is our own protection, not a foreign debugger.
    if (_blocker_active)
        return 0;

    // If cannot be traced, already has a tracer
    if (adbg_ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        return 1;
    }

    // If first call succeeded, second should fail; a second success means
    // something is interposing ptrace to always answer 0 (LD_PRELOAD hook)
    if (adbg_ptrace(PTRACE_TRACEME, 0, 0, 0) == 0) {
        return 1;
    }

    return 0;
}

/* ============================================================
 * Extended Detection Functions
 * ============================================================ */

/**
 * Check for injected libraries in /proc/self/maps
 * Debuggers often inject their own libraries
 */
int ADBG_SECTION_ATTR adbg_check_proc_maps(void)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    int found_injection = 0;

    while (fgets(line, sizeof(line), fp)) {
        /* Match only SPECIFIC injection markers. Substrings like
         * "/usr/local/lib" must NOT appear here: distros (and our own
         * challenge Dockerfiles) legitimately install libs there, which
         * made every run "detect" a debugger and refuse to start. */
        if (strstr(line, "libfrida")    ||
            strstr(line, "frida-agent") ||
            strstr(line, "frida-gadget")||
            strstr(line, "gum-js")      ||
            strstr(line, "libinj")      ||
            strstr(line, "libintercept")||
            strstr(line, "libpreload")  ||
            strstr(line, "memfd:")) {
            found_injection = 1;
            break;
        }
    }
    fclose(fp);
    return found_injection;
}

/**
 * Simple breakpoint detection
 * Checks for INT3 instruction (0xCC) at function entry
 */
int ADBG_SECTION_ATTR adbg_check_breakpoints(void)
{
    /* This is a simplified check - in real code you'd scan code segments */
    volatile int dummy = 0;

    /* Take this function's own address. A direct cast from function pointer
     * to void* is ill-formed in strict C++, so go through memcpy (the
     * representation is usable that way on POSIX — dlsym relies on it). */
    void *ptr = NULL;
    void (*fnptr)(void) = (void (*)(void))adbg_check_breakpoints;
    memcpy(&ptr, &fnptr, sizeof(ptr));
    unsigned char *code = (unsigned char *)ptr;

    /* Check first few bytes for INT3 (0xCC) */
    for (int i = 0; i < 16; i++) {
        if (code[i] == 0xCC) {
            return 1;  // Found breakpoint
        }
    }

    (void)dummy;  /* Prevent optimization */
    return 0;
}

/**
 * Timing-based detection
 * Compares execution time to detect single-stepping
 */
int ADBG_SECTION_ATTR adbg_check_timing(void)
{
    struct timespec start, end;
    volatile int sum = 0;

    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Simple computation loop */
    for (int i = 0; i < 1000; i++) {
        sum += i;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    long duration = (end.tv_sec - start.tv_sec) * 1000000000L +
                    (end.tv_nsec - start.tv_nsec);

    /* If execution took too long (>10ms), might be single-stepped */
    if (duration > 10000000L) {
        (void)sum;  /* Prevent optimization */
        return 1;
    }

    (void)sum;  /* Prevent optimization */
    return 0;
}

/**
 * Frida / dynamic-instrumentation detection.
 * Three independent signals (renamed frida-server builds defeat any single
 * one of them):
 *   1. injected agent mappings in /proc/self/maps (frida-agent, frida-gadget,
 *      gum-js, libpreload, or a memfd: mapping)
 *   2. Frida worker thread names (the "comm" file of every task under
 *      /proc/self/task: gum-js-loop, pool-frida-*)
 *   3. the default frida-server control port 127.0.0.1:27042 accepting
 *      connections
 */
int ADBG_SECTION_ATTR adbg_check_frida(void)
{
    /* 1. maps scan (specific markers only — see adbg_check_proc_maps) */
    {
        FILE *fp = fopen("/proc/self/maps", "r");
        if (fp) {
            char line[512];
            while (fgets(line, sizeof(line), fp)) {
                if (strstr(line, "frida")  ||
                    strstr(line, "gum-js") ||
                    strstr(line, "memfd:")) {
                    fclose(fp);
                    return 1;
                }
            }
            fclose(fp);
        }
    }

    /* 2. thread-name scan */
    {
        DIR *d = opendir("/proc/self/task");
        if (d) {
            struct dirent *de;
            char comm_path[320], comm[64];
            while ((de = readdir(d)) != NULL) {
                if (de->d_name[0] == '.')
                    continue;
                snprintf(comm_path, sizeof(comm_path),
                         "/proc/self/task/%s/comm", de->d_name);
                FILE *fp = fopen(comm_path, "r");
                if (!fp)
                    continue;
                if (fgets(comm, sizeof(comm), fp)) {
                    /* gum-js-loop / pool-frida-* are Frida-specific. "gmain"
                     * is deliberately NOT matched: legit GLib applications
                     * run a worker thread with that exact name. */
                    if (strstr(comm, "gum-js-loop") ||
                        strstr(comm, "pool-frida")) {
                        fclose(fp);
                        closedir(d);
                        return 1;
                    }
                }
                fclose(fp);
            }
            closedir(d);
        }
    }

    /* 3. default frida-server port probe (fast refuse when nothing listens) */
    {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd >= 0) {
            struct sockaddr_in sa;
            memset(&sa, 0, sizeof(sa));
            sa.sin_family = AF_INET;
            sa.sin_port = htons(27042);
            sa.sin_addr.s_addr = inet_addr("127.0.0.1");
            if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
                close(fd);
                return 1;
            }
            close(fd);
        }
    }

    return 0;
}

/* ============================================================
 * Main API Functions
 * ============================================================ */

int ADBG_SECTION_ATTR adbg_check_all(void)
{
    return adbg_check_mask(ADBG_CHECK_ALL);
}

int ADBG_SECTION_ATTR adbg_check_mask(int checks)
{
    int detected = 0;

    if (checks & ADBG_CHECK_LD_PRELOAD) {
        detected |= adbg_check_ldpreload();
        if (detected) return 1;
    }

    if (checks & ADBG_CHECK_GDB) {
        detected |= adbg_check_gdb();
        if (detected) return 1;
    }

    if (checks & ADBG_CHECK_PARENT) {
        detected |= adbg_check_parent();
        if (detected) return 1;
    }

    if (checks & ADBG_CHECK_TRACER_PID) {
        detected |= adbg_check_tracer_pid();
        if (detected) return 1;
    }

    if (checks & ADBG_CHECK_SIGTRAP) {
        detected |= adbg_check_sigtrap();
        if (detected) return 1;
    }

    if (checks & ADBG_CHECK_PTRACE) {
        detected |= adbg_check_ptrace();
        if (detected) return 1;
    }

    if (checks & ADBG_CHECK_PROC_MAPS) {
        detected |= adbg_check_proc_maps();
        if (detected) return 1;
    }

    if (checks & ADBG_CHECK_BREAKPOINT) {
        detected |= adbg_check_breakpoints();
        if (detected) return 1;
    }

    if (checks & ADBG_CHECK_TIMING) {
        detected |= adbg_check_timing();
        if (detected) return 1;
    }

    if (checks & ADBG_CHECK_FRIDA) {
        detected |= adbg_check_frida();
        if (detected) return 1;
    }

    return detected;
}

int ADBG_SECTION_ATTR adbg_check_config(const adbg_config_t *config)
{
    if (!config) {
        return adbg_check_all();
    }

    int detected = 0;

    if (config->enabled_checks & ADBG_CHECK_LD_PRELOAD) {
        if (adbg_check_ldpreload()) {
            _debug_log(config, "LD_PRELOAD detected\n");
            detected = 1;
        }
    }

    if (config->enabled_checks & ADBG_CHECK_GDB) {
        if (adbg_check_gdb()) {
            _debug_log(config, "GDB fingerprints detected\n");
            detected = 1;
        }
    }

    if (config->enabled_checks & ADBG_CHECK_PARENT) {
        if (adbg_check_parent()) {
            _debug_log(config, "Parent is a debugger\n");
            detected = 1;
        }
    }

    if (config->enabled_checks & ADBG_CHECK_TRACER_PID) {
        if (adbg_check_tracer_pid()) {
            _debug_log(config, "TracerPid indicates debugging\n");
            detected = 1;
        }
    }

    if (config->enabled_checks & ADBG_CHECK_SIGTRAP) {
        if (adbg_check_sigtrap()) {
            _debug_log(config, "SIGTRAP handling detected\n");
            detected = 1;
        }
    }

    if (config->enabled_checks & ADBG_CHECK_PTRACE) {
        if (adbg_check_ptrace()) {
            _debug_log(config, "ptrace detected\n");
            detected = 1;
        }
    }

    if (config->enabled_checks & ADBG_CHECK_PROC_MAPS) {
        if (adbg_check_proc_maps()) {
            _debug_log(config, "Injected libraries found in /proc/self/maps\n");
            detected = 1;
        }
    }

    if (config->enabled_checks & ADBG_CHECK_BREAKPOINT) {
        if (adbg_check_breakpoints()) {
            _debug_log(config, "Breakpoints detected\n");
            detected = 1;
        }
    }

    if (config->enabled_checks & ADBG_CHECK_TIMING) {
        if (adbg_check_timing()) {
            _debug_log(config, "Timing anomaly detected (single-stepping?)\n");
            detected = 1;
        }
    }

    if (config->enabled_checks & ADBG_CHECK_FRIDA) {
        if (adbg_check_frida()) {
            _debug_log(config, "Frida/dynamic instrumentation detected\n");
            detected = 1;
        }
    }

    if (detected && config->verbose) {
        _debug_log(config, "Debugger detected!\n");
    } else if (!detected && config->verbose) {
        _debug_log(config, "No debugger detected\n");
    }

    return detected;
}

int ADBG_SECTION_ATTR adbg_detect(const adbg_config_t *config)
{
    adbg_config_t local_config;
    const adbg_config_t *cfg = config;

    if (!config) {
        adbg_get_default_config(&local_config);
        cfg = &local_config;
    }

    int detected = adbg_check_config(cfg);

    if (detected) {
        // Call user callback if set
        if (cfg->action_flags & ADBG_ACTION_CALLBACK && cfg->on_detected) {
            cfg->on_detected(cfg->callback_user_data);
        }

        // Take action based on flags
        if (cfg->action_flags & ADBG_ACTION_EXIT) {
            _debug_log(cfg, "Exiting with code %d\n", cfg->exit_code);
            fflush(stderr);
            exit(cfg->exit_code);
        }

        if (cfg->action_flags & ADBG_ACTION_ABORT) {
            _debug_log(cfg, "Aborting...\n");
            fflush(stderr);
            abort();
        }
    }

    return detected;
}

/* ============================================================
 * Utility Functions
 * ============================================================ */

const char *adbg_get_version(void)
{
    return "ADBG v4.1 - Extended Detection (10 methods)";
}

const char *adbg_get_check_name(int flag)
{
    switch (flag) {
        case ADBG_CHECK_LD_PRELOAD:  return "LD_PRELOAD";
        case ADBG_CHECK_GDB:         return "GDB";
        case ADBG_CHECK_PARENT:      return "Parent";
        case ADBG_CHECK_TRACER_PID:  return "TracerPid";
        case ADBG_CHECK_SIGTRAP:     return "SIGTRAP";
        case ADBG_CHECK_PTRACE:      return "ptrace";
        case ADBG_CHECK_PROC_MAPS:   return "ProcMaps";
        case ADBG_CHECK_BREAKPOINT:  return "Breakpoint";
        case ADBG_CHECK_TIMING:      return "Timing";
        case ADBG_CHECK_FRIDA:       return "Frida";
        case ADBG_CHECK_BASIC:       return "Basic";
        case ADBG_CHECK_ADVANCED:    return "Advanced";
        case ADBG_CHECK_STEALTH:     return "Stealth";
        case ADBG_CHECK_STANDARD:    return "Standard";
        case ADBG_CHECK_ALL:         return "All";
        default:                     return "Unknown";
    }
}

void adbg_apply_hardening(void)
{
    /* Anti-dump hardening. Not a detection: applies countermeasures and
     * returns. Best effort — failures are ignored on purpose so a hardened
     * kernel or restricted container never breaks program startup. */
    char line[512];
    FILE *fp;
    char *end;

    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    /* Exclude writable private mappings from core dumps. Parse the maps
     * line range and madvise it; PROT_NONE gaps are skipped by the kernel
     * (madvise on unmapped ranges returns ENOMEM — ignored). */
    fp = fopen("/proc/self/maps", "r");
    if (!fp)
        return;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long start, stop;
        int perms_ok = 0;
        char *p = line;

        start = strtoul(p, &end, 16);
        if (end == p || *end != '-')
            continue;
        p = end + 1;
        stop = strtoul(p, &end, 16);
        if (end == p)
            continue;
        p = end + 1; /* permissions */
        if (p[0] == 'r' && p[1] == 'w' && p[3] != 's')
            perms_ok = 1; /* writable, private */
        if (perms_ok && stop > start)
            madvise((void *)start, (size_t)(stop - start), MADV_DONTDUMP);
    }
    fclose(fp);
}

/* ============================================================
 * Auto-run Constructor
 * ============================================================ */

__attribute__((constructor))
static void adbg_auto_init(void)
{
    if (!_auto_run_enabled) {
        return;  // Disabled, manual mode only
    }

    adbg_detect(&_global_config);
}
