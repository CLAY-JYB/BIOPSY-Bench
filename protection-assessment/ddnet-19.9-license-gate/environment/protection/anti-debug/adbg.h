#ifndef ADBG_H
#define ADBG_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * Detection Method Flags
 * ============================================================ */

#define ADBG_CHECK_NONE           0
#define ADBG_CHECK_LD_PRELOAD     (1 << 0)   /* LD_PRELOAD detection */
#define ADBG_CHECK_GDB            (1 << 1)   /* GDB fingerprints */
#define ADBG_CHECK_PARENT         (1 << 2)   /* Parent process check */
#define ADBG_CHECK_TRACER_PID     (1 << 3)   /* TracerPid check */
#define ADBG_CHECK_SIGTRAP        (1 << 4)   /* SIGTRAP handling */
#define ADBG_CHECK_PTRACE         (1 << 5)   /* ptrace check */
#define ADBG_CHECK_PROC_MAPS      (1 << 6)   /* /proc/self/maps injection check */
#define ADBG_CHECK_BREAKPOINT     (1 << 7)   /* Breakpoint detection */
#define ADBG_CHECK_TIMING         (1 << 8)   /* Timing-based detection */
#define ADBG_CHECK_FRIDA          (1 << 9)   /* Frida/dynamic-instrumentation detection */

/* All checks combined */
#define ADBG_CHECK_ALL            0x3FF

/* Common combinations */
#define ADBG_CHECK_BASIC          (ADBG_CHECK_PTRACE | ADBG_CHECK_TRACER_PID)
#define ADBG_CHECK_ADVANCED       (ADBG_CHECK_ALL & ~ADBG_CHECK_PTRACE)
#define ADBG_CHECK_STEALTH        (ADBG_CHECK_TRACER_PID | ADBG_CHECK_PARENT | ADBG_CHECK_SIGTRAP)
#define ADBG_CHECK_STANDARD       (ADBG_CHECK_PTRACE | ADBG_CHECK_TRACER_PID | ADBG_CHECK_PARENT | ADBG_CHECK_GDB)

/* ============================================================
 * Action Flags
 * ============================================================ */

#define ADBG_ACTION_NONE          0         /* Do nothing */
#define ADBG_ACTION_EXIT          (1 << 0)  /* Exit on detection */
#define ADBG_ACTION_ABORT         (1 << 1)  /* Abort on detection */
#define ADBG_ACTION_CALLBACK      (1 << 2)  /* Call user callback */

/* Default action: exit with code 1 */
#define ADBG_ACTION_DEFAULT        ADBG_ACTION_EXIT

/* ============================================================
 * Configuration Structure
 * ============================================================ */

typedef struct {
    /* Which checks to enable (bitmask of ADBG_CHECK_* flags) */
    int enabled_checks;

    /* Action to take on detection (bitmask of ADBG_ACTION_* flags) */
    int action_flags;

    /* Exit/abort code (default: 1) */
    int exit_code;

    /* Enable verbose logging (1 = enabled, 0 = disabled) */
    int verbose;

    /* User callback function (for ADBG_ACTION_CALLBACK) */
    void (*on_detected)(void *user_data);
    void *callback_user_data;
} adbg_config_t;

/* ============================================================
 * Default Configuration
 * ============================================================ */

/* Get default configuration (all checks enabled, exit on detection) */
void adbg_get_default_config(adbg_config_t *config);

/* Initialize config with specific checks and action */
void adbg_init_config(adbg_config_t *config, int checks, int action);

/* ============================================================
 * Individual Detection Functions
 * ============================================================ */

/**
 * Check if LD_PRELOAD is set or getenv is hooked
 * @return 1 if detected, 0 otherwise
 */
int adbg_check_ldpreload(void);

/**
 * Check for GDB-specific fingerprints
 * @return 1 if detected, 0 otherwise
 */
int adbg_check_gdb(void);

/**
 * Check if parent process is a debugging tool
 * @return 1 if detected, 0 otherwise
 */
int adbg_check_parent(void);

/**
 * Check TracerPid in /proc/self/status
 * @return 1 if detected, 0 otherwise
 */
int adbg_check_tracer_pid(void);

/**
 * Detect via SIGTRAP signal handling
 * @return 1 if detected, 0 otherwise
 */
int adbg_check_sigtrap(void);

/**
 * Check if process is being traced via ptrace
 * @return 1 if detected, 0 otherwise
 */
int adbg_check_ptrace(void);

/**
 * Check for injected libraries in /proc/self/maps
 * @return 1 if detected, 0 otherwise
 */
int adbg_check_proc_maps(void);

/**
 * Check for software breakpoints
 * @return 1 if detected, 0 otherwise
 */
int adbg_check_breakpoints(void);

/**
 * Timing-based detection (detects single-step execution)
 * @return 1 if detected, 0 otherwise
 */
int adbg_check_timing(void);

/**
 * Detect Frida / dynamic instrumentation frameworks
 * Scans /proc/self/maps for injected agents, thread names for Frida's
 * gum-js-loop/gmain workers, and probes the default frida-server port
 * (127.0.0.1:27042).
 * @return 1 if detected, 0 otherwise
 */
int adbg_check_frida(void);

/* ============================================================
 * Main API Functions
 * ============================================================ */

/**
 * Run all detection checks with default configuration
 * @return 1 if any debugger detected, 0 otherwise
 */
int adbg_check_all(void);

/**
 * Run specific checks based on bitmask
 * @param checks Bitmask of ADBG_CHECK_* flags
 * @return 1 if any debugger detected, 0 otherwise
 */
int adbg_check_mask(int checks);

/**
 * Run detection checks with custom configuration
 * @param config Pointer to configuration structure
 * @return 1 if any debugger detected, 0 otherwise
 */
int adbg_check_config(const adbg_config_t *config);

/**
 * Check and take action based on configuration
 * This is the main high-level API
 * @param config Pointer to configuration structure
 * @return Result code (never returns on EXIT/ABORT actions)
 */
int adbg_detect(const adbg_config_t *config);

/* ============================================================
 * Utility Functions
 * ============================================================ */

/**
 * Get library version string
 * @return version string
 */
const char *adbg_get_version(void);

/**
 * Get check name by flag
 * @param flag ADBG_CHECK_* flag
 * @return Check name string
 */
const char *adbg_get_check_name(int flag);

/**
 * Enable/disable auto-run on program start
 * Call this before main() via constructor or explicitly
 * @param enable 1 to enable, 0 to disable
 * @param config Optional configuration (NULL for defaults)
 */
void adbg_set_auto_run(int enable, const adbg_config_t *config);

/**
 * Best-effort anti-dump hardening (not a check — applies countermeasures):
 *   - prctl(PR_SET_DUMPABLE, 0): blocks ptrace-attach and core dumps from
 *     non-privileged tracers, and hides the process in /proc of others
 *   - madvise(MADV_DONTDUMP) over writable private mappings: excludes them
 *     from core dumps (no OSS packer does this — 1 syscall per region)
 * Safe to call multiple times; failures are ignored (best effort).
 */
void adbg_apply_hardening(void);

/**
 * DebugBlocker (self-ptrace): fork a child that PTRACE_ATTACHes to this
 * process and forwards every signal stop back, consuming the one tracer
 * slot the kernel allows — no external debugger (gdb/strace/frida-ptrace)
 * can attach afterwards. PTRACE_O_EXITKILL makes the tracee die with the
 * blocker child, so the child cannot simply be killed.
 *
 * Start the blocker BEFORE adbg_apply_hardening(): a non-dumpable process
 * denies the child's attach too.
 *
 * @return 0  blocker engaged (we are now self-traced)
 *         1  a debugger already holds the tracer slot (detected!)
 *         -1 environment denied ptrace (seccomp/sandbox) — run without
 *            the blocker rather than failing the program
 */
int adbg_debug_blocker_start(void);

#ifdef __cplusplus
}
#endif

#endif  /* ADBG_H */
