#!/usr/bin/env bash
set -euo pipefail

# Force locale for consistent decimal handling (LC_ALL=C ensures '.' as decimal separator)
export LC_ALL=C
export LANG=C

# ===== UNIFIED VERIFIER BASELINE BEGIN (byte-identical across the RE skills; canonical source: script/verifier_blocks/baseline_doc.txt -- edit there first, then re-embed in every skill's template so the copies stay identical) =====
# Baseline invariants -- every skill, every task:
#   1. Ground truth is root-only (chmod -R go-rwx): agent code executed at verification time runs as nobody and must not be able to read it.
#   2. Agent-supplied inputs are realpath-confined to agent_output and size-capped (report/input-class files 10MB, submitted binary artifacts 64MB, image-class artifacts 256MB).
#      Rejected inputs fail closed (repointed to /dev/null or scored as empty) -- never scored as-is.
#   3. Agent/analyzed code executes as 'nobody' via setpriv; the drop wraps EXECUTION of agent code only, and static analysis tools (objdump, ent, file, readelf) run as the verifier.
#      On a ROOT verifier an unavailable drop is FAIL-CLOSED: the affected bucket scores 0 rather than running agent code as root (non-root dev verifiers keep run-as-is).
#   4. execve/execveat gate: agent code executing any verifier-side binary (/app, /tests, /solution) other than the allowed target voids the dynamic bucket it fed.
#   5. Agent-declared commands: shell operators are rejected with ONE strict rule everywhere -- [;&|`$()<>] (the bash -c runners require parens in the set; argv-list runners could tolerate more but apply the same rule).
#      First-token policy is per domain: the verifier's binary under test, or the agent's own confined executable under agent_output.
#   6. Array scoring: case-insensitive whole-word F1 with a 0.5 precision floor and a dump cap (listing more than GT+3 items scores 0) -- vocabulary dumps earn nothing.
#   7. Fact booleans: wrong AND missing answers are penalized, clamped >= 0 -- guessing "true" everywhere farms nothing.
#   8. Self-consistency: a claim contradicting the SAME report's own declarations is voided (counted as a miss, noted in details).
# "Untestable" semantics -- three distinct cases, do not mix them:
#   - verifier tool missing          -> drop the property from the denominator (agents are not penalized for the environment)
#   - GT section empty/inapplicable  -> full credit for that sub-score (nothing to dodge)
#   - verification reference missing -> FAIL-CLOSED zero + loud note (task assembly defect; a farmable degradation is worse than a visible zero)
# Shared principle (implemented per domain, not as shared code):
#   - CONTROL PROBE: a differential check only counts when its control (mutating or omitting something the claim says should not matter) does NOT produce the same outcome.
#     The wrong-key rejection gate, the wire discrimination precheck, and the plain-run marker control are this one principle.
# Domain-specific mechanisms stay below in each template next to their scorers, each with a "why not portable" note.
# Porting criterion: port a mechanism only when the target skill has the SAME gaming vector AND no stronger existing coverage -- code similarity alone is not a reason.
# Scorer protocol (unified): every score_* function echoes the numeric score on the FIRST line, detail lines after it.
# Detail symbols: ✓ pass   ⊘ partial   ✗ fail   ⚠ warning   ⊖ clamp(score capped).
# Buckets: 100 points total, all dynamic (the per-skill split lives in each template's domain layer).
# reward.json carries the 0..1 score; reward-details.json uses explicit snake_case bucket fields with 0.xxxx point values and a float >= max "passed" verdict.
# ===== UNIFIED VERIFIER BASELINE END =====

# ==============================================================================
# SOFTWARE PROTECTION REVERSE ENGINEERING - VERIFICATION TEST (domain layer)
# ==============================================================================
# Challenge: ffmpeg-9.0.1-transcode-unlock
#
# SCORING LAW (fixed, identical across every task — zero verifier knobs; all
# per-task variation arrives via construction-time stamps under
# /app/ground_truth/, never via hand-edited test.sh sections):
#
#   License Verification  60  = key terminal 50 + chain-ladder progress 10
#     key    50   the challenge binary accepts the key (flag{...} + exit 0).
#                 The dominant bucket: only a recovered/forged key earns it.
#     ladder 10   rung-flat 10/n_rungs, ORDERED prefix (stops at the first
#                 missed rung), the first missed rung earns a byte fraction
#                 of its weight when its counting probe stamped a total.
#                 A key that prints the flag traverses the whole chain by
#                 determinism, so the ladder auto-awards full credit without
#                 gdb (verifier flakiness never deducts from a real solve).
#                 Compressed from 30 so progress alone cannot inflate.
#
#   Property Validation   40  = obfuscation pool 20 + easy pool 20
#     O family (obfuscation>0) the hard core, OBFUSCATION POOL = 20, flat over
#                              its testable items: one per scored function,
#                              bytes at the stamped range differ from prepack.
#     EASY POOL = 20, flat over its testable items, is P + D + X together:
#     P family (packing>0)     packer signature absent / no RWX LOAD /
#                              ldd set == oracle / entry section == oracle /
#                              PT_INTERP == oracle
#     D family (anti-debug>0)  one item per available tool: the flag prints
#                              under that tool's observation
#     X family (always)        exit-code and rejection-line equality vs the
#                              oracle for the GT key, the wrong-key probe,
#                              and three fixed malformed keys; plus 3-run
#                              determinism
#     An empty pool donates its weight to the other (oracle still reaches full).
#
#   Retired from scoring: entropy / instruction-count /
#   branch-density statistical ranges. Every surviving item is an exact
#   boolean, set-equality, or byte comparison.
#   Interlock (I) is likewise NOT a direct scoring family: the guard
#   network's tamper/poison response is exercised INDIRECTLY by the X
#   behavioral-equality items -- tampering with a guard corrupts the key
#   path, so the submitted binary's right-/wrong-key behaviour diverges
#   from the oracle and the X items fail.
#
# ANTI-CHEAT PREREQUISITE STRUCTURE. Anti-cheat checks are
# PRECONDITIONS, not deductions: a failed prerequisite zeroes every dependent
# scoring stage, never just the item it touched.
#   Tier 0 (global — failure zeroes BOTH buckets):
#     - privilege drop unavailable -> fail-closed zero (root verifier never
#       runs analyzed code)
#     - ground truth missing -> loud fail_out zero
#     - agent input outside confinement -> the submission reads as empty
#     - EXEC CHEAT: any analyzed code executing a verifier-side binary
#       (/app /tests /solution) -> the property bucket voids immediately
#   Tier 1 (per artifact — failure zeroes that artifact's items, others may
#     still earn): plausibility gate, wrong-key rejection, exec-gated
#     GT-key flag reproduction
#   Tier 2 (per item): every behavioral item executes analyzed code through
#     the gated runner (strace execve/execveat + exec gate). The LICENSE
#     flag terminal keeps its documented exemption (fixed verifier-built
#     binary, key-only input — no agent code executes); D-family runs are
#     tool-observed (the observing tool is present by definition, and the
#     key-conditional exec cheat is already caught by the Tier 1 gated run).
#
# All ground truth values are read from /app/ground_truth/ during verification.
# ==============================================================================

# ------------------------------------------------------------------------------
# PATH CONFIGURATION
# ------------------------------------------------------------------------------

CHALLENGE_BIN="/app/binary"
GROUND_TRUTH_DIR="/app/ground_truth"
ORACLE_BIN="$GROUND_TRUTH_DIR/binaries/origin_binary"
PREPACK_BIN="$GROUND_TRUTH_DIR/binaries/prepack_binary"
RUBRIC="$GROUND_TRUTH_DIR/rubric.json"
CORRECT_KEY=$(cat "$GROUND_TRUTH_DIR/input.txt" 2>/dev/null | tr -d '\n\r')

AGENT_OUTPUT_DIR="/logs/artifacts/agent_output"
INPUT_FILE="$AGENT_OUTPUT_DIR/input.txt"
BINARIES_DIR="$AGENT_OUTPUT_DIR/binaries"
export INPUT_FILE

REWARD="/logs/verifier/reward.json"
REWARD_DETAILS="/logs/verifier/reward-details.json"

# ------------------------------------------------------------------------------
# THE LAW (fixed constants — no per-task tuning lives here)
# ------------------------------------------------------------------------------

LICENSE_LADDER_MAX=10     # chain-depth progress (compressed; was 30)
LICENSE_FLAG_MAX=50       # key terminal — the dominant bucket (was 20)
PROPERTY_MAX=40           # deterministic item bucket = obfuscation 20 + easy 20
OBF_MAX=20                # obfuscation-defeat pool (the hard property core)
EASY_MAX=20               # packing + anti-debug-bypass + behavior pool
TRACE_PARTIAL_MAX=$LICENSE_LADDER_MAX   # core_b ladder cap alias (shared block)

# core_b's ladder (byte-shared with the malware template) reads the legacy
# {points:[...]} shape; the law adapts the rubric's rungs into it at startup.
# Flat weights are the LAW — no weight field ships, core_b's // 1 default
# supplies them.
TRACE_POINTS_FILE="/tmp/rubric-points.json"
TRACE_GDB_TIMEOUT=30      # gdb budget for the ladder
PROP_VALGRIND_TIMEOUT=120 # valgrind budget for the per-tool bypass items
PROP_RUN_TIMEOUT=60       # plain behavioral run budget

# The three fixed malformed keys for the X-family probes (deterministic,
# identical across tasks; each is compared against the oracle's own reaction)
MALFORMED_KEYS=(
    ""
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "!!!!####$$$$%%%%^^^^"
)

# Fixed wrong-key probe (control probe, baseline principle): submitted
# binaries must still reject a wrong key. Also feeds the X-family equality
# items via the oracle's own reaction to the same probe.
WRONG_KEY_PROBE="INVALID_PROBE_KEY_0000000000000000"

# Legacy symbol-mode fallback for pre-stamp trees (address mode is the only
# stamped mode; these stay empty under the law)
TRACE_FUNCTIONS=()
TRACE_SCORES=()

SCORING_CONFIG=(
    "License Verification|60|score_license_verification|license_verification"
    "Property Validation|40|score_property_validation|property_validation"
)

# ===== @VERIFIER-CORE-A-BEGIN (byte-identical across the RE skills; canonical source: script/verifier_blocks/core_a.sh -- edit there, not here) =====

# --- capability probes ---------------------------------------------------------
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Single float chokepoint: bc when present (fast), python3 fallback (the firmware/protocol verifier images may not ship bc; the fallback strips the bc `scale=N;` dialect prefix before evaluating).
# Both print plain numbers.
float_compare() {
    if command_exists bc; then
        printf '%s\n' "$1" | bc -l
    else
        printf '%s\n' "$1" | python3 -c '
import re, sys
expr = sys.stdin.read().strip()
expr = re.sub(r"scale\s*=\s*\d+\s*;", "", expr)
try:
    v = eval(expr, {"__builtins__": {}}, {})
    print(int(v) if isinstance(v, bool) else v)
except Exception:
    print("")
'
    fi
}

# --- baseline #1: ground truth is root-only (no-op when not run as root) -------
chmod -R go-rwx "$GROUND_TRUTH_DIR" 2>/dev/null || true
mkdir -p "$(dirname "$REWARD")"

# --- baseline #2: agent-input confinement + size caps ---------------------------
VER_CAP_TEXT=$((10 * 1024 * 1024))     # report/input-class agent files
VER_CAP_BINARY=$((64 * 1024 * 1024))   # submitted binary artifacts
VER_CAP_IMAGE=$((256 * 1024 * 1024))   # image-class artifacts (repacks, trees)

# Confine an agent-supplied FILE: must exist, resolve inside agent_output, and be <= cap (default VER_CAP_TEXT).
# Echoes the resolved real path on success.
# Kills symlinks pointing at the ground truth (such a file would otherwise be compared against itself) and oversized-file DoS.
confined_agent_path() {
    local p="$1" cap="${2:-$VER_CAP_TEXT}" real sz
    [ -f "$p" ] || return 1
    real=$(readlink -f "$p" 2>/dev/null) || return 1
    case "$real" in
        "$AGENT_OUTPUT_DIR"|"$AGENT_OUTPUT_DIR"/*);;
        *) return 1;;
    esac
    sz=$(stat -c %s "$real" 2>/dev/null) || return 1
    [ "$sz" -le "$cap" ] || return 1
    echo "$real"
}

# Confine an agent-supplied DIRECTORY (extracted trees / roots): must be a relative path, resolve inside agent_output, exist, and the entry itself must not be a symlink (a symlinked root used to walk the oracle tree for free).
confined_agent_dir() {
    local p="$1" real
    [ -n "$p" ] || return 1
    case "$p" in /*) return 1 ;; esac
    real=$(readlink -f "$AGENT_OUTPUT_DIR/$p" 2>/dev/null) || return 1
    case "$real" in
        "$AGENT_OUTPUT_DIR"/*);;
        *) return 1;;
    esac
    [ -d "$real" ] || return 1
    [ ! -L "$AGENT_OUTPUT_DIR/$p" ] || return 1
    echo "$real"
}

# --- baseline #3: privilege drop (FAIL-CLOSED on a root verifier) ---------------
# Wraps EXECUTION of agent/analyzed code only; static analysis tools run as the verifier.
# VERIFIER_RUNAS is exported so embedded python scorers can reuse the same drop via shlex.split(os.environ["VERIFIER_RUNAS"]).
# VER_DROP_OK is exported for the python core's gate (verifier_core.drop_fail_closed): a root
# verifier with no usable drop must REFUSE every agent-code run (denied observables, the
# affected bucket scores 0) instead of executing analyzed code as root.
VER_RUNAS=()
VER_DROP_OK=1
if command_exists setpriv && id nobody >/dev/null 2>&1 \
   && setpriv --reuid=nobody --regid=nogroup --clear-groups /bin/true >/dev/null 2>&1; then
    chmod -R a+rX "$AGENT_OUTPUT_DIR" 2>/dev/null || true
    VER_RUNAS=(setpriv --reuid=nobody --regid=nogroup --clear-groups)
    export VERIFIER_RUNAS="${VER_RUNAS[*]}"
elif [ "$(id -u)" = "0" ]; then
    VER_DROP_OK=0
    echo "✗ fail-closed: privilege drop unavailable on a root verifier; agent-code execution refused (affected buckets score 0)" >&2
fi
export VER_DROP_OK

# --- baseline #4: execve/execveat gate (plain-text strace logs) ------------------
# rc 0 = violation (the traced run executed a verifier-side binary). $2 (optional) is the ONE exempted verifier-side target -- the binary under test when the activation command runs it directly (its first execve would otherwise void every legitimate run).
# For strace -xx logs use the python core's exec_gate(), which decodes escapes first.
exec_gate_violation() {
    local trace="$1" allowed="${2:-}" p
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        [ "$p" = "$allowed" ] && continue
        case "$p" in
            /app|/app/*|/tests|/tests/*|/solution|/solution/*) return 0 ;;
        esac
    done < <(grep -oE 'execve(at)?\(([^,]*, )?"[^"]*"' "$trace" 2>/dev/null \
        | sed -E 's/^execve(at)?\(([^,]*, )?"//; s/"$//')
    return 1
}

# --- baseline #5: agent-declared command gate ------------------------------------
# ONE strict rule everywhere (the bash -c runners require parens in the set; argv-list runners could tolerate more but apply the same rule for uniformity).
# First-token policy is per domain, on top of this check.
cmd_operators_safe() {
    ! printf '%s' "$1" | grep -qE '[;&|`$()<>]'
}

# --- baseline #6: array scoring --------------------------------------------------
# Case-insensitive whole-word F1 with the 0.5 precision floor and the dump cap (agent listing more than GT+3 items scores 0).
# Args: gt items and agent items as pipe-separated strings, then max points; echoes points.
calculate_array_f1() {
    local gt_items="$1" agent_items="$2" max_points="$3"

    gt_items=$(echo "$gt_items" | xargs | tr ' ' '|')
    agent_items=$(echo "$agent_items" | xargs | tr ' ' '|')

    if [ -z "$gt_items" ] && [ -z "$agent_items" ]; then
        echo "$max_points"
        return
    fi
    if [ -z "$gt_items" ] || [ -z "$agent_items" ]; then
        echo "0"
        return
    fi

    local gt_count agent_count
    gt_count=$(echo "$gt_items" | tr '|' '\n' | grep -v '^$' | wc -l)
    agent_count=$(echo "$agent_items" | tr '|' '\n' | grep -v '^$' | wc -l)

    if [ "$agent_count" -gt $((gt_count + 3)) ]; then
        echo "0"
        return
    fi

    local tp=0
    # exact (case-insensitive) whole-string match -- substring matching would let one concatenated string containing every plausible name score near-perfect recall
    local gt_item
    for gt_item in $(echo "$gt_items" | tr '|' ' '); do
        if [ -n "$gt_item" ] && echo "$agent_items" | tr '|' '\n' | grep -qiwx "$gt_item"; then
            tp=$((tp + 1))
        fi
    done

    local fp=0 agent_item
    for agent_item in $(echo "$agent_items" | tr '|' ' '); do
        if [ -n "$agent_item" ] && ! echo "$gt_items" | tr '|' '\n' | grep -qiwx "$agent_item"; then
            fp=$((fp + 1))
        fi
    done

    local fn=$((gt_count - tp))
    local precision recall f1
    if [ $((tp + fp)) -eq 0 ]; then
        precision=1.0
    else
        precision=$(float_compare "scale=4; $tp.0 / ($tp + $fp)")
    fi

    # precision floor: below 0.5 the whole array scores 0
    if [ $((tp + fp)) -gt 0 ] && [ "$(float_compare "$precision < 0.5")" = "1" ]; then
        echo "0"
        return
    fi

    if [ $((tp + fn)) -eq 0 ]; then
        recall=1.0
    else
        recall=$(float_compare "scale=4; $tp.0 / ($tp + $fn)")
    fi

    # NB: no && / || inside float_compare expressions -- the python3 fallback cannot parse the bc boolean dialect
    if [ "$(float_compare "$precision == 0")" = "1" ] && [ "$(float_compare "$recall == 0")" = "1" ]; then
        f1=0
    else
        f1=$(float_compare "scale=4; 2 * $precision * $recall / ($precision + $recall)")
    fi

    float_compare "scale=4; $f1 * $max_points"
}

# --- baseline #7 helper: fact-boolean points, misses penalized, clamped >= 0 ----
fact_bool_points() {
    # args: hits misses total_checks max_points
    local pts
    pts=$(float_compare "scale=4; ($1 - $2) * $4 / $3")
    [ "$(float_compare "$pts < 0")" = "1" ] && pts=0
    echo "$pts"
}

# --- baseline #9: reward writing is hardened, failures are loud -------------------
TOTAL_SCORE=0
DETAILS_JSON="{}"

# Always leave a reward.json behind, even when the script dies mid-scoring (set -e kills it on any unexpected failure): a partial score beats a missing file, and the harness treats a missing file as a hard verifier error. rm -f first so a pre-existing (possibly immutable) file cannot shadow our write; a failed write screams on stderr instead of silently leaving an agent-forged score behind.
write_reward() {
    local score
    score=$(float_compare "scale=4; ${TOTAL_SCORE:-0} / 100" 2>/dev/null)
    [ -n "$score" ] || score="0.0000"
    case "$score" in .*) score="0$score";; esac
    rm -f "$REWARD" "$REWARD_DETAILS" 2>/dev/null || true
    if ! printf '{"score": %s}\n' "$score" >"$REWARD" 2>/dev/null; then
        echo "verifier: could not write $REWARD (pre-existing immutable file?)" >&2
    fi
    if ! printf '{"score": %s, "details": %s}\n' "$score" "${DETAILS_JSON:-{\}}" >"$REWARD_DETAILS" 2>/dev/null; then
        echo "verifier: could not write $REWARD_DETAILS" >&2
    fi
}
trap write_reward EXIT

# Hard failure (missing ground truth / required interpreter): score 0.0000 with an error details blob, via the EXIT trap.
fail_out() {
    echo "verifier: $1" >&2
    DETAILS_JSON='{"error": "true"}'
    exit 0
}

# --- unified scoring loop ---------------------------------------------------------
# SCORING_CONFIG format (all scorers are fixed-weight): "display name|max points|scorer function|json field (snake_case)" Every scorer echoes its numeric score on the first line, details after.
run_all_scorers() {
    VER_CAT_NAMES=()
    VER_CAT_SCORES=()
    VER_CAT_MAXES=()
    VER_CAT_DETAILS=()
    VER_CAT_FIELDS=()
    VER_CAT_POINTS=()
    VER_CAT_MAXPOINTS=()
    TOTAL_SCORE=0

    local entry name max_points func_name json_field output raw_score details score points maxpoints
    for entry in "${SCORING_CONFIG[@]}"; do
        IFS='|' read -r name max_points func_name json_field <<< "$entry"
        output=$("${func_name}" || true)
        [ -n "$output" ] || output="0
scorer error"
        raw_score=$(echo "$output" | head -1)
        details=$(echo "$output" | tail -n +2)
        score=$(float_compare "scale=4; ${raw_score:-0} + 0")
        [ -n "$score" ] || score=0

        VER_CAT_NAMES+=("$name")
        VER_CAT_SCORES+=("$score")
        VER_CAT_MAXES+=("$max_points")
        VER_CAT_DETAILS+=("$details")
        VER_CAT_FIELDS+=("$json_field")

        points=$(float_compare "scale=4; $score / 100")
        case "$points" in .*) points="0$points";; esac
        VER_CAT_POINTS+=("$points")
        maxpoints=$(float_compare "scale=4; $max_points / 100")
        case "$maxpoints" in .*) maxpoints="0$maxpoints";; esac
        VER_CAT_MAXPOINTS+=("$maxpoints")

        TOTAL_SCORE=$(float_compare "$TOTAL_SCORE + $score")
    done
}

# --- unified report + reward-details JSON ------------------------------------------
ver_print_report() {
    local title="$1" i sym disp
    echo "==============================================================================="
    echo "$title"
    echo "==============================================================================="
    for i in "${!VER_CAT_NAMES[@]}"; do
        sym="✗"
        [ "$(float_compare "${VER_CAT_SCORES[$i]} > 0")" = "1" ] && sym="⊘"
        [ "$(float_compare "${VER_CAT_SCORES[$i]} >= ${VER_CAT_MAXES[$i]}")" = "1" ] && sym="✓"
        disp=$(float_compare "scale=4; ${VER_CAT_SCORES[$i]} / 100")
        case "$disp" in .*) disp="0$disp";; esac
        local maxdisp
        maxdisp=$(float_compare "scale=4; ${VER_CAT_MAXES[$i]} / 100")
        case "$maxdisp" in .*) maxdisp="0$maxdisp";; esac
        printf "  %s %-38s %6s / %s\n" "$sym" "${VER_CAT_NAMES[$i]}:" "$disp" "$maxdisp"
        if [ -n "${VER_CAT_DETAILS[$i]}" ]; then
            echo "${VER_CAT_DETAILS[$i]}" | while IFS= read -r line; do
                [ -n "$line" ] && echo "    $line"
            done
        fi
        echo ""
    done
    echo "  ----------------------------------------"
    local total_disp
    total_disp=$(float_compare "scale=4; $TOTAL_SCORE / 100")
    case "$total_disp" in .*) total_disp="0$total_disp";; esac
    printf "  %-40s %6s / %s\n" "TOTAL SCORE:" "$total_disp" "1.00"
    echo "==============================================================================="
}

ver_build_details_json() {
    local json="{" i passed
    for i in "${!VER_CAT_FIELDS[@]}"; do
        [ "$i" -gt 0 ] && json+=","
        if [ "$(float_compare "${VER_CAT_SCORES[$i]} >= ${VER_CAT_MAXES[$i]}")" = "1" ]; then
            passed=true
        else
            passed=false
        fi
        json+="
  \"${VER_CAT_FIELDS[$i]}\": {
    \"passed\": $passed,
    \"points\": ${VER_CAT_POINTS[$i]},
    \"max_points\": ${VER_CAT_MAXPOINTS[$i]}
  }"
    done
    json+="
}"
    DETAILS_JSON="$json"
}
# ===== @VERIFIER-CORE-A-END =====

# --- domain input confinement (baseline #2 applied to this skill's inputs) -----
_real=$(confined_agent_path "$INPUT_FILE") || _real=""
if [ -n "$_real" ]; then
    INPUT_FILE="$_real"
else
    echo "verifier: input.txt rejected (symlink outside agent_output or over 10MB)" >&2
    INPUT_FILE="/dev/null"
fi

[ -f "$GROUND_TRUTH_DIR/input.txt" ] \
    || fail_out "missing ground truth: $GROUND_TRUTH_DIR/input.txt"

# ------------------------------------------------------------------------------
# THE RUBRIC (the only per-task input; written by stamp_ground_truth 8.06)
#   rubric.json
#.rungs              ordered stations {name, vaddr, iter{name,vaddr,total}}
#.levels             {packing, anti_debug, obfuscation, interlock}
#.packer_signature   hex bytes present iff the construction knows them
#.scored_functions   [{vaddr, size}]  (obfuscation anchors ∩ hosts)
#.tool_blacklist     tools that cannot run this carrier
#.activation         canonical invocation argv
# ------------------------------------------------------------------------------

[ -s "$RUBRIC" ] || fail_out "missing rubric: $RUBRIC (run stamp_ground_truth 8.06)"

ACTIVATION_ARGS=()
if command_exists jq; then
    while IFS= read -r _a; do
        [ -n "$_a" ] && ACTIVATION_ARGS+=("$_a")
    done < <(jq -r '.activation[]?' "$RUBRIC" 2>/dev/null || true)
fi
export ACTIVATION_ARGS

LEVEL_PACKING=0; LEVEL_ANTI_DEBUG=0; LEVEL_OBFUSCATION=0; LEVEL_INTERLOCK=0
PACKER_SIGNATURE_HEX=""
TOOL_BLACKLIST=""
if command_exists jq; then
    LEVEL_PACKING=$(jq -r '.levels.packing // 0' "$RUBRIC")
    LEVEL_ANTI_DEBUG=$(jq -r '.levels.anti_debug // 0' "$RUBRIC")
    LEVEL_OBFUSCATION=$(jq -r '.levels.obfuscation // 0' "$RUBRIC")
    LEVEL_INTERLOCK=$(jq -r '.levels.interlock // 0' "$RUBRIC")
    # informational only: interlock is NOT a direct scoring family (see header) --
    # its defeat is covered indirectly by the X behavioral-equality items
    PACKER_SIGNATURE_HEX=$(jq -r '.packer_signature // ""' "$RUBRIC")
    TOOL_BLACKLIST=$(jq -r '(.tool_blacklist // []) | join(" ")' "$RUBRIC")
    # adapt the rubric rungs into core_b's legacy {points:[...]} shape
    jq '{points: .rungs}' "$RUBRIC" > "$TRACE_POINTS_FILE" 2>/dev/null \
        || fail_out "rubric.json unreadable: $RUBRIC"
fi

# ===== @VERIFIER-CORE-B-BEGIN (byte-identical across the malware/protection templates; canonical source: script/verifier_blocks/core_b.sh -- edit there, not here) =====

# --- oracle-relative code-shape metrics (static analysis: runs as the verifier,
# not dropped; --no-show-raw-insn puts the mnemonic in $2) -------------------------

get_text_size() {
    local sz
    sz=$(readelf -SW "$1" 2>/dev/null | awk '$2 == ".text" { print $6; exit }')
    [ -n "$sz" ] && echo $((16#$sz)) || echo ""
}

get_insn_count() {
    objdump -d --no-show-raw-insn "$1" 2>/dev/null | grep -cE '^[[:space:]]*[0-9a-f]+:'
}

get_branch_count() {
    objdump -d --no-show-raw-insn "$1" 2>/dev/null \
        | awk '/^[[:space:]]*[0-9a-f]+:/ {print $2}' \
        | grep -cE '^(j|call|ret|loop)'
}

get_indirect_branch_count() {
    objdump -d --no-show-raw-insn "$1" 2>/dev/null \
        | grep -cE '^[[:space:]]*[0-9a-f]+:[[:space:]]+(jmp|call)[[:space:]]+\*'
}

has_rwx_load() {
    readelf -lW "$1" 2>/dev/null | grep ' LOAD ' | grep -qE '(^|[[:space:]])(RWE|WE)([[:space:]]|$)'
}

get_section_entropy() {
    local tmp
    tmp=$(mktemp)
    if ! objcopy --dump-section "$2=$tmp" "$1" >/dev/null 2>&1 || [ ! -s "$tmp" ]; then
        rm -f "$tmp"; return 1
    fi
    ent "$tmp" 2>/dev/null | grep 'Entropy' | sed -n 's/.*= *\([0-9.]*\).*/\1/p'
    rm -f "$tmp"
}

# Statistical deviation score: 1.0 (within 20%) .. 0 (80%+ off). Shared by the
# entropy and code-shape property tests.
calculate_deviation_score() {
    local val1=$1
    local val2=$2

    if [ -z "$val1" ] || [ -z "$val2" ]; then
        echo "0"
        return
    fi

    local min max ratio deviation
    if [ "$(float_compare "$val1 < $val2")" = "1" ]; then
        min=$val1
        max=$val2
    else
        min=$val2
        max=$val1
    fi

    ratio=$(float_compare "scale=4; $min / $max")
    deviation=$(float_compare "scale=4; 1 - $ratio")

    local score
    if [ "$(float_compare "$deviation < 0.2")" = "1" ]; then
        score="1.0"
    elif [ "$(float_compare "$deviation < 0.4")" = "1" ]; then
        score="0.8"
    elif [ "$(float_compare "$deviation < 0.6")" = "1" ]; then
        score="0.6"
    elif [ "$(float_compare "$deviation < 0.8")" = "1" ]; then
        score="0.4"
    else
        score="0"
    fi

    echo "$score"
}

# --- anti-stub artifact gate -------------------------------------------------------
# A submitted binary must be: the agent's OWN file (symlink-confined to
# agent_output, <= VER_CAP_BINARY), a real 64-bit ELF executable (ET_EXEC or
# runnable PIE), plausibly sized (file size AND .text volume >= 1/4 of the
# oracle), and NOT a byte copy of the challenge binary.
validate_submission() {
    local bin="$1"
    [ -f "$bin" ] && [ -x "$bin" ] || return 1
    local real
    real=$(readlink -f "$bin" 2>/dev/null) || return 1
    case "$real" in
        "$AGENT_OUTPUT_DIR"|"$AGENT_OUTPUT_DIR"/*);;
        *) return 1;;
    esac
    local sz
    sz=$(stat -c %s "$real" 2>/dev/null) || return 1
    [ "$sz" -le "$VER_CAP_BINARY" ] || return 1
    local ftype
    ftype=$(file -b "$bin" 2>/dev/null)
    echo "$ftype" | grep -q "ELF 64-bit" || return 1
    if ! echo "$ftype" | grep -q "executable"; then
        # `file` reports PIE as "shared object"; the interpreter segment
        # distinguishes a runnable PIE from an actual shared library
        echo "$ftype" | grep -q "shared object" && echo "$ftype" | grep -q "interpreter" || return 1
    fi
    local osz bsz
    osz=$(stat -c %s "$ORACLE_BIN" 2>/dev/null)
    if [ -n "$osz" ] && [ "$osz" -gt 0 ]; then
        bsz=$(stat -c %s "$bin") || return 1
        [ "$bsz" -ge $((osz / 4)) ] || return 1
    fi
    if command_exists readelf && [ -x "$ORACLE_BIN" ]; then
        local o_text b_text
        o_text=$(get_text_size "$ORACLE_BIN")
        b_text=$(get_text_size "$bin")
        if [ -n "$o_text" ] && [ "$o_text" -gt 0 ] && [ -n "$b_text" ]; then
            [ "$b_text" -ge $((o_text / 4)) ] || return 1
        fi
    fi
    [ "$(sha256sum <"$bin" 2>/dev/null | cut -d' ' -f1)" != "$(sha256sum <"$CHALLENGE_BIN" 2>/dev/null | cut -d' ' -f1)" ] || return 1
    return 0
}

# --- defeat-property tests shared verbatim by both skills ---------------------------
# rc 0 = property holds, 1 = tested and fails, 2 = untestable (tool/oracle
# missing -> dropped from the denominator, per the baseline's untestable table)

prop_unpack() {
    if ! command_exists ent || [ ! -x "$ORACLE_BIN" ]; then return 2; fi
    local be oe
    be=$(ent "$1" 2>/dev/null | grep 'Entropy' | sed -n 's/.*= *\([0-9.]*\).*/\1/p')
    oe=$(ent "$ORACLE_BIN" 2>/dev/null | grep 'Entropy' | sed -n 's/.*= *\([0-9.]*\).*/\1/p')
    if [ -z "$be" ] || [ -z "$oe" ]; then return 1; fi
    # 1. whole-file entropy within 20% of the oracle
    [ "$(calculate_deviation_score "$be" "$oe")" = "1.0" ] || return 1
    # 2. no writable+executable LOAD segment (packer self-decryption hallmark)
    if command_exists readelf && has_rwx_load "$1"; then return 1; fi
    # 3. .text entropy below the packed threshold -- whole-file entropy
    #    dilutes on large binaries; the code section does not
    if command_exists objcopy; then
        local te
        te=$(get_section_entropy "$1" ".text" || true)
        if [ -n "$te" ] && [ "$(float_compare "$te >= 7.2")" = "1" ]; then return 1; fi
    fi
    return 0
}

prop_deobf() {
    # 1. instruction count within 20%  (obfuscation inflates code volume)
    # 2. branch density within 20%     (flattening dispatchers inflate the
    #                                    branch share even at equal volume)
    # 3. indirect branches <= 4x oracle + 16 (virtualization dispatches
    #                                    through computed targets)
    if ! command_exists objdump || [ ! -x "$ORACLE_BIN" ]; then return 2; fi
    local bi oi bb ob bid oid
    bi=$(get_insn_count "$1");  oi=$(get_insn_count "$ORACLE_BIN")
    if [ -z "$bi" ] || [ "$bi" -eq 0 ] || [ -z "$oi" ] || [ "$oi" -eq 0 ]; then return 1; fi
    [ "$(calculate_deviation_score "$bi" "$oi")" = "1.0" ] || return 1
    bb=$(get_branch_count "$1"); ob=$(get_branch_count "$ORACLE_BIN")
    if [ "$bb" -gt 0 ] && [ "$ob" -gt 0 ]; then
        local bd od
        bd=$(float_compare "scale=6; $bb / $bi")
        od=$(float_compare "scale=6; $ob / $oi")
        [ "$(calculate_deviation_score "$bd" "$od")" = "1.0" ] || return 1
    fi
    bid=$(get_indirect_branch_count "$1"); oid=$(get_indirect_branch_count "$ORACLE_BIN")
    if [ "$bid" -gt $((oid * 4 + 16)) ]; then return 1; fi
    return 0
}

# --- GDB chain-depth ladder (shared partial-credit mechanism) ------------------------
# How deep does a REJECTED key/command drive the verification chain in the
# EVASION-FREE ORACLE? ORDERED-PREFIX semantics: rungs score in
# execution order, the ladder STOPS at the first missed rung, and the first
# missed rung may still earn a BYTE-FRACTION of its weight when it carries an
# iter (counting) probe -- the probe fires once per still-matching comparison
# byte, so count/total is the matched-prefix fraction. Random touching of
# deep code earns nothing; only the ordered prefix scores.
#
# Only called on rejection: a valid key/command deterministically traverses
# the whole chain (the caller short-circuits to full credit), so misses under
# it indicate verifier flakiness and are never used to deduct.
#
# Two breakpoint modes:
#   ADDRESS (preferred): TRACE_POINTS_FILE (trace_points.json in the ground
#     truth) carries build-time-extracted probe vaddrs, optionally with an
#     "iter" sub-object {name, vaddr, total} per rung. The ladder `starti`s
#     the oracle, derives the PIE load base from `info proc mappings` via
#     embedded python, and breaks on base+vaddr. No symbol name is involved,
#     so challenge binaries can hide/localize their license-chain symbols.
#   SYMBOL (legacy): breakpoints on TRACE_FUNCTIONS[] names -- for tasks
#     whose ground truth predates trace_points.json (no counting probes).
#
# Usage: run_trace_ladder <stdin_file> <gdb target argv...>
# Echoes the score (first line) + per-checkpoint details; rc 1 when it cannot
# run (no oracle / no breakpoints configured).
run_trace_ladder() {
    local stdin_file="$1"; shift
    [ -f "$ORACLE_BIN" ] && [ -x "$ORACLE_BIN" ] || return 1

    # ---- resolve both modes into parallel arrays --------------------------
    # TP_*  : entry probes (stage rungs); TPI_*: counting probes ("" if none)
    local TP_NAMES=() TP_WEIGHTS=() TP_VADDRS=() fn _i _rec _npts
    local TPI_NAMES=() TPI_VADDRS=() TPI_TOTALS=()
    if [ -s "${TRACE_POINTS_FILE:-}" ] && command_exists jq; then
        _npts=$(jq -r '.points | length' "$TRACE_POINTS_FILE" 2>/dev/null || echo 0)
        if [ "${_npts:-0}" -gt 0 ] 2>/dev/null; then
            local _flds=()
            for _i in $(seq 0 $((_npts - 1))); do
                _rec=$(jq -r ".points[$_i] | .name, .vaddr, (.weight // 1),
                               (.iter.name // \"\"), (.iter.vaddr // 0),
                               (.iter.total // 0)" \
                        "$TRACE_POINTS_FILE" 2>/dev/null) || continue
                mapfile -t _flds <<<"$_rec"
                [ "${#_flds[@]}" -ge 2 ] || continue
                TP_NAMES+=("${_flds[0]}")
                TP_VADDRS+=("$(( ${_flds[1]} ))")
                TP_WEIGHTS+=("${_flds[2]:-1}")
                if [ -n "${_flds[3]:-}" ] && [ "${_flds[5]:-0}" != "0" ]; then
                    TPI_NAMES+=("${_flds[3]}")
                    TPI_VADDRS+=("$(( ${_flds[4]} ))")
                    TPI_TOTALS+=("${_flds[5]}")
                else
                    TPI_NAMES+=(""); TPI_VADDRS+=("0"); TPI_TOTALS+=("0")
                fi
            done
        fi
    fi
    if [ "${#TP_NAMES[@]}" -eq 0 ]; then
        if [ "${#TRACE_FUNCTIONS[@]}" -eq 0 ]; then return 1; fi
        TP_NAMES=("${TRACE_FUNCTIONS[@]}")
        for _i in "${!TRACE_FUNCTIONS[@]}"; do
            TP_WEIGHTS+=("${TRACE_SCORES[$_i]:-1}")
            TPI_NAMES+=(""); TPI_VADDRS+=("0"); TPI_TOTALS+=("0")
        done
    fi

    # ---- emit the gdb script ---------------------------------------------
    {
        cat <<'EOF'
set pagination off
set confirm off
set breakpoint pending on
set width 0
set height 0
set print thread-events off
handle SIGPIPE nostop noprint pass
handle SIGALRM nostop noprint pass
EOF
        if [ "${#TP_VADDRS[@]}" -gt 0 ]; then
            # ADDRESS mode: stop at the loader entry (inferior loaded, base
            # fixed -- gdb disables ASLR by default), read the image base
            # off the mappings, then place absolute breakpoints. Entry
            # probes print TRACE:<name> once; counting probes print
            # TRACEDIT:<name> on EVERY hit (the hit count IS the signal).
            cat <<EOF
starti
python
import gdb
_pts = [
EOF
            for _i in "${!TP_NAMES[@]}"; do
                echo "    (\"${TP_NAMES[$_i]}\", ${TP_VADDRS[$_i]}, ${TPI_VADDRS[$_i]:-0}, \"${TPI_NAMES[$_i]:-}\"),"
            done
            cat <<EOF
]
_base = None
for _ln in gdb.execute("info proc mappings", to_string=True).splitlines():
    if _ln.rstrip().endswith("$ORACLE_BIN"):
        _base = int(_ln.split()[0], 16)
        break
if _base is None:
    gdb.write("TRACE:NOBASE\n")
else:
    for _name, _off, _ioff, _iname in _pts:
        gdb.execute("break *%d" % (_base + _off))
        gdb.execute('commands\nsilent\nprintf "TRACE:%s\\\\n", "' + _name + '"\ncontinue\nend')
        if _ioff and _iname:
            gdb.execute("break *%d" % (_base + _ioff))
            gdb.execute('commands\nsilent\nprintf "TRACEDIT:%s\\\\n", "' + _iname + '"\ncontinue\nend')
end
continue
quit
EOF
        else
            # SYMBOL mode (legacy; no counting probes)
            for fn in "${TP_NAMES[@]}"; do
                cat <<EOF
break $fn
commands
    silent
    printf "TRACE:$fn\n"
    continue
end
EOF
            done
            cat <<'EOF'
run
quit
EOF
        fi
    } >/tmp/verifier-trace.gdb

    set +e
    # -nx: skip ~/.gdbinit (pwndbg slows startup on large binaries and can
    # swallow the inferior's stdout). TRACE_GDB_TIMEOUT tunes the run for
    # slow carriers (defaults to 30s).
    timeout "${TRACE_GDB_TIMEOUT:-30}" gdb -nx -q -batch -x /tmp/verifier-trace.gdb --args "$@" \
        < "$stdin_file" >/tmp/verifier-trace.log 2>&1
    set -e

    if grep -qF "TRACE:NOBASE" /tmp/verifier-trace.log; then
        echo "0"
        echo "⚠ address trace failed: could not derive the oracle PIE load base (no mapping for $ORACLE_BIN in gdb)"
        return 0
    fi

    # ---- ordered-prefix scoring with a byte-fraction failing rung ---------
    local details=() weighted_total=0 weighted_hit=0 idx=0 n=1 fn stopped=0
    for fn in "${TP_NAMES[@]}"; do
        local w="${TP_WEIGHTS[$idx]:-1}"
        weighted_total=$(float_compare "$weighted_total + $w")
        if [ "$stopped" -eq 1 ]; then
            details+=("✗ checkpoint $n ($fn) not reached (ladder stopped)")
            idx=$((idx + 1)); n=$((n + 1)); continue
        fi
        if grep -qF "TRACE:$fn" /tmp/verifier-trace.log; then
            weighted_hit=$(float_compare "$weighted_hit + $w")
            details+=("✓ checkpoint $n ($fn) passed")
        elif [ -n "${TPI_NAMES[$idx]:-}" ]; then
            # first missed rung with a counting probe: byte-fraction credit.
            # The probe fired once per still-matching comparison byte, so
            # the hit count over the stamped total is the matched-prefix
            # fraction.
            local _hits=0 _frac=0
            _hits=$(grep -cF "TRACEDIT:${TPI_NAMES[$idx]}" /tmp/verifier-trace.log || true)
            if [ "$_hits" -gt "${TPI_TOTALS[$idx]}" ]; then _hits="${TPI_TOTALS[$idx]}"; fi
            _frac=$(float_compare "scale=4; $_hits / ${TPI_TOTALS[$idx]}")
            if [ "$(float_compare "$_frac > 0")" = "1" ]; then
                weighted_hit=$(float_compare "scale=4; $weighted_hit + $w * $_frac")
                details+=("⊘ checkpoint $n ($fn) partial: matched prefix $_hits/${TPI_TOTALS[$idx]} bytes")
            else
                details+=("✗ checkpoint $n ($fn) failed at byte 0 (0/${TPI_TOTALS[$idx]})")
            fi
            stopped=1
        else
            details+=("✗ checkpoint $n ($fn) failed (no counting probe)")
            stopped=1
        fi
        idx=$((idx + 1)); n=$((n + 1))
    done

    local score=0
    if [ "$(float_compare "$weighted_total > 0")" = "1" ]; then
        score=$(float_compare "scale=4; $weighted_hit * $TRACE_PARTIAL_MAX / $weighted_total")
    fi
    echo "$score"
    printf '%s\n' "${details[@]}"
}

# ===== @VERIFIER-CORE-B-END =====

# ==============================================================================
# DOMAIN FUNCTIONS
# ==============================================================================

# --- expected flag: derived at verification time from the ORACLE binary and
# the ground-truth key. The flag depends on the key blob, so a stub that never
# recovered the GT key cannot predict it.
EXPECTED_FLAG=""

compute_expected_flag() {
    if [ -x "$ORACLE_BIN" ] && [ -n "$CORRECT_KEY" ]; then
        # || true INSIDE the substitution: under set -e + pipefail an oracle
        # that prints no flag must degrade to the empty-flag warning below
        EXPECTED_FLAG=$(echo "$CORRECT_KEY" | timeout 60 "$ORACLE_BIN" "${ACTIVATION_ARGS[@]}" 2>/dev/null \
            | grep -oE 'flag\{[^}]*\}' | head -1 || true)
    fi
}

# --- behavioral run helpers ----------------------------------------------------
# ANTI-CHEAT PREREQUISITE, TIER 2: every execution of ANALYZED code goes
# through the gated runner. run_bin wraps the run in strace -f
# (execve/execveat only) and applies the exec gate — executing anything under
# /app, /tests, or /solution (mirroring the oracle, replaying the challenge
# binary, reading verifier internals) sets EXEC_CHEAT, and the property
# scorer immediately voids the WHOLE bucket: an exec cheat falsifies every
# behavioral item at once, so the dependent scope is everything.
# The LICENSE flag terminal keeps its documented exemption (a fixed
# verifier-built binary fed a key string — no agent code executes there).
EXEC_CHEAT=0

run_bin() {
    local bin="$1" keyf="$2" out rc gate_trace=""
    if command_exists strace; then
        gate_trace=$(mktemp)
    fi
    set +e
    if [ -n "$gate_trace" ]; then
        out=$(timeout "$PROP_RUN_TIMEOUT" strace -f -e trace=execve,execveat \
              -o "$gate_trace" "${VER_RUNAS[@]}" "$bin" "${ACTIVATION_ARGS[@]}" \
              < "$keyf" 2>/dev/null)
    else
        out=$(timeout "$PROP_RUN_TIMEOUT" "${VER_RUNAS[@]}" "$bin" "${ACTIVATION_ARGS[@]}" < "$keyf" 2>/dev/null)
    fi
    rc=$?
    set -e
    if [ -n "$gate_trace" ]; then
        if exec_gate_violation "$gate_trace"; then
            EXEC_CHEAT=1
            echo "✗ exec cheat: $bin executed a verifier-side binary — property bucket voided" >&2
        fi
        rm -f "$gate_trace"
    fi
    echo "rc$rc"
    printf '%s\n' "$out"
}

oracle_rejection_line() {
    # the oracle's own rejection message line for a given key file
    local keyf="$1"
    run_bin "$ORACLE_BIN" "$keyf" | grep -vE '^rc[0-9]+$' | grep -E 'Invalid|invalid|denied|Denied|reject|Reject|expired|Expired' | head -1 || true
}

# ==============================================================================
# LICENSE VERIFICATION — 60 = key terminal 50 + chain-ladder progress 10
# ==============================================================================
score_license_verification() {
    local score=0 ladder=0 flag=0
    local test_key=""
    local details=()

    if [ -f "$INPUT_FILE" ]; then
        test_key=$(cat "$INPUT_FILE" 2>/dev/null | tr -d '\n\r' | head -1)
    fi

    if [ -n "$test_key" ]; then
        if [ "$VER_DROP_OK" -ne 1 ]; then
            echo "0"
            echo "✗ fail-closed: privilege drop unavailable on a root verifier -- analyzed binaries must never run as root"
            return
        fi

        # ---- flag terminal (20): challenge binary accepts the key ----------
        # Plain dropped run, deliberately NOT traced (D>=1 anti-debug fires
        # under any tracer) and deliberately not exec-gated (the license run
        # feeds a fixed verifier-built binary a key string).
        local lic_out lic_rc
        set +e
        lic_out=$(echo "$test_key" | timeout "$PROP_RUN_TIMEOUT" "${VER_RUNAS[@]}" "$CHALLENGE_BIN" "${ACTIVATION_ARGS[@]}" 2>/dev/null)
        lic_rc=$?
        set -e
        if [ "$lic_rc" -eq 0 ] && grep -qE 'flag\{[A-Za-z0-9]{5}(-[A-Za-z0-9]{5}){4}\}' <<<"$lic_out"; then
            flag=$LICENSE_FLAG_MAX
            details+=("✓ flag terminal: key accepted, flag printed ($LICENSE_FLAG_MAX/$LICENSE_FLAG_MAX)")
        else
            details+=("✗ flag terminal: key rejected (exit=$lic_rc) (0/$LICENSE_FLAG_MAX)")
        fi

        # ---- ordered chain ladder (30) --------------------------------------
        if [ "$flag" -eq "$LICENSE_FLAG_MAX" ]; then
            # Deterministic-traversal ruling: a key the challenge binary
            # accepts necessarily drove the whole chain in the evasion-free
            # oracle; running gdb under it would only let verifier flakiness
            # deduct from a real solve.
            ladder=$LICENSE_LADDER_MAX
            details+=("✓ chain ladder: auto-full (flag proved the full traversal) ($LICENSE_LADDER_MAX/$LICENSE_LADDER_MAX)")
        else
            local trace_out temp_input
            temp_input=$(mktemp)
            printf '%s\n' "$test_key" > "$temp_input"
            trace_out=$(run_trace_ladder "$temp_input" "$ORACLE_BIN" \
                ${ACTIVATION_ARGS[@]+"${ACTIVATION_ARGS[@]}"} || true)
            rm -f "$temp_input"
            if [ -n "$trace_out" ]; then
                local trace_score=$(echo "$trace_out" | head -1)
                if [ "$(float_compare "$trace_score > $LICENSE_LADDER_MAX")" = "1" ]; then
                    trace_score=$LICENSE_LADDER_MAX
                fi
                ladder="$trace_score"
                local pts_display=$(float_compare "scale=4; $ladder / 100")
                case "$pts_display" in .*) pts_display="0$pts_display";; esac
                details+=("⊘ chain ladder: $ladder/$LICENSE_LADDER_MAX ($pts_display/0.1000)")
                while IFS= read -r line; do
                    [ -n "$line" ] && details+=("   $line")
                done <<< "$(echo "$trace_out" | tail -n +2)"
            else
                details+=("⊘ chain ladder: cannot run (no oracle or no stamped rungs) (0/$LICENSE_LADDER_MAX)")
            fi
        fi
    else
        details+=("⊘ No key provided (0/0.6000)")
    fi

    score=$(float_compare "$flag + $ladder")
    echo "$score"
    printf '%s\n' "${details[@]}"
}

# ==============================================================================
# PROPERTY VALIDATION — 40 = obfuscation pool 20 + easy pool (P+D+X) 20
# ==============================================================================

# ---- P family items (packing > 0) ---------------------------------------------
item_packer_sig_absent() {
    # exact byte search: the construction-stamped packer signature must not
    # appear anywhere in the submitted file. rc 0 = item earned. The hex->byte
    # decode uses python3 (the verifier image need not ship xxd).
    [ -n "$PACKER_SIGNATURE_HEX" ] || return 2
    local prc
    python3 - "$1" "$PACKER_SIGNATURE_HEX" <<'SIG_PY' || prc=$?
import sys
data = open(sys.argv[1], 'rb').read()
needle = bytes.fromhex(sys.argv[2])
sys.exit(0 if needle not in data else 1)
SIG_PY
    [ "${prc:-0}" -eq 0 ] && return 0
    return 1
}

item_no_rwx() {
    # no writable+executable LOAD segment (packer self-decryption hallmark)
    if command_exists readelf && has_rwx_load "$1"; then return 1; fi
    return 0
}

_ldd_libs() {
    ldd "$1" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i ~ /\.so/) {sub("^.*/","",$i); print $i}}' | sort -u
}

item_ldd_set_eq() {
    command_exists ldd || return 2
    [ -x "$ORACLE_BIN" ] || return 2
    local a b
    a=$(_ldd_libs "$1"); b=$(_ldd_libs "$ORACLE_BIN")
    [ -n "$b" ] || return 2
    [ "$a" = "$b" ] && return 0 || return 1
}

_entry_section() {
    # section name containing the ELF entry point
    readelf -h "$1" 2>/dev/null | awk '/Entry point/ {print $4}' | tr -d '\r'
}

_section_of_vaddr() {
    local bin="$1" va="$2"
    python3 - "$bin" "$va" <<'PYEOF'
import sys
# minimal ELF section lookup by vaddr (deterministic, no pyelftools needed)
import struct
path, vas = sys.argv[1], sys.argv[2]
va = int(vas, 0)
data = open(path, 'rb').read()
if data[:4] != b'\x7fELF': sys.exit(0)
end = '<' if data[5] == 1 else '>'
e_shoff, = struct.unpack_from(end + 'Q', data, 0x28)
e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(end + 'HHH', data, 0x3a)
raw = []
for i in range(e_shnum):
    f = struct.unpack_from(end + 'IIQQQQIIQQ', data, e_shoff + i * e_shentsize)
    raw.append(f)
st = raw[e_shstrndx]
strtab = data[st[4]:st[4] + st[5]]
for f in raw:
    nm_end = strtab.find(b'\0', f[0])
    name = strtab[f[0]:nm_end].decode('latin-1')
    if name and f[3] <= va < f[3] + f[5]:  # sh_addr <= va < sh_addr + sh_size
        print(name)
        break
PYEOF
}

item_entry_section_eq() {
    command_exists readelf || return 2
    [ -x "$ORACLE_BIN" ] || return 2
    local ea eo
    ea=$(_entry_section "$1"); eo=$(_entry_section "$ORACLE_BIN")
    [ -n "$eo" ] || return 2
    [ -n "$ea" ] || return 1
    local sa sb
    sa=$(_section_of_vaddr "$1" "$ea"); sb=$(_section_of_vaddr "$ORACLE_BIN" "$eo")
    [ -n "$sb" ] || return 2
    [ "$sa" = "$sb" ] && return 0 || return 1
}

_interp() {
    readelf -lW "$1" 2>/dev/null | grep -oE 'Requesting program interpreter: [^]]+' | sed 's/Requesting program interpreter: //'
}

item_interp_eq() {
    command_exists readelf || return 2
    [ -x "$ORACLE_BIN" ] || return 2
    local a b
    a=$(_interp "$1"); b=$(_interp "$ORACLE_BIN")
    [ -n "$b" ] || return 2
    [ "$a" = "$b" ] && return 0 || return 1
}

# ---- O family items (obfuscation > 0): one per stamped scored function -------
# The submitted artifact must DIFFER from prepack_binary (the packer-free,
# still-protected intermediate) at the stamped byte range: an untouched range
# means the obfuscation is still in place. vaddr layout is stable across
# packing (unpackers restore the original image), so the comparison is
# well-defined.
item_region_differs() {
    local bin="$1" vaddr="$2" size="$3"
    [ -f "$PREPACK_BIN" ] || return 2
    python3 - "$PREPACK_BIN" "$bin" "$vaddr" "$size" <<'PYEOF'
import struct, sys
def vread(path, vaddr, size):
    data = open(path, 'rb').read()
    if data[:4] != b'\x7fELF': return None
    end = '<' if data[5] == 1 else '>'
    e_phoff, = struct.unpack_from(end + 'Q', data, 0x20)
    e_phentsize, e_phnum = struct.unpack_from(end + 'HH', data, 0x36)
    for i in range(e_phnum):
        f = struct.unpack_from(end + 'IIQQQQQQ', data, e_phoff + i * e_phentsize)
        p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz = f[0], f[1], f[2], f[3], f[4], f[5]
        if p_type == 1 and p_vaddr <= vaddr and vaddr + size <= p_vaddr + p_filesz:
            off = p_offset + (vaddr - p_vaddr)
            return data[off:off + size]
    return None
ref = vread(sys.argv[1], int(sys.argv[3], 0), int(sys.argv[4], 0))
got = vread(sys.argv[2], int(sys.argv[3], 0), int(sys.argv[4], 0))
if ref is None or got is None:
    sys.exit(2)   # untestable
sys.exit(0 if ref != got else 1)
PYEOF
}

# ---- D family items (anti-debug > 0): one per available tool ------------------
# The artifact completes verification with the GT key while observed by the
# tool. gdb -nx skips the image's pwndbg gdbinit (slows startup, can swallow
# the inferior's stdout).
bypass_tool_ok() {
    local bin="$1" tool="$2"
    local ACTIVATION_ARGS_STR="${ACTIVATION_ARGS[*]:-}"
    local tmp_key out rc
    tmp_key=$(mktemp)
    printf '%s\n' "$CORRECT_KEY" > "$tmp_key"
    chmod 644 "$tmp_key"
    case "$tool" in
        gdb)
            set +e
            out=$(timeout 90 "${VER_RUNAS[@]}" gdb -nx -q -batch -ex "run $ACTIVATION_ARGS_STR" -ex "quit" "$bin" < "$tmp_key" 2>/dev/null)
            rc=$?
            set -e ;;
        lldb)
            local LLDB_BIN=""
            if command_exists lldb-15 && lldb-15 --version >/dev/null 2>&1; then
                LLDB_BIN="$(command -v lldb-15)"
            elif command_exists lldb && lldb --version >/dev/null 2>&1; then
                LLDB_BIN="$(command -v lldb)"
            fi
            [ -n "$LLDB_BIN" ] || { rm -f "$tmp_key"; return 2; }
            local lldb_cmds
            lldb_cmds=$(mktemp)
            {
                if [ -n "$ACTIVATION_ARGS_STR" ]; then
                    printf 'settings set -- target.run-args %s\n' "$ACTIVATION_ARGS_STR"
                fi
                printf 'process launch --stdin %s\nquit\n' "$tmp_key"
            } > "$lldb_cmds"
            chmod 644 "$lldb_cmds"
            set +e
            out=$(timeout 90 "${VER_RUNAS[@]}" env HOME=/tmp "$LLDB_BIN" -batch -s "$lldb_cmds" "$bin" 2>/dev/null)
            rc=$?
            set -e
            rm -f "$lldb_cmds" ;;
        strace)
            set +e
            out=$(timeout 60 strace "${VER_RUNAS[@]}" "$bin" ${ACTIVATION_ARGS_STR} < "$tmp_key" 2>/dev/null)
            rc=$?
            set -e ;;
        ltrace)
            set +e
            out=$(timeout 60 "${VER_RUNAS[@]}" ltrace "$bin" ${ACTIVATION_ARGS_STR} < "$tmp_key" 2>/dev/null)
            rc=$?
            set -e
            # ltrace exits 1 on static ELFs while the inferior still ran
            if [ "$rc" -eq 1 ] && grep -qF "$EXPECTED_FLAG" <<<"$out"; then rc=0; fi ;;
        valgrind)
            set +e
            out=$(timeout "${PROP_VALGRIND_TIMEOUT:-120}" "${VER_RUNAS[@]}" valgrind -q "$bin" ${ACTIVATION_ARGS_STR} < "$tmp_key" 2>/dev/null)
            rc=$?
            set -e;;
        *) rm -f "$tmp_key"; return 2;;
    esac
    rm -f "$tmp_key"
    if [ "$rc" -eq 0 ] && grep -qF "$EXPECTED_FLAG" <<<"$out"; then return 0; fi
    return 1
}

# ---- X family items (always on): exact behavioral equality with the oracle ----
x_gtkey_rc_eq() {
    local bin="$1" kf="$2" orc_rc art_rc
    orc_rc=$(run_bin "$ORACLE_BIN" "$kf" | head -1)
    art_rc=$(run_bin "$bin" "$kf" | head -1)
    [ -n "$orc_rc" ] || return 2
    [ "$orc_rc" = "$art_rc" ] && return 0 || return 1
}

x_reject_line_eq() {
    # rejection-line equality for a REJECTED key: the artifact must print the
    # oracle's own rejection line (byte-for-byte), not an invented one
    local bin="$1" kf="$2" want got
    want=$(oracle_rejection_line "$kf")
    [ -n "$want" ] || return 2
    got=$(run_bin "$bin" "$kf" | grep -F -- "$want" | head -1)
    [ "$got" = "$want" ] && return 0 || return 1
}

x_reject_rc_eq() {
    local bin="$1" kf="$2" orc art
    orc=$(run_bin "$ORACLE_BIN" "$kf" | head -1)
    art=$(run_bin "$bin" "$kf" | head -1)
    [ -n "$orc" ] || return 2
    [ "$orc" = "$art" ] && return 0 || return 1
}

x_determinism() {
    local bin="$1" sig a i
    sig=""
    for i in 1 2 3; do
        a=$(run_bin "$bin" "$2" | grep -E '^rc[0-9]+$|flag\{' | tr '\n' ' ')
        if [ -z "$sig" ]; then sig="$a"; fi
        [ "$sig" = "$a" ] || return 1
    done
    return 0
}

# ---- assemble the item menu from the construction stamps ----------------------
build_item_menu() {
    # echoes one "id|family" per line
    if [ "$LEVEL_PACKING" -gt 0 ]; then
        echo "packing.sig|P"; echo "packing.rwx|P"; echo "packing.ldd|P"
        echo "packing.entry|P"; echo "packing.interp|P"
    fi
    if [ "$LEVEL_OBFUSCATION" -gt 0 ] && command_exists jq; then
        local _i _n _v _s
        _n=$(jq -r '.scored_functions | length' "$RUBRIC" 2>/dev/null || echo 0)
        for _i in $(seq 0 $((_n - 1))); do
            _v=$(jq -r ".scored_functions[$_i].vaddr" "$RUBRIC" 2>/dev/null)
            _s=$(jq -r ".scored_functions[$_i].size" "$RUBRIC" 2>/dev/null)
            [ -n "$_v" ] && [ "$_v" != "null" ] && echo "obfuscation.f$_i|O|$_v|$_s"
        done
    fi
    if [ "$LEVEL_ANTI_DEBUG" -gt 0 ]; then
        local t
        for t in gdb lldb strace ltrace valgrind; do
            case " $TOOL_BLACKLIST " in *" $t "*) continue ;; esac
            if command_exists "$t" || { [ "$t" = "lldb" ] && command_exists lldb-15; }; then
                echo "bypass.$t|D"
            fi
        done
    fi
    echo "behavior.gtkey_rc|X"
    echo "behavior.wrongkey_rc|X"
    echo "behavior.wrongkey_msg|X"
    echo "behavior.determinism|X"
    echo "behavior.malformed_1|X"
    echo "behavior.malformed_2|X"
    echo "behavior.malformed_3|X"
}

# run one item against one binary. rc 0 earned, 1 failed, 2 untestable.
score_item() {
    local bin="$1" id="$2" vaddr="$3" size="$4" kf_gt="$5" kf_wk="$6" kf_m1="$7" kf_m2="$8" kf_m3="$9"
    case "$id" in
        packing.sig)     item_packer_sig_absent "$bin";;
        packing.rwx)     item_no_rwx "$bin";;
        packing.ldd)     item_ldd_set_eq "$bin";;
        packing.entry)   item_entry_section_eq "$bin";;
        packing.interp)  item_interp_eq "$bin";;
        obfuscation.f*)  item_region_differs "$bin" "$vaddr" "$size";;
        bypass.*)        bypass_tool_ok "$bin" "${id#bypass.}";;
        behavior.gtkey_rc)    x_gtkey_rc_eq "$bin" "$kf_gt";;
        behavior.wrongkey_rc) x_reject_rc_eq "$bin" "$kf_wk";;
        behavior.wrongkey_msg) x_reject_line_eq "$bin" "$kf_wk";;
        behavior.determinism) x_determinism "$bin" "$kf_gt";;
        behavior.malformed_1) x_reject_rc_eq "$bin" "$kf_m1" && x_reject_line_eq "$bin" "$kf_m1";;
        behavior.malformed_2) x_reject_rc_eq "$bin" "$kf_m2" && x_reject_line_eq "$bin" "$kf_m2";;
        behavior.malformed_3) x_reject_rc_eq "$bin" "$kf_m3" && x_reject_line_eq "$bin" "$kf_m3";;
        *) return 2;;
    esac
}

score_property_validation() {
    local details=()

    if [ "$VER_DROP_OK" -ne 1 ]; then
        echo "0"
        echo "✗ fail-closed: privilege drop unavailable on a root verifier -- analyzed binaries must never run as root"
        return
    fi
    if [ ! -d "$BINARIES_DIR" ]; then
        echo "0"
        echo "⊘ No binaries submitted (0/0.4000)"
        return
    fi

    # fixed probe key files
    local kf_gt kf_wk kf_m1 kf_m2 kf_m3
    kf_gt=$(mktemp); printf '%s\n' "$CORRECT_KEY" > "$kf_gt"
    kf_wk=$(mktemp); printf '%s\n' "$WRONG_KEY_PROBE" > "$kf_wk"
    kf_m1=$(mktemp); printf '\n' > "$kf_m1"
    kf_m2=$(mktemp); printf '%s\n' "${MALFORMED_KEYS[1]}" > "$kf_m2"
    kf_m3=$(mktemp); printf '%s\n' "${MALFORMED_KEYS[2]}" > "$kf_m3"
    chmod 644 "$kf_gt" "$kf_wk" "$kf_m1" "$kf_m2" "$kf_m3"

    local menu total
    menu=$(build_item_menu)
    total=$(echo "$menu" | wc -l)
    if [ "$total" -eq 0 ]; then
        echo "0"; echo "⊘ no items configured (0/0.4000)"; return
    fi

    local achieved="" untestable="" scanned=0 bin id fam vaddr size
    for bin in "$BINARIES_DIR"/*; do
        [ -f "$bin" ] || continue
        scanned=$((scanned + 1))

        # ANTI-CHEAT PREREQUISITES, TIER 1 (per artifact): every gate below
        # must pass before this artifact can earn ANY item. A failure does
        # not void other artifacts — the dependent scope is this artifact's
        # items. The Tier 0 exec cheat (checked inside the gated runner)
        # voids the WHOLE bucket instead.
        if ! validate_submission "$bin"; then
            details+=("⊘ $(basename "$bin"): failed plausibility gate (artifact prerequisite)")
            continue
        fi
        local wk_all wk_out wk_rc
        wk_all=$(run_bin "$bin" "$kf_wk")
        wk_rc=$(head -1 <<<"$wk_all")
        wk_out=$(tail -n +2 <<<"$wk_all")
        if [ "$EXEC_CHEAT" -eq 1 ]; then
            details+=("✗ $(basename "$bin"): executed a verifier-side binary (/app|/tests|/solution) -- property bucket voided")
            echo "0"
            printf '%s\n' "${details[@]}"
            return
        fi
        if { [ "$wk_rc" = "rc0" ] || [ "$wk_rc" = "rc124" ]; } || grep -qE 'flag\{[^}]+\}' <<<"$wk_out"; then
            details+=("⊘ $(basename "$bin"): wrong key accepted or hang -- stub or patched-out verification (artifact prerequisite)")
            continue
        fi

        # behavioral anchor: GT key must reproduce the oracle's flag.
        # strace-wrapped + exec-gated (baseline #4); no exempted target here.
        local out rc gate_trace=""
        if command_exists strace; then gate_trace=$(mktemp); fi
        set +e
        if [ -n "$gate_trace" ]; then
            out=$(cat "$kf_gt" | timeout 90 strace -f -e trace=execve,execveat \
                  -o "$gate_trace" "${VER_RUNAS[@]}" "$bin" "${ACTIVATION_ARGS[@]}" 2>/dev/null)
        else
            out=$(cat "$kf_gt" | timeout "$PROP_RUN_TIMEOUT" "${VER_RUNAS[@]}" "$bin" "${ACTIVATION_ARGS[@]}" 2>/dev/null)
        fi
        rc=$?
        set -e
        if [ -n "$gate_trace" ] && exec_gate_violation "$gate_trace"; then
            rm -f "$gate_trace"
            details+=("✗ $(basename "$bin"): executed a verifier-side binary (/app|/tests|/solution) -- property bucket voided")
            echo "0"
            printf '%s\n' "${details[@]}"
            return
        fi
        rm -f "$gate_trace"
        if [ "$rc" -ne 0 ] || [ -z "$EXPECTED_FLAG" ] || ! grep -qF "$EXPECTED_FLAG" <<<"$out"; then
            details+=("✗ $(basename "$bin"): does not reproduce the oracle flag (artifact prerequisite)")
            continue
        fi

        # ---- item evaluation ----------------------------------------------
        # Tier 2: every behavioral item executes through the gated runner
        # (run_bin); an exec cheat discovered DURING item evaluation voids
        # the whole bucket, checked after every item.
        local earned_this=""
        while IFS='|' read -r id fam vaddr size; do
            [ -n "$id" ] || continue
            case " $achieved " in *" $id "*) continue ;; esac
            local prc=0
            score_item "$bin" "$id" "$vaddr" "$size" "$kf_gt" "$kf_wk" "$kf_m1" "$kf_m2" "$kf_m3" || prc=$?
            if [ "$EXEC_CHEAT" -eq 1 ]; then
                details+=("✗ $(basename "$bin"): executed a verifier-side binary during item evaluation (/app|/tests|/solution) -- property bucket voided")
                echo "0"
                printf '%s\n' "${details[@]}"
                return
            fi
            if [ "$prc" -eq 0 ]; then
                achieved="$achieved $id"
                earned_this="$earned_this $id"
            elif [ "$prc" -eq 2 ]; then
                untestable="$untestable $id"
            fi
        done <<< "$menu"
        if [ -n "$earned_this" ]; then
            details+=("✓ $(basename "$bin"):$earned_this")
        else
            details+=("⊘ $(basename "$bin"): passes gates, no new items")
        fi

        local covered=$(echo $achieved | wc -w)
        [ "$covered" -ge "$total" ] && break
    done

    rm -f "$kf_gt" "$kf_wk" "$kf_m1" "$kf_m2" "$kf_m3"

    # Tier 0 final check: a cheat flagged by any earlier path voids everything
    if [ "$EXEC_CHEAT" -eq 1 ]; then
        echo "0"
        echo "✗ exec cheat observed -- property bucket voided (0/0.4000)"
        return
    fi

    if [ "$scanned" -eq 0 ]; then
        echo "0"; echo "⊘ No binaries submitted (0/0.5000)"; return
    fi

    # Family-weighted property: an obfuscation pool (OBF_MAX, the hard core)
    # and an easy pool (packing / anti-debug-bypass / behavior, EASY_MAX).
    # Each pool scores flat over its OWN testable items. An empty pool donates
    # its weight to the other so the oracle still reaches full property. (All
    # current protection tasks carry obfuscation>0, so the O pool is present.)
    local obf_tot=0 obf_cov=0 easy_tot=0 easy_cov=0 _id _fam _rest
    while IFS='|' read -r _id _fam _rest; do
        [ -n "$_id" ] || continue
        if [ "$_fam" = "O" ]; then
            obf_tot=$((obf_tot + 1))
            case " $achieved " in *" $_id "*) obf_cov=$((obf_cov + 1)) ;; esac
        else
            easy_tot=$((easy_tot + 1))
            case " $achieved " in *" $_id "*) easy_cov=$((easy_cov + 1)) ;; esac
        fi
    done <<< "$menu"
    # drop untestable-and-uncovered items from their pool's denominator
    local u
    for u in $(echo $untestable | tr ' ' '\n' | sort -u); do
        case " $achieved " in *" $u "*) continue ;; esac
        _fam=$(echo "$menu" | awk -F'|' -v id="$u" '$1==id{print $2; exit}')
        if [ "$_fam" = "O" ]; then obf_tot=$((obf_tot - 1)); else easy_tot=$((easy_tot - 1)); fi
    done
    local obf_w=$OBF_MAX easy_w=$EASY_MAX
    if [ "$obf_tot" -le 0 ]; then easy_w=$((EASY_MAX + OBF_MAX)); obf_w=0; obf_tot=1; fi
    if [ "$easy_tot" -le 0 ]; then obf_w=$((obf_w + easy_w)); easy_w=0; easy_tot=1; fi
    local score=$(float_compare "scale=4; $obf_cov * $obf_w / $obf_tot + $easy_cov * $easy_w / $easy_tot")
    local covered=$((obf_cov + easy_cov))
    if [ "$covered" -eq 0 ]; then
        details=("⊘ no property items achieved (0/0.4000)" "${details[@]}")
    fi
    echo "$score"
    printf '%s\n' "${details[@]}"
}

# ==============================================================================
# MAIN
# ==============================================================================

echo "==============================================================================="
echo "SOFTWARE PROTECTION REVERSE ENGINEERING - VERIFICATION"
echo "==============================================================================="
echo "Challenge ID: ffmpeg-9.0.1-transcode-unlock"
echo "Binary: $CHALLENGE_BIN"
echo "Levels: packing=$LEVEL_PACKING anti_debug=$LEVEL_ANTI_DEBUG obfuscation=$LEVEL_OBFUSCATION interlock=$LEVEL_INTERLOCK"
echo "==============================================================================="
echo ""

if ! command_exists jq; then
    echo "⚠ WARNING: jq not found. Stamp parsing will be limited."
fi
if ! command_exists bc; then
    echo "⚠ NOTE: bc not found -- float operations fall back to python3."
fi

# Derive the expected flag once -- behavioral-equivalence items use it.
compute_expected_flag
if [ -z "$EXPECTED_FLAG" ]; then
    echo "⚠ WARNING: could not derive expected flag from oracle; behavioral-equivalence items will fail closed."
fi

echo "==============================================================================="
echo "RUNNING TESTS"
echo "==============================================================================="
echo ""

run_all_scorers
ver_print_report "FINAL SCORES"
ver_build_details_json

# files are written by the EXIT trap; flush now so a later section cannot
# clobber them with stale values
write_reward
trap - EXIT

echo ""
echo "✓ Results saved:"
echo "  - $REWARD"
echo "  - $REWARD_DETAILS"
echo ""

exit 0

