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
# Challenge: ddnet-19.9-license-gate
#
# Scoring scheme (pure dynamic; tunables in TASK CONFIGURATION below):
#   License Verification 50  DYNAMIC  valid key -> 50 short-circuit (flag +
#                                     exit 0 on the challenge binary, run
#                                     dropped + exec-gated like every other
#                                     analyzed-code execution); a rejected key
#                                     earns chain-depth credit up to
#                                     TRACE_PARTIAL_MAX = 20 via the oracle
#                                     GDB trace (core_b ladder)
#   Property Validation  50  DYNAMIC  defeat-property coverage (order- and
#                                     naming-free), behaviorally tested
#
# All ground truth values are read from /app/ground_truth/ during verification.
# ==============================================================================

# ------------------------------------------------------------------------------
# PATH CONFIGURATION
# ------------------------------------------------------------------------------

CHALLENGE_BIN="/app/binary"
GROUND_TRUTH_DIR="/app/ground_truth"
ORACLE_BIN="$GROUND_TRUTH_DIR/binaries/origin_binary"
CORRECT_KEY=$(cat "$GROUND_TRUTH_DIR/input.txt" 2>/dev/null | tr -d '\n\r')

AGENT_OUTPUT_DIR="/logs/artifacts/agent_output"
INPUT_FILE="$AGENT_OUTPUT_DIR/input.txt"
BINARIES_DIR="$AGENT_OUTPUT_DIR/binaries"
export INPUT_FILE

REWARD="/logs/verifier/reward.json"
REWARD_DETAILS="/logs/verifier/reward-details.json"

# ------------------------------------------------------------------------------
# TASK CONFIGURATION (per-task fills; template ships commented defaults)
# ------------------------------------------------------------------------------

# Checkpoint functions along the license verification chain, in execution
# order (from the unstripped oracle build). Only affects REJECTED keys: a
# valid key short-circuits to 50; a rejected one earns (weighted fraction of
# checkpoints reached) * TRACE_PARTIAL_MAX.
TRACE_FUNCTIONS=(
    "stage_probe_1"
    "stage_probe_2"
    "stage_probe_3"
    "stage_probe_4"
)
TRACE_SCORES=(
    # "1.0"
    # "2.0"
)

# Max partial credit (within the 50-point License bucket) for a REJECTED key
# that still drives the verification chain partway down. Kept well below 60 so
# a near-miss key never scores close to a fully valid one.
TRACE_PARTIAL_MAX=20

# Decoupled trace points (preferred over TRACE_FUNCTIONS): vaddrs of the
# license-chain probes, extracted from the PRE-strip oracle at build time
# and exported to tests/ground_truth/trace_points.json (see
# export_verifier_artifacts.sh). When the file exists the ladder breaks on
# PIE-base-corrected ADDRESSES, so no checkpoint symbol name ever has to
# exist in a shipped binary -- semantic names (verify/checkpointN) survived
# `strip --strip-all` in .dynsym and handed the agent the chain for free
# (2026-08-26 leak audit). Weights come from the JSON (trace_points.weight);
# TRACE_SCORES only feeds legacy symbol mode.
TRACE_POINTS_FILE="$GROUND_TRUTH_DIR/trace_points.json"

# Defeat properties (50-point bucket): observable properties a defeated
# artifact can have. Scored by COVERAGE -- (distinct properties achieved by any
# submitted artifact) / (configured properties) * PROPERTIES_MAX -- which is
# order- and naming-free, matching the challenge premise that protections
# have no fixed peel order.
#   unpack -> whole-file entropy within 20% of the oracle, no RWX LOAD
#             segment, .text section entropy below 7.2   (core_b)
#   bypass -> prints the expected flag with the GT key while observed by
#             every available tool: gdb, lldb, strace, ltrace, valgrind
#                                                      (domain impl below)
#   deobf  -> instruction count within 20% of the oracle, branch density
#             within 20%, indirect branches <= 4x oracle + 16   (core_b)
DEFEAT_PROPERTIES=(
    "unpack"
    "bypass"
)
PROPERTIES_MAX=50

# Activation args the challenge binary needs to reach its protected feature
# (e.g. a transcode invocation). Empty for pure stdin-key programs. Appended
# to EVERY behavioral run: oracle flag derivation, the wrong-key probe, and
# every tool in the bypass matrix.
ACTIVATION_ARGS=(
    # "-f" "lavfi" "-i" "anullsrc" "-t" "0.05" "-f" "null" "-"
)

# Tools the bypass matrix skips for this task (space-separated subset of
# "gdb lldb strace ltrace valgrind"). Empty = exercise every available tool.
# Use only when a tool cannot run this carrier at all (e.g. ltrace on static
# builds exiting non-{0,1} while the flag still prints).
BYPASS_SKIP_TOOLS="ltrace"

# Per-task timeout tuning for slow carriers (seconds; defaults suit most
# builds). TRACE_GDB_TIMEOUT feeds the core_b chain-depth ladder; the
# valgrind knob feeds the bypass matrix run.
TRACE_GDB_TIMEOUT=90
PROP_VALGRIND_TIMEOUT=240

SCORING_CONFIG=(
    # Pure-dynamic scoring: every challenge has a key to verify and
    # protections to defeat. Per-task tuning:
    #   - trim DEFEAT_PROPERTIES to the protections this challenge has
    #   - fill TRACE_FUNCTIONS for license chain-depth partial credit
    "License Verification|50|score_license_verification|license_verification"
    "Property Validation|50|score_property_validation|property_validation"
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
        "$AGENT_OUTPUT_DIR"|"$AGENT_OUTPUT_DIR"/*) ;;
        *) return 1 ;;
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
        "$AGENT_OUTPUT_DIR"/*) ;;
        *) return 1 ;;
    esac
    [ -d "$real" ] || return 1
    [ ! -L "$AGENT_OUTPUT_DIR/$p" ] || return 1
    echo "$real"
}

# --- baseline #3: privilege drop (FAIL-CLOSED on a root verifier) ---------------
# Wraps EXECUTION of agent/analyzed code only; static analysis tools run as the verifier.
# VERIFIER_RUNAS is exported so embedded python scorers can reuse the same drop via shlex.split(os.environ["VERIFIER_RUNAS"]).
VER_RUNAS=()
VER_DROP_OK=1
if command_exists setpriv && id nobody >/dev/null 2>&1 \
   && setpriv --reuid=nobody --regid=nogroup --clear-groups /bin/true >/dev/null 2>&1; then
    chmod -R a+rX "$AGENT_OUTPUT_DIR" 2>/dev/null || true
    VER_RUNAS=(setpriv --reuid=nobody --regid=nogroup --clear-groups)
    export VERIFIER_RUNAS="${VER_RUNAS[*]}"
elif [ "$(id -u)" = "0" ]; then
    VER_DROP_OK=0
fi

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
    case "$score" in .*) score="0$score" ;; esac
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
        case "$points" in .*) points="0$points" ;; esac
        VER_CAT_POINTS+=("$points")
        maxpoints=$(float_compare "scale=4; $max_points / 100")
        case "$maxpoints" in .*) maxpoints="0$maxpoints" ;; esac
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
        case "$disp" in .*) disp="0$disp" ;; esac
        local maxdisp
        maxdisp=$(float_compare "scale=4; ${VER_CAT_MAXES[$i]} / 100")
        case "$maxdisp" in .*) maxdisp="0$maxdisp" ;; esac
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
    case "$total_disp" in .*) total_disp="0$total_disp" ;; esac
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
        "$AGENT_OUTPUT_DIR"|"$AGENT_OUTPUT_DIR"/*) ;;
        *) return 1 ;;
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
# EVASION-FREE ORACLE? Breakpoints on the chain probes with per-checkpoint
# weights (default 1 each), partial credit capped at TRACE_PARTIAL_MAX.
# Only called on rejection: a valid key/command deterministically traverses
# the whole chain, so misses under it indicate verifier flakiness and are
# never used to deduct.
#
# Two breakpoint modes (2026-08-26 address decoupling):
#   ADDRESS (preferred): TRACE_POINTS_FILE (trace_points.json in the ground
#     truth) carries build-time-extracted probe vaddrs. The ladder `starti`s
#     the oracle, derives the PIE load base from `info proc mappings` via
#     embedded python, and breaks on base+vaddr. No symbol name is involved,
#     so challenge binaries can hide/localize their license-chain symbols.
#   SYMBOL (legacy): breakpoints on TRACE_FUNCTIONS[] names -- for tasks
#     whose ground truth predates trace_points.json.
#
# Usage: run_trace_ladder <stdin_file> <gdb target argv...>
# Echoes the score (first line) + per-checkpoint details; rc 1 when it cannot
# run (no oracle / no breakpoints configured).
run_trace_ladder() {
    local stdin_file="$1"; shift
    [ -f "$ORACLE_BIN" ] && [ -x "$ORACLE_BIN" ] || return 1

    # ---- resolve both modes into TP_NAMES / TP_WEIGHTS / TP_VADDRS -------
    local TP_NAMES=() TP_WEIGHTS=() TP_VADDRS=() fn _i _rec _npts
    if [ -s "${TRACE_POINTS_FILE:-}" ] && command_exists jq; then
        _npts=$(jq -r '.points | length' "$TRACE_POINTS_FILE" 2>/dev/null || echo 0)
        if [ "${_npts:-0}" -gt 0 ] 2>/dev/null; then
            local _flds=()
            for _i in $(seq 0 $((_npts - 1))); do
                _rec=$(jq -r ".points[$_i] | .name, .vaddr, (.weight // 1)" \
                        "$TRACE_POINTS_FILE" 2>/dev/null) || continue
                mapfile -t _flds <<<"$_rec"
                [ "${#_flds[@]}" -ge 2 ] || continue
                TP_NAMES+=("${_flds[0]}")
                TP_VADDRS+=("$(( ${_flds[1]} ))")
                TP_WEIGHTS+=("${_flds[2]:-1}")
            done
        fi
    fi
    if [ "${#TP_NAMES[@]}" -eq 0 ]; then
        if [ "${#TRACE_FUNCTIONS[@]}" -eq 0 ]; then return 1; fi
        TP_NAMES=("${TRACE_FUNCTIONS[@]}")
        for _i in "${!TRACE_FUNCTIONS[@]}"; do
            TP_WEIGHTS+=("${TRACE_SCORES[$_i]:-1}")
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
            # off the mappings, then place absolute breakpoints.
            cat <<EOF
starti
python
import gdb
_pts = [
EOF
            for _i in "${!TP_NAMES[@]}"; do
                echo "    ("${TP_NAMES[$_i]}", ${TP_VADDRS[$_i]}),"
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
    for _name, _off in _pts:
        gdb.execute("break *%d" % (_base + _off))
        gdb.execute('commands\nsilent\nprintf "TRACE:%s\n", "' + _name + '"\ncontinue\nend')
end
continue
quit
EOF
        else
            # SYMBOL mode (legacy)
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

    local details=() weighted_total=0 weighted_hit=0 idx=0 n=1 fn
    for fn in "${TP_NAMES[@]}"; do
        # :-1 default also guards set -u on an empty/unset TP_WEIGHTS
        local w="${TP_WEIGHTS[$idx]:-1}"
        weighted_total=$(float_compare "$weighted_total + $w")
        if grep -qF "TRACE:$fn" /tmp/verifier-trace.log; then
            weighted_hit=$(float_compare "$weighted_hit + $w")
            details+=("✓ checkpoint $n ($fn) reached")
        else
            details+=("✗ checkpoint $n ($fn) NOT reached")
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
# DOMAIN FUNCTIONS (protection-specific; each keeps a "why not portable" note)
# ==============================================================================

# ------------------------------------------------------------------------------
# Expected flag: derived at verification time from the ORACLE binary + the
# ground-truth key. The flag depends on the key blob, so an agent that never
# recovered the GT key cannot predict it. Behavioral checks require submitted
# artifacts to reproduce this flag -- a stub that merely exits 0 scores
# nothing.
# ------------------------------------------------------------------------------
EXPECTED_FLAG=""

compute_expected_flag() {
    if [ -x "$ORACLE_BIN" ] && [ -n "$CORRECT_KEY" ]; then
        # || true INSIDE the substitution: under set -e + pipefail an oracle
        # that prints no flag must degrade to the empty-flag warning below,
        # not silently kill the whole verifier mid-run
        EXPECTED_FLAG=$(echo "$CORRECT_KEY" | timeout 60 "$ORACLE_BIN" "${ACTIVATION_ARGS[@]}" 2>/dev/null \
            | grep -oE 'flag\{[^}]*\}' | head -1 || true)
    fi
}

# ------------------------------------------------------------------------------
# Negative behavioral gate (this skill's CONTROL PROBE instance, baseline
# principle): submitted binaries must still reject wrong keys. Runs the binary
# with a guaranteed-invalid key; it must exit non-zero (and not via a
# timeout), and must not print a flag. Kills flag-printing stubs and binaries
# whose verification was patched out rather than genuinely defeated.
# ------------------------------------------------------------------------------
WRONG_KEY_PROBE="INVALID_PROBE_KEY_0000000000000000"

check_wrong_key_rejected() {
    local bin="$1"
    local out rc
    set +e
    out=$(echo "$WRONG_KEY_PROBE" | timeout 30 "${VER_RUNAS[@]}" "$bin" "${ACTIVATION_ARGS[@]}" 2>/dev/null)
    rc=$?
    set -e
    [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ] && ! grep -qE 'flag\{[^}]+\}' <<<"$out"
}

# ------------------------------------------------------------------------------
# bypass property (domain): the artifact must complete verification while
# observed by every available tool from the matrix: debuggers (gdb, lldb),
# tracers (strace, ltrace) and the instrumentation framework (valgrind).
# WHY NOT PORTABLE: checks flag-on-stdout with the GT key; malware's bypass
# observes trigger side effects instead.
# ------------------------------------------------------------------------------
prop_bypass() {
    # rc 0 = property holds, 1 = tested and fails, 2 = untestable
    [ -n "$EXPECTED_FLAG" ] || return 2
    # activation args as one string for the -ex/run-args style interfaces
    local ACTIVATION_ARGS_STR="${ACTIVATION_ARGS[*]:-}"
    # lldb resolution: bare `lldb` on PATH resolves to the LLVM-22 bundle's
    # lldb (the verifier image's /usr/bin/lldb symlink; no /opt/llvm-22 here), which
    # fails to even start (missing libpython3.11). Prefer the distro
    # /usr/bin/lldb-15 -- but only when it actually starts -- and fall back
    # to PATH lldb only if it runs.
    local LLDB_BIN=""
    if command_exists lldb-15 && lldb-15 --version >/dev/null 2>&1; then
        LLDB_BIN="$(command -v lldb-15)"
    elif command_exists lldb && lldb --version >/dev/null 2>&1; then
        LLDB_BIN="$(command -v lldb)"
    fi
    command_exists gdb || [ -n "$LLDB_BIN" ] \
        || command_exists strace || command_exists ltrace \
        || command_exists valgrind || return 2

    skip_tool() {
        case " $BYPASS_SKIP_TOOLS " in *" $1 "*) return 0 ;; esac
        return 1
    }

    local tmp_key out rc
    tmp_key=$(mktemp)
    printf '%s\n' "$CORRECT_KEY" > "$tmp_key"

    if command_exists gdb && ! skip_tool gdb; then
        # -nx: do NOT load ~/.gdbinit. This image installs pwndbg there, and
        # pwndbg both slows startup on large binaries and can swallow the
        # inferior's stdout -- making the flag invisible without -nx.
        set +e
        out=$(timeout 90 "${VER_RUNAS[@]}" gdb -nx -q -batch -ex "run $ACTIVATION_ARGS_STR" -ex "quit" "$1" < "$tmp_key" 2>/dev/null)
        rc=$?
        set -e
        if [ "$rc" -ne 0 ] || ! grep -qF "$EXPECTED_FLAG" <<<"$out"; then
            rm -f "$tmp_key"; return 1
        fi
    fi

    if [ -n "$LLDB_BIN" ] && ! skip_tool lldb; then
        local lldb_cmds
        lldb_cmds=$(mktemp)
        # bare run-args with an empty value makes lldb misfire on default
        # (empty-args) tasks: emit the setting only when args exist
        {
            if [ -n "$ACTIVATION_ARGS_STR" ]; then
                printf 'settings set -- target.run-args %s\n' "$ACTIVATION_ARGS_STR"
            fi
            printf 'process launch --stdin %s\nquit\n' "$tmp_key"
        } > "$lldb_cmds"
        # lldb opens --stdin AS nobody: both the key file and the command
        # file must be world-readable (gdb is unaffected -- its stdin fd is
        # opened by the root shell before the drop)
        chmod 644 "$tmp_key" "$lldb_cmds"
        set +e
        out=$(timeout 90 "${VER_RUNAS[@]}" env HOME=/tmp "$LLDB_BIN" -batch -s "$lldb_cmds" "$1" 2>/dev/null)
        rc=$?
        set -e
        rm -f "$lldb_cmds"
        if [ "$rc" -ne 0 ] || ! grep -qF "$EXPECTED_FLAG" <<<"$out"; then
            rm -f "$tmp_key"; return 1
        fi
    fi

    if command_exists strace && ! skip_tool strace; then
        set +e
        out=$(timeout 60 strace "${VER_RUNAS[@]}" "$1" ${ACTIVATION_ARGS_STR} < "$tmp_key" 2>/dev/null)
        rc=$?
        set -e
        if [ "$rc" -ne 0 ] || ! grep -qF "$EXPECTED_FLAG" <<<"$out"; then
            rm -f "$tmp_key"; return 1
        fi
    fi

    if command_exists ltrace && ! skip_tool ltrace; then
        set +e
        out=$(timeout 60 "${VER_RUNAS[@]}" ltrace "$1" ${ACTIVATION_ARGS_STR} < "$tmp_key" 2>/dev/null)
        rc=$?
        set -e
        # ltrace exits 1 on static ELFs ("Couldn't find .dynsym") while the
        # trace itself completed and the inferior ran -- the flag check is
        # the discriminator here, not ltrace's own exit status
        if { [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; } || ! grep -qF "$EXPECTED_FLAG" <<<"$out"; then
            rm -f "$tmp_key"; return 1
        fi
    fi

    if command_exists valgrind && ! skip_tool valgrind; then
        set +e
        out=$(timeout "${PROP_VALGRIND_TIMEOUT:-120}" "${VER_RUNAS[@]}" valgrind -q "$1" ${ACTIVATION_ARGS_STR} < "$tmp_key" 2>/dev/null)
        rc=$?
        set -e
        if [ "$rc" -ne 0 ] || ! grep -qF "$EXPECTED_FLAG" <<<"$out"; then
            rm -f "$tmp_key"; return 1
        fi
    fi

    rm -f "$tmp_key"
    return 0
}

# ==============================================================================
# SCORING FUNCTIONS
# ==============================================================================

# ------------------------------------------------------------------------------
# License Verification -- 50-point bucket:
#   - valid key (flag + exit 0 on the challenge binary) -> 60, short-circuit.
#     The run is dropped to nobody and strace-wrapped (baseline #3/#4: the
#     challenge binary itself is the one exempted verifier-side target).
#     Trace misses never deduct here: a valid key deterministically traverses
#     the whole chain, so a miss means verifier flakiness.
#   - rejected key -> partial chain-depth credit via the core_b ladder,
#     up to TRACE_PARTIAL_MAX (20).
#   - no key -> 0.
# ------------------------------------------------------------------------------
score_license_verification() {
    local score=0
    local test_key=""
    local details=()

    if [ -f "$INPUT_FILE" ]; then
        test_key=$(cat "$INPUT_FILE" 2>/dev/null | tr -d '\n\r' | head -1)
    fi

    if [ -n "$test_key" ]; then
        if [ "$VER_DROP_OK" -ne 1 ]; then
            echo "0"
            echo "✗ fail-closed: privilege drop unavailable on a root verifier -- analyzed binaries must never run as root (0/0.5000)"
            return
        fi

        # A valid key must exit 0 AND print a flag{...} (the binary is fixed, so any
    # well-formed flag satisfies the oracle; no EXPECTED_FLAG comparison) --
        # matching the documented contract (correct key -> flag{...}, exit 0).
        # Dropped, but deliberately NOT traced: the challenge binary carries
        # real anti-debug by design (D>=1 fires under any tracer and kills the
        # run before verification), and the exec-gate guards AGENT-authored
        # code executions -- the license run feeds a fixed verifier-built
        # binary a key string, so there is nothing for that gate to catch here.
        local lic_out lic_rc
        set +e
        lic_out=$(echo "$test_key" | timeout 60 "${VER_RUNAS[@]}" "$CHALLENGE_BIN" "${ACTIVATION_ARGS[@]}" 2>/dev/null)
        lic_rc=$?
        set -e

        if [ "$lic_rc" -eq 0 ] && grep -qE 'flag\{[^}]+\}' <<<"$lic_out"; then
            score=50
            details+=("✓ Key accepted, flag printed (0.5000/0.5000)")
            details+=("   Key: ${test_key:0:25}...")
            echo "$score"
            printf '%s\n' "${details[@]}"
            return
        fi
        details+=("✗ Key rejected (exit=$lic_rc) (0/0.5000)")
        details+=("   Key: ${test_key:0:25}...")

        # Partial credit: how deep the rejected key drives the verification
        # chain in the oracle (core_b ladder; rc 1 when it cannot run).
        local trace_out temp_input
        temp_input=$(mktemp)
        printf '%s\n' "$test_key" > "$temp_input"
        # the ladder honors the activation args: arg-gated features must be
        # reachable on the chain-depth path exactly as on every other run
        trace_out=$(run_trace_ladder "$temp_input" "$ORACLE_BIN" \
            ${ACTIVATION_ARGS[@]+"${ACTIVATION_ARGS[@]}"} || true)
        rm -f "$temp_input"
        if [ -n "$trace_out" ]; then
            local trace_score=$(echo "$trace_out" | head -1)
            if [ "$(float_compare "$trace_score > 0")" = "1" ]; then
                score="$trace_score"
                local pts_display=$(float_compare "scale=4; $trace_score / 100")
                case "$pts_display" in .*) pts_display="0$pts_display";; esac
                details+=("⊘ Partial chain-depth credit ($pts_display/0.5000)")
            fi
            while IFS= read -r line; do
                [ -n "$line" ] && details+=("$line")
            done <<< "$(echo "$trace_out" | tail -n +2)"
        fi
    else
        details+=("⊘ No key provided (0/0.5000)")
    fi

    echo "$score"
    printf '%s\n' "${details[@]}"
}

# ------------------------------------------------------------------------------
# Property Validation -- 50-point bucket, scored by COVERAGE:
#   (distinct properties achieved by any submitted artifact)
#   / (configured DEFEAT_PROPERTIES) * PROPERTIES_MAX
# Order- and naming-free: any artifact in binaries/ can earn any property,
# matching the challenge premise that protections have no fixed peel order.
# Every artifact first passes the full gate chain (plausibility, .text volume,
# non-original, wrong-key rejection, oracle-flag reproduction); only then are
# properties tested.
# ------------------------------------------------------------------------------
score_property_validation() {
    local details=()
    local total=${#DEFEAT_PROPERTIES[@]}

    if [ "$total" -eq 0 ]; then
        echo "0"
        echo "⊘ No defeat properties configured (0/0.5000)"
        return
    fi
    if [ ! -d "$BINARIES_DIR" ]; then
        echo "0"
        echo "⊘ No binaries submitted (0/0.5000)"
        return
    fi
    if [ "$VER_DROP_OK" -ne 1 ]; then
        echo "0"
        echo "✗ fail-closed: privilege drop unavailable on a root verifier -- analyzed binaries must never run as root (0/0.5000)"
        return
    fi

    local achieved=""
    local untestable=""
    local scanned=0
    local bin prop
    for bin in "$BINARIES_DIR"/*; do
        [ -f "$bin" ] || continue
        scanned=$((scanned + 1))

        if ! validate_submission "$bin"; then
            details+=("⊘ $(basename "$bin"): failed plausibility gate")
            continue
        fi
        if ! check_wrong_key_rejected "$bin"; then
            details+=("⊘ $(basename "$bin"): wrong key accepted -- stub or patched-out verification")
            continue
        fi

        # Behavioral anchor: with the GT key the artifact must reproduce the
        # flag (activation args included -- the flag-derivation context is
        # the oracle's, which may need them to reach the protected feature).
        # The run is strace-wrapped (baseline #4) and privilege-dropped to
        # nobody (baseline #3); artifacts never touch verifier-side trees,
        # so the gate has NO exempted target here.
        local out rc gate_trace=""
        if command_exists strace; then
            gate_trace=$(mktemp)
        fi
        set +e
        if [ -n "$gate_trace" ]; then
            out=$(echo "$CORRECT_KEY" | timeout 90 strace -f -e trace=execve,execveat \
                  -o "$gate_trace" "${VER_RUNAS[@]}" "$bin" "${ACTIVATION_ARGS[@]}" 2>/dev/null)
        else
            out=$(echo "$CORRECT_KEY" | timeout 60 "${VER_RUNAS[@]}" "$bin" "${ACTIVATION_ARGS[@]}" 2>/dev/null)
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
            details+=("✗ $(basename "$bin"): does not reproduce the oracle flag")
            continue
        fi

        local props="" prc
        for prop in "${DEFEAT_PROPERTIES[@]}"; do
            prc=0
            case "$prop" in
                unpack) prop_unpack "$bin" || prc=$? ;;
                bypass) prop_bypass "$bin" || prc=$? ;;
                deobf)  prop_deobf  "$bin" || prc=$? ;;
                *)      details+=("⚠ unknown property: $prop"); prc=2 ;;
            esac
            if [ "$prc" -eq 0 ]; then
                props="$props $prop"
            elif [ "$prc" -eq 2 ]; then
                # untestable in this environment: drop from the denominator so
                # agents are not penalized for missing verifier tools
                untestable="$untestable $prop"
            fi
        done

        # merge newly achieved properties into the coverage set
        local merged="$achieved"
        for prop in $props; do
            case " $achieved " in
                *" $prop "*) : ;;
                *) merged="$merged $prop" ;;
            esac
        done
        if [ "$merged" != "$achieved" ]; then
            achieved="$merged"
            details+=("✓ $(basename "$bin"):$props")
        else
            details+=("⊘ $(basename "$bin"): passes gates, no new properties")
        fi

        # early exit once every configured property is covered
        local covered=$(echo $achieved | wc -w)
        if [ "$covered" -ge "$total" ]; then break; fi
    done

    if [ "$scanned" -eq 0 ]; then
        echo "0"
        echo "⊘ No binaries submitted (0/0.5000)"
        return
    fi

    local covered=$(echo $achieved | wc -w)
    # exclude properties that no tool in this environment could test
    local testable=$total
    for prop in $(echo $untestable | tr ' ' '\n' | sort -u); do
        case " $achieved " in
            *" $prop "*) : ;;
            *) testable=$((testable - 1)) ;;
        esac
    done
    [ "$testable" -gt 0 ] || testable=1
    local score=$(float_compare "scale=4; $covered * $PROPERTIES_MAX / $testable")
    if [ "$covered" -eq 0 ]; then
        details=("⊘ no defeat properties achieved (0/0.5000)" "${details[@]}")
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
echo "Challenge ID: ddnet-19.9-license-gate"
echo "Binary: $CHALLENGE_BIN"
echo "==============================================================================="
echo ""

if ! command_exists jq; then
    echo "⚠ WARNING: jq not found. JSON parsing will be limited."
fi
if ! command_exists bc; then
    echo "⚠ NOTE: bc not found -- float operations fall back to python3."
fi

# Derive the expected flag once -- all behavioral-equivalence checks use it.
compute_expected_flag
if [ -z "$EXPECTED_FLAG" ]; then
    echo "⚠ WARNING: could not derive expected flag from oracle; behavioral-equivalence checks will fail closed."
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


