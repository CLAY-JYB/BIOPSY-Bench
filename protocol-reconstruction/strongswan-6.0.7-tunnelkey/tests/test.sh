#!/usr/bin/env bash
set -euo pipefail

# Force locale for consistent decimal handling
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
# PROTOCOL RECONSTRUCTION - VERIFICATION TEST (V5.1, pure dynamic)
# ==============================================================================
# Challenge: strongswan-6.0.7-tunnelkey
#
# Scoring (reference/scoring.md -- V5.1: the meeting directive "drop the
# direct answer-writing parts, maximize dynamic verification aimed at
# the FINAL PRODUCT"):
#
#   ├── Session Ladder          70   DYNAMIC  the agent's submitted client
#   │                                          against ONE clean live
#   │                                          oracle run; every stage is
#   │                                          graded element-wise from
#   │                                          the oracle's per-frame
#   │                                          FORMAT log (best attempt
#   │                                          wins; dual-path decode
#   │                                          separates grammar from
#   │                                          crypto)
#   │     ① handshake            20  7 format elements
#   │     ② authentication       20  opcode/structure/mac value/KEX shape
#   │     ③ data exchange        15  TX crypto, per-command grammar,
#   │                                    same-key readback, round persistence
#   │     ④ flag                 10  FLAG grammar, token value, flag
#   │                                    DELIVERED on stdout (per-run
#   │                                    derived flag -- a statically
#   │                                    dumped constant never matches)
#   │     ⑤ close                 5  BYE grammar, ACK delivered, clean FIN
#   └── Robustness Battery     30   DYNAMIC  13 single-fault oracle runs
#          chaff burst / corrupted reply (retransmit) / min-fragments /
#          escape-dense chaff / stream noise / forced resync / slow
#          reply / drip feed / ERR-on-HELLO / parallel isolation /
#          hostile length / server drop (reconnect) / duplicated reply
#          graded handled-fully / survived / died, renormalized over the
#          level-applicable probe set
#
# The written report is NOT scored and NOT required. The only submission
# contract is the final product:
#
#   /logs/artifacts/agent_output/client    (executable, <= 64 MB)
#   invoked as:  client HOST PORT [--parallel N]
#
# Anti-cheat (each closes a concrete vector):
#   - per-run log secret: the oracle's environment holds it; the client
#     runs unprivileged under the drop and cannot read the log or forge
#     its secret-prefixed lines
#   - per-connection nonce AND per-connection flag derivation: recorded
#     bytes and statically dumped constants score nothing
#   - probe order is randomized per run: counting invocations from a
#     stateful client cannot farm the battery
#   - connect witness + exec gate on the ladder run: the client must
#     talk to THE oracle's port and never execute verifier-side trees
#   - fail-closed privilege drop (baseline #3)
#
# All structural inputs (levels, message table) come from
# inlined GT config (levels/messages/states) — root-only knowledge, the agent never sees it.
# ==============================================================================

# ------------------------------------------------------------------------------
# PATH CONFIGURATION
# ------------------------------------------------------------------------------

GROUND_TRUTH_DIR="/app/ground_truth"
GT_CONFIG='{"levels":{"F":4,"E":4,"C":3,"S":3,"X":3,"M":2,"L":1,"T":1},"messages":[{"name":"BIND","role":"handshake_init","opcode":"0x28","dir":"c2s","fields":[{"name":"wire_rev","type":"u32","width":4,"sem":"version","span":[1,5],"endian":"big","bits":0,"tag":17},{"name":"client_class","type":"u16","width":2,"sem":"value","span":[6,5],"endian":"big","bits":0,"tag":19}],"example_payload_hex":"2800110280200013028120"},{"name":"BIND_OK","role":"handshake_ack","opcode":"0x83","dir":"s2c","fields":[{"name":"wire_rev","type":"u32","width":4,"sem":"version","span":[1,5],"endian":"big","bits":0,"tag":21},{"name":"channel_id","type":"u32","width":4,"sem":"value","span":[6,5],"endian":"big","bits":0,"tag":23},{"name":"route_nonce","type":"bstr","width":12,"sem":"nonce","span":[11,15],"endian":"big","bits":0,"tag":25},{"name":"broker_pub","type":"bstr","width":32,"sem":"key","span":[26,35],"endian":"big","bits":0,"tag":27}],"example_payload_hex":"830015028020001702812000190ca2a2a2a2a2a2a2a2a2a2a2a2001b20a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3"},{"name":"DECLARE_Q","role":"params","opcode":"0xd7","dir":"c2s","fields":[{"name":"flow_window","type":"u16","width":2,"sem":"value","span":[1,5],"endian":"big","bits":0,"tag":29},{"name":"max_msg","type":"u16","width":2,"sem":"value","span":[6,5],"endian":"big","bits":0,"tag":31}],"example_payload_hex":"d7001d028020001f028120"},{"name":"Q_DECLARED","role":"params_ack","opcode":"0xc8","dir":"s2c","fields":[{"name":"broker_window","type":"u16","width":2,"sem":"value","span":[1,5],"endian":"big","bits":0,"tag":33},{"name":"admin_code","type":"u32","width":4,"sem":"token","span":[6,5],"endian":"big","bits":0,"tag":35}],"example_payload_hex":"c800210280200023028120"},{"name":"SASL","role":"auth","opcode":"0xca","dir":"c2s","fields":[{"name":"producer_pub","type":"bstr","width":32,"sem":"key","span":[1,35],"endian":"big","bits":0,"tag":37},{"name":"sasl_tag","type":"bstr","width":16,"sem":"key","span":[36,19],"endian":"big","bits":0,"tag":39}],"example_payload_hex":"ca002520a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0002710a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"},{"name":"SASL_OK","role":"auth_ack","opcode":"0x5b","dir":"s2c","fields":[{"name":"pub_status","type":"u8","width":1,"sem":"status","span":[1,4],"endian":"big","bits":0,"tag":41},{"name":"broker_sig","type":"bstr","width":8,"sem":"key","span":[5,11],"endian":"big","bits":0,"tag":43}],"example_payload_hex":"5b00290140002b08a1a1a1a1a1a1a1a1"},{"name":"CONSUME","role":"read","opcode":"0x5a","dir":"c2s","fields":[{"name":"routing_key","type":"str","width":16,"sem":"name","span":[1,6],"endian":"big","bits":0,"tag":45}],"example_payload_hex":"5a002d03657830"},{"name":"DELIVERED","role":"read_ack","opcode":"0xfb","dir":"s2c","fields":[{"name":"routing_key","type":"str","width":16,"sem":"name","span":[1,6],"endian":"big","bits":0,"tag":47},{"name":"msg_body","type":"u32","width":4,"sem":"value","span":[7,5],"endian":"big","bits":0,"tag":49}],"example_payload_hex":"fb002f036578300031028120"},{"name":"PUBLISH","role":"write","opcode":"0xd0","dir":"c2s","fields":[{"name":"routing_key","type":"str","width":16,"sem":"name","span":[1,6],"endian":"big","bits":0,"tag":51},{"name":"msg_body","type":"u32","width":4,"sem":"value","span":[7,5],"endian":"big","bits":0,"tag":53}],"example_payload_hex":"d00033036578300035028120"},{"name":"PUBLISHED","role":"write_ack","opcode":"0xb2","dir":"s2c","fields":[{"name":"pub_status","type":"u8","width":1,"sem":"status","span":[1,4],"endian":"big","bits":0,"tag":55}],"example_payload_hex":"b200370140"},{"name":"ROUTE_CHECK","role":"compute","opcode":"0xcf","dir":"c2s","fields":[{"name":"msg_count","type":"u16","width":2,"sem":"value","span":[1,5],"endian":"big","bits":0,"tag":57},{"name":"q_depth","type":"u16","width":2,"sem":"value","span":[6,5],"endian":"big","bits":0,"tag":59}],"example_payload_hex":"cf0039028020003b028120"},{"name":"ROUTE_RESULT","role":"compute_ack","opcode":"0x21","dir":"s2c","fields":[{"name":"route_score","type":"u32","width":4,"sem":"value","span":[1,5],"endian":"big","bits":0,"tag":61}],"example_payload_hex":"21003d028020"},{"name":"ADMIN_KEY","role":"flag_req","opcode":"0xa2","dir":"c2s","fields":[{"name":"admin_code","type":"u32","width":4,"sem":"token","span":[1,5],"endian":"big","bits":0,"tag":63}],"example_payload_hex":"a2003f028020"},{"name":"ADMIN_KEY_RES","role":"flag_res","opcode":"0xab","dir":"s2c","fields":[{"name":"vhost_key","type":"str","width":48,"sem":"flag","span":[1,6],"endian":"big","bits":0,"tag":65}],"example_payload_hex":"ab004103657830"},{"name":"NACK","role":"error","opcode":"0xfa","dir":"s2c","fields":[{"name":"nack_code","type":"u8","width":1,"sem":"status","span":[1,4],"endian":"big","bits":0,"tag":67}],"example_payload_hex":"fa00430140"},{"name":"UNBIND","role":"close","opcode":"0xe6","dir":"c2s","fields":[{"name":"unbind_reason","type":"u8","width":1,"sem":"reason","span":[1,4],"endian":"big","bits":0,"tag":69}],"example_payload_hex":"e600450140"},{"name":"UNBOUND","role":"close_ack","opcode":"0x9e","dir":"s2c","fields":[{"name":"nack_code","type":"u8","width":1,"sem":"status","span":[1,4],"endian":"big","bits":0,"tag":71}],"example_payload_hex":"9e00470140"},{"name":"KEEPALIVE","role":"ping","opcode":"0x99","dir":"c2s","fields":[{"name":"ka_seq","type":"u32","width":4,"sem":"seq","span":[1,5],"endian":"big","bits":0,"tag":73}],"example_payload_hex":"990049028020"},{"name":"KEEPALIVE_ACK","role":"ping_ack","opcode":"0x65","dir":"s2c","fields":[{"name":"ka_echo","type":"u32","width":4,"sem":"value","span":[1,5],"endian":"big","bits":0,"tag":75}],"example_payload_hex":"65004b028020"},{"name":"Q_STATUS","role":"stat","opcode":"0x55","dir":"c2s","fields":[{"name":"q_id","type":"u8","width":1,"sem":"value","span":[1,4],"endian":"big","bits":0,"tag":77}],"example_payload_hex":"55004d0140"},{"name":"Q_INFO","role":"stat_ack","opcode":"0xec","dir":"s2c","fields":[{"name":"q_text","type":"str","width":24,"sem":"value","span":[1,6],"endian":"big","bits":0,"tag":79}],"example_payload_hex":"ec004f03657830"}],"states":[{"name":"WAIT_HELLO","transitions":[{"input":"HELLO","next":"WAIT_PARAMS"}]},{"name":"WAIT_PARAMS","transitions":[{"input":"PARAMS","next":"WAIT_AUTH"}]},{"name":"WAIT_AUTH","transitions":[{"input":"AUTH","next":"SESSION"}]},{"name":"SESSION","transitions":[{"input":"GET|SET|SUM|FLAG","next":"SESSION"},{"input":"BYE","next":"CLOSED"},{"input":"protocol_error","next":"RESYNC"}]},{"name":"RESYNC","transitions":[{"input":"HELLO","next":"WAIT_PARAMS"},{"input":"duplicate_sequence","next":"SESSION","action":"retransmit_accepted"}]}]}'

AGENT_OUTPUT_DIR="/logs/artifacts/agent_output"
CLIENT_BIN="$AGENT_OUTPUT_DIR/client"

ORACLE_BIN="/app/ground_truth/oracle/oracle_server"
REWARD="/logs/verifier/reward.json"
REWARD_DETAILS="/logs/verifier/reward-details.json"

# per-run scratch (mktemp, never fixed paths: the analyzed client runs
# between the rm and the root-side writes)
RUN_DIR="$(mktemp -d /tmp/verrun.XXXXXX)"

# ------------------------------------------------------------------------------
# TASK CONFIGURATION
# ------------------------------------------------------------------------------
# Everything task-specific lives in the ground truth (protocol levels,
# message table); only the challenge id differs per task:
#   Challenge: strongswan-6.0.7-tunnelkey

SCORING_CONFIG=(
    "Session Ladder|70|score_ladder|session_ladder"
    "Robustness Battery|30|score_robustness|robustness_battery"
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

command -v python3 >/dev/null || fail_out "python3 required by the verifier"
echo "$GT_CONFIG" | python3 -c "import json,sys; json.load(sys.stdin)" >/dev/null 2>&1 || fail_out "inline GT config is not valid JSON"

# ===== @VERIFIER-CORE-P-BEGIN (byte-identical across the firmware/protocol templates; canonical source: script/verifier_blocks/core_p.py -- edit there, not here). Embedded scorers import it after sys.path.insert(0, "/tmp"). =====
cat >/tmp/verifier_core.py <<'VERIFIER_CORE_PY'
"""Vendored verifier core for the python-embedding templates (byte-identical
across the firmware/protocol test.sh copies; canonical source:
script/verifier_blocks/core_p.py -- edit there, not in a template).

Implements the shared verifier baseline in python: the agent-input realpath
jail + size caps, the agent-declared command gate, the execve/execveat
anti-cheat gate for strace -xx logs, and the unified array/boolean scoring
policies. Written to /tmp/verifier_core.py by the embedding test.sh; scorers
import it after `sys.path.insert(0, "/tmp")`.
"""
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys

AGENT_DIR = os.path.realpath("/logs/artifacts/agent_output")
CAP_TEXT = 10 * 1024 * 1024      # report/input-class agent files
CAP_BINARY = 64 * 1024 * 1024    # submitted binary artifacts
CAP_IMAGE = 256 * 1024 * 1024    # image-class artifacts (repacks, trees)

# verifier-side trees: executing anything under these from analyzed code is a wrapper cheat and voids the dynamic bucket it fed
GATE_PREFIXES = ("/app", "/tests", "/solution")

# the ONE strict operator rule (see baseline #5; mirrors cmd_operators_safe in the bash core -- the bash -c runners require parens, argv runners apply the same set for uniformity)
_OPERATOR_RE = re.compile(r"[;&|`$()<>]")


def cmd_operators_safe(cmd):
    """True when the agent-declared command has no shell operators."""
    return not _OPERATOR_RE.search(str(cmd or ""))


def load_agent(path, cap=CAP_TEXT):
    """Load an agent-supplied JSON file under the realpath jail + size cap.
    Returns {} when rejected -- every downstream check then reads empty
    values (fail closed), never the file as-is."""
    try:
        real = os.path.realpath(path)
        if not (real == AGENT_DIR or real.startswith(AGENT_DIR + os.sep)):
            return {}
        if os.path.getsize(real) > cap:
            return {}
        return json.load(open(real))
    except Exception:
        return {}


def confined_own_file(rel):
    """The agent's OWN executable for an activation-style command: no shell
    operators, one path, symlinks resolved and confined to agent_output, must
    exist and be executable. Returns the resolved real path, or None."""
    rel = str(rel or "").strip()
    if not rel or not cmd_operators_safe(rel):
        return None
    p = rel if os.path.isabs(rel) else os.path.join(AGENT_DIR, rel)
    try:
        real = os.path.realpath(p)
    except Exception:
        return None
    if not real.startswith(AGENT_DIR + os.sep):
        return None
    if not (os.path.isfile(real) and os.access(real, os.X_OK)):
        return None
    return real


def confined_agent_dir(rel):
    """The agent's own directory (extracted tree/root): relative path,
    realpath inside agent_output, exists, and the entry itself is not a
    symlink (a symlinked root used to walk the oracle tree for free).
    Returns the resolved real path, or None."""
    rel = str(rel or "").strip()
    if not rel or os.path.isabs(rel):
        return None
    cand = os.path.join(AGENT_DIR, rel)
    try:
        real = os.path.realpath(cand)
    except Exception:
        return None
    if not real.startswith(AGENT_DIR + os.sep):
        return None
    if not os.path.isdir(real) or os.path.islink(cand):
        return None
    return real


def confined_input_file(rel, cap=CAP_TEXT):
    """Agent-supplied DATA file (trigger inputs, exposure inputs -- no
    executable bit required): realpath jail + size cap, absolute or relative
    to agent_output. Returns the resolved real path, or None (the caller
    fails the claim closed)."""
    rel = str(rel or "").strip()
    if not rel:
        return None
    p = rel if os.path.isabs(rel) else os.path.join(AGENT_DIR, rel)
    try:
        real = os.path.realpath(p)
    except Exception:
        return None
    if not real.startswith(AGENT_DIR + os.sep):
        return None
    if not os.path.isfile(real):
        return None
    if os.path.getsize(real) > cap:
        return None
    return real


def _dehex(s):
    """decode strace -xx \\xHH escapes (latin1: paths are bytes)"""
    return bytes(int(h, 16) for h in
                 re.findall(r'\\x([0-9a-f]{2})', s)).decode("latin1")


def exec_gate(logtext, allowed=None):
    """True when the traced analyzed run executed ANY verifier-side binary.
    execve AND execveat both feed the gate (tracing execve alone let an
    impostor side-step it via execveat); -xx escapes are decoded first.
    `allowed` exempts the ONE verifier-side target that is the binary under
    test (agents running it directly would otherwise void every run)."""
    for m in re.findall(r'execve\("((?:\\x[0-9a-f]{2})*)"', logtext):
        p = _dehex(m)
        if allowed and p == allowed:
            continue
        if p.startswith(GATE_PREFIXES):
            return True
    for m in re.findall(r'execveat\([^,]+, "((?:\\x[0-9a-f]{2})*)"', logtext):
        p = _dehex(m)
        if allowed and p == allowed:
            continue
        if p.startswith(GATE_PREFIXES):
            return True
    return False


def sha256_file(p):
    try:
        return hashlib.sha256(open(p, "rb").read()).hexdigest()
    except OSError:
        return None


def array_f1(want, got):
    """Unified array policy: case-insensitive whole-word F1 over deduped
    sets, 0.5 precision floor, dump cap (listing more than want+3 items
    scores 0). Both empty -> 1.0; one side empty -> 0.0."""
    def norm(xs):
        if not isinstance(xs, list):
            xs = [xs]
        return [str(x or "").strip().lower() for x in xs]
    wl, gl = norm(want or []), norm(got or [])
    if not wl and not gl:
        return 1.0
    if not wl or not gl:
        return 0.0
    if len(gl) > len(wl) + 3:
        return 0.0        # dump cap: listing far beyond the truth is worth 0
    wset, gset = set(wl), set(gl)
    tp = len(wset & gset)
    p = tp / len(gset)
    r = tp / len(wset)
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return f if p >= 0.5 else 0.0


def bool_frac(hits, misses, n):
    """Unified fact-boolean policy: wrong AND missing penalized, >= 0."""
    return max(0, hits - misses) / (n or 1)


def runas_argv():
    """The verifier's privilege-drop prefix (VERIFIER_RUNAS env, set by the
    bash core); [] when the drop is unavailable (non-root dev verifiers)."""
    return shlex.split(os.environ.get("VERIFIER_RUNAS", ""))


def run_confined(argv, trace_path=None, timeout=60, strace_set=None, xx=False,
                 stdin_bytes=None):
    """Run agent/analyzed code under the unified privilege drop, optionally
    strace-wrapped so the caller can apply the exec gate and match syscall
    observables. argv MUST already be confined (confined_own_file / the
    verifier's own target binary). Returns (proc_or_None, stdout+stderr,
    trace_text); proc is None on timeout OR spawn failure -- deliberately
    indistinguishable, since both deny every observable symptom (the caller
    labels them "timeout"/"failed" alike). With trace_path the tracer runs as
    the verifier and only the target is dropped (the trace file is
    verifier-written). xx=True hex-escapes every string (decode with _dehex
    before matching). stdin_bytes feeds the process (trigger-class inputs);
    capture is binary and decoded with errors='replace' so byte-exact
    stdin/stdout round-trips survive."""
    prefix = []
    if trace_path is not None:
        prefix = ["strace", "-f", "-s", "4096"]
        if xx:
            prefix.append("-xx")
        prefix += ["-e", "trace=" + (strace_set or "execve,execveat"),
                   "-o", trace_path]
    try:
        # cwd = agent output dir: multi-file triggers resolve their bare
        # argv tokens (credentials, keys) beside the submitted input —
        # exactly where the agent stages them.
        r = subprocess.run(prefix + runas_argv() + argv, input=stdin_bytes,
                           capture_output=True, timeout=timeout,
                           cwd=AGENT_DIR)
    except Exception:
        return None, "", ""
    out = ((r.stdout or b"") + (r.stderr or b"")).decode("utf-8", "replace")
    trace = ""
    if trace_path is not None:
        try:
            trace = open(trace_path, errors="replace").read()
        except OSError:
            trace = ""
    return r, out, trace
VERIFIER_CORE_PY

# ------------------------------------------------------------------------------
# shared client contract check (the fixed-path convention replaces the
# old client_command parsing: no shell string ever reaches a shell)
# ------------------------------------------------------------------------------
check_client() {
    local real sz
    [ -e "$CLIENT_BIN" ] || {
        echo "✗ no submission at $CLIENT_BIN -- the deliverable is an executable named 'client' in the agent output directory (invoked as: client HOST PORT [--parallel N])"
        return 1; }
    real=$(readlink -f "$CLIENT_BIN" 2>/dev/null) || return 1
    case "$real" in
        "$AGENT_OUTPUT_DIR"/*) ;;
        *) echo "✗ client resolves outside the agent output directory"; return 1 ;;
    esac
    [ -f "$real" ] || { echo "✗ client is not a regular file"; return 1; }
    sz=$(stat -c %s "$real" 2>/dev/null) || return 1
    [ "$sz" -le "$VER_CAP_BINARY" ] || {
        echo "✗ client exceeds the ${VER_CAP_BINARY}-byte submission cap"; return 1; }
    [ -x "$real" ] || { echo "✗ client is not executable (chmod +x)"; return 1; }
    echo "$real"
}

# ------------------------------------------------------------------------------
# 1. SESSION LADDER (dynamic, 70) -- one clean oracle run
# ------------------------------------------------------------------------------
# The oracle serves on loopback with a fresh per-connection nonce and the
# FORMAT/milestone log enabled. The submitted client runs ONCE under
# strace (cheat gate + connect witness) and the unprivileged drop; the
# python mapper grades the 23 ladder elements from the oracle's own
# conn-attributed log lines.
# ------------------------------------------------------------------------------

score_ladder() {
    local max=70 score=0
    local portfile mslog outlog stracelog

    if [ ! -x "$ORACLE_BIN" ]; then
        echo "0"
        echo "✗ oracle binary missing at $ORACLE_BIN"
        return
    fi
    local client_real
    client_real=$(check_client) || { echo "0"; echo "$client_real"; return; }

    if [ "$VER_DROP_OK" -ne 1 ]; then
        echo "0"
        echo "✗ fail-closed: privilege drop unavailable on a root verifier -- analyzed binaries must never run as root"
        return
    fi

    portfile="$RUN_DIR/port"; mslog="$RUN_DIR/ms"; outlog="$RUN_DIR/out"
    stracelog="$RUN_DIR/strace"
    local msecret="ms$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
    PROTO_MILESTONE_LOG="$mslog" PROTO_MILESTONE_SECRET="$msecret" \
        "$ORACLE_BIN" >"$portfile" 2>/dev/null &
    local opid=$!
    local tries=0
    until [ -s "$portfile" ]; do
        tries=$((tries+1)); [ $tries -ge 100 ] && break; sleep 0.1
    done
    local port
    port=$(grep -a '^LISTENING ' "$portfile" 2>/dev/null | awk '{print $2}')
    if [ -z "$port" ]; then
        kill $opid 2>/dev/null || true
        echo "0"
        echo "✗ oracle failed to start"
        return
    fi

    # run the FINAL PRODUCT once: full strace observation (cheat gate +
    # connect witness) under the unprivileged drop
    timeout 120 strace -f -s 4096 -xx \
        -e trace=%network,execve,execveat,read,write -o "$stracelog" \
        "${VER_RUNAS[@]}" "$client_real" 127.0.0.1 "$port" >"$outlog" 2>/dev/null || true
    sleep 0.3
    kill $opid 2>/dev/null || true

    # cheat gate: the client never legitimately touches verifier-side
    # trees (baseline #4, no exemptions)
    if ! CHEAT=$(python3 - "$stracelog" <<'PYEOF'
import sys
sys.path.insert(0, "/tmp")
import verifier_core as vc
try:
    log = open(sys.argv[1], errors="replace").read()
    print(1 if vc.exec_gate(log) else 0)
except Exception:
    print(2)   # unreadable trace: fail CLOSED
PYEOF
    ); then CHEAT=2; fi
    if [ "$CHEAT" != "0" ]; then
        echo "0"
        if [ "$CHEAT" = "2" ]; then
            echo "✗ wire capture missing/unparseable -- ladder voided (task assembly defect)"
        else
            echo "✗ client executed a verifier-side binary (/app|/tests|/solution) -- ladder voided"
        fi
        return
    fi
    # witness: the client actually connected to THE oracle's endpoint --
    # inet transports show the port in the sockaddr, the T3 unix carrier
    # shows the socket path ($port carries whichever LISTENING printed).
    # The trace runs with -xx, so ALSO try the fully hex-escaped form of
    # the path (every byte as \xNN); one of the two must appear.
    port_x=$(printf '%s' "$port" | python3 -c 'import sys; s=sys.stdin.read(); print("".join("\\x%02x" % b for b in s.encode()))')
    if ! grep -q "sin_port=htons($port)" "$stracelog" 2>/dev/null \
       && ! grep -qF "sun_path=\"$port\"" "$stracelog" 2>/dev/null \
       && ! grep -qF "sun_path=\"$port_x\"" "$stracelog" 2>/dev/null; then
        echo "0"
        echo "✗ client never connected to the oracle's endpoint"
        return
    fi

    # map the oracle's log to the 23 ladder elements
    python3 - "$mslog" "$outlog" "$GT_CONFIG" "$max" <<'PYEOF'
import json, re, sys

mslog, outlog, gt_json, MAX = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
gt = json.loads(gt_json)
L = gt.get("levels", {})

# message lookup by canonical ROLE (the semantic layer mints a per-task
# name for every role; older reports without the role field fall back to
# the canonical name, which equals the role's legacy spelling)
def op_of(role):
    for m in gt.get("messages", []):
        if m.get("role") == role or m.get("name", "").upper() == role:
            try:
                return int(str(m.get("opcode", "")), 16)
            except Exception:
                return None
    return None

OP_HELLO = op_of("handshake_init")
OP_AUTH = op_of("auth")
OP_SET, OP_GET = op_of("write"), op_of("read")
OP_SUM, OP_FLAG, OP_BYE = op_of("compute"), op_of("flag_req"), op_of("close")

# ---- parse the conn-attributed log (sequentially: frame lines bucket
# into pre-hello / post-hello per connection, so stage ① grades only
# handshake ATTEMPTS, never later traffic) ------------------------------
conns = {}
try:
    raw = open(mslog, errors="replace").read().splitlines()
except Exception:
    raw = []

def conn(cid):
    return conns.setdefault(cid, {"frames_pre": [], "frames_post": [],
                                  "auth": [], "cmds": [], "rounds": 0,
                                  "flag": [], "closes": [], "delivered": [],
                                  "hello": False, "auth_ok": False})

for line in raw:
    m = re.match(r"^\S+ conn=(\d+) (.*)$", line)
    if not m:
        continue
    cid, body = m.group(1), m.group(2)
    c = conn(cid)
    if body == "hello_ok":
        c["hello"] = True
    elif body == "auth_ok":
        c["auth_ok"] = True
    elif body == "round":
        c["rounds"] += 1
    elif body.startswith("frame "):
        d = dict(kv.split("=", 1) for kv in body.split()[1:])
        d = {k: int(v) for k, v in d.items()}
        (c["frames_post"] if c["hello"] else c["frames_pre"]).append(d)
    elif body.startswith("auth "):
        d = dict(kv.split("=", 1) for kv in body.split()[1:])
        c["auth"].append({k: int(v) for k, v in d.items()})
    elif body.startswith("cmd "):
        d = dict(kv.split("=", 1) for kv in body.split()[1:])
        # op=<NAME> is a string; every other field is numeric
        c["cmds"].append({k: (v if k == "op" else int(v))
                          for k, v in d.items()})
    elif body.startswith("flag "):
        d = dict(kv.split("=", 1) for kv in body.split()[1:])
        c["flag"].append({k: int(v) for k, v in d.items()})
    elif body.startswith("flag_delivered "):
        c["delivered"].append(body.split("value=", 1)[1])
    elif body.startswith("close "):
        d = dict(kv.split("=", 1) for kv in body.split()[1:])
        # chaos=<name> is a string; every other field is numeric
        c["closes"].append({k: (v if k == "chaos" else int(v))
                            for k, v in d.items()})

details = []
score = 0.0

# ---------- ① handshake: 7 elements over pre-hello frames ---------------
# attempts from every connection, cut at its hello_ok: a successful
# client's ① evidence is its HELLO attempts only, never later traffic
hs_frames = []
for c in conns.values():
    hs_frames += c["frames_pre"]
hello_frames = [f for f in hs_frames if f.get("op") == OP_HELLO]

def anyf(frames, key):
    return any(f.get(key) == 1 for f in frames)

hs = 0.0
if anyf(hello_frames, "bnd") or anyf(hs_frames, "bnd"):
    hs += 3; details.append("✓ ① frame boundary (3)")
else:
    details.append("✗ ① frame boundary")
if anyf(hello_frames, "magic") or anyf(hs_frames, "magic"):
    hs += 4; details.append("✓ ① magic value (4)")
else:
    details.append("✗ ① magic value")
if hello_frames:
    hs += 2; details.append("✓ ① opcode HELLO (2)")
elif any(f.get("op") == OP_HELLO for f in hs_frames):
    hs += 2; details.append("✓ ① opcode HELLO (2)")
else:
    details.append("✗ ① opcode HELLO")
ver_ok = any(f.get("ver") == 1 for f in hello_frames) or \
         any(c["hello"] for c in conns.values())
if ver_ok:
    hs += 3; details.append("✓ ① version (3)")
else:
    details.append("✗ ① version")
if anyf(hello_frames, "len") or anyf(hs_frames, "len"):
    hs += 2; details.append("✓ ① length field (2)")
else:
    details.append("✗ ① length field")
if anyf(hello_frames, "crc") or anyf(hs_frames, "crc"):
    hs += 3; details.append("✓ ① checksum (3)")
else:
    details.append("✗ ① checksum")
if anyf(hello_frames, "dec"):
    hs += 3; details.append("✓ ① payload structure (3)")
else:
    details.append("✗ ① payload structure")
score += hs

# ---------- ② authentication: level-applicable element set -------------
auth_lines = [a for c in conns.values() for a in c["auth"]]
auth_frames = [f for c in conns.values()
               for f in c["frames_pre"] + c["frames_post"]
               if f.get("op") == OP_AUTH]
au = 0.0
if L.get("C", 0) in (3, 7, 8):   # kex levels: pubkey rides AUTH
    if auth_lines:
        au += 3 + 4                       # reached the handler: opcode+structure
        a0 = auth_lines[0]
        if a0.get("macval") == 1:
            au += 8; details.append("✓ ② auth MAC value (8)")
        else:
            details.append("✗ ② auth MAC value")
        if a0.get("pub") == 1:
            au += 3; details.append("✓ ② KEX pubkey present (3)")
        else:
            details.append("✗ ② KEX pubkey present")
        if a0.get("curve") == 1:
            au += 2; details.append("✓ ② pubkey on curve (2)")
        else:
            details.append("✗ ② pubkey on curve")
    else:
        # never decoded: partial credit from the raw frames
        if auth_frames:
            au += 3
            details.append("⊘ ② opcode AUTH only (3/20)")
            if any(f.get("plain") == 1 and f.get("dec") == 1
                   for f in auth_frames):
                au += 4
                details.append("⊘ ② structure via plaintext decode (+4)")
        else:
            details.append("✗ ② no AUTH attempt observed")
else:
    # static-key C (non-KEX): opcode/structure/value/keystream
    if auth_lines:
        au += 3 + 4
        a0 = auth_lines[0]
        if a0.get("macval") == 1:
            au += 8
        if a0.get("crypt") == 1:
            au += 5
    elif auth_frames:
        au += 3
        if any(f.get("plain") == 1 and f.get("dec") == 1
               for f in auth_frames):
            au += 4
score += au

# ---------- ③ data exchange ---------------------------------------------
all_cmds = [d for c in conns.values() for d in c["cmds"]]
all_frames = [f for c in conns.values()
              for f in c["frames_pre"] + c["frames_post"]]
total_rounds = sum(c["rounds"] for c in conns.values())
ex = 0.0
if any(d.get("op") == "SET" for d in all_cmds) or \
   any(f.get("op") == OP_SET and f.get("plain") == 1 and f.get("dec") == 1
       for f in all_frames):
    ex += 3; details.append("✓ ③ SET grammar (3)")
else:
    details.append("✗ ③ SET grammar")
get_lines = [d for d in all_cmds if d.get("op") == "GET"]
get_plain = any(f.get("op") == OP_GET and f.get("plain") == 1
                and f.get("dec") == 1 for f in all_frames)
if get_lines or get_plain:
    ex += 1.5
    if any(d.get("samekey") == 1 for d in get_lines):
        ex += 1.5; details.append("✓ ③ GET grammar + same-key readback (3)")
    else:
        details.append("⊘ ③ GET grammar only (1.5/3)")
else:
    details.append("✗ ③ GET grammar")
if any(d.get("op") == "SUM" for d in all_cmds) or \
   any(f.get("op") == OP_SUM and f.get("plain") == 1 and f.get("dec") == 1
       for f in all_frames):
    ex += 3; details.append("✓ ③ SUM grammar (3)")
else:
    details.append("✗ ③ SUM grammar")
if any(d.get("crypt") == 1 for d in all_cmds):
    ex += 3; details.append("✓ ③ TX session crypto (3)")
else:
    details.append("✗ ③ TX session crypto")
if total_rounds >= 2:
    ex += 1.5
if total_rounds >= 3:
    ex += 1.5
if total_rounds >= 3:
    details.append("✓ ③ multi-round persistence (3)")
elif total_rounds == 2:
    details.append("⊘ ③ two rounds only (1.5/3)")
else:
    details.append("✗ ③ multi-round persistence")
score += ex

# ---------- ④ flag --------------------------------------------------------
flag_lines = [f0 for c in conns.values() for f0 in c["flag"]]
flag_plain = any(f.get("op") == OP_FLAG and f.get("plain") == 1
                 and f.get("dec") == 1 for f in all_frames)
fl = 0.0
if flag_lines or flag_plain:
    fl += 2; details.append("✓ ④ FLAG request grammar (2)")
else:
    details.append("✗ ④ FLAG request grammar")
if any(d.get("token_ok") == 1 for d in flag_lines):
    fl += 4; details.append("✓ ④ flag token value (4)")
else:
    details.append("✗ ④ flag token value")
delivered = [v for c in conns.values() for v in c["delivered"]]
try:
    stdout = open(outlog, errors="replace").read()
except Exception:
    stdout = ""
if delivered and any(v in stdout for v in delivered):
    fl += 4; details.append("✓ ④ flag delivered on stdout (4)")
else:
    details.append("✗ ④ flag delivered on stdout")
score += fl

# ---------- ⑤ close -------------------------------------------------------
cl = 0.0
bye_cmd = any(d.get("op") == "BYE" for d in all_cmds)
bye_plain = any(f.get("op") == OP_BYE and f.get("plain") == 1
                and f.get("dec") == 1 for f in all_frames)
if bye_cmd or bye_plain:
    cl += 2; details.append("✓ ⑤ BYE grammar (2)")
else:
    details.append("✗ ⑤ BYE grammar")
bye_close = [d for c in conns.values() for d in c["closes"] if d.get("bye") == 1]
if bye_close:
    if bye_close[-1].get("sendfail") == 0:
        cl += 1.5; details.append("✓ ⑤ BYE_ACK delivered (1.5)")
    else:
        details.append("✗ ⑤ BYE_ACK delivered")
    if bye_close[-1].get("fin") == 1 and bye_close[-1].get("rst") == 0:
        cl += 1.5; details.append("✓ ⑤ orderly close (1.5)")
    else:
        details.append("✗ ⑤ orderly close")
score += cl

score = round(min(score, MAX), 2)
print(score)
for d in details:
    print(d)
print("handshake %.1f/20, auth %.1f/20, exchange %.1f/15, "
      "flag %.1f/10, close %.1f/5" % (hs, au, ex, fl, cl))

# ---- state-machine coverage (reported metric; the stage points above
# ARE the per-node accuracy grade) ----------------------------------
states = [s.get("name", "?") for s in (gt.get("states") or [])]
visited = []
if any(c["hello"] for c in conns.values()):
    visited.append("hello")
if any(c["auth_ok"] for c in conns.values()):
    visited.append("auth")
if total_rounds >= 1:
    visited.append("exchange")
if flag_lines or flag_plain:
    visited.append("flag")
if bye_close:
    visited.append("close")
print("state machine coverage: %d of %d ladder nodes (%s)%s"
      % (len(visited), 5, ",".join(visited),
         ("; declared states: %s" % ",".join(states)) if states else ""))
PYEOF
}

# ------------------------------------------------------------------------------
# 2. ROBUSTNESS BATTERY (dynamic, 30) -- one single-fault oracle run per
#    applicable probe, order randomized per verifier run
# ------------------------------------------------------------------------------

score_robustness() {
    local max=30
    local client_real
    client_real=$(check_client) || { echo "0"; echo "$client_real"; return; }
    if [ "$VER_DROP_OK" -ne 1 ]; then
        echo "0"
        echo "✗ fail-closed: privilege drop unavailable"
        return
    fi

    python3 - "$ORACLE_BIN" "$client_real" "$GT_CONFIG" "$RUN_DIR" "$max" <<'PYEOF'
import json, os, random, re, shlex, subprocess, sys, time

ORACLE, CLIENT, GT, RUN_DIR, MAX = (sys.argv[1], sys.argv[2], sys.argv[3],
                                    sys.argv[4], float(sys.argv[5]))
gt = json.loads(GT)
L = gt.get("levels", {})
rnd = random.Random(int.from_bytes(os.urandom(8), "big"))

# probe table: (name, points, applicability, parallel?, error node)
# error-node weight per the construction contract: an error state entered
# deeper in the dialog costs more to recover, so command-node faults weigh
# 1.5x against framing-node and handshake-node faults at 1.0x. Points are
# node-weighted before renormalization.
NODE_W = {"frame": 1.0, "hello": 1.0, "command": 1.5}
PROBES = [
    ("chaffburst",   3.0, L.get("X", 0) >= 2, False, "frame"),
    ("corruptreply", 3.0, L.get("F", 0) >= 3, False, "command"),
    ("minfrag",      3.0, L.get("X", 0) >= 3, False, "frame"),
    ("escapedense",  2.0, L.get("F", 0) == 5, False, "frame"),
    ("noise",        2.0, L.get("F", 0) >= 3, False, "frame"),
    ("resync",       3.0, L.get("S", 0) >= 3, False, "command"),
    ("delay",        1.5, True,                   False, "command"),
    ("drip",         1.5, True,                   False, "command"),
    ("errhello",     1.0, L.get("S", 0) >= 1, False, "hello"),
    ("parallel",     3.0, True,                   True, "command"),   # C10
    ("badlen",       3.0, L.get("F", 0) >= 3, False, "frame"),
    ("drop",         2.0, L.get("S", 0) >= 1, False, "command"),
    ("dupreply",     2.0, True,                   False, "command"),
]
applicable = [(n, p * NODE_W[w], par, w)
              for (n, p, ok, par, w) in PROBES if ok]
if not applicable:
    print("0"); print("⊘ no applicable probes at these levels"); sys.exit(0)
rnd.shuffle(applicable)          # invocation-order fingerprinting is dead

def start_oracle(chaos=None):
    env = dict(os.environ)
    ms = os.path.join(RUN_DIR, "ms-%s" % (chaos or "clean"))
    try:
        os.unlink(ms)
    except OSError:
        pass
    env["PROTO_MILESTONE_LOG"] = ms
    env["PROTO_MILESTONE_SECRET"] = "probe"
    cmd = [ORACLE, "0"] + (["--chaos", chaos] if chaos else [])
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, env=env)
    line = proc.stdout.readline().decode(errors="replace")
    m = re.search(r"LISTENING (\S+)", line)
    return (proc, m.group(1), ms) if m else (proc, None, ms)

def run_client(port, parallel=False):
    cmd = [CLIENT, "127.0.0.1", str(port)]
    if parallel:
        cmd += ["--parallel", "2"]
    # same unprivileged drop the ladder run uses (core_a exports the
    # argv; an empty env means no setpriv -- the ladder already failed
    # closed in that case, keep the belt here anyway)
    drop = shlex.split(os.environ.get("VERIFIER_RUNAS", "") or "")
    try:
        out = subprocess.run(["timeout", "120"] + drop + cmd,
                             capture_output=True, text=True, timeout=130)
        return out.stdout, (out.returncode == 0)
    except subprocess.TimeoutExpired:
        return "", False

def _role_opcodes():
    """role -> opcode from the GT message table (the semantic layer mints
    per-task names; roles are the invariant identifiers)"""
    out = {}
    for msg in gt.get("messages", []):
        try:
            out[msg.get("role") or msg.get("name", "").upper()] = \
                int(str(msg.get("opcode", "")), 16)
        except Exception:
            pass
    return out

ROLES = _role_opcodes()

def parse(ms):
    """-> dict: conns with milestones + chaos markers + per-role frame
    counts (decoded inbound frames, used for recovery-branch verdicts)"""
    st = {"hello": 0, "auth": 0, "rounds": 0, "flag": 0,
          "retrans": 0, "resync_rec": 0, "conn_ids": set(),
          "hello_frames": 0, "auth_frames": 0, "close": 0}
    try:
        lines = open(ms, errors="replace").read().splitlines()
    except Exception:
        return st
    for line in lines:
        m = re.match(r"^\S+ conn=(\d+) (.*)$", line)
        if not m:
            continue
        st["conn_ids"].add(m.group(1))
        b = m.group(2)
        if b == "hello_ok": st["hello"] += 1
        elif b == "auth_ok": st["auth"] += 1
        elif b == "round": st["rounds"] += 1
        elif b == "flag_sent": st["flag"] += 1
        elif b == "chaos_retrans observed=1": st["retrans"] = 1
        elif b == "chaos_resync_recovered=1": st["resync_rec"] = 1
        elif b.startswith("close bye=1"): st["close"] += 1
        if b.startswith("frame rc=1 ") and " op=" in b:
            try:
                opv = int(b.rsplit(" op=", 1)[1].split()[0])
            except Exception:
                continue
            if opv == ROLES.get("handshake_init"):
                st["hello_frames"] += 1
            elif opv == ROLES.get("auth"):
                st["auth_frames"] += 1
    return st

def ladder_done(st):
    return st["flag"] >= 1

details, earned, denom = [], 0.0, sum(p for _, p, _, _ in applicable)

for name, pts, parallel, node in applicable:
    proc, port, ms = start_oracle(None if name == "parallel" else name)
    if port is None:
        details.append("✗ %s: oracle failed to start (probe voided)" % name)
        proc.kill()
        continue
    out, clean_exit = run_client(port, parallel)
    time.sleep(0.2)
    proc.kill(); proc.wait()
    st = parse(ms)
    # verdict levels: 1.0 handled with the correct recovery branch for the
    # error code, 0.75 handled but the expected branch was not observed,
    # 0.5 survived (engaged, orderly exit, no completion), 0 died
    level = 0.0
    verdict = "died"
    if name == "parallel":
        # C10: TWO concurrent ladders from one process invocation
        if st["flag"] >= 2 and clean_exit:
            level, verdict = 1.0, "handled"
        elif st["flag"] >= 1:
            level, verdict = 0.5, "survived"
    elif name == "resync":
        # command-node ERR(resync): the correct branch restarts the
        # ladder in-band (HELLO again on the same connection)
        if ladder_done(st) and st["resync_rec"]:
            level, verdict = 1.0, "handled+branch(re-ladder)"
        elif ladder_done(st) and st["hello_frames"] >= 2:
            level, verdict = 1.0, "handled+branch(re-hello)"
        elif ladder_done(st):
            level, verdict = 0.75, "handled, branch unseen"
        elif st["hello"] >= 1 and clean_exit:
            level, verdict = 0.5, "survived"
    elif name == "errhello":
        # handshake-node ERR(version): the correct branch retries HELLO
        if ladder_done(st) and clean_exit:
            if st["hello_frames"] >= 2:
                level, verdict = 1.0, "handled+branch(hello retry)"
            else:
                level, verdict = 0.75, "handled, branch unseen"
        elif st["hello"] >= 1 and clean_exit:
            level, verdict = 0.5, "survived"
    elif name == "drop":
        # command-node connection drop: the correct branch reconnects
        # with a fresh session and completes the ladder
        if len(st["conn_ids"]) >= 2 and ladder_done(st) and clean_exit:
            level, verdict = 1.0, "handled+branch(reconnect)"
        elif clean_exit and st["hello"] >= 1:
            level, verdict = 0.5, "survived"
    elif name == "corruptreply":
        # command-node corrupted reply: the correct branch retransmits
        # the request (the retrans marker fires on the second command)
        if ladder_done(st) and st["retrans"]:
            level, verdict = 1.0, "handled+branch(retransmit)"
        elif ladder_done(st):
            level, verdict = 0.75, "handled, branch unseen"
        elif st["hello"] >= 1 and clean_exit:
            level, verdict = 0.5, "survived"
    else:
        if ladder_done(st) and clean_exit:
            level, verdict = 1.0, "handled"
        elif st["hello"] >= 1 and clean_exit:
            # survived: engaged the faulted server and exited orderly
            # without completing (a client that never connects died)
            level, verdict = 0.5, "survived"
    tag = "✓" if level >= 1.0 else ("⊘" if level > 0 else "✗")
    details.append("%s %s[%s]: %s" % (tag, name, node, verdict))
    earned += pts * level

score = round(earned / denom * MAX, 2)
print(score)
for d in details:
    print(d)
print("battery: %.1f of %.1f applicable points (renormalized to %d)"
      % (earned, denom, int(MAX)))
PYEOF
}

# ==============================================================================
# MAIN
# ==============================================================================

echo ""
echo "==============================================================================="
echo "PROTOCOL RECONSTRUCTION VERIFICATION (V5.1 pure dynamic)"
echo "==============================================================================="
echo "Challenge: strongswan-6.0.7-tunnelkey"
echo "Oracle: $ORACLE_BIN"
echo "Client: $CLIENT_BIN"
echo "==============================================================================="

run_all_scorers
ver_print_report "PROTOCOL RECONSTRUCTION VERIFICATION"
ver_build_details_json

# files are written by the EXIT trap; flush now so a later section cannot
# clobber them with stale values
write_reward
trap - EXIT

rm -rf "$RUN_DIR"

echo ""
echo "✓ Results saved:"
echo "  - $REWARD"
echo "  - $REWARD_DETAILS"
exit 0

