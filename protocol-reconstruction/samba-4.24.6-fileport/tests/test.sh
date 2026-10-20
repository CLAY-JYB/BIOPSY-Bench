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
# PROTOCOL RECONSTRUCTION - VERIFICATION TEST (pure dynamic)
# ==============================================================================
# Challenge: samba-4.24.6-fileport
#
# Scoring (reference/scoring.md: the score is
# the STATE-MACHINE COVERAGE the submitted client demonstrated):
#
#   FSM Coverage              100   DYNAMIC   the dialog graph's items,
#                                            weighted and counted once,
#                                            over the observation plan
#                                            (3 clean runs + 1
#                                            diagnostic run + the
#                                            level-applicable fault
#                                            runs -- a fresh oracle and
#                                            a fresh log secret every
#                                            run, evidence UNIONED)
#
#     success edges (accept/self/idle-timeout)    2.0 each
#     value-gated edges (pass + fail sides)       3.0 each (0.5+0.5)
#     recovery edges (error state's way back)     1.5 each
#     declared error edges (probeable wrongness)  0.5 each
#     success points (working states entered)     1.5 each
#     error points (error states entered)         0.25 each
#
#     score = sum(weight x ratio) / sum(weight) x 100
#
#     The evidence is the oracle's own conn-attributed milestone log
#     (edge on=<op> from=<s> to=<t> rc=<0|1>), so a submission earns
#     items only by actually driving the dialog: the graph, the weights
#     and the expected flag are root-only GT knowledge.
#
# Gates G1-G5 (anti-cheat as PREREQUISITES with targeted voiding -- a
# failed gate voids the runs that depend on it, never the whole score
# from an unrelated stage):
#   G1 submission contract (path jail, size cap, exec bit)
#   G2 fail-closed privilege drop (no root analysis, ever)
#   G3 exec/wrapper gate per run (strace: nothing under /app /tests
#      /solution is ever executed by the analyzed client)
#   G4 connect witness per run (the client talked to THIS oracle's
#      endpoint -- recorded bytes from elsewhere are worthless)
#   G5 milestone-line integrity (each run's lines carry that run's
#      random secret; the client cannot read the log it never sees)
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
GT_CONFIG='{"levels":{"F":4,"E":5,"C":9,"S":4,"X":7,"M":3,"L":6,"T":3},"messages":[{"name":"CAN_OPEN","role":"handshake_init","opcode":"0xa7","dir":"c2s","fields":[{"name":"bus_rev","type":"u32","width":4,"sem":"version","span":[8,32],"endian":"big","bits":32},{"name":"bus_class","type":"u16","width":2,"sem":"value","span":[40,16],"endian":"big","bits":16}],"example_payload_hex":"a7000800008008"},{"name":"CAN_ACK","role":"handshake_ack","opcode":"0xbd","dir":"s2c","fields":[{"name":"bus_rev","type":"u32","width":4,"sem":"version","span":[8,32],"endian":"big","bits":32},{"name":"can_session","type":"u32","width":4,"sem":"value","span":[40,32],"endian":"big","bits":32},{"name":"sec_nonce","type":"bstr","width":16,"sem":"nonce","span":[72,128],"endian":"big","bits":0},{"name":"gw_pub","type":"bstr","width":32,"sem":"key","span":[200,256],"endian":"big","bits":0}],"example_payload_hex":"bd000800008008000045454545454545454545454545454545c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5"},{"name":"FILTER_SET","role":"params","opcode":"0xee","dir":"c2s","fields":[{"name":"baud_window","type":"u16","width":2,"sem":"value","span":[8,16],"endian":"big","bits":16},{"name":"max_dlc","type":"u16","width":2,"sem":"value","span":[24,16],"endian":"big","bits":16}],"example_payload_hex":"ee00088008"},{"name":"FILTER_OK","role":"params_ack","opcode":"0x38","dir":"s2c","fields":[{"name":"gw_window","type":"u16","width":2,"sem":"value","span":[8,16],"endian":"big","bits":16},{"name":"seed_code","type":"u32","width":4,"sem":"token","span":[24,32],"endian":"big","bits":32}],"example_payload_hex":"38000880080000"},{"name":"SECURITY_ACCESS","role":"auth","opcode":"0xe0","dir":"c2s","fields":[{"name":"sec_tag","type":"bstr","width":16,"sem":"key","span":[8,128],"endian":"big","bits":0}],"example_payload_hex":"e005050505050505050505050505050505"},{"name":"ACCESS_OK","role":"auth_ack","opcode":"0xf3","dir":"s2c","fields":[{"name":"tx_status","type":"u8","width":1,"sem":"status","span":[8,8],"endian":"big","bits":8},{"name":"gw_confirm","type":"bstr","width":8,"sem":"key","span":[16,64],"endian":"big","bits":0}],"example_payload_hex":"f3028585858585858585"},{"name":"RECV_FRAME","role":"read","opcode":"0xfa","dir":"c2s","fields":[{"name":"can_id","type":"str","width":16,"sem":"name","span":[8,29],"endian":"big","bits":0}],"example_payload_hex":"fac530f060"},{"name":"FRAME_DATA","role":"read_ack","opcode":"0xa2","dir":"s2c","fields":[{"name":"can_id","type":"str","width":16,"sem":"name","span":[8,29],"endian":"big","bits":0},{"name":"dlc","type":"u32","width":4,"sem":"value","span":[37,32],"endian":"big","bits":32}],"example_payload_hex":"a2c530f06400400000"},{"name":"SEND_FRAME","role":"write","opcode":"0xf0","dir":"c2s","fields":[{"name":"can_id","type":"str","width":16,"sem":"name","span":[8,29],"endian":"big","bits":0},{"name":"dlc","type":"u32","width":4,"sem":"value","span":[37,32],"endian":"big","bits":32}],"example_payload_hex":"f0c530f06400400000"},{"name":"FRAME_SENT","role":"write_ack","opcode":"0xb0","dir":"s2c","fields":[{"name":"tx_status","type":"u8","width":1,"sem":"status","span":[8,8],"endian":"big","bits":8}],"example_payload_hex":"b002"},{"name":"CHECKSUM_CALC","role":"compute","opcode":"0xca","dir":"c2s","fields":[{"name":"data_lo","type":"u16","width":2,"sem":"value","span":[8,16],"endian":"big","bits":16},{"name":"data_hi","type":"u16","width":2,"sem":"value","span":[24,16],"endian":"big","bits":16}],"example_payload_hex":"ca00088008"},{"name":"CHECKSUM_VAL","role":"compute_ack","opcode":"0xe3","dir":"s2c","fields":[{"name":"crc_val","type":"u32","width":4,"sem":"value","span":[8,32],"endian":"big","bits":32}],"example_payload_hex":"e300080000"},{"name":"SEED_KEY","role":"flag_req","opcode":"0x4f","dir":"c2s","fields":[{"name":"seed_code","type":"u32","width":4,"sem":"token","span":[8,32],"endian":"big","bits":32}],"example_payload_hex":"4f00080000"},{"name":"SEED_KEY_RES","role":"flag_res","opcode":"0x98","dir":"s2c","fields":[{"name":"security_key","type":"str","width":48,"sem":"flag","span":[8,29],"endian":"big","bits":0}],"example_payload_hex":"98c530f060"},{"name":"BUS_ERR","role":"error","opcode":"0xe8","dir":"s2c","fields":[{"name":"err_code","type":"u8","width":1,"sem":"status","span":[8,8],"endian":"big","bits":8}],"example_payload_hex":"e802"},{"name":"CAN_CLOSE","role":"close","opcode":"0xb6","dir":"c2s","fields":[{"name":"close_reason","type":"u8","width":1,"sem":"reason","span":[8,8],"endian":"big","bits":8}],"example_payload_hex":"b602"},{"name":"CAN_CLOSED","role":"close_ack","opcode":"0x75","dir":"s2c","fields":[{"name":"err_code","type":"u8","width":1,"sem":"status","span":[8,8],"endian":"big","bits":8}],"example_payload_hex":"7502"},{"name":"BUS_CHK","role":"ping","opcode":"0x5d","dir":"c2s","fields":[{"name":"bus_seq","type":"u32","width":4,"sem":"seq","span":[8,32],"endian":"big","bits":32}],"example_payload_hex":"5d00080000"},{"name":"BUS_OK","role":"ping_ack","opcode":"0x6f","dir":"s2c","fields":[{"name":"bus_echo","type":"u32","width":4,"sem":"value","span":[8,32],"endian":"big","bits":32}],"example_payload_hex":"6f00080000"},{"name":"DTC_READ","role":"stat","opcode":"0x91","dir":"c2s","fields":[{"name":"dtc_id","type":"u8","width":1,"sem":"value","span":[8,8],"endian":"big","bits":8}],"example_payload_hex":"9102"},{"name":"DTC_INFO","role":"stat_ack","opcode":"0x5a","dir":"s2c","fields":[{"name":"dtc_text","type":"str","width":24,"sem":"value","span":[8,29],"endian":"big","bits":0}],"example_payload_hex":"5ac530f060"},{"name":"CLAIM_BUS","role":"mux_open","opcode":"0x25","dir":"c2s","fields":[{"name":"baud_window","type":"u16","width":2,"sem":"value","span":[8,16],"endian":"big","bits":16},{"name":"max_dlc","type":"u16","width":2,"sem":"value","span":[24,16],"endian":"big","bits":16}],"example_payload_hex":"2500088008"},{"name":"BUS_CLAIMED","role":"mux_ack","opcode":"0xe2","dir":"s2c","fields":[{"name":"can_session","type":"u16","width":2,"sem":"value","span":[8,16],"endian":"big","bits":16},{"name":"seed_code","type":"u16","width":2,"sem":"token","span":[24,16],"endian":"big","bits":16}],"example_payload_hex":"e200088008"}],"states":[{"name":"LINK","kind":"handshake"},{"name":"NEG0","kind":"negotiate"},{"name":"NEG1","kind":"negotiate"},{"name":"NEG2","kind":"negotiate"},{"name":"NEG3","kind":"negotiate"},{"name":"AUTHGATE","kind":"auth"},{"name":"MODE0","kind":"mode"},{"name":"MODE1","kind":"mode"},{"name":"MODE2","kind":"mode"},{"name":"MODE3","kind":"mode"},{"name":"MODE4","kind":"mode"},{"name":"MODE5","kind":"mode"},{"name":"MODE6","kind":"mode"},{"name":"MODE7","kind":"mode"},{"name":"FLAGPORT","kind":"flag"},{"name":"E_RETRY","kind":"error"},{"name":"E_RESYNC","kind":"error"},{"name":"CLOSED","kind":"terminal"}],"fsm":{"form":"ftp-ctrl","entry":0,"terminal":17,"flag":14,"states":[{"id":0,"name":"LINK","kind":"handshake","timeout_ms":0,"timeout_edge":null,"edges":[{"on":"handshake_init","cls":"accept","next":1,"err":null,"act":null,"down":false,"bracket":false}]},{"id":1,"name":"NEG0","kind":"negotiate","timeout_ms":8707,"timeout_edge":15,"edges":[{"on":"params","cls":"value","next":2,"err":"STATE","act":null,"down":false,"bracket":false,"cond":{"sem":"value","op":"GE","operand":29},"alt":1},{"on":"auth","cls":"err","next":1,"err":"STATE","act":null,"down":false,"bracket":false},{"on":"mux_open","cls":"err","next":1,"err":"VERSION","act":null,"down":false,"bracket":false},{"on":"ping","cls":"err","next":1,"err":"STATE","act":null,"down":false,"bracket":false}]},{"id":2,"name":"NEG1","kind":"negotiate","timeout_ms":9451,"timeout_edge":15,"edges":[{"on":"stat","cls":"value","next":3,"err":"STATE","act":null,"down":false,"bracket":false,"cond":{"sem":"value","op":"GE","operand":180},"alt":2},{"on":"mux_open","cls":"err","next":2,"err":"STATE","act":null,"down":false,"bracket":false},{"on":"handshake_init","cls":"err","next":2,"err":"STATE","act":null,"down":false,"bracket":false},{"on":"ping","cls":"err","next":2,"err":"VERSION","act":null,"down":false,"bracket":false}]},{"id":3,"name":"NEG2","kind":"negotiate","timeout_ms":8790,"timeout_edge":15,"edges":[{"on":"params","cls":"value","next":4,"err":"STATE","act":null,"down":false,"bracket":false,"cond":{"sem":"value","op":"LE","operand":216},"alt":3},{"on":"write","cls":"err","next":3,"err":"TOKEN","act":null,"down":false,"bracket":false},{"on":"ping","cls":"err","next":3,"err":"STATE","act":null,"down":false,"bracket":false},{"on":"flag_req","cls":"err","next":3,"err":"VERSION","act":null,"down":false,"bracket":false}]},{"id":4,"name":"NEG3","kind":"negotiate","timeout_ms":8117,"timeout_edge":15,"edges":[{"on":"stat","cls":"value","next":5,"err":"STATE","act":null,"down":false,"bracket":false,"cond":{"sem":"value","op":"LE","operand":55},"alt":4},{"on":"flag_req","cls":"err","next":4,"err":"VERSION","act":null,"down":false,"bracket":false},{"on":"read","cls":"err","next":4,"err":"VERSION","act":null,"down":false,"bracket":false},{"on":"handshake_init","cls":"err","next":4,"err":"VERSION","act":null,"down":false,"bracket":false}]},{"id":5,"name":"AUTHGATE","kind":"auth","timeout_ms":9603,"timeout_edge":null,"edges":[{"on":"auth","cls":"accept","next":6,"err":null,"act":null,"down":false,"bracket":false},{"on":"params","cls":"err","next":5,"err":"STATE","act":null,"down":false,"bracket":false},{"on":"read","cls":"err","next":5,"err":"STATE","act":null,"down":false,"bracket":false},{"on":"flag_req","cls":"err","next":5,"err":"AUTH","act":null,"down":false,"bracket":false}]},{"id":6,"name":"MODE0","kind":"mode","timeout_ms":0,"timeout_edge":null,"edges":[{"on":"write","cls":"self","next":6,"err":null,"act":"kv_set","down":false,"bracket":false},{"on":"params","cls":"accept","next":7,"err":null,"act":null,"down":false,"bracket":false},{"on":"close","cls":"accept","next":17,"err":null,"act":null,"down":false,"bracket":false},{"on":"ping","cls":"self","next":6,"err":null,"act":"heartbeat","down":false,"bracket":false},{"on":"stat","cls":"self","next":6,"err":null,"act":null,"down":false,"bracket":false},{"on":"mux_open","cls":"self","next":6,"err":null,"act":null,"down":false,"bracket":false},{"on":"compute","cls":"err","next":16,"err":"RESYNC","act":null,"down":true,"bracket":false},{"on":"read","cls":"err","next":6,"err":"TOKEN","act":null,"down":false,"bracket":false},{"on":"compute","cls":"err","next":6,"err":"CREDIT","act":null,"down":false,"bracket":false},{"on":"handshake_init","cls":"err","next":6,"err":"RESYNC","act":null,"down":false,"bracket":false}]},{"id":7,"name":"MODE1","kind":"mode","timeout_ms":0,"timeout_edge":null,"edges":[{"on":"read","cls":"self","next":7,"err":null,"act":"kv_get","down":false,"bracket":false},{"on":"params","cls":"accept","next":8,"err":null,"act":null,"down":false,"bracket":false},{"on":"close","cls":"accept","next":17,"err":null,"act":null,"down":false,"bracket":false},{"on":"ping","cls":"self","next":7,"err":null,"act":"heartbeat","down":false,"bracket":false},{"on":"stat","cls":"self","next":7,"err":null,"act":null,"down":false,"bracket":false},{"on":"mux_open","cls":"self","next":7,"err":null,"act":null,"down":false,"bracket":false},{"on":"auth","cls":"err","next":7,"err":"RESYNC","act":null,"down":false,"bracket":false},{"on":"handshake_init","cls":"err","next":7,"err":"CHANNEL","act":null,"down":false,"bracket":false},{"on":"write","cls":"err","next":7,"err":"STATE","act":null,"down":false,"bracket":false}]},{"id":8,"name":"MODE2","kind":"mode","timeout_ms":0,"timeout_edge":null,"edges":[{"on":"compute","cls":"self","next":8,"err":null,"act":"kv_sum","down":false,"bracket":false},{"on":"params","cls":"accept","next":9,"err":null,"act":null,"down":false,"bracket":false},{"on":"close","cls":"accept","next":17,"err":null,"act":null,"down":false,"bracket":false},{"on":"ping","cls":"self","next":8,"err":null,"act":"heartbeat","down":false,"bracket":false},{"on":"stat","cls":"self","next":8,"err":null,"act":null,"down":false,"bracket":false},{"on":"mux_open","cls":"self","next":8,"err":null,"act":null,"down":false,"bracket":false},{"on":"read","cls":"err","next":8,"err":"REAUTH","act":null,"down":false,"bracket":false},{"on":"write","cls":"err","next":8,"err":"CHANNEL","act":null,"down":false,"bracket":false},{"on":"flag_req","cls":"err","next":8,"err":"STATE","act":null,"down":false,"bracket":false}]},{"id":9,"name":"MODE3","kind":"mode","timeout_ms":0,"timeout_edge":null,"edges":[{"on":"write","cls":"self","next":9,"err":null,"act":"kv_set","down":false,"bracket":false},{"on":"params","cls":"accept","next":10,"err":null,"act":null,"down":false,"bracket":false},{"on":"close","cls":"accept","next":17,"err":null,"act":null,"down":false,"bracket":false},{"on":"ping","cls":"self","next":9,"err":null,"act":"heartbeat","down":false,"bracket":false},{"on":"stat","cls":"self","next":9,"err":null,"act":null,"down":false,"bracket":false},{"on":"mux_open","cls":"self","next":9,"err":null,"act":null,"down":false,"bracket":false},{"on":"read","cls":"err","next":9,"err":"RESYNC","act":null,"down":false,"bracket":false},{"on":"auth","cls":"err","next":9,"err":"REAUTH","act":null,"down":false,"bracket":false},{"on":"compute","cls":"err","next":9,"err":"REAUTH","act":null,"down":false,"bracket":false}]},{"id":10,"name":"MODE4","kind":"mode","timeout_ms":0,"timeout_edge":null,"edges":[{"on":"read","cls":"self","next":10,"err":null,"act":"kv_get","down":false,"bracket":false},{"on":"params","cls":"accept","next":11,"err":null,"act":null,"down":false,"bracket":false},{"on":"close","cls":"accept","next":17,"err":null,"act":null,"down":false,"bracket":false},{"on":"ping","cls":"self","next":10,"err":null,"act":"heartbeat","down":false,"bracket":false},{"on":"stat","cls":"self","next":10,"err":null,"act":null,"down":false,"bracket":false},{"on":"mux_open","cls":"self","next":10,"err":null,"act":null,"down":false,"bracket":false},{"on":"auth","cls":"err","next":10,"err":"RESYNC","act":null,"down":false,"bracket":false},{"on":"compute","cls":"err","next":10,"err":"RESYNC","act":null,"down":false,"bracket":false},{"on":"flag_req","cls":"err","next":10,"err":"UNKNOWN","act":null,"down":false,"bracket":false}]},{"id":11,"name":"MODE5","kind":"mode","timeout_ms":0,"timeout_edge":null,"edges":[{"on":"compute","cls":"self","next":11,"err":null,"act":"kv_sum","down":false,"bracket":false},{"on":"params","cls":"accept","next":12,"err":null,"act":null,"down":false,"bracket":false},{"on":"close","cls":"accept","next":17,"err":null,"act":null,"down":false,"bracket":false},{"on":"ping","cls":"self","next":11,"err":null,"act":"heartbeat","down":false,"bracket":false},{"on":"stat","cls":"self","next":11,"err":null,"act":null,"down":false,"bracket":false},{"on":"mux_open","cls":"self","next":11,"err":null,"act":null,"down":false,"bracket":false},{"on":"flag_req","cls":"err","next":11,"err":"RESYNC","act":null,"down":false,"bracket":false},{"on":"write","cls":"err","next":11,"err":"CHANNEL","act":null,"down":false,"bracket":false},{"on":"auth","cls":"err","next":11,"err":"CREDIT","act":null,"down":false,"bracket":false}]},{"id":12,"name":"MODE6","kind":"mode","timeout_ms":0,"timeout_edge":null,"edges":[{"on":"write","cls":"self","next":12,"err":null,"act":"kv_set","down":false,"bracket":false},{"on":"params","cls":"accept","next":13,"err":null,"act":null,"down":false,"bracket":false},{"on":"close","cls":"accept","next":17,"err":null,"act":null,"down":false,"bracket":false},{"on":"ping","cls":"self","next":12,"err":null,"act":"heartbeat","down":false,"bracket":false},{"on":"stat","cls":"self","next":12,"err":null,"act":null,"down":false,"bracket":false},{"on":"mux_open","cls":"self","next":12,"err":null,"act":null,"down":false,"bracket":false},{"on":"read","cls":"err","next":12,"err":"CHANNEL","act":null,"down":false,"bracket":false},{"on":"handshake_init","cls":"err","next":12,"err":"STATE","act":null,"down":false,"bracket":false},{"on":"flag_req","cls":"err","next":12,"err":"STATE","act":null,"down":false,"bracket":false}]},{"id":13,"name":"MODE7","kind":"mode","timeout_ms":0,"timeout_edge":null,"edges":[{"on":"read","cls":"self","next":13,"err":null,"act":"kv_get","down":false,"bracket":false},{"on":"flag_req","cls":"accept","next":14,"err":null,"act":"token_check","down":false,"bracket":false},{"on":"ping","cls":"self","next":13,"err":null,"act":"heartbeat","down":false,"bracket":false},{"on":"stat","cls":"self","next":13,"err":null,"act":null,"down":false,"bracket":false},{"on":"mux_open","cls":"self","next":13,"err":null,"act":null,"down":false,"bracket":false},{"on":"params","cls":"err","next":13,"err":"REAUTH","act":null,"down":false,"bracket":false},{"on":"close","cls":"err","next":13,"err":"AUTH","act":null,"down":false,"bracket":false},{"on":"auth","cls":"err","next":13,"err":"AUTH","act":null,"down":false,"bracket":false}]},{"id":14,"name":"FLAGPORT","kind":"flag","timeout_ms":0,"timeout_edge":null,"edges":[{"on":"close","cls":"accept","next":17,"err":null,"act":null,"down":false,"bracket":false},{"on":"ping","cls":"err","next":14,"err":"TOKEN","act":null,"down":false,"bracket":false},{"on":"stat","cls":"err","next":14,"err":"STATE","act":null,"down":false,"bracket":false},{"on":"compute","cls":"err","next":14,"err":"TOKEN","act":null,"down":false,"bracket":false}]},{"id":15,"name":"E_RETRY","kind":"error","timeout_ms":0,"timeout_edge":null,"edges":[{"on":"params","cls":"accept","next":2,"err":null,"act":"resend","down":false,"bracket":false}]},{"id":16,"name":"E_RESYNC","kind":"error","timeout_ms":0,"timeout_edge":null,"edges":[{"on":"handshake_init","cls":"accept","next":0,"err":null,"act":"reladder","down":false,"bracket":false}]},{"id":17,"name":"CLOSED","kind":"terminal","timeout_ms":0,"timeout_edge":null,"edges":[]}]}}'

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
#   Challenge: samba-4.24.6-fileport

SCORING_CONFIG=(
    "FSM Coverage|100|score_coverage|fsm_coverage"
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

# Confine an agent-supplied DIRECTORY (extracted trees / roots): must be a relative path, resolve inside agent_output, exist, and the entry itself must not be a symlink (a symlinked root would walk the oracle tree for free).
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
    symlink (a symlinked root would walk the oracle tree for free).
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


_DROP_FAIL_NOTED = False


def drop_fail_closed():
    """True when the bash core flagged baseline #3's hard case: a ROOT
    verifier with no usable privilege drop (VER_DROP_OK=0). Every
    agent-code execution must then be REFUSED -- the denied-observable
    failed-run shape every caller already scores as 0 -- never run as
    root. Non-root dev verifiers never set the flag (their run-as-is is
    the documented behavior)."""
    global _DROP_FAIL_NOTED
    if os.environ.get("VER_DROP_OK", "1") == "1":
        return False
    if not _DROP_FAIL_NOTED:
        _DROP_FAIL_NOTED = True
        print("✗ fail-closed: privilege drop unavailable on a root verifier; "
              "agent-code runs are refused and score 0", file=sys.stderr)
    return True


def run_confined(argv, trace_path=None, timeout=60, strace_set=None, xx=False,
                 stdin_bytes=None):
    """Run agent/analyzed code under the unified privilege drop, optionally
    strace-wrapped so the caller can apply the exec gate and match syscall
    observables. argv MUST already be confined (confined_own_file / the
    verifier's own target binary). Returns (proc_or_None, stdout+stderr,
    trace_text); proc is None on timeout OR spawn failure OR the baseline #3
    fail-closed refusal -- deliberately indistinguishable, since all three
    deny every observable symptom (the caller labels them "timeout"/"failed"
    alike). With trace_path the tracer runs as
    the verifier and only the target is dropped (the trace file is
    verifier-written). xx=True hex-escapes every string (decode with _dehex
    before matching). stdin_bytes feeds the process (trigger-class inputs);
    capture is binary and decoded with errors='replace' so byte-exact
    stdin/stdout round-trips survive."""
    if drop_fail_closed():
        return None, "", ""
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
# FSM COVERAGE (the single scorer, 100)
# ------------------------------------------------------------------------------
# The score is the DIALOG-GRAPH coverage the submitted client demonstrated
# against the oracle, over the observation plan:
#
#   3 clean runs + 1 diagnostic run + the level-applicable fault runs
#
# Every run gets a FRESH oracle (fresh nonce, fresh per-run log secret)
# and is observed under strace; a run that fails a gate contributes
# NOTHING (its log is excluded) instead of zeroing anything else.
#
# Items and weights (derived from the GT graph's cls/kind, never stored
# in the binary):
#   success edge (accept / self / timeout)      2.0
#   value-gated edge (pass side + fail side)    3.0   (0.5 + 0.5)
#   recovery edge (an error state's way back)   1.5
#   declared error edge (probeable wrongness)   0.5
#   success point (a working state entered)     1.5
#   error point (an error state entered)        0.25
#
# score = sum(weight x ratio) / sum(weight) x 100, each item counted ONCE
# across the whole plan (the union of every valid run's evidence).
#
# Gates G1-G5 are PREREQUISITES with targeted voiding (never a global
# zero from an unrelated stage):
#   G1 submission contract (path jail, size, exec bit)  -> voids all runs
#   G2 fail-closed privilege drop                       -> voids all runs
#   G3 exec/wrapper gate (per run, strace)              -> voids that run
#   G4 connect witness (per run, strace)                -> voids that run
#   G5 milestone-line integrity (per-run secret prefix) -> inherent: the
#      scorer only parses lines carrying THIS run's secret
# ------------------------------------------------------------------------------

score_coverage() {
    local max=100
    local client_real
    client_real=$(check_client) || { echo "0"; echo "$client_real"; return; }
    if [ "$VER_DROP_OK" -ne 1 ]; then
        echo "0"
        echo "G2 fail-closed: privilege drop unavailable on a root verifier -- analyzed binaries must never run as root"
        return
    fi

    python3 - "$ORACLE_BIN" "$client_real" "$GT_CONFIG" "$RUN_DIR" "$max" <<'PYSCORER'
import json, os, random, re, shlex, subprocess, sys, time

ORACLE, CLIENT, GT, RUN_DIR, MAX = (sys.argv[1], sys.argv[2], sys.argv[3],
                                    sys.argv[4], float(sys.argv[5]))
gt = json.loads(GT)
L = gt.get("levels", {})
fsm = gt.get("fsm") or {}
# the heaviest graphs (16+ FSM states, the asterisk-class S7) truncate
# mid-plan inside the base deep clock under strace; their deep budget
# doubles. A measurement-budget call, the expected maximum is the
# structural one either way -- an earlier comment promised this and
# the code never did it, and the S7 graph's tail starved on it.
heavy_graph = len(fsm.get("states") or []) >= 16
rnd = random.Random(int.from_bytes(os.urandom(8), "big"))
drop = shlex.split(os.environ.get("VERIFIER_RUNAS", "") or "")

if not fsm.get("states"):
    print("0"); print("GT config carries no fsm graph (task assembly defect)")
    sys.exit(0)

# ---- the item table, derived from cls/kind -------------------------------
W_EDGE_OK, W_EDGE_VAL, W_EDGE_REC, W_EDGE_ERR = 2.0, 3.0, 1.5, 0.5
W_POINT_OK, W_POINT_ERR = 1.5, 0.25

role_op = {}
for msg in gt.get("messages", []):
    try:
        role_op[msg.get("role") or msg.get("name", "").upper()] = \
            int(str(msg.get("opcode", "")), 16)
    except Exception:
        pass

items = []
states = fsm["states"]
# an error state whose ONLY incoming edges are S5 forced-reauth carriers
# (the down-flagged REAUTH err edges) is structurally unreachable: the
# carrier is answered by the once-per-connection interception and the
# dialog HOLDS -- the declared transition never takes. Its recovery
# edges and error-point credit are excluded from the expected maximum
_incoming = {}
for st in states:
    for e in st.get("edges", []):
        _incoming.setdefault(e["next"], []).append(e)
def _orphaned(st):
    if st["kind"] != "error":
        return False
    inc = _incoming.get(st["id"], [])
    return len(inc) > 0 and all(
        e.get("cls") == "err" and e.get("err") == "REAUTH"
        and e.get("down") for e in inc)
for st in states:
    sid, kind = st["id"], st["kind"]
    if _orphaned(st):
        continue
    for e in st.get("edges", []):
        opv = role_op.get(e["on"])
        if e["cls"] == "err":
            items.append(("err", ("e_err", sid, opv), 0.5,
                          "%s:%s(err)" % (st["name"], e["on"])))
        elif e["cls"] == "value":
            items.append(("val", ("e_val", sid, opv, e.get("next")), 3.0,
                          "%s:%s(value)" % (st["name"], e["on"])))
        elif kind == "error":
            items.append(("rec", ("e_ok", sid, opv, e["next"]), 1.5,
                          "%s:%s(recovery)" % (st["name"], e["on"])))
        else:
            items.append(("ok", ("e_ok", sid, opv, e["next"]), 2.0,
                          "%s:%s" % (st["name"], e["on"])))
    if st.get("timeout_edge") is not None:
        items.append(("ok", ("e_ok", sid, -1, st["timeout_edge"]), 2.0,
                      "%s:idle-timeout" % st["name"]))
    if kind == "error":
        items.append(("pt_err", ("pt", sid), 0.25,
                      "%s(error state)" % st["name"]))
    else:
        items.append(("pt_ok", ("pt", sid), 1.5, st["name"]))

# ---- the observation plan -------------------------------------------------
FAULTS = [
    ("chaffburst",   L.get("X", 0) >= 2), ("corruptreply", L.get("F", 0) >= 3),
    ("minfrag",      L.get("X", 0) >= 3), ("escapedense",  L.get("F", 0) == 5),
    ("noise",        L.get("F", 0) >= 3), ("resync",       L.get("S", 0) >= 3),
    ("delay",        True),                ("drip",         True),
    ("errhello",     L.get("S", 0) >= 1),  ("parallel",     True),
    ("badlen",       L.get("F", 0) >= 3),  ("drop",         L.get("S", 0) >= 1),
    ("dupreply",     True),
    ("errstate",     L.get("S", 0) >= 6),  ("errauth",     L.get("S", 0) >= 5),
    ("errtoken",     L.get("S", 0) >= 3),  ("errcredit",   L.get("L", 0) >= 3),
    ("errchannel",   L.get("L", 0) >= 2),  ("errunknown",  L.get("S", 0) >= 3),
]
plan = ([("clean", None)] * 3) + [("diagnostic", None)] + \
       [(n, (None if n == "parallel" else n))
        for n, ok in FAULTS if ok]
rnd.shuffle(plan[4:])

seen_runs = [0]

def one_run(tag, chaos):
    ms = os.path.join(RUN_DIR, "ms-%s-%d" % (tag, os.getpid() * 1000
                                                        + len(notes)))
    sec = "s" + os.urandom(8).hex()
    env = dict(os.environ)
    env["PROTO_MILESTONE_LOG"] = ms
    env["PROTO_MILESTONE_SECRET"] = sec
    # the deep clean runs pre-run the walker's timeout pass (the idle
    # deadlines are otherwise unreachable organic timing on a heavy
    # graph); short fault runs keep the default pass-last behavior.
    # The knob rides the CLIENT's environment (the walker reads it);
    # the oracle's env carries only the milestone log and secret
    cenv = dict(os.environ)
    if chaos is None and seen_runs[0] < 2:
        cenv["PROTO_TMO_PASS"] = "1"
    cmd = [ORACLE, "0"] + (["--chaos", chaos] if chaos else [])
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, env=env)
    line = proc.stdout.readline().decode(errors="replace")
    m = re.search(r"LISTENING (\S+)", line)
    if not m:
        proc.kill(); return None, None, "oracle failed to start"
    port = m.group(1)
    strace_log = ms.replace("ms-", "st-")
    ccmd = [CLIENT, "127.0.0.1", port]
    if tag == "parallel":
        ccmd += ["--parallel", "2"]
    try:
        # the first TWO clean runs carry the deep-walker budget: a
        # heavy graph's tail edge is timing-dependent (which conn ate
        # a -2), so a second full-plan pass is the union's backstop
        deep = 2400 if heavy_graph else 1200
        clock = str(deep) if chaos is None and seen_runs[0] < 2 else (
            "60" if chaos is None else "45")
        subprocess.run(["timeout", clock, "strace", "-f", "-s", "4096",
                        "-xx", "-e", "trace=%network,execve,execveat",
                        "-o", strace_log] + drop + ccmd,
                       capture_output=True, env=cenv,
                           timeout=(deep + 10 if (chaos is None
                                                  and seen_runs[0] < 2)
                                    else 50))
    except subprocess.TimeoutExpired:
        pass
    time.sleep(0.2)
    proc.kill(); proc.wait()
    tlog = ""
    try:
        tlog = open(strace_log, errors="replace").read()
    except OSError:
        return None, None, "G3 voided: trace missing"
    if not tlog:
        return None, None, "G3 voided: trace empty"
    sys.path.insert(0, "/tmp")
    import verifier_core as vc
    if vc.exec_gate(tlog):        # True = a verifier-side tree was exec'd
        return None, None, "G3 voided: executed a verifier-side tree"
    port_x = "".join("\\x%02x" % b for b in port.encode())
    if ("sin_port=htons(%s)" % port) not in tlog \
       and ('sun_path="%s"' % port) not in tlog \
       and ('sun_path="%s"' % port_x) not in tlog:
        return None, None, "G4 voided: never connected to the oracle"
    if chaos is None:
        seen_runs[0] += 1     # clean runs consumed a deep budget slot
    ok, fail, pts = set(), set(), set()
    try:
        for ln in open(ms, errors="replace"):
            mm = re.match(r"^%s conn=\d+ (.*)$" % re.escape(sec), ln)
            if not mm:
                continue
            b = mm.group(1)
            em = re.match(r"^edge on=(-?\d+) from=(\d+) to=(\d+) rc=(\d)", b)
            if em:
                opv, f_, t_, rc_ = (int(em.group(1)), int(em.group(2)),
                                    int(em.group(3)), int(em.group(4)))
                pts.add(f_); pts.add(t_)
                if rc_ == 1:
                    ok.add((f_, opv, t_))
                else:
                    fail.add((f_, opv, t_))
    except OSError:
        return None, None, "milestone log unreadable"
    return ok, fail, pts

evidence_ok, evidence_fail, seen_pts = set(), set(), set()
notes, valid_runs = [], 0
for tag, chaos in plan:               # sequential: one oracle, one client,
    try:                              # one trace at a time -- no shared
        ok, fail, pts = one_run(tag, chaos)
    except Exception as ex:           # scratch names, no thread state
        notes.append("x %s: run crashed (%r)" % (tag, ex))
        continue
    if ok is None:
        notes.append("x %s: %s" % (tag, pts))
        continue
    valid_runs += 1
    evidence_ok |= ok
    evidence_fail |= fail
    seen_pts |= pts

if valid_runs == 0:
    print("0")
    for n in notes[:8]:
        print(n)
    sys.exit(0)

# ---- grade the union ------------------------------------------------------
val_alt = {}
val_probeable = {}
for st in states:
    for e in st.get("edges", []):
        if e["cls"] == "value":
            opv = role_op.get(e["on"])
            val_alt[(st["id"], opv)] = e.get("alt")
            # a gate whose field does not exist in the op's schema is
            # vacuously true: nothing can violate it, so the fail side
            # is structural, not behavioral (the walker's builder and
            # the server's matcher resolve the same slot)
            cond = e.get("cond") or {}
            sem = cond.get("sem")
            sems = set()
            for msg in gt.get("messages") or []:
                mv = msg.get("opcode")
                if isinstance(mv, str):
                    mv = int(mv, 16)
                if mv == opv:
                    sems.update(f.get("sem") for f in
                                (msg.get("fields") or []))
            val_probeable[(st["id"], opv)] = sem in sems

earned = denom = 0.0
cats = {}
for kind, key, w, label in items:
    denom += w
    r = 0.0
    if kind == "err":
        r = 1.0 if (key[1], key[2]) in {(a, b) for a, b, _ in evidence_fail} else 0.0
    elif kind == "val":
        hit_pass = (key[1], key[2], key[3]) in evidence_ok
        alt = val_alt.get((key[1], key[2]))
        if val_probeable.get((key[1], key[2]), True):
            hit_fail = (alt is not None
                        and (key[1], key[2], alt) in evidence_fail)
        else:
            hit_fail = True   # vacuous gate: fail side is structural
        r = (0.5 if hit_pass else 0.0) + (0.5 if hit_fail else 0.0)
    elif kind in ("ok", "rec"):
        r = 1.0 if (key[1], key[2], key[3]) in evidence_ok else 0.0
    else:
        r = 1.0 if key[1] in seen_pts else 0.0
    earned += w * r
    c = cats.setdefault(kind, [0, 0.0, 0.0])
    c[0] += 1; c[1] += w; c[2] += w * r

score = round(earned / denom * MAX, 2) if denom else 0.0
print(score)
for kind, key, w, label in items:
    # name the zero-credit items: a GT below max must say WHICH graph
    # piece stayed dark (the walk's own coverage diagnosis)
    r = None
    if kind == "err":
        r = 1.0 if (key[1], key[2]) in {(a, b) for a, b, _ in
                                        evidence_fail} else 0.0
    elif kind == "val":
        hit_pass = (key[1], key[2], key[3]) in evidence_ok
        alt = val_alt.get((key[1], key[2]))
        if val_probeable.get((key[1], key[2]), True):
            hit_fail = (alt is not None
                        and (key[1], key[2], alt) in evidence_fail)
        else:
            hit_fail = True
        r = (0.5 if hit_pass else 0.0) + (0.5 if hit_fail else 0.0)
    elif kind in ("ok", "rec"):
        r = 1.0 if (key[1], key[2], key[3]) in evidence_ok else 0.0
    else:
        r = 1.0 if key[1] in seen_pts else 0.0
    if r == 0.0 or (kind == "val" and r < 1.0):
        notes.append("MISSING %s (credit %.1f/%.1f)" % (label, r * w, w))
print("plan: %d valid runs (%d voided by gates)" % (valid_runs,
                                                    len(plan) - valid_runs))
NAME = {"ok": "success edges", "val": "value-gated edges",
        "rec": "recovery edges", "err": "error edges",
        "pt_ok": "success points", "pt_err": "error points"}
for k in ("ok", "val", "rec", "err", "pt_ok", "pt_err"):
    if k in cats:
        n, wmax, wgot = cats[k]
        print("  %-18s %2d items  %4.1f / %4.1f" % (NAME[k], n, wgot, wmax))
for n in notes[:8]:
    print(n)
PYSCORER
}

# ==============================================================================
# MAIN
# ==============================================================================

echo ""
echo "==============================================================================="
echo "PROTOCOL RECONSTRUCTION VERIFICATION (pure dynamic)"
echo "==============================================================================="
echo "Challenge: samba-4.24.6-fileport"
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

