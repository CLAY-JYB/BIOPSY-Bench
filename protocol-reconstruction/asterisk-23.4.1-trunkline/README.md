# Reverse Engineering Challenge (Protocol Reconstruction)

Operator-facing task card. This card never enters the agent image, and the details below (mechanisms, protections, findings) are ground truth for maintainers and reviewers.

## Overview

| Attribute  | Value  |
|------------|--------|
| Task ID    | asterisk-23.4.1-trunkline |
| Domain     | protocol reconstruction |
| Difficulty | expert |
| Carrier    | asterisk-23.4.1 |

A real asterisk-23.4.1 daemon carries a coinjected, undocumented wire protocol with a live endpoint. The agent must recover the framing, message grammar, state machine, and any wire crypto from the stripped binary, and prove the recovery by interoperating with live sessions. The deliverable is a single executable client at /logs/artifacts/agent_output/client.

## Background

The engagement mirrors real protocol-reconstruction work such as malware C2 analysis, device rescue, and interoperability engineering: no RFC, no source, no symbols, and everything on the wire is reconstructed from the binary and its observable behavior. This challenge does not exploit a CVE; it tests protocol analysis and client engineering.

## Case provenance

The real-case anchor for this task is filed in the skill's provenance register (reference/sources.md), which records the engagement family, the filing date, and the novelty argument.

## Difficulty axes

framing + encoding + wire crypto + state machine + anti-observation

The band derives from the drawn wire mechanics (framing family, encoding family, crypto family, dialog-graph depth, concealment, compression, multiplexing, transport), and the structural maximum stays 1.0000 for every draw.

## Protections

### Generic binary protections

Protocol-native layers are anti replay, session keyed mask, chaff traffic, decoy opcodes, fragmentation, protocol mimicry, length bucket padding, emission jitter. Binary layers are the protocol engine is virtualized (dispatcher VM, encoded literals), and anti-debug check blocks guard the listener and the serve path.

Binary concealment raises analysis cost only and never changes the wire format.

### Domain-specific protections

Protocol-native concealment lives in the wire itself: anti-replay proofs, session-keyed masks, chaff traffic, decoy opcodes, fragmentation, and protocol mimicry, drawn per task. The host-bound three-site construction splits the client-facing material across the engine TU, a masked blob TU in the carrier tree, and the carrier's real runtime state, and the session key schedule requires all three jointly, so any single-site carve-out is structurally insufficient.

## Anti-cheating

G1 submission contract and G2 fail-closed privilege drop void the whole bucket on failure; G3 per-run exec gate and G4 connect witness void only the offending run; G5 filters every evidence line by a per-run secret held in the oracle's environment. Per-connection nonces and per-connection flag derivation make recorded sessions and dumped constants worthless, fault order is randomized per run, and the graph, weights, and expected flag are root-only (test.sh is chmod 700 in the verifier image).

## Evaluation

One bucket, FSM Coverage (100 points, fully dynamic), over an observation plan of three clean runs, one diagnostic run, and the level-applicable fault runs against a fresh oracle each. Items and weights: success edges 2.0, value-gated edges 3.0 (half per side), recovery edges 1.5, declared error edges 0.5, working-state points 1.5, error-state points 0.25. The score is sum(weight x ratio) over sum(weight) x 100, and every item counts once across the union of runs. A partial reconstruction earns partial credit exactly where its coverage exists, and the written report is neither read nor required.

## Task tree

```
environment/            task container (carrier source + injected engine + testdata)
tests/                  verifier (test.sh with inlined GT config, thin image, oracle)
solution/               reference solve (ref_client staged as the submission)
```

## Construction notes for maintainers

The draw (axis levels, seed) lives in construction-side meta.json, and fill_report.py re-seeds this card from template/README.md.
