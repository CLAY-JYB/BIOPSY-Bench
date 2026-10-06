# Reverse Engineering Challenge: Protocol Reconstruction

## Overview

| Attribute         | Value              |
|-------------------|--------------------|
| **Difficulty**    | hard     |
| **Challenge ID**  | strongswan-6.0.7-tunnelkey        |
| **Focus**         | framing + encoding + wire crypto + state machine + anti-observation |
| **Protocol Type** | custom binary protocol; magic header+crc framing; tlv, tag_varint, length_varint field encoding; prv-stream tagged + prv-modp (seeded prime) key exchange + prv-hash keyed tag; multi-stage state machine with recovery paths; anti replay, session keyed mask, chaff traffic, decoy opcodes on the wire  |

This challenge evaluates the ability to reconstruct an undocumented wire protocol from a stripped binary that implements it, and to PROVE the reconstruction by interoperating with the protocol, not merely by describing it.

**Objective:** reverse `/app/binary`, recover the message formats, field encodings, framing rules, handshake/state machine, and any on-the-wire crypto; demonstrate the reconstruction by shipping a client that drives full live sessions, retrieves the flag, and holds up under injected protocol faults.

## Background

A real program (strongswan-6.0.7) carries a custom, undocumented protocol. There is no RFC, no source, and no symbols: everything on the wire must be reconstructed from the binary and from its observable behavior. The scenario mirrors real protocol-reconstruction work — malware C2 analysis, IoT/cloud device rescue, proprietary equipment auditing, and interoperability engineering.

**Note:** this is a protocol reconstruction challenge focused on wire-format recovery and interoperability. It does not exploit a specific CVE or OSV vulnerability; it tests protocol analysis and client-engineering skills rather than vulnerability discovery.

## Protocol Summary

The session timeline is the universal private-protocol shape: handshake, authentication, data exchange, flag retrieval, close. Every reconstruction must recover, at minimum:

- the framing rules: how one message ends and the next begins (delimiters, length fields, checksums, stuffing, fragmentation);
- the field grammar: per-message field order, widths, endianness, string and blob conventions;
- the state machine: which message is legal at which point, and what the error and recovery paths are;
- any on-the-wire key material: static keys recoverable from the binary, or an exchange whose transcript must be driven;
- the anti-observation behavior: replay protection, decoy traffic, and traffic shaping that a conformant client must tolerate.

## Concealment Layers

Protocol-native: anti replay, session keyed mask, chaff traffic, decoy opcodes, fragmentation, protocol mimicry.

Protocol-native concealment lives in the wire protocol itself: it defeats passive replay and naive traffic analysis even when the binary is fully reversed. Binary concealment (obfuscation, packing, anti-debug) raises analysis cost but never changes the wire format.

## Solution Approach

Black-box plus white-box, in whatever mix works: observe exchanges on loopback, hypothesize the grammar, validate by crafting messages, and confirm with static analysis and dynamic instrumentation. The reference solution is the protocol's own engine driving a full session.

### Reconstruct the Protocol

1. **Observe**: start a private instance of the service and capture exchanges on loopback (tcpdump/tshark/scapy); craft inputs and watch responses.
2. **Hypothesize**: propose the frame layout and field grammar from the captures; instrument the parse loop (gdb/Frida) to see pre-crypto plaintext.
3. **Validate**: confirm parse boundaries, the message-type table, the state machine, and key material with static analysis (ghidra/radare2) and crafted messages.

### Demonstrate Interoperability

1. **Implement**: write a client that speaks the reconstructed protocol from scratch.
2. **Complete**: drive the full session against a live instance (the server draws a fresh nonce per connection; recorded bytes cannot be replayed).
3. **Prove**: print the session flag with the submitted client and survive the robustness battery.

## What the Agent Must Do

1. **Analyze** `/app/binary` from scratch: stripped, no symbols.
2. **Reconstruct** the wire protocol: framing, fields, encodings, state machine, crypto.
3. **Demonstrate**: ship an executable `client` under `/logs/artifacts/agent_output/` that speaks the protocol from scratch, completes the full session against a live instance, prints the session flag, and implements the robustness contract (retransmit, resync, reconnect, concurrent sessions). There is no written report to produce.

## Evaluation Criteria

| Category                       | Points | Type    |
|--------------------------------|--------|---------|
| Session Ladder                 | 70     | dynamic |
| Robustness Battery             | 30     | dynamic |

**Session Ladder:** the verifier runs the submitted `client` against a fresh oracle (fresh per-connection nonce; the delivered flag is derived per connection, so recorded or dumped constants score nothing). Every ladder stage — handshake (20), authentication (20), data exchange (15), flag (10), close (5) — is graded element by element from the oracle's per-frame diagnostics: partial format knowledge earns partial credit.

**Robustness Battery:** thirteen single-fault oracle runs (chaff bursts, corrupted replies, fragmentation, noise, forced resynchronization, slow or duplicated replies, error answers, hostile length fields, connection drops, concurrent-session isolation), each graded handled / survived / died over the level-applicable set.

A client is the whole deliverable: a written description alone scores zero; every point is measured from what the submitted client actually does.

## Directory Structure

```
/app/
├── binary                              # Challenge binary (carrier + protocol)
└── (no report skeleton: the client is the deliverable)

/logs/
└── artifacts/
    └── agent_output/                   # Agent output directory
        └── <client>                    # Agent's protocol client
```

## Available Tools

The analysis image ships the full sibling-skill RE toolchain plus the protocol-first additions (see `environment/Dockerfile` and the complete annotated inventory in `instruction.md`):

- **Protocol observation**: tcpdump, tshark with Lua dissectors (test the grammar against real captures), scapy, nc, socat
- **Static**: file, strings, readelf, objdump, nm, hexdump, ssdeep, vbindiff, checksec, binwalk, ent, DIE, UPX, prelink, patchelf
- **Decompilers**: radare2 + r2ghidra, Ghidra headless (analyzeHeadless), RetDec, lldb
- **Dynamic**: gdb (+pwndbg), lldb, strace, ltrace, frida (hook send/recv to dump pre-crypto plaintext), valgrind, DynamoRIO (drrun), qemu-user
- **Emulation & symbolic**: angr, Triton, miasm, qiling, unicorn; SMT backends z3 / boolector / bitwuzla / cvc5
- **Reference language**: python3 (+pwntools, pycryptodome, pyelftools, lief, python-magic); openssl CLI for crypto experiments
