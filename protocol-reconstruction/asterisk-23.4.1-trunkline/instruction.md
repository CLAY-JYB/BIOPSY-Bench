You are an expert protocol reverse engineer, versed in the full body of reverse-engineering knowledge and every tool listed in AVAILABLE TOOLS. You are required to combine this knowledge with these tools to recover the wire protocol and prove it by interoperating with the binary.

# Reverse Engineering Challenge: Protocol Reconstruction

## Objective

A binary at /app/binary speaks an undocumented wire protocol with a live endpoint. The engagement is to recover the protocol's framing, message grammar, state machine, and any wire crypto from the binary and its traffic, and prove the recovery by building a client that speaks the protocol from scratch and completes live sessions with the oracle server. Which messages exist, how fields are laid out, and what the session must prove are part of the puzzle.

GIVEN
- target binary /app/binary (stripped, the protocol's only implementation)
- test data /app/testdata/sample-session.pcap (one complete recorded session, both directions, one packet per protocol frame, LINKTYPE_USER0 so each packet payload is the raw frame as emitted). The recording is from an earlier session, and the server draws fresh per-connection material at every connection, so these bytes verify observation work but cannot be replayed for score.

NOT GIVEN
- No protocol documentation, no specs, no symbols, no captures of a good session. Nothing names the messages or their opcodes.

## Output Contract, the final product

The ONLY deliverable is an executable client.

```
/logs/artifacts/agent_output/client
```

- it must be an executable file (a `#!/usr/bin/env ...` script or an ELF, chmod +x), at most 64 MB
- the verifier invokes it as

```
client HOST PORT            # drive one full session, print the session flag
client HOST PORT --parallel N   # drive N concurrent sessions in ONE process
```

- HOST and PORT arrive as the first two arguments, and the flag your client retrieves must be printed to stdout
- there is no report to write, because everything scored is measured from what your client actually does against live servers

## Scoring (100 points, all dynamic)

Session Ladder (70), one clean oracle run graded element by element from the server's view of your traffic. Partial knowledge scores, so a handshake attempt with the right magic but a bad checksum earns the magic element, not zero. The ladder follows.
- handshake (20) covers frame boundary, magic, message type, version, length field, checksum and payload structure
- authentication (20) covers message type, field structure, authenticator value and key-exchange shape
- data exchange (15) covers uplink encryption, per-command grammar (write, read, compute), same-key readback and multi-round persistence
- flag (10) covers request grammar, token value, and the flag DELIVERED on stdout, where the flag is derived per connection so a value recorded or dumped from an earlier run never matches
- close (5) covers BYE grammar, acknowledgment delivered and orderly close

Robustness Battery (30), separate oracle runs each with exactly one injected fault, graded handled, survived or died.
- decoy and chaff bursts, corrupted replies (retransmit and recover), minimum-size transport fragments, escape-dense frames, junk bytes between frames, a forced mid-session resynchronization, one slow reply, byte-at-a-time delivery, an error answer to a valid first handshake, concurrent-session isolation (--parallel), hostile length fields, a server that drops the connection mid-session (reconnect with a fresh nonce), and duplicated replies

A conformant client reads until the expected reply type arrives (skipping decoys and duplicates), retransmits when a reply is lost, recognizes error answers (retry at the handshake, redo the ladder in-band mid-session), detects a dropped connection and reconnects, and buffers partial transport writes instead of assuming message boundaries.

## Available Tools

The environment is a fully equipped, offline protocol-analysis box with full static and dynamic RE (Ghidra headless, radare2 with r2ghidra, binutils, RetDec), debugging and tracing (gdb with pwndbg, strace, lldb, frida, qemu-user, dynamorio), traffic capture and crafting (tcpdump, tshark, scapy, netcat, socat), symbolic execution (angr, triton, z3), and the standard build toolchain (gcc, python3 with pwntools, capstone, keystone and pyelftools) for writing the interoperating client. Sandbox rules keep the analysis box offline for the whole engagement, and no network oracle exists during analysis. The binary itself can serve the protocol locally (finding that listener entry is part of the work), and the disclosed fault modes can be applied to a local instance the same way, so a robust client can be developed and hardened against the battery before verification. Budget your time, because the analysis phase is capped at 2 hours of wall clock. A runnable client that drives the session always outscores a perfect analysis that never ships, so deliver before you polish.
