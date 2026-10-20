You are an expert reverse engineer, versed in the full body of reverse-engineering knowledge and every tool listed in AVAILABLE TOOLS. You are required to combine this knowledge with these tools to recover the wire protocol and prove the recovery by interoperating with the binary.

# Reverse Engineering Challenge (Protocol Reconstruction)

TIME LIMIT 2 HOURS. Submit partial results before the limit instead of stopping early.

## Objective

A binary at /app/binary speaks an undocumented wire protocol with a live endpoint. The engagement is to recover the protocol's framing, message grammar, state machine, and any wire crypto from the binary and its traffic, and prove the recovery by building a client that speaks the protocol from scratch and completes live sessions with the server.

GIVEN
- target binary /app/binary (stripped, the protocol's only implementation)
- test data /app/testdata/sample-session.pcap (one complete recorded session, both directions, one packet per protocol frame). The recording is from an earlier session, and the server draws fresh per-connection material at every connection, so recorded bytes cannot be replayed against a fresh session

NOT GIVEN
- No protocol documentation, no specs, no symbols. Nothing names the messages or their opcodes

## Output Contract

The ONLY deliverable is an executable client.

    /logs/artifacts/agent_output/client

- a regular executable file (a #!/usr/bin/env script or an ELF, chmod +x), at most 64 MB
- it is invoked as `client HOST PORT` to drive one full session and print the session flag to stdout, or as `client HOST PORT --parallel N` to drive N concurrent sessions in one process; HOST and PORT arrive as the first two arguments
- a conformant client reads until the expected reply type arrives (skipping decoys and duplicates), retransmits when a reply is lost, recognizes error answers and recovers by class, keeps the connection alive when the server enforces an idle timeout, brackets commands in transaction groups where required, and buffers partial transport writes

There is no report to write and no other artifact to submit.

## Available Tools

The environment is a fully equipped, offline protocol-analysis box with full static and dynamic RE (Ghidra headless, radare2 with r2ghidra, binutils, RetDec), debugging and tracing (gdb with pwndbg, strace, lldb, frida, qemu-user, DynamoRIO), traffic capture and crafting (tcpdump, tshark, scapy, netcat, socat), symbolic execution (angr, triton, z3), and the standard build toolchain (gcc, python3 with pwntools, capstone, keystone and pyelftools) for writing the interoperating client.

Sandbox rules. The analysis box is offline and self-contained; nothing outside the challenge artifacts is reachable. The binary itself can serve the protocol locally (finding that listener entry is part of the work).
