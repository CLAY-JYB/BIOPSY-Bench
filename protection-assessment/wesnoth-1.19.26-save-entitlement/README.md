# Reverse Engineering Challenge: Protection Assessment

## Overview

| Attribute           | Value                |
|---------------------|----------------------|
| **Difficulty**      | hard                 |
| **Challenge ID**    | wesnoth-1.19.26-save-entitlement |
| **Focus**           | virtualized save-data entitlement protection |
| **Protection Type** | multi-layer (VM-obfuscated, anti-debug-hardened, packed) |

**Objective:** locate the hidden license-key verification routine in `/app/binary`, defeat the protections around it (which may be interdependent), recover the full verification logic end-to-end, and derive a key that validates, per the contract in `instruction.md`. A correct key makes the binary print `flag{...}` and exit 0; a wrong key prints an error message and exits non-zero.

## Background

The binary implements commercial-style software protection over a license-checking routine. This mirrors real protection-assessment practice:
- license enforcement and IP-protection reviews, unpacking and deprotection engagements, red-team binary analysis
- the challenge tests binary analysis and anti-protection bypass, not vulnerability discovery: no CVE or OSV exploit is involved
- rationale and citations in the skill repository: `reference/design.md`, `reference/sources.md`

## Case provenance

This challenge instantiates a filed construction case. The filing:
- is registered in the skill repository's provenance register (`reference/sources.md`)
- pins the carrier program sha256-verified in the skill's `codebase/source.yaml`
- clears the two-distribution standard: in-distribution with real deployments while novel as a combination, with the novelty route recorded in the register row

## Protection difficulty axes

The challenge composes independent protection axes; this task's values are recorded on this card as `P#D#O#I#` (+ the A level):

| Axis  | Covers                                                                                                        |
|-------|---------------------------------------------------------------------------------------------------------------|
| **A** | verification algorithm: tutorial (CRC32) / easy (RC4) / medium (AES) / hard (RSA-512) / expert (RSA-2048)     |
| **P** | packing: none / UPX / UPX+stealth / hARMless / PageGuard / multi-layer                                        |
| **D** | anti-debug: none / basic / standard / advanced (multi-probe incl. frida detection + self-ptrace DebugBlocker) |
| **O** | obfuscation: none / simple / medium / complex / VM virtualization / maximum                                   |
| **I** | interdependency: linear / simple circular / advanced circular / extreme circular guards                       |

**This task**: `A3 P2 D3 O3 I3` — medium algorithm (A3), stealth UPX packing (P2), advanced anti-debug (D3), real xollvm obfuscation (O3), all-to-all interlock with anti-debug↔checksum binding (I3); difficulty profile **expert**.

Concretely: the activation stage and the save-progress gate are compiled through the xollvm plugin with virtualization (VM bytecode dispatcher) plus mixed-boolean-arithmetic rewriting, constant/string encryption and anti-decompiler trampolines; the anti-debug probes (D3) sit inside the virtualized stage immediately ahead of the key check; after compilation the binary is stripped, UPX-packed at maximum compression, and stealth-processed so `upx -d` refuses the artifact.

## Protection architecture

The binary implements multi-layer (VM-obfuscated, anti-debug-hardened, packed) protection:

1. **Startup activation** — `main()` reads the entitlement key from stdin and enters the save-data license activation stage before any game subsystem initializes.
2. **Virtualized stage (O5)** — the activation stage and the key check execute as VM bytecode behind a switch-based dispatcher (4 virtual registers, 64-bit, 44 opcodes); the D3 anti-debug probes (TracerPid, parent process, timing, INT3 breakpoints, /proc maps, frida) run inside the same virtualized stage, immediately ahead of the key check.
3. **Second virtualized gate** — a second license gate inside the achievements subsystem guards sub-achievement progress persistence (the licensed save format).
4. **Packing (P2)** — after compilation the binary is stripped, UPX-packed at maximum compression, and stealth-processed (magic/p_info/section-name defeat) so `upx -d` refuses the artifact.

## Verification algorithm

The verification routine is one of several paradigms: **partial-key** (per-group transforms + checksum signature), **stream-cipher** (RC4 / TEA / XTEA / LFSR keystream), **name-serial hash** (custom hash + checksum), **license state-machine** (multi-stage checkpoint validation via ARX / polynomial-hash bit-transforms), or **weak public-key signature** (Wiener-weak RSA: the private exponent falls to continued fractions). The license key is a transport encoding (Base64 / Base32 / Base62 / Base58 / Hex / URL / ASCII85) of the variant's verification blob (16-440 bytes depending on variant); a valid key prints `flag{XXXXX-XXXXX-XXXXX-XXXXX-XXXXX}`.

**This task**: license state-machine — the verification chain validates a hex-encoded 72-byte license blob in three staged checkpoints: (1) transport format, (2) embedded magic, (3) a Salsa20/BLAKE2b-derived authentication block compared against an expected MAC. The flag is derived at runtime from the verified blob, so a stubbed gate cannot reproduce it.

## Intended solve path

- reconnoiter the binary: type, architecture, entropy, which protections are present
- map the protection dependencies before removing anything (protections may protect one another; there is no fixed peel order)
- defeat the protections in the order the dependency structure allows, saving defeat-demonstrating binaries along the way
- locate the verification routine in the defeated binary and reconstruct the full validation chain, including chained stages
- derive a key that satisfies the recovered logic and confirm `flag{...}` plus exit 0
- the key and binaries per `instruction.md`

The reference solution (`solution/solve.sh`) walks exactly this path; the skill's `reference/design.md` documents the design rationale.

## Evaluation

| Category             | Points | Type    | Action                                            |
|----------------------|--------|---------|---------------------------------------------------|
| License verification | 50     | dynamic | the derived key actually validates against the binary |
| Property validation  | 50     | dynamic | the defeat binaries genuinely carry the defeats  |

- Scoring
  - License verification (50, dynamic):
    - the submitted key is fed to the binary with the privilege drop; full marks require `flag{...}` and exit 0 together
    - a rejected key earns partial credit for how deep it drives the verification chain in the oracle, capped at 20
    - the wrong-key control runs first: a submission whose wrong-key behavior no longer matches the original scores nothing
  - Property validation (50, dynamic):
    - order- and naming-free, matching the premise that protections have no fixed peel order
    - any artifact in `binaries/` passing the full gate chain (real ELF with plausible code volume, not the original, still rejects wrong keys, reproduces the oracle flag) can earn any of the configured properties: unpack (entropy within 20% of the oracle), bypass (prints the flag with the GT key under gdb, lldb, strace, ltrace, valgrind), deobf (instruction count, branch density, indirect branches near the oracle's)
    - score scales with the distinct properties covered out of the configured set
- Notes
  - a correct key alone, with no defeat binaries, caps at 50/100
  - full marks require the key and the defeat evidence

`tests/test.sh` is the scoring authority.

## Task tree

The task source directory:

```
README.md                      # this task card
instruction.md                 # the agent-facing challenge (static by design)
task.toml                      # harness metadata (id, difficulty, network policy)
environment/                   # build context: the carrier source, protection build, the challenge binary
tests/                         # the verifier (test.sh, ground truth, defeat properties)
solution/                      # the reference solve + ground truth
```

The challenge container at runtime:

```
/app/
└── binary                     # the protected challenge binary (read-only)

/logs/artifacts/agent_output/  # the agent's writable deliverables (contract in instruction.md)
├── input.txt
└── binaries/                  # defeat-demonstrating binaries, any names
```

The tool environment is disclosed to the agent in `instruction.md`; the installed inventory lives in `environment/Dockerfile` and, skill-side, in `reference/tools.md`.
