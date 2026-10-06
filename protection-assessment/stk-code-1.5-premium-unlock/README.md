# Reverse Engineering Challenge: Protection Assessment

## Overview

| Attribute           | Value                |
|---------------------|----------------------|
| **Difficulty**      | expert               |
| **Challenge ID**    | stk-code-1.5-premium-unlock |
| **Focus**           | premium-content entitlement protection (story mode, challenges, karts and tracks behind a license key) |
| **Protection Type** | multi-layer (packed, anti-debug-hardened, interlock-guarded) |

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

**This task**: `A4 P3 D3 O3 I3` — hard algorithm (A4), hARMless layered packing (P3), advanced anti-debug (D3), real xollvm obfuscation (O3), all-to-all interlock guard network with anti-debug↔checksum binding (I3); difficulty profile **expert**.

- **Packing (P3)**: hARMless layered encryption (AES-256-ECB + ChaCha20 + RC4) with a polymorphic memfd loader — no section headers, no public unpacker
- **Anti-Debug (D2)**: standard debugger detection (ptrace TRACEME, TracerPid, parent process, gdb fingerprints) anchored ahead of the license activation stage
- **Anti-Tamper (I2)**: interlock guard network — Aucsmith IVK ring + Chang-Atallah overlap edges of CRC32 section checks with a self-keyed poison response; a tampered binary silently corrupts the key so even the valid license is rejected
- **Cryptographic Verification (A4)**: RSA-512 signed entitlement validation

## Protection architecture

The binary implements multi-layer (packed, anti-debug-hardened, interlock-guarded) protection:

1. **Packing layer** — hARMless encrypts every section with three stacked ciphers (RC4 over ChaCha20 over AES-256-ECB) and executes from a memfd; the stub is polymorphic per pack (re-keyed magic, syscall table and string block), so signatures and `upx -d`-class tooling are useless — the analyst must dump the decrypted image from a live process or emulate the loader.
2. **Anti-debug layer** — ptrace/TracerPid/parent/gdb checks run before the license stage; under gdb, lldb, strace or frida the process exits before any verification output.
3. **Interlock layer** — guard sections CRC32 each other in a ring plus overlap edges; the expected checksums are embedded post-compile, and the poison mask is derived from a guard section's own bytes (self-key). Tampering any guarded region — including the anti-debug code — taints the run and the key is corrupted before `verify()`.
4. **Verification layer** — RSA-512 signature validation over the entitlement blob; the key arrives Base64-encoded and the flag is derived at runtime from the verified blob, so a stubbed gate cannot reproduce it.

## Verification algorithm

The verification routine is one of several paradigms: **partial-key** (per-group transforms + checksum signature), **stream-cipher** (RC4 / TEA / XTEA / LFSR keystream), **name-serial hash** (custom hash + checksum), **license state-machine** (multi-stage checkpoint validation via ARX / polynomial-hash bit-transforms), or **weak public-key signature** (Wiener-weak RSA: the private exponent falls to continued fractions). The license key is a transport encoding (Base64 / Base32 / Base62 / Base58 / Hex / URL / ASCII85) of the variant's verification blob (16-440 bytes depending on variant); a valid key prints `flag{XXXXX-XXXXX-XXXXX-XXXXX-XXXXX}`.

**This task**: weak public-key signature — RSA-512 (A4 V4.1). The binary embeds a textbook-RSA entitlement check (`sig^e mod n == PKCS-prefixed SHA256 digest` over the license fields) with a Wiener-weak keypair, so the private exponent falls to a continued-fraction attack once `(n, e)` are extracted; the verification blob is transported as a Base64 string and validated through 4 chained checkpoints.

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
    - any artifact in `binaries/` passing the full gate chain (real ELF with plausible code volume, not the original, still rejects wrong keys, reproduces the oracle flag) can earn any of the configured properties: unpack (entropy within 20% of the oracle), bypass (prints the flag with the GT key under gdb, lldb, strace, ltrace, valgrind)
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
