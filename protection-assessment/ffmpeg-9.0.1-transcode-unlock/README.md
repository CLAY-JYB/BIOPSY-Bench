# Reverse Engineering Challenge: Protection Assessment

## Overview

| Attribute           | Value                |
|---------------------|----------------------|
| **Difficulty**      | hard                 |
| **Challenge ID**    | ffmpeg-9.0.1-transcode-unlock |
| **Focus**           | per-engine commercial transcoding tier (the transcode engine runs only under a valid entitlement key) |
| **Protection Type** | multi-layer (PageGuard-packed, anti-debug-hardened) |

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

**This task**: `A3 P4 D3 O3 I3` — medium algorithm (A3), PageGuard packing (P4), advanced anti-debug + DebugBlocker (D3), real xollvm obfuscation (O3), all-to-all interlock with anti-debug↔checksum binding (I3); difficulty profile **expert**.

Three independent layers protect the license check:

- **Packing (P4, PageGuard)** — the license-check code is isolated in a dedicated `g_pg` ELF section that is stored XOR-encrypted with a self-derived key (CRC32 of the runtime section's own bytes). At load time a constructor maps those pages `PROT_NONE`; the first execution fault triggers a SIGSEGV handler that decrypts exactly one page, remaps it R+X and resumes. Plaintext code only ever exists one page at a time, in memory, on demand. There is no public unpacker for this scheme.
- **Anti-debug (D1, passive)** — a check anchored immediately before the `verify()` call combines `/proc/self/status` `TracerPid` inspection, `/proc/self/maps` injection scanning and INT3 breakpoint scanning of the check path; detection terminates the run.
- **Cryptographic verification (A3)** — a real AEAD-style key check (see below) rather than a magic-string comparison.

## Protection architecture

The binary implements multi-layer (PageGuard-packed, anti-debug-hardened) protection:

1. **Verification unit placement** — the verification code is compiled into the `fftools` translation units (`verification.o` linked into the converter); the license key is read once from stdin at startup into a global, and the gate sits at the top of the transcode function, so the protected feature only runs under a valid key.
2. **PageGuard coupling** — the `g_pg` section (license algorithm) and `g_pg_rt` section (fault runtime) are page-owning and adjacent in the executable segment; the on-disk XOR key is derived from the runtime bytes, so patching the runtime breaks decryption (anti-tamper coupling). All runtime syscalls are raw (no PLT) to survive faults.
3. **Anti-debug ordering** — the anti-debug check runs before the verification call; the sections are stripped from the final binary so the check must be found dynamically.
4. **Invocation contract** — `echo KEY | ./binary -f lavfi -i anullsrc -t 0.05 -f null -` (the program's own options for a minimal headless transcode — this is what reaches the protected feature).

## Verification algorithm

The verification routine is one of several paradigms: **partial-key** (per-group transforms + checksum signature), **stream-cipher** (RC4 / TEA / XTEA / LFSR keystream), **name-serial hash** (custom hash + checksum), **license state-machine** (multi-stage checkpoint validation via ARX / polynomial-hash bit-transforms), or **weak public-key signature** (Wiener-weak RSA: the private exponent falls to continued fractions). The license key is a transport encoding (Base64 / Base32 / Base62 / Base58 / Hex / URL / ASCII85) of the variant's verification blob (16-440 bytes depending on variant); a valid key prints `flag{XXXXX-XXXXX-XXXXX-XXXXX-XXXXX}`.

**This task** uses the **stream-cipher/AEAD paradigm**: the submitted key is a Base58 transport encoding of a 56-byte license blob. Verification checks length, a 4-byte magic (`LNS3`) and a 16-byte Poly1305-style MAC computed over the blob with key material embedded in the binary (ChaCha20-derived keystream), through three checkpoints; the `flag{XXXXX-XXXXX-XXXXX-XXXXX-XXXXX}` output is derived at runtime from the verified blob. Every constant needed to mint a valid key is embedded in the binary.

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
