# Reverse Engineering Challenge (Protection Assessment)

## Overview

| Attribute           | Value                |
|---------------------|----------------------|
| **Difficulty**      | hard                 |
| **Challenge ID**    | wesnoth-1.19.26-save-entitlement |
| **Focus**           | save-data entitlement protection (sub-achievement persistence through the licensed save format) |
| **Protection Type** | multi-layer (xollvm-obfuscated, anti-debug-hardened, interlock-guarded, stealth-UPX packed) |

**Objective.** Locate the hidden license-key verification routine in `/app/binary`, defeat the protections around it (which may be interdependent), recover the full verification logic end-to-end, and derive a key that validates, per the contract in `instruction.md`. A correct key makes the binary print `flag{...}` and exit 0. A wrong key prints an error message and exits non-zero.

## Background

The binary implements commercial-style software protection over a license-checking routine. This mirrors real protection-assessment practice.
- license enforcement and IP-protection reviews, unpacking and deprotection engagements, red-team binary analysis
- the challenge tests binary analysis and anti-protection bypass, not vulnerability discovery. No CVE or OSV exploit is involved
- rationale and citations in the skill repository at `reference/design.md` and `reference/sources.md`

## Case provenance

This challenge instantiates a filed construction case. The filing records the following.
- is registered in the skill repository's provenance register (`reference/sources.md`)
- pins the carrier program sha256-verified in the skill's `codebase/source.yaml`
- clears the two-distribution standard. The task is in-distribution with real deployments while novel as a combination, and the novelty route is recorded in the register row

## Protection difficulty axes

The challenge composes independent protection axes. This task's values are recorded on this card as `P#D#O#I#` plus the A level.

| Axis  | Covers                                                                                                        |
|-------|---------------------------------------------------------------------------------------------------------------|
| **A** | verification algorithm with tiers tutorial (CRC32), easy (RC4), medium (AES), hard (RSA-512), and expert (RSA-2048)     |
| **P** | packing with options none, UPX, UPX+stealth, hARMless, PageGuard, and multi-layer                                        |
| **D** | anti-debug with tiers none, basic, standard, and advanced. Advanced means many probes including frida detection and a self-ptrace DebugBlocker |
| **O** | obfuscation with tiers none, simple, medium, complex, VM virtualization, and maximum                                   |
| **I** | interdependency with tiers linear, simple circular, advanced circular, and extreme circular guards                       |

**This task** is `A3 P2 D3 O3 I3`. It has a medium algorithm (A3), stealth UPX packing (P2), advanced anti-debug (D3), real xollvm obfuscation (O3), and an all-to-all interlock that binds the anti-debug into the checksum mesh (I3). The current four-band law (reference/levels.md) derives **expert** for this stack because `I3` is an all-to-all interlock.

In concrete terms the verification core is compiled through the xollvm plugin. The plugin applies anti-decompiler, bogus control flow, flattening, MBA, shield, and constant and string encryption to `validate_input`. There is no VM pass. The call site in `src/wesnoth.cpp` is wrapped by an all-to-all interlock guard net that also covers the anti-debug code in section `g_adbg`, so a traced or tampered run silently corrupts the key. After the guard CRCs are stamped the binary is stripped, UPX-packed at maximum compression, and stealth-processed so `upx -d` refuses the artifact.

## Protection architecture

The binary implements multi-layer (xollvm-obfuscated, anti-debug-hardened, interlock-guarded, stealth-UPX packed) protection:

1. **Startup activation.** `main()` reads the entitlement key from stdin and enters the save-data license activation stage before any game subsystem initializes.
2. **Interlock layer (I3).** The `validate_input` call site in `src/wesnoth.cpp` is wrapped by a four-guard all-to-all CRC32 network plus a data canary. The real anti-debug code is merged into section `g_adbg` and CRC'd by a guard. Expected checksums are stamped post-compile. A tampered or traced run poisons the key, meaning the valid key is silently corrupted before the real check.
3. **Anti-debug layer (D3).** The advanced probe set (TracerPid, parent process, timing, INT3 breakpoints, /proc maps, frida) plus anti-dump hardening runs ahead of the key check and feeds the interlock taint path. DebugBlocker is deliberately off on this carrier because its self-ptrace child wedges wesnoth's stdout after the gate returns. This is a documented D3 fallback.
4. **Obfuscation layer (O3).** `verification.c` is compiled through the xollvm plugin with anti-decompiler, bogus control flow, flattening, MBA, and constant and string encryption on `validate_input`. There is no VM pass. The earlier virtualization claim was retired as build-risky fake-O.
5. **Second license gate.** A second gate inside the achievements subsystem (`save_progress_licensed()`) guards sub-achievement progress persistence through the licensed save format.
6. **Packing (P2).** After compilation the binary is stripped, UPX-packed at maximum compression, and stealth-processed (magic/p_info/section-name defeat) so `upx -d` refuses the artifact.

## Verification algorithm

The verification routine follows one of several paradigms. The options are **partial-key** (per-group transforms plus checksum signature), **stream-cipher** (RC4, TEA, XTEA, or LFSR keystream), **name-serial hash** (custom hash plus checksum), **license state-machine** (multi-stage checkpoint validation through ARX or polynomial-hash bit transforms), and **weak public-key signature** (Wiener-weak RSA where the private exponent falls to continued fractions). The license key is a transport encoding (Base64, Base32, Base62, Base58, Hex, URL, or ASCII85) of the variant's verification blob (16 to 440 bytes depending on variant). A valid key prints `flag{XXXXX-XXXXX-XXXXX-XXXXX-XXXXX}`.

**This task** uses the license state-machine paradigm. The verification chain validates a hex-encoded 72-byte license blob in three staged checkpoints. Checkpoint 1 checks transport format. Checkpoint 2 checks embedded magic. Checkpoint 3 checks a Salsa20 and BLAKE2b derived authentication block against an expected MAC. The flag is derived at runtime from the verified blob, so a stubbed gate cannot reproduce it.

## Intended solve path

- reconnoiter the binary for type, architecture, entropy, and which protections are present
- map the protection dependencies before removing anything. Protections may protect one another and there is no fixed peel order.
- defeat the protections in the order the dependency structure allows, saving defeat-demonstrating binaries along the way
- locate the verification routine in the defeated binary and reconstruct the full validation chain, including chained stages
- derive a key that satisfies the recovered logic and confirm `flag{...}` plus exit 0
- the key and binaries per `instruction.md`

Calibration note. The checked-in `solution/solve.sh` is not a cold-start reverse-engineering solver. It copies `solution/ground_truth/input.txt` and `binaries/origin_binary` to the output directory so the verifier can be calibrated against full-credit artifacts. The unprotected `origin_binary` is built in a separate Docker stage and is not present in the agent runtime image.

## Evaluation

| Category             | Points | Type    | Action                                            |
|----------------------|--------|---------|---------------------------------------------------|
| License verification | 50     | dynamic | the derived key actually validates against the binary |
| Property validation  | 50     | dynamic | the defeat binaries genuinely carry the defeats  |

- Scoring
- License verification (50, dynamic):
- the submitted key is fed to the binary with the privilege drop. Full marks require `flag{...}` and exit 0 together
- a rejected key earns partial credit for how deep it drives the verification chain in the oracle, capped at 20
- the wrong-key control runs first. A submission whose wrong-key behavior no longer matches the original scores nothing
- Property validation (50, dynamic):
- order- and naming-free, matching the premise that protections have no fixed peel order
- any artifact in `binaries/` passing the full gate chain (real ELF with plausible code volume, not the original, still rejects wrong keys, reproduces the oracle flag) can earn the configured properties. Unpack checks entropy within 20 percent of the oracle. Bypass prints the flag with the GT key under gdb, lldb, strace, ltrace, and valgrind. Deobf checks instruction count, branch density, and indirect branches near the oracle's
- score scales with the distinct properties covered out of the configured set
- Notes
- a correct key alone, with no defeat binaries, caps at 50/100
- full marks require the key and the defeat evidence

`tests/test.sh` is the scoring authority.

## Task tree

The task source directory is as follows.

```
README.md                      # this task card
instruction.md                 # the agent-facing challenge (static by design)
task.toml                      # harness metadata (id, difficulty, network policy)
environment/                   # build context: the carrier source, protection build, the challenge binary
tests/                         # the verifier (test.sh, ground truth, defeat properties)
solution/                      # the reference solve + ground truth
```

The challenge container at runtime is as follows.

```
/app/
└── binary                     # the protected challenge binary (read-only)

/logs/artifacts/agent_output/  # the agent's writable deliverables (contract in instruction.md)
├── input.txt
└── binaries/                  # defeat-demonstrating binaries, any names
```

The tool environment is disclosed to the agent in `instruction.md`. The installed inventory lives in `environment/Dockerfile` and in `reference/tools.md`.
