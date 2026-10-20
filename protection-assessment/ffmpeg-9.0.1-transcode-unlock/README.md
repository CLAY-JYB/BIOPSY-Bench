# Reverse Engineering Challenge (Protection Assessment)

Operator-facing task card. This card never enters the agent image, and the details below (mechanisms, protections, findings) are ground truth for maintainers and reviewers.

## Overview

| Attribute           | Value                |
|---------------------|----------------------|
| **Task ID**         | ffmpeg-9.0.1-transcode-unlock          |
| **Domain**          | protection assessment |
| **Difficulty**      | expert       |
| **Focus**           | per-machine codec licensing tier (the transcode engine runs only under a valid subscription entitlement, MPEG-LA/Fraunhofer-style TERM license analog) |

**Objective.** Locate the hidden license-key verification routine in `/app/binary`, defeat the protections around it (which may be interdependent), recover the full verification logic end-to-end, and derive a key that validates. The deliverables are `input.txt` with the key and `binaries/` with defeat-demonstrating binaries at `/logs/artifacts/agent_output/`, per the contract in `instruction.md`.

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

## Difficulty axes

The challenge composes independent protection axes. This task's values are recorded on this card as `P#D#O#I#` plus the A level.

| Axis  | Covers                                                                                                        |
|-------|---------------------------------------------------------------------------------------------------------------|
| **A** | verification algorithm with tiers tutorial (CRC32), easy (RC4), medium (AES), hard (RSA-512), and expert (RSA-2048)     |
| **P** | packing with options none, UPX, UPX+stealth, hARMless, PageGuard, and multi-layer                                        |
| **D** | anti-debug with tiers none, basic, standard, and advanced. Advanced means many probes including frida detection and a self-ptrace DebugBlocker |
| **O** | obfuscation with tiers none, simple, medium, complex, VM virtualization, and maximum                                   |
| **I** | interdependency with tiers linear, simple circular, advanced circular, and extreme circular guards                       |

**This task** is `A3 P2D3O3I3`. It has a medium algorithm (A3), UPX+stealth packing (P2), advanced anti-debug with DebugBlocker (D3), real xollvm obfuscation (O3), and an all-to-all interlock that binds the anti-debug into the checksum mesh (I3). The current four-band law (reference/levels.md) derives **hard** for this stack.

The protection stack is genuinely applied at build time.

- **Interlock (I3).** An all-to-all CRC32 guard network (four guard sections plus a data canary) wraps the `validate_input` call site in `fftools/ffmpeg.c`. The anti-debug library is merged into section `g_adbg` with a guard CRC over it. Tampering the anti-debug or any guard poisons the key. Expected checksums are stamped post-compile.
- **Anti-debug (D3).** The advanced probe set (ptrace, TracerPid, parent, gdb, and frida fingerprints, breakpoint and timing probes) plus anti-dump hardening and a self-ptrace DebugBlocker is anchored at the top of the transcode function. Under a debugger or tracer the probe feeds the interlock taint path. The submitted key is corrupted before the real verifier sees it.
- **Obfuscation (O3).** `validate_input` is compiled through the xollvm plugin with anti-decompiler, bogus control flow, flattening, MBA, and constant and string encryption. Only that translation unit routes through the plugin compiler, and the obfuscated core is then compressed inside the stealth-UPX packing layer.
- **Packing (P2, UPX+stealth).** The whole binary is UPX-compressed and then stealth-processed (UPX magic, `p_info`, and section-name scrub) so the stock `upx -d` refuses it. The agent must recognize the mangled UPX overlay and reverse the stealth modifications to unpack and dump the real executable before any static analysis of the verification core is possible.
- **Cryptographic verification (A3).** A real AEAD-style key check (see below) rather than a magic-string comparison.

## Protections

### Generic binary protections

The binary implements multi-layer (UPX+stealth-packed, xollvm-obfuscated, anti-debug-hardened, interlock-guarded) protection as follows.

The binary implements multi-layer (UPX+stealth-packed, xollvm-obfuscated, anti-debug-hardened, interlock-guarded) protection:

1. **Verification unit placement.** The verification code is compiled into the `fftools` translation units with `verification.o` linked into the converter. The license key is read once from stdin at startup into a global, and the gate sits at the top of the transcode function, so the protected feature only runs under a valid key.
2. **Stealth-UPX packing.** The entire executable is UPX-compressed and stealth-processed (magic / `p_info` / section-name scrub) so the stock `upx -d` refuses it; the agent must repair or bypass the stealth modifications to unpack. The interlock guard sections (`g_s*`, `g_canary`, `g_adbg`) and their CRCs apply to the unpacked image.
3. **Anti-debug anchoring (D3).** The advanced probe set is anchored at the top of the transcode function, before the verification call. Under a tracer the probe corrupts the key via the interlock taint path, so the run ends in a clean `Invalid key` rejection rather than a crash.
4. **Invocation contract.** `echo KEY |./binary -f lavfi -i anullsrc -t 0.05 -f null -` uses the program's own options for a minimal headless transcode, and this is what reaches the protected feature.

The layers may be interdependent and protect one another, with no fixed peel order, and they raise analysis cost only: the behavioral verdicts are unaffected.

### Domain-specific protections

The verification routine follows one of several paradigms: **partial-key** (per-group transforms plus checksum signature), **stream-cipher** (RC4, TEA, XTEA, or LFSR keystream), **name-serial hash** (custom hash plus checksum), **license state-machine** (multi-stage checkpoint validation through ARX or polynomial-hash bit transforms), and **weak public-key signature** (Wiener-weak RSA where the private exponent falls to continued fractions). The license key is a transport encoding of the variant's verification blob, with the encoding, the length, and the character set undisclosed to the agent.


**This task** uses the **stream-cipher/AEAD paradigm**. The submitted key is a Base58 transport encoding of a 56-byte license blob. Verification enforces a field-level license chain: key length, magic, version, feature bits, a validity window, user and machine-fingerprint binding (the license is node-locked to the deployment's machine identity), and a 16-byte Poly1305-style MAC over the blob, through eight ordered checkpoints. The license is a time-limited subscription: an expiry window is enforced and a clock-rollback guard is armed. The `flag{XXXXX-XXXXX-XXXXX-XXXXX-XXXXX}` output is derived at runtime from the verified blob. Every constant needed to mint a valid key is embedded in the binary.

## Anti-cheating

A stub that prints the flag regardless of input is not a valid deliverable, and neither is an unmodified copy of the original. The wrong-key behavior control requires the rejection path to keep working as in the original. Defeat properties are verified against oracle measurements, not claims. Executing verifier-side binaries voids the whole verification bucket, and anti-cheat prerequisites are preconditions, not deductions: a failed gate zeroes every dependent scoring stage.

## Evaluation

| Category             | Points | Type    | Action                                            |
|----------------------|--------|---------|---------------------------------------------------|
| License verification | 50     | dynamic | the derived key actually validates against the binary |
| Property validation  | 50     | dynamic | the defeat binaries genuinely carry the defeats  |

- License verification (50, dynamic): the submitted key is fed to the binary with the privilege drop. Full marks require `flag{...}` and exit 0 together, and a rejected key earns partial credit for how deep it drives the verification chain in the oracle, capped at 20. The wrong-key control runs first: a submission whose wrong-key behavior no longer matches the original scores nothing.
- Property validation (50, dynamic): order- and naming-free, matching the premise that protections have no fixed peel order. Any artifact in `binaries/` passing the full gate chain (real ELF with plausible code volume, not the original, still rejects wrong keys, reproduces the oracle flag) can earn the configured properties, and every surviving property item is an exact boolean, set-equality, or byte comparison. The score scales with the distinct properties covered out of the configured set.
- Notes: a correct key alone, with no defeat binaries, caps at 50/100; full marks require the key and the defeat evidence.

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

## Construction notes for maintainers

The axis digits on this card must match the construction stamps (environment/construction.json, tests/ground_truth/rubric.json); regenerate the card from the stamps whenever they change. The checked-in `solution/solve.sh` is a calibration solve: it stages `solution/ground_truth/input.txt` and `binaries/origin_binary` so the verifier can be calibrated against full-credit artifacts. The unprotected `origin_binary` is built in a separate Docker stage and is not present in the agent runtime image.
