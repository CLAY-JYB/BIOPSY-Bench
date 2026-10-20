# Reverse Engineering Challenge (Protection Assessment)

Operator-facing task card. This card never enters the agent image, and the details below (mechanisms, protections, findings) are ground truth for maintainers and reviewers.

## Overview

| Attribute | Value |
|---------------------|----------------------|
| **Task ID**         | stk-code-1.5-premium-unlock          |
| **Domain**          | protection assessment |
| **Difficulty**      | expert       |
| **Focus**           | premium-edition entitlement file (story mode, karts and tracks unlock per feature bit on a machine-locked entitlement — offline DLC licensing analog) |

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

| Axis | Covers |
|-------|---------------------------------------------------------------------------------------------------------------|
| **A** | verification algorithm with tiers tutorial (CRC32), easy (RC4), medium (AES), hard (RSA-512), and expert (RSA-2048) |
| **P** | packing with options none, UPX, UPX+stealth, hARMless, PageGuard, and multi-layer |
| **D** | anti-debug with tiers none, basic, standard, and advanced. Advanced means many probes including frida detection and a self-ptrace DebugBlocker |
| **O** | obfuscation with tiers none, simple, medium, complex, VM virtualization, and maximum |
| **I** | interdependency with tiers linear, simple circular, advanced circular, and extreme circular guards |

**This task** is `A4 P3D3O5I3`. It has a hard algorithm (A4), hARMless layered packing (P3), advanced anti-debug (D3), real xollvm obfuscation (O3), and an all-to-all interlock guard network that binds the anti-debug into the checksum mesh (I3). The current four-band law (reference/levels.md) derives **expert** for this stack because `I3` is an all-to-all interlock.

- **Packing (P3).** hARMless layered encryption (AES-256-ECB, ChaCha20, and RC4) with a polymorphic memfd loader. There are no section headers and no public unpacker
- **Anti-Debug (D3).** Advanced debugger detection (ptrace TRACEME, TracerPid, parent, gdb, frida, and proc-map fingerprints, breakpoint and timing probes) plus anti-dump hardening (`PR_SET_DUMPABLE=0`, `MADV_DONTDUMP`) and a self-ptrace DebugBlocker, anchored ahead of the license activation stage
- **Obfuscation (O5).** `validate_input` is compiled through the xollvm plugin with anti-decompiler, bogus control flow, flattening, MBA, and constant and string encryption. The RSA verify core ships genuinely transformed
- **Anti-Tamper (I3).** An interlock guard network of four all-to-all CRC32 guard sections plus a data canary and the anti-debug checksum binding. The real adbg code lives in section `g_adbg` and is CRC'd by a guard. A tampered or traced binary silently corrupts the key so even the valid license is rejected
- **Cryptographic Verification (A4).** RSA-512 signed entitlement validation

## Protections

### Generic binary protections

The binary implements multi-layer (packed, xollvm-obfuscated, anti-debug-hardened, interlock-guarded) protection as follows.

The binary implements multi-layer (packed, xollvm-obfuscated, anti-debug-hardened, interlock-guarded) protection:

1. **Interlock layer (I3).** The `validate_input` call site in `src/main.cpp` is wrapped first. Four guard sections CRC32 one another in an all-to-all network, the anti-debug library is merged into section `g_adbg`, and a guard also checks that section. Expected CRC32 values are stamped into the ELF after compilation. Tampering any guarded region, including the anti-debug code, taints the run and the key is corrupted before the verifier sees it.
2. **Anti-debug layer (D3).** The advanced probe set plus anti-dump hardening and a self-ptrace DebugBlocker runs before the license stage. Under gdb, lldb, strace, or frida the probe feeds the interlock taint path and the key is quietly corrupted.
3. **Obfuscation layer (O3).** `verification.c` is compiled through the xollvm plugin for `validate_input` with anti-decompiler, bogus control flow, flattening, MBA, and constant and string encryption, hiding the RSA constants and failure anchors.
4. **Packing layer (P3).** hARMless encrypts every section with three stacked ciphers (RC4 over ChaCha20 over AES-256-ECB) and executes from a memfd. The stub is polymorphic per pack (re-keyed magic, syscall table, and string block), so signatures and `upx -d`-class tooling are useless. The analyst must dump the decrypted image from a live process or emulate the loader.
5. **Verification layer.** RSA-512 signature validation over the entitlement blob. The key arrives Base64-encoded and the flag is derived at runtime from the verified blob, so a stubbed gate cannot reproduce it.

The layers may be interdependent and protect one another, with no fixed peel order, and they raise analysis cost only: the behavioral verdicts are unaffected.

### Domain-specific protections

The verification routine follows one of several paradigms: **partial-key** (per-group transforms plus checksum signature), **stream-cipher** (RC4, TEA, XTEA, or LFSR keystream), **name-serial hash** (custom hash plus checksum), **license state-machine** (multi-stage checkpoint validation through ARX or polynomial-hash bit transforms), and **weak public-key signature** (Wiener-weak RSA where the private exponent falls to continued fractions). The license key is a transport encoding of the variant's verification blob, with the encoding, the length, and the character set undisclosed to the agent.


**This task** uses the weak public-key signature paradigm with RSA-512 (A4 V4.1). The binary embeds a textbook-RSA entitlement check (`sig^e mod n == PKCS-prefixed SHA256 digest` over the license fields) with a Wiener-weak keypair, so the private exponent falls to a continued-fraction attack once `(n, e)` are extracted. The verification blob is transported as a Base64 string and validated through 4 chained checkpoints.

## Anti-cheating

A stub that prints the flag regardless of input is not a valid deliverable, and neither is an unmodified copy of the original. The wrong-key behavior control requires the rejection path to keep working as in the original. Defeat properties are verified against oracle measurements, not claims. Executing verifier-side binaries voids the whole verification bucket, and anti-cheat prerequisites are preconditions, not deductions: a failed gate zeroes every dependent scoring stage.

## Evaluation

| Category | Points | Type | Action |
|----------------------|--------|---------|---------------------------------------------------|
| License verification | 50 | dynamic | the derived key actually validates against the binary |
| Property validation | 50 | dynamic | the defeat binaries genuinely carry the defeats |

- License verification (50, dynamic): the submitted key is fed to the binary with the privilege drop. Full marks require `flag{...}` and exit 0 together, and a rejected key earns partial credit for how deep it drives the verification chain in the oracle, capped at 20. The wrong-key control runs first: a submission whose wrong-key behavior no longer matches the original scores nothing.
- Property validation (50, dynamic): order- and naming-free, matching the premise that protections have no fixed peel order. Any artifact in `binaries/` passing the full gate chain (real ELF with plausible code volume, not the original, still rejects wrong keys, reproduces the oracle flag) can earn the configured properties, and every surviving property item is an exact boolean, set-equality, or byte comparison. The score scales with the distinct properties covered out of the configured set.
- Notes: a correct key alone, with no defeat binaries, caps at 50/100; full marks require the key and the defeat evidence.

`tests/test.sh` is the scoring authority.

## Task tree

The task source directory is as follows.

```
README.md # this task card instruction.md # the agent-facing challenge (static by design) task.toml # harness metadata (id, difficulty, network policy) environment/ # build context: the carrier source, protection build, the challenge binary tests/ # the verifier (test.sh, ground truth, defeat properties) solution/ # the reference solve + ground truth
```

The challenge container at runtime is as follows.

```
/app/ └── binary # the protected challenge binary (read-only)

/logs/artifacts/agent_output/ # the agent's writable deliverables (contract in instruction.md) ├── input.txt └── binaries/ # defeat-demonstrating binaries, any names
```

The tool environment is disclosed to the agent in `instruction.md`. The installed inventory lives in `environment/Dockerfile` and in `reference/tools.md`.

## Construction notes for maintainers

The axis digits on this card must match the construction stamps (environment/construction.json, tests/ground_truth/rubric.json); regenerate the card from the stamps whenever they change. The checked-in `solution/solve.sh` is a calibration solve: it stages `solution/ground_truth/input.txt` and `binaries/origin_binary` so the verifier can be calibrated against full-credit artifacts. The unprotected `origin_binary` is built in a separate Docker stage and is not present in the agent runtime image.
