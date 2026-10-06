# Reverse Engineering Challenge (Protection Assessment)

## Overview

| Attribute           | Value                |
|---------------------|----------------------|
| **Difficulty**      | hard                 |
| **Challenge ID**    | ffmpeg-9.0.1-transcode-unlock |
| **Focus**           | per-engine commercial transcoding tier (the transcode engine runs only under a valid entitlement key) |
| **Protection Type** | multi-layer (PageGuard-packed, xollvm-obfuscated, anti-debug-hardened, interlock-guarded) |

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

**This task** is `A3 P4 D3 O3 I3`. It has a medium algorithm (A3), PageGuard packing (P4), advanced anti-debug with DebugBlocker (D3), real xollvm obfuscation (O3), and an all-to-all interlock that binds the anti-debug into the checksum mesh (I3). The current four-band law (reference/levels.md) derives **expert** for this stack because `I3` is an all-to-all interlock.

The protection stack is genuinely applied at build time.

- **Interlock (I3).** An all-to-all CRC32 guard network (four guard sections plus a data canary) wraps the `validate_input` call site in `fftools/ffmpeg.c`. The anti-debug library is merged into section `g_adbg` with a guard CRC over it. Tampering the anti-debug or any guard poisons the key. Expected checksums are stamped post-compile.
- **Anti-debug (D3).** The advanced probe set (ptrace, TracerPid, parent, gdb, and frida fingerprints, breakpoint and timing probes) plus anti-dump hardening and a self-ptrace DebugBlocker is anchored at the top of the transcode function. Under a debugger or tracer the probe feeds the interlock taint path. The submitted key is corrupted before the real verifier sees it.
- **Obfuscation (O3).** `validate_input` is compiled through the xollvm plugin with anti-decompiler, bogus control flow, flattening, MBA, and constant and string encryption. Only that translation unit routes through the plugin compiler, and the obfuscated core is buried beneath the PageGuard page-encryption layer.
- **Packing (P4, PageGuard).** The license-check code is isolated in a dedicated `g_pg` ELF section that is stored XOR-encrypted with a self-derived key (CRC32 of the runtime section's own bytes). At load time a constructor maps those pages `PROT_NONE`. The first execution fault triggers a SIGSEGV handler that decrypts exactly one page, remaps it R+X, and resumes. Plaintext code only ever exists one page at a time, in memory, on demand. There is no public unpacker for this scheme.
- **Cryptographic verification (A3).** A real AEAD-style key check (see below) rather than a magic-string comparison.

## Protection architecture

The binary implements multi-layer (PageGuard-packed, xollvm-obfuscated, anti-debug-hardened, interlock-guarded) protection:

1. **Verification unit placement.** The verification code is compiled into the `fftools` translation units with `verification.o` linked into the converter. The license key is read once from stdin at startup into a global, and the gate sits at the top of the transcode function, so the protected feature only runs under a valid key.
2. **PageGuard coupling.** The `g_pg` section (license algorithm) and `g_pg_rt` section (fault runtime) are page-owning and adjacent in the executable segment. The on-disk XOR key is derived from the runtime bytes, so patching the runtime breaks decryption (anti-tamper coupling). All runtime syscalls are raw with no PLT to survive faults. The guard sections (`g_s*`, `g_canary`, `g_adbg`) are disjoint from `g_pg`, so the section encryption does not invalidate the interlock CRCs.
3. **Anti-debug anchoring (D3).** The advanced probe set is anchored at the top of the transcode function, before the verification call. Under a tracer the probe corrupts the key via the interlock taint path, so the run ends in a clean `Invalid key` rejection rather than a crash.
4. **Invocation contract.** `echo KEY | ./binary -f lavfi -i anullsrc -t 0.05 -f null -` uses the program's own options for a minimal headless transcode, and this is what reaches the protected feature.

## Verification algorithm

The verification routine follows one of several paradigms. The options are **partial-key** (per-group transforms plus checksum signature), **stream-cipher** (RC4, TEA, XTEA, or LFSR keystream), **name-serial hash** (custom hash plus checksum), **license state-machine** (multi-stage checkpoint validation through ARX or polynomial-hash bit transforms), and **weak public-key signature** (Wiener-weak RSA where the private exponent falls to continued fractions). The license key is a transport encoding (Base64, Base32, Base62, Base58, Hex, URL, or ASCII85) of the variant's verification blob (16 to 440 bytes depending on variant). A valid key prints `flag{XXXXX-XXXXX-XXXXX-XXXXX-XXXXX}`.

**This task** uses the **stream-cipher/AEAD paradigm**. The submitted key is a Base58 transport encoding of a 56-byte license blob. Verification checks length, a 4-byte magic (`LNS3`), and a 16-byte Poly1305-style MAC computed over the blob with key material embedded in the binary (ChaCha20-derived keystream), through three checkpoints. The `flag{XXXXX-XXXXX-XXXXX-XXXXX-XXXXX}` output is derived at runtime from the verified blob. Every constant needed to mint a valid key is embedded in the binary.

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
- any artifact in `binaries/` passing the full gate chain (real ELF with plausible code volume, not the original, still rejects wrong keys, reproduces the oracle flag) can earn the configured properties. Unpack checks entropy within 20 percent of the oracle. Bypass prints the flag with the GT key under gdb, lldb, strace, ltrace, and valgrind
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
