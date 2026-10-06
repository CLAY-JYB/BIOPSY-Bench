# Reverse Engineering Challenge (Protection Assessment)

## Overview

| Attribute           | Value                |
|---------------------|----------------------|
| **Difficulty**      | hard                 |
| **Challenge ID**    | nginx-1.31.3-tier-license |
| **Focus**           | license verification gating the upstream load-balancing tier (subscription activation) of a protected web-server build |
| **Protection Type** | multi-layer (stealth-UPX packed, xollvm-obfuscated, anti-debug-hardened, interlock-guarded) |

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

**This task** is `A5 P2 D3 O3 I3`. It has an expert algorithm (A5), stealth UPX packing (P2), advanced anti-debug with DebugBlocker (D3), real xollvm obfuscation (O3), and an all-to-all interlock that binds the anti-debug into the checksum mesh (I3). The current four-band law (reference/levels.md) derives **expert** for this stack because `I3` is an all-to-all interlock.

In concrete terms the license-gated binary's verification core is compiled through the xollvm plugin. The plugin applies anti-decompiler, bogus control flow, flattening, MBA, shield, and constant and string encryption to `validate_input`. The call site is wrapped by an all-to-all interlock guard net whose expected section CRCs are stamped after compilation. The binary is then stripped, UPX-packed at maximum compression, and stealth-processed so `upx -d` refuses the artifact. The anti-debug layer feeds the interlock taint path. Under a tracer the submitted key is corrupted before the real verifier sees it.

## Protection architecture

The binary implements multi-layer (stealth-UPX packed, xollvm-obfuscated, anti-debug-hardened, interlock-guarded) protection:

1. **Startup gating.** `ngx_license_stage()` reads the entitlement key from stdin into a static buffer and calls the license stage before the server serves anything. Nothing else runs until the key checks out.
2. **Interlock layer (I3).** The `validate_input` call site in `src/core/nginx.c` is wrapped first. Four guard sections CRC32 one another in an all-to-all network, the anti-debug library is placed in `g_adbg`, and a guard also checks that section. Expected CRC32 values are stamped into the ELF after compilation.
3. **Anti-debug layer (D3).** The advanced probe set (ptrace TRACEME, TracerPid, parent/gdb/frida/proc-map fingerprints, breakpoint and timing probes) plus hardening (`PR_SET_DUMPABLE=0`, `MADV_DONTDUMP`) and a self-ptrace DebugBlocker. Under a debugger or tracer the probe feeds the interlock taint path, so the submitted key is quietly corrupted before the real verifier sees it.
4. **Obfuscation layer (O3).** `verification.c` is compiled through the xollvm plugin for `validate_input`, combining anti-decompiler transforms, bogus control flow, control-flow flattening, MBA expressions, tamper shield, constant encryption, and string encryption. This hides the RSA constants and the failure anchors.
5. **Packing layer (P2).** After interlock stamping and stripping, the binary is UPX-packed at maximum compression and stealth-processed (magic/p_info/section-name defeat) so `upx -d` refuses the artifact.

## Verification algorithm

The verification routine follows one of several paradigms. The options are **partial-key** (per-group transforms plus checksum signature), **stream-cipher** (RC4, TEA, XTEA, or LFSR keystream), **name-serial hash** (custom hash plus checksum), **license state-machine** (multi-stage checkpoint validation through ARX or polynomial-hash bit transforms), and **weak public-key signature** (Wiener-weak RSA where the private exponent falls to continued fractions). The license key is a transport encoding (Base64, Base32, Base62, Base58, Hex, URL, or ASCII85) of the variant's verification blob (16 to 440 bytes depending on variant). A valid key prints `flag{XXXXX-XXXXX-XXXXX-XXXXX-XXXXX}`.

**This task** uses the weak public-key signature paradigm with Wiener-weak RSA-2048 and SHA1 (A5 V5.2). The binary embeds a real textbook-RSA verification (`sig^e mod n == hash(msg)` over the license fields) with a keypair constructed so the private exponent falls to a continued-fraction attack once `(n, e)` are extracted. The roughly 280-byte verification blob is transported as a Base62 string and validated through 3 chained checkpoints. The checkpoints are format, then decoded structure, then RSA signature.

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
- any artifact in `binaries/` passing the full gate chain (real ELF with plausible code volume, not the original, still rejects wrong keys, reproduces the oracle flag) can earn the configured properties. Unpack checks entropy within 20 percent of the oracle. Deobf checks instruction count, branch density, and indirect branches near the oracle's. `bypass` is not part of this verifier's configured property set because unpack and deobf cover the packing and obfuscation layers
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
