# Reverse Engineering Challenge: Protection Assessment

## Overview

| Attribute           | Value                |
|---------------------|----------------------|
| **Difficulty**      | hard                 |
| **Challenge ID**    | nginx-1.31.3-tier-license |
| **Focus**           | license verification gating the upstream load-balancing tier (subscription activation) of a protected web-server build |
| **Protection Type** | multi-layer (UPX packing + tigress obfuscation + interlock anti-tamper) |

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

**This task**: `A5 P1 D3 O3 I3` — expert algorithm (A5), plain UPX packing (P1), advanced anti-debug (D3), real xollvm obfuscation (O3), all-to-all interlock with anti-debug↔checksum binding (I3); difficulty profile **expert**.

Concretely: the license-gated binary is compiled from a tigress-obfuscated translation unit (flattened, opaque-predicated, literal/arithmetic-encoded `main`), then wrapped in an interlock guard ring whose section checksums are embedded after compilation, then stripped, then UPX-packed. The packing layer is independent (peels with `upx -d`); the obfuscation and integrity layers interlock around the verify call — the guard ring CRCs the obfuscated guard code, so deobfuscating or patching it trips the poison response.

## Protection architecture

The binary implements multi-layer (UPX packing + tigress obfuscation + interlock anti-tamper) protection:

- **UPX packing (P1)** — the whole ELF is UPX-compressed (`upx -6`), with the stock UPX! signature intact: `upx -d` peels it, which makes recon trivial but still hides every static string and section until then.
- **Tigress source obfuscation (O3)** — the license-checking `main()` translation unit is transformed by tigress (control-flow flattening with switch dispatch, opaque predicates over linked-list structures, string-literal encoding and arithmetic-encoding passes) before compilation; the flattened dispatcher and encoded constants survive unpacking and must be structurally simplified to recover the gate.
- **Interlock ring anti-tamper (I1)** — an Aucsmith-style guard ring wraps the `verify()` call site: four guard nodes CRC32 each other's dedicated ELF sections (ring topology) plus a data canary; a mismatch poisons the license path (fixed-mask key corruption → even the valid key is rejected) instead of trapping. True checksums are embedded post-compile, so any byte patched in a guard or canary section flips the run to a clean rejection.
- **No anti-debug (D0)** — deliberately absent on this task: no ptrace / TracerPid / debugger probes; dynamic analysis tooling runs unopposed, and the difficulty sits in the obfuscation + integrity interplay instead.

## Verification algorithm

The verification routine is one of several paradigms: **partial-key** (per-group transforms + checksum signature), **stream-cipher** (RC4 / TEA / XTEA / LFSR keystream), **name-serial hash** (custom hash + checksum), **license state-machine** (multi-stage checkpoint validation via ARX / polynomial-hash bit-transforms), or **weak public-key signature** (Wiener-weak RSA: the private exponent falls to continued fractions). The license key is a transport encoding (Base64 / Base32 / Base62 / Base58 / Hex / URL / ASCII85) of the variant's verification blob (16-440 bytes depending on variant); a valid key prints `flag{XXXXX-XXXXX-XXXXX-XXXXX-XXXXX}`.

**This task**: weak public-key signature — Wiener-weak RSA-2048 + SHA1 (A5 V5.2). The binary embeds a real textbook-RSA verification (`sig^e mod n == hash(msg)` over the license fields) with a keypair constructed so the private exponent falls to a continued-fraction attack once `(n, e)` are extracted; the ~280-byte verification blob is transported as a Base62 string and validated through 3 chained checkpoints (format → decoded structure → RSA signature).

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
    - any artifact in `binaries/` passing the full gate chain (real ELF with plausible code volume, not the original, still rejects wrong keys, reproduces the oracle flag) can earn the configured properties: unpack (entropy within 20% of the oracle), deobf (instruction count, branch density, indirect branches near the oracle's) — this task configures no `bypass` property (it carries no anti-debug layer to bypass)
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
