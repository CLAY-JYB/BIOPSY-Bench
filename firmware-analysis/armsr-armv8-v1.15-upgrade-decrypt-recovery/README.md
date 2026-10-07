# Reverse Engineering Challenge (Firmware Analysis)

Operator-facing task card, never entering the agent image. The graded strings below (findings, versions, CVEs) are ground truth.

## Overview

| Attribute         | Value              |
|-------------------|--------------------|
| **Difficulty**    | expert     |
| **Challenge ID**  | armsr-armv8-v1.15-upgrade-decrypt-recovery        |
| **Focus**         | vendor-bespoke-chain image, squashfs rootfs, aarch64 userland |
| **Firmware Type** | ARM64 virtual (hub/camera class) (armsr/armv8)  |

**Objective.** reverse `/app/firmware.bin` end-to-end, from an opaque blob to working artifacts, per the contract in `instruction.md`.

## Background

The artifact ships with no documentation, no symbols, and no header descriptions. What is inside, and where, is part of the puzzle. This mirrors real firmware analysis practice as follows.
- large-scale image studies, OWASP FSTM, binwalk/sasquatch workflows, encrypted-firmware engagements
- rationale and citations in the skill repository, under `reference/design.md` and `reference/sources.md`

## Case provenance

This challenge instantiates a filed real-world case. The filing is as follows.
- is registered in the skill repository's provenance register (`reference/sources.md`)
- pins the carrier program sha256-verified in the skill's `codebase/source.yaml`
- clears the two-distribution standard, in-distribution with real deployments while novel as a combination, with the novelty route recorded in the register row

Scenario family 'decrypt-chain', filed case, evilsocket, TP-Link Tapo C200, vendor RSA decryption keys published inside GPL source releases (2025-12), plus tangrs, TP-Link TL-SG2008P smart-switch firmware decryption (2025-09), together the keys-in-shipped-software pattern this family builds (https://www.evilsocket.net/2025/12/18/TP-Link-Tapo-C200-Hardcoded-Keys-Buffer-Overflows-and-Privacy-in-the-Era-of-AI-Assisted-Reverse-Engineering/). Full register at reference/sources.md.

## Difficulty axes

Difficulty is graded along independent axes. This task's combination is `I7F2X3-V1M1` (I#F#X#, plus -O#P#D#T# when binary concealment is on, plus -V#M# solver-path hardening), as follows.

| Axis  | Covers                                                                                                               |
|-------|----------------------------------------------------------------------------------------------------------------------|
| **I** | image encapsulation, covering bare blob / sysupgrade / vendor factory header / vendor chain / obfuscated layout / encryption  |
| **F** | filesystem, covering initramfs / standard squashfs / non-standard squashfs (headerless, custom magic, endianness swap) / ext4 |
| **X** | cross-arch, meaning which OpenWrt target family the image is built for (x86_64 / mipsel / mips / aarch64)                    |

Enabled axes are I7 = vendor-bespoke-chain, F2, X3 (ARM64 virtual (hub/camera class), aarch64).

Target armsr/armv8 / profile generic is aarch64 (64-bit, little-endian, linux), with userland binaries running under qemu-aarch64-static.

Seeded findings (the only graded ones) are the inert backdoor marker daemon (magic account + runtime-derived marker, TEST-NET endpoint) and vulnerable component versions. The graded component is the current image's mosquitto 2.1.2. The seeded advisory context (CVE-2024-10525, VDE-2025-033) rides the GIVEN previous release v1.1, whose mosquitto 2.0.18 is the last release inside the advisories' affected range.

None beyond the image structure itself. The embedded binaries are unmodified distribution builds.

- the I/F concealment hides in the image structure itself, defeating naive `binwalk -Me` runs and the assumption that the payload sits at offset zero
- the O/P/D concealment raises the analysis cost of the inner binaries without changing the layout

## Intended solve path

- reconnaissance of the blob
- extraction along whatever concealment the I/F axes carry (decrypt, identify, unpack)
- static inventory of components and findings
- user-mode emulation of the extracted binaries (the tree as sysroot)
- correlation of execution behavior with the static picture (trigger demonstrations where the engagement asks for one)
- the artifacts per `instruction.md`

The reference solution (`solution/solve.sh`) walks exactly this path. The skill's `reference/design.md` documents the design rationale.

## Evaluation

Scoring weights are per-task (the inline GT config's `scoring.buckets`), with the bucket shapes fixed. Evaluation is pure dynamic. Nothing written is graded, only delivered artifacts.

| Category                            | Weight | Type    | Action                                                       |
|-------------------------------------|--------|---------|--------------------------------------------------------------|
| Extraction & emulation verification | 72     | dynamic | the extracted components actually run (per-task sub-weights) |
| Reconstruction                      | 28     | dynamic | the rebuilt image genuinely rebuilds and (on rehost tasks) boots |
| Demonstration                       | none   | dynamic | scenario engagements only, where the verifier drives the engagement's trigger against the byte-verified component |

Every point is earned by a delivered artifact (`extracted_fs/`, `firmware_repacked.bin`, `activation.keys`, `decrypted.bin` on ring/encrypted engagements), verified by executing it or checking its bytes.

## Task tree

The task source directory is as follows.

```
README.md                      # this task card
instruction.md                 # the agent-facing challenge (rendered per task)
task.toml                      # harness metadata (id, difficulty, network policy)
environment/                   # build context: the image + the ground-truth export stage
tests/                         # the verifier (test.sh, diagnosis graph, ground truth)
solution/                      # the reference solve + ground truth
```

The challenge container at runtime is as follows.

```
/app/
└── firmware.bin                # the challenge image (opaque, read-only)

/logs/artifacts/agent_output/   # the agent's writable deliverables (contract in instruction.md)
├── extracted_fs/               # the recovered file tree at its in-image paths
├── firmware_repacked.bin       # the rebuilt image (also the boot disk on rehost tasks)
├── activation.keys             # token=/account= lines (scored only through execution)
└── decrypted.bin               # ring/encrypted engagements
```

Chain engagements additionally ship `/app/firmware_v1.1.bin`, the previous release, as given evidence.

The tool environment is disclosed to the agent in `instruction.md`. The installed inventory lives in `environment/Dockerfile` and, skill-side, in `reference/tools.md`.
