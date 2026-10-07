# Reverse Engineering Challenge (Firmware Analysis)

Operator-facing task card, never entering the agent image. The graded strings below (findings, versions, CVEs) are ground truth.

## Overview

| Attribute         | Value              |
|-------------------|--------------------|
| **Difficulty**    | hard     |
| **Challenge ID**  | x86-generic-v1.11-advisory-impact-triage        |
| **Focus**         | ring-chain-hardened image, squashfs rootfs, x86 userland |
| **Firmware Type** | 32-bit x86 legacy/embedded (x86/generic)  |

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

Scenario family 'cve-impact', filed case, CERT/CC VU#471747, dnsmasq May-2026 six-CVE wave (CVE-2026-2291/-4890/-4891/-4892/-4893/-5172, fixed 2.92rel2, 'nearly all non-ancient versions' affected) (https://kb.cert.org/vuls/id/471747). Full register at reference/sources.md.

## Difficulty axes

Difficulty is graded along independent axes. This task's combination is `I8F2X6-O3P1D3T0-V1M1` (I#F#X#, plus -O#P#D#T# when binary concealment is on, plus -V#M# solver-path hardening), as follows.

| Axis  | Covers                                                                                                               |
|-------|----------------------------------------------------------------------------------------------------------------------|
| **I** | image encapsulation, covering bare blob / sysupgrade / vendor factory header / vendor chain / obfuscated layout / encryption  |
| **F** | filesystem, covering initramfs / standard squashfs / non-standard squashfs (headerless, custom magic, endianness swap) / ext4 |
| **X** | cross-arch, meaning which OpenWrt target family the image is built for (x86_64 / mipsel / mips / aarch64)                    |

Enabled axes are I8 = ring-chain-hardened, F2, X6 (32-bit x86 legacy/embedded, x86).

Target x86/generic / profile generic is x86 (32-bit, little-endian, linux), with userland binaries running natively.

Seeded findings (the only graded ones) are the inert backdoor marker daemon (magic account + runtime-derived marker, TEST-NET endpoint) and vulnerable component versions, dnsmasq 2.91 (CVE-2026-2291, CVE-2026-4890, CVE-2026-4891, CVE-2026-4892, CVE-2026-4893, CVE-2026-5172).

Binary concealment (O/P/D) is layered on the embedded binaries, namely upx_packing, nrv_compression, runtime_decompression, int3_check, proc_maps_check, frida_detection, time_delta_check, control_flow_flattening, mba_expressions, instruction_substitution.

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
| Extraction & emulation verification | 68     | dynamic | the extracted components actually run (per-task sub-weights) |
| Reconstruction                      | 24     | dynamic | the rebuilt image genuinely rebuilds and (on rehost tasks) boots |
| Demonstration                       | 8      | dynamic | scenario engagements only, where the verifier drives the engagement's trigger against the byte-verified component |

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
