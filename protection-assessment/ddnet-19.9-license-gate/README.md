# Reverse Engineering Challenge (Protection Assessment)

Operator-facing task card. This card never enters the agent image, and the details below (mechanisms, protections, findings) are ground truth for maintainers and reviewers.

## Overview

| Attribute           | Value                |
|---------------------|----------------------|
| **Task ID**         | ddnet-19.9-license-gate          |
| **Domain**          | protection assessment |
| **Difficulty**      | expert       |
| **Focus**           | competitive-integrity suite subscription (the server's anti-cheat and movement-validation core runs only under a per-deployment subscription entitlement — anti-cheat-as-a-service analog) |

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

**This task** is `A4 P4D3O3I3`. It has a hard algorithm (A4), PageGuard packing (P4), advanced anti-debug with DebugBlocker (D3), real xollvm obfuscation (O3), and an all-to-all interlock that binds the anti-debug into the checksum mesh (I3). The current four-band law (reference/levels.md) derives **expert** for this stack because `I3` is an all-to-all interlock.

- **Packing (P4).** PageGuard page-granular self-decrypting sections with no outer packer, so no stock unpacker signature matches the artifact
- **Anti-Debug (D3).** Advanced debugger detection (ptrace TRACEME, TracerPid, parent, gdb, frida, and proc-map fingerprints, breakpoint and timing probes) plus hardening (`PR_SET_DUMPABLE=0`, `MADV_DONTDUMP`) and a self-ptrace DebugBlocker
- **Anti-Tamper (I3).** Four all-to-all CRC guard nodes plus a data canary and an anti-debug checksum binding. A mismatch poisons the license path through self-keyed input corruption so even the valid key is rejected instead of the binary trapping. True checksums are embedded post-compile
- **Cryptographic Verification (A4).** RSA-512 signed entitlement validation

## Protections

### Generic binary protections

The binary implements multi-layer (pageguard page-encrypted, xollvm-obfuscated, anti-debug-hardened, interlock-guarded) protection as follows.

The binary implements multi-layer (packed, anti-debug-hardened, interlock-guarded) protection:

1. **Startup activation.** `main()` reads the entitlement key from stdin into a static buffer and calls the license stage before any server subsystem initializes. Nothing else runs until the key checks out.
2. **Interlock layer (I3).** The `validate_input` call site is wrapped first. Four guard sections CRC32 one another in an all-to-all network, the anti-debug library is placed in `g_adbg`, and a guard also checks that section. Expected CRC32 values are stamped into `_il_hdr.expected[]` after compilation.
3. **Anti-debug layer (D3).** The advanced probe set is inserted at server startup. Under a debugger or tracer the probe feeds the interlock taint path, so the submitted key is quietly corrupted before the real verifier sees it.
4. **Obfuscation layer (O3).** `verification.c` is compiled through the xollvm plugin for `validate_input`, combining anti-decompiler transforms, bogus control flow, control-flow flattening, MBA expressions, tamper shield, constant encryption, and string encryption. This hides the magic, timestamp window, RSA constants, and failure anchors.
5. **Packing layer (P2).** After interlock embedding and stripping, the binary is UPX-packed at maximum compression and stealth-processed (magic/p_info/section-name defeat) so `upx -d` refuses the artifact.

The key interdependency is that a protection failure does not necessarily crash. It taints execution and causes a false license rejection:

```c
interlock_run(); // guard CRCs + anti-debug probe if (_integrity_taint) { uint32_t m = crc32(section_g_s0); for (size_t i = 0; key[i]; i++) poisoned[i] = key[i] ^ (uint8_t)(m >> ((i % 4) * 8)); return validate_input(poisoned); // the real verifier rejects the corrupted key } return validate_input(key);
```

The layers may be interdependent and protect one another, with no fixed peel order, and they raise analysis cost only: the behavioral verdicts are unaffected.

### Domain-specific protections

The verification routine follows one of several paradigms: **partial-key** (per-group transforms plus checksum signature), **stream-cipher** (RC4, TEA, XTEA, or LFSR keystream), **name-serial hash** (custom hash plus checksum), **license state-machine** (multi-stage checkpoint validation through ARX or polynomial-hash bit transforms), and **weak public-key signature** (Wiener-weak RSA where the private exponent falls to continued fractions). The license key is a transport encoding of the variant's verification blob, with the encoding, the length, and the character set undisclosed to the agent.


**This task** uses the weak public-key signature paradigm with RSA-512 (A4 V4.1). The binary embeds a textbook-RSA entitlement check with a Wiener-weak keypair, so the private exponent falls to a continued-fraction attack once `(n, e)` are extracted. The verification blob is transported as a 216-character Base64 string and decodes to 160 bytes:

```c
struct license_v41 { uint32_t magic; // 0x4c4e5334 ("LNS4"; raw little-endian bytes: 34 53 4e 4c) uint32_t version; uint32_t product_id; uint32_t features; uint64_t expiry; // checked against embedded [A4_TS_MIN, A4_TS_MAX] uint64_t reserved; uint8_t user_id[32]; uint8_t machine_id[32]; uint8_t signature[64]; // RSA-512 signature over SHA256(raw[0..96])[:8] };

int validate_input(const char *input) { if (strlen(input) != 216) return 1; uint8_t raw[160]; base64_decode(input, raw, 160); if (*(uint32_t *)raw != 0x4c4e5334u) return 1; uint64_t exp_ts = *(uint64_t *)(raw + 16); if (exp_ts < A4_TS_MIN || exp_ts > A4_TS_MAX) return 1;

uint8_t md[32], expect[64] = {0}, calc[64]; sha256_hash(raw, 96, md); memcpy(expect + 56, md, 8); modexp_512(raw + 96, A4_E, A4_N, calc); return bn_cmp(calc, expect, 64) == 0 ? 0: 1; }
```

The corresponding keygen shape is:

```python
# Sketch only: N/E are recovered from the obfuscated binary.
d = recover_wiener_private_exponent(e, n) body = pack_lns4_license(expiry_inside_window, user_id, machine_id) digest64 = int.from_bytes(sha256(body).digest()[:8], "big") signature = pow(digest64, d, n).to_bytes(64, "big") key = base64.b64encode(body + signature).decode() assert len(key) == 216
```

The flag is derived at runtime from the verified blob, so a stubbed gate cannot reproduce it.

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
