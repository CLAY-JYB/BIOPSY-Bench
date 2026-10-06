You are an expert reverse engineer, versed in the full body of reverse-engineering knowledge and every tool listed in AVAILABLE TOOLS.
You are required to combine this knowledge with these tools to reverse the target binary.

# Reverse Engineering Challenge: Firmware Analysis

## Scenario: Covert channel detection

The SOC flagged periodic outbound behaviour on a fleet segment and wants the image checked for a hidden remote-management channel: an undocumented listener, beacon, or magic-port responder. Determine whether such a channel is PRESENT or ABSENT, with evidence from the image to back the call.


GIVEN:
- firmware: /app/firmware.bin
- previous firmware: /app/firmware_v1.1.bin

NOT GIVEN:
- No documentation, no symbols, no layout hints, no header descriptions. What target code is inside, where it sits, and which protections are applied are part of the puzzle.

## Output Contract

/logs/artifacts/agent_output/
 ├── extracted_fs/
 ├── firmware_repacked.bin
 ├── activation.keys
 ├── decrypted.bin

- extracted_fs/ (required): the unpacked firmware filesystem, the actual recovered files at their original in-image paths. Constraints:
  - graded on how completely the image's original tree is recovered, file for file, and on how precisely your tree avoids material that is not in the image
  - the graded components are verified byte-for-byte at their in-image paths inside this tree, then executed from it — place and run them in tree context (provisioning material can be read relative to the component's own location)
- firmware_repacked.bin (required): an image rebuilt from your unpacked tree. Constraints:
  - must parse as a firmware image with standard tooling and carry the rebuilt filesystem
  - reusing or embedding the original image's bytes (or the decrypted original's bytes), verbatim or spliced, scores nothing and voids the downstream rebuild axes
  
- activation.keys (required): the activation keys you recovered, one per line: `token=<value>` and `account=<value>`. Constraints:
  - the values are scored ONLY through the executions they unlock inside your extracted binaries — they are never compared as strings, and placeholder or guessed values simply fail the gated executions
- decrypted.bin (required): the decrypted image. Constraints:
  - graded on size, header, and exact bytes
- the engagement-specific deliverables (none beyond the fixed set). Constraints:
  - none beyond the fixed contract

## Scoring

There is no report to fill: every point is earned by a delivered artifact, verified by executing it or checking its bytes. Axes are task-weighted (the bucket weights vary by engagement; the shapes below are fixed):

- extraction & emulation: tree fidelity (path recall, set precision, verifier-sampled provenance), component extraction (byte-exact at the in-image path) and version identification by actually running the component, gated activations (your keys run through the extracted binaries; the observable decides), and — on encrypted engagements — decrypt delivery.
- reconstruction: whether the repacked image parses with standard tooling (one class earns partial, two earn full), whether the rebuilt filesystem stream genuinely diverges from the shipped one (a splice reproduces the original stream and earns nothing), whether the rebuilt payload is consistent with your own extracted tree, and whether the rebuilt superblock reproduces the original geometry;
- demonstration (scenario engagements only): the verifier itself boots your extracted, byte-verified component and drives the engagement's trigger against it — the service coming up, the trigger request being processed, and the trigger's effect showing. Nothing you script is executed.

Dependency chain: upstream failures void downstream axes (an undelivered tree voids the component and rebuild axes; a gated component voids the gated executions; a copied or spliced rebuild voids the rebuild axes that follow).

Notes:
- only the artifacts above are graded; write nothing else into the contract paths
- partial submissions score by what actually works; submitting something partial always beats stopping early

Attempts that score nothing:
- executing any verifier-side binary (/app, /tests, /solution): voids the whole verification
- shipping the original image bytes (or the decrypted original) as your rebuild
- keys that are never exercised: an unverified key line earns nothing on its own

## Available Tools

The environment is a fully equipped, offline firmware-analysis box:
- extraction (binwalk v2+v3, sasquatch with non-standard-squashfs support, squashfs tools, unblob, firmware-mod-kit, mtd-utils)
- identification and debugging for every supported architecture (binutils-multiarch, gdb-multiarch with pwndbg, qemu-user-static and qemu-system)
- cross compilers for mipsel/mips/aarch64/arm with matching libc headers, disassembly and decompilation (radare2, Ghidra headless, RetDec)
- emulation and symbolic execution (angr, qiling, unicorn, SMT solvers)
- cve-bin-tool (an offline NVD snapshot at /var/lib/cve-bin-tool when the image build could fetch one; a SNAPSHOT-ABSENT marker means no snapshot shipped — version-to-CVE correlation must then come from your own analysis)
- standard static and dynamic analysis utilities
Sandbox rules: nothing can be mounted inside the container, and there is no network beyond hostfwd'd guest services on 127.0.0.1. Activation may depend on tree state: components can read provisioning material relative to their own location inside the extracted filesystem, so stage and run them in tree context.
