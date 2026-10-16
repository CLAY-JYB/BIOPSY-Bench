You are an expert reverse engineer, versed in the full body of reverse-engineering knowledge and every tool listed in AVAILABLE TOOLS. You are required to combine this knowledge with these tools to reverse the target binary.

# Reverse Engineering Challenge (Firmware Analysis)

## Scenario (Covert channel detection)

The SOC flagged periodic outbound behaviour on a fleet segment and wants the image checked for a hidden remote-management channel, an undocumented listener, beacon, or magic-port responder. Determine whether such a channel is PRESENT or ABSENT, with evidence from the image to back the call.

GIVEN
- firmware, /app/firmware.bin

NOT GIVEN
- No documentation, no symbols, no layout hints, no header descriptions. What target code is inside, where it sits, and which protections are applied are part of the puzzle.

## Output Contract

/logs/artifacts/agent_output/
 ├── extracted_fs/
 ├── firmware_repacked.bin
 ├── activation.keys
decrypted.bin

- extracted_fs/ (required), the unpacked firmware filesystem, the actual recovered files at their original in-image paths. Constraints as follows.
  - graded on how completely the image's original tree is recovered, file for file, and on how precisely your tree avoids material that is not in the image
  - the graded components are verified byte-for-byte at their in-image paths inside this tree, then executed from it. Place and run them in tree context (provisioning material can be read relative to the component's own location)
- firmware_repacked.bin (required), an image rebuilt from your unpacked tree. Constraints as follows.
  - must parse as a firmware image with standard tooling and carry the rebuilt filesystem
  - reusing or embedding the original image's bytes (or the decrypted original's bytes), verbatim or spliced, scores nothing and voids the downstream rebuild axes
  
- activation.keys (required), the activation keys you recovered, one per line, `token=<value>` and `account=<value>`. Constraints as follows.
  - the values are scored ONLY through the executions they unlock inside your extracted binaries. They are never compared as strings, and placeholder or guessed values simply fail the gated executions
- decrypted.bin (required), the decrypted image. Constraints as follows.
  - graded on size, header, and exact bytes

## Scoring

There is no report to fill. Every point is earned by a delivered artifact, verified by executing it or checking its bytes. Three result axes (task-weighted at 40/30/30 shape; emulation is how the verifier runs things, not a separate axis). The axes are as follows.

- extraction, two ways to earn. Content correctness (decrypt delivery on encrypted engagements, and your tree's fidelity measured by path recall, set precision, and verifier-sampled byte provenance) and emulation runs (each graded component boots from your own tree as its system root; a checkpoint chain inside the binary scores how far execution travels, and the gated activations pay only through the observable your keys unlock).
- reconstruction, all dynamic. Standard tools must genuinely parse the repack, unsquashfs must genuinely unpack it with a payload consistent with your own tree, the geometry reported by the tools must match the original, and a run battery proves the rebuilt image is alive. On other engagements the battery runs the extracted components straight out of the rebuilt filesystem.
- triggering, the engagement's special path driven for real. Where the engagement says you craft the input, your poc_input.bin is fed verbatim to the byte-verified component; where it rides recovered keys, your keys drive the gated path. Five ordered execution checkpoints pay process points by depth, the end effect pays result points, and five reruns pay stability. A benign control input must stay shallower than yours, or the process points void.

Dependency chain. Upstream failures void downstream axes (an undelivered tree voids the component and rebuild axes, a gated component voids the gated executions, and a copied or spliced rebuild voids the rebuild axes that follow).

Notes as follows.
- only the artifacts above are graded. Write nothing else into the contract paths
- partial submissions score by what actually works. Submitting something partial always beats stopping early

Attempts that score nothing are as follows.
- executing any verifier-side binary (/app, /tests, /solution), voids the whole verification
- shipping the original image bytes (or the decrypted original) as your rebuild
- keys that are never exercised, an unverified key line earns nothing on its own

## Available Tools

The environment is a fully equipped, offline firmware-analysis box, stocked as follows.
- extraction (binwalk v2+v3, sasquatch with non-standard-squashfs support, squashfs tools, unblob, firmware-mod-kit, mtd-utils)
- identification and debugging for every supported architecture (binutils-multiarch, gdb-multiarch with pwndbg, qemu-user-static and qemu-system)
- cross compilers for mipsel/mips/aarch64/arm with matching libc headers, disassembly and decompilation (radare2, Ghidra headless, RetDec)
- emulation and symbolic execution (angr, qiling, unicorn, SMT solvers)
- cve-bin-tool (an offline NVD snapshot at /var/lib/cve-bin-tool when the image build could fetch one. A SNAPSHOT-ABSENT marker means no snapshot shipped, and version-to-CVE correlation must then come from your own analysis)
- standard static and dynamic analysis utilities
Sandbox rules. Nothing can be mounted inside the container, and there is no network beyond hostfwd'd guest services on 127.0.0.1. Activation may depend on tree state. Components can read provisioning material relative to their own location inside the extracted filesystem, so stage and run them in tree context.
