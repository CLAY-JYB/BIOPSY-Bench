You are an expert reverse engineer, versed in the full body of reverse-engineering knowledge and every tool listed in AVAILABLE TOOLS. You are required to combine this knowledge with these tools to reverse the target binary.

# Reverse Engineering Challenge (Firmware Analysis)

TIME LIMIT 2 HOURS. Submit partial results before the limit instead of stopping early.

## Scenario (Backdoor audit)

An audit engagement. The client suspects an undocumented maintenance capability in this batch of devices (an account or helper that official documentation does not mention). Sweep the image and decide whether such a backdoor is PRESENT or ABSENT, backed by evidence a second auditor can pick up. Suspicion is not the finding. The image bytes are.

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

- extracted_fs/ (required), the unpacked firmware filesystem: the actual recovered files at their original in-image paths, as complete a recovery of the original tree as you can achieve. Run target components in tree context (provisioning material is read relative to the component's own location)
- firmware_repacked.bin (required), an image genuinely rebuilt from your unpacked tree: it must parse as a firmware image with standard tooling, carry the rebuilt filesystem, and contain no reused or embedded bytes of the original image (or of the decrypted original), verbatim or spliced

- activation.keys (required), the activation keys you actually recovered, one per line, `token=<value>` and `account=<value>`. Guessed or placeholder values are worthless: the keys are only ever as good as the executions they unlock
- decrypted.bin (required), the decrypted image: graded on size, header, and exact bytes

## Available Tools

The environment is a fully equipped, offline firmware-analysis box, stocked as follows.
- extraction (binwalk v2+v3, sasquatch with non-standard-squashfs support, squashfs tools, unblob, firmware-mod-kit, mtd-utils)
- identification and debugging for every supported architecture (binutils-multiarch, gdb-multiarch with pwndbg, qemu-user-static and qemu-system)
- cross compilers for mipsel/mips/aarch64/arm with matching libc headers, disassembly and decompilation (radare2, Ghidra headless, RetDec)
- emulation and symbolic execution (angr, qiling, unicorn, SMT solvers)
- cve-bin-tool (an offline NVD snapshot at /var/lib/cve-bin-tool when the image build could fetch one. A SNAPSHOT-ABSENT marker means no snapshot shipped, and version-to-CVE correlation must then come from your own analysis)
- standard static and dynamic analysis utilities

Sandbox rules. The analysis box is offline and self-contained; nothing outside the challenge artifacts is reachable. Nothing can be mounted inside the container, and guest services are reachable only on 127.0.0.1.
