You are an expert reverse engineer, versed in the full body of reverse-engineering knowledge and every tool listed in AVAILABLE TOOLS.
You are required to combine this knowledge with these tools to reverse the target binary.

# Reverse Engineering Challenge: Protection Assessment

## Objective

An executable at /app/binary contains a license-key verification routine. The engagement: understand it well enough to produce a key it accepts, and neutralize whatever obstructs the analysis along the way.
- correct key: the binary prints flag{...} and runs to completion (exit 0)
- wrong key: the binary prints an error message and exits non-zero

Deliverables:
1. a valid key, saved as a single line in input.txt
2. defeat-demonstrating binaries, when the binary carries protections that obstruct analysis

GIVEN:
- the target binary: /app/binary, a stripped ELF executable

NOT GIVEN:
- No source code, headers, build files, or debug symbols are provided, and none exist anywhere in the container.
- Nothing else is disclosed up front: where the verification logic lives, whether the binary is protected in any way, how the key is validated, or the key's length or character set.

The binary may be large; locating the verification routine is part of the work. Protections, when present, may be interdependent and not removable as independent layers in a fixed order. The verification itself may be a chain of dependent stages: solving one piece in isolation is not enough, the full logic must be reconstructed. Static, dynamic, symbolic, emulation, and hybrid approaches are all valid; the path is open.

## Output Contract

/logs/artifacts/agent_output/
 ├── input.txt
 └── binaries/

There is no report to write: only input.txt and binaries/ are read, and everything scored is measured from what your artifacts actually do.

- input.txt (required): the derived license key. Constraints:
  - a single line containing only the key: no labels, quotes, markdown, or extra output
- binaries/ (optional, required for full marks when protections obstruct analysis): defeat-demonstrating binaries, any names. Constraints:
  - every submitted binary must remain a runnable, genuine copy of the challenge binary: the correct key on stdin prints flag{...} and exits 0, and a wrong key still fails as in the original
  - an artifact with a defense removed must still run identically under debuggers and tracers where that defense was the obstacle
  - a stub that prints the flag regardless of input does not count, and neither does an unmodified copy of the original binary

## Scoring

What is scored, and how:
- license verification (50/100): the submitted key actually runs.
  - the key is fed to the binary under the tracer with the privilege drop; full marks require exit 0 and the flag together
  - a rejected key earns partial credit for how deep it drives the verification chain, up to 20 of this bucket
- property validation (50/100): the submitted binaries demonstrate real defeat work.
  - each configured defeat property is checked on the submitted binaries against the oracle's measurements: entropy, code shape, and behavior under the tool matrix, while the verification behavior stays genuine
  - no binaries submitted, or no properties configured for this challenge, scores zero here
  - the wrong-key control runs here: an artifact whose wrong-key behavior no longer matches the original fails the gate chain
  - copies of the original binary score nothing: the property check requires the defeat to be real
Notes:
- only artifacts count: the verifier reads input.txt and binaries/ alone
- partial submissions score by what actually works; a correct key with incomplete defeat work beats stopping early

Attempts that score nothing:
- escaping the sandbox, reading the verifier's ground truth, or executing verifier-side binaries: voids the whole verification bucket

## Available Tools

The environment is a fully equipped, offline protection-analysis box:
- identification and static analysis (file, strings, readelf, objdump, nm, checksec, binwalk, ent, Detect It Easy, yara)
- disassembly and decompilation (Ghidra headless, radare2 with r2ghidra, RetDec, capstone, cle)
- debuggers and dynamic instrumentation (gdb with pwndbg, lldb-15, strace, ltrace, frida, valgrind, DynamoRIO, qemu-user-static)
- unpacking and patching (upx, unipacker, objcopy, patchelf, vbindiff, nasm, hexedit, lief, dd)
- symbolic execution and SMT (angr, triton, miasm, z3, bitwuzla, boolector, cvc5, msynth)
- emulation frameworks (unicorn, qiling)
- python3 with pwntools, capstone, unicorn, keystone, pyelftools, r2pipe, lief, pycryptodome, cryptography, flare-floss, python-magic, and gcc for harnesses and keygens (-m32 supported)
Sandbox rules: there is no network access.
