#!/usr/bin/env python3
"""
xollvm Random Command Generator for C/C++ Binaries
Generates randomized xollvm obfuscation commands using LLVM 22

xollvm is an annotation-driven LLVM 22 obfuscator with zero LLVM source edits.
It supports code virtualization via the 'vm' pass.

================================================================================
USAGE EXAMPLES
================================================================================

# Generate a single command with default settings:
./xollvm.py -i program.c

# Generate commands with specific obfuscation passes:
./xollvm.py -i program.c --passes "mba,bcf,flattening"

# Use preset configurations:
./xollvm.py -i program.c --preset light
./xollvm.py -i program.c --preset heavy
./xollvm.py -i program.c --preset maximum

# Generate multiple variants:
./xollvm.py -i program.c -n 5

# Use seed for reproducible results:
./xollvm.py -i program.c --seed 42

# Output to file:
./xollvm.py -i program.c -n 10 -o commands.txt
./xollvm.py -i program.c -n 10 --json -o commands.json

================================================================================
XOLLVM OPTIONS
================================================================================

OBFUSCATION PASSES (via annotation: __attribute__((annotate("obf: ...")))):
  mba                 Mixed Boolean-Arithmetic expression rewriting
  substitution        Instruction substitution with equivalent idioms
  vcall               Virtual call hardening via synthetic vtables
  split               Basic block splitting
  sdiff               Semantic diffusion (volatile-slot masking)
  bcf                 Bogus control flow (opaque predicates + fake edges)
  flattening          CFG flattening with dispatcher
  constenc            Constant encryption
  shield              Anti-optimization shield
  adec                Anti-decompiler (trampolines, junk bytes)
  vm                  Code virtualization (conflicts with flattening)
  strenc              String encryption (module-level)

PRESETS:
  light               Expression-level only (mba, substitution)
  heavy               Structural + post-hardening (mba, bcf, flattening, shield, adec)
  maximum             VM virtualization with hardening

COMPILATION PIPELINE:
  1. clang -S -emit-llvm -O0 input.c -o input.ll
  2. opt -passes=obfuscation input.ll -S -o output.ll -obf-seed=SEED
  3. clang output.ll -O2 -o output

NOTE: xollvm requires:
  - LLVM 22
  - Source annotations: __attribute__((annotate("obf: pass_name")))
  - Can be built as static extension or loadable plugin (.so)

================================================================================
COMMAND LINE OPTIONS
================================================================================

  -h, --help            Show help message
  -n COUNT              Number of commands to generate (default: 1)
  -i INPUT              Input C file (default: program.c)
  --passes PASSES       Comma-separated obfuscation passes (default: random)
  --preset PRESET        Use preset: light, heavy, maximum (default: random)
  --seed SEED           Random seed for reproducibility
  -o OUTPUT             Output file (print to stdout if not specified)
  --json                Output in JSON format

================================================================================
"""

import random
import argparse
import json
from typing import List, Optional, Set
from dataclasses import dataclass


# xollvm ships as a loadable LLVM pass plugin (Obfuscator.so) at /usr/local/lib.
# opt only registers the `obfuscation` pass and the -obf-seed/-obf-deterministic
# options once the plugin is loaded; without -load-pass-plugin opt errors
# "unknown pass name 'obfuscation'" / "Unknown command line argument '-obf-seed'".
XOLLOVM_PLUGIN_PATH = "/usr/local/lib/Obfuscator.so"
# In-container path to the annotation injector (see xollvm_prep.py). The
# protection scripts always live under /protection in the Docker build context.
XOLLOVM_PREP = "/protection/obfuscation/xollvm_prep.py"


class ObfuscationPass:
    """xollvm obfuscation passes"""
    CONSTENC = ("constenc", "Constant encryption")
    MBA = ("mba", "Mixed Boolean-Arithmetic")
    SUBSTITUTION = ("substitution", "Instruction substitution")
    VCALL = ("vcall", "Virtual call hardening")
    SPLIT = ("split", "Basic block splitting")
    SDIFF = ("sdiff", "Semantic diffusion")
    BCF = ("bcf", "Bogus control flow")
    FLATTENING = ("flattening", "CFG flattening")
    SHIELD = ("shield", "Anti-optimization shield")
    ADEC = ("adec", "Anti-decompiler")
    VM = ("vm", "Code virtualization")
    STRENC = ("strenc", "String encryption (module-level)")


class Preset:
    """Obfuscation presets"""
    LIGHT = ("light", "Expression-level only")
    HEAVY = ("heavy", "Structural + post-hardening")
    MAXIMUM = ("maximum", "VM virtualization")


@dataclass
class XollvmConfig:
    """xollvm obfuscation configuration"""
    passes: Set[str] = None
    seed: Optional[int] = None
    output_file: Optional[str] = None

    def __post_init__(self):
        if self.passes is None:
            self.passes = set()


def get_preset_passes(preset: str) -> Set[str]:
    """Get annotation string for a preset"""
    if preset == "light":
        # Expression-level only
        return {ObfuscationPass.MBA[0], ObfuscationPass.SUBSTITUTION[0]}
    elif preset == "heavy":
        # Structural + post-hardening
        return {ObfuscationPass.MBA[0], ObfuscationPass.BCF[0],
                ObfuscationPass.FLATTENING[0], ObfuscationPass.SHIELD[0],
                ObfuscationPass.ADEC[0]}
    elif preset == "maximum":
        # VM virtualization + everything COMPATIBLE with it. vm conflicts
        # with flattening (documented pass constraint), so maximum is the
        # union of the VM and the non-control-flow passes — the historical
        # {vm}-only preset silently shipped LESS than O3's "heavy" set while
        # being labeled maximum.
        return {ObfuscationPass.VM[0], ObfuscationPass.MBA[0],
                ObfuscationPass.SUBSTITUTION[0], ObfuscationPass.STRENC[0],
                ObfuscationPass.CONSTENC[0], ObfuscationPass.SHIELD[0],
                ObfuscationPass.ADEC[0]}
    return set()


def random_light_passes() -> Set[str]:
    """Generate random light obfuscation passes"""
    passes = {ObfuscationPass.MBA[0], ObfuscationPass.SUBSTITUTION[0]}
    # Maybe add constant encryption
    if random.random() < 0.4:
        passes.add(ObfuscationPass.CONSTENC[0])
    return passes


def random_heavy_passes() -> Set[str]:
    """Generate random heavy obfuscation passes"""
    passes = {ObfuscationPass.MBA[0], ObfuscationPass.BCF[0],
              ObfuscationPass.FLATTENING[0], ObfuscationPass.SHIELD[0],
              ObfuscationPass.ADEC[0]}
    # Maybe add other passes
    if random.random() < 0.3:
        passes.add(ObfuscationPass.SPLIT[0])
    if random.random() < 0.2:
        passes.add(ObfuscationPass.SDIFF[0])
    return passes


def generate_random_config(use_preset: Optional[str] = None, seed: Optional[int] = None) -> XollvmConfig:
    """
    Generate a random xollvm configuration

    Args:
        use_preset: Optional preset name (light, heavy, maximum)
        seed: Random seed for reproducibility

    Returns:
        XollvmConfig object with random settings
    """
    config = XollvmConfig()

    if use_preset:
        config.passes = get_preset_passes(use_preset)
    else:
        # Randomly choose between light, heavy, and maximum
        choice = random.choices(["light", "heavy", "maximum"], weights=[0.4, 0.4, 0.2])[0]
        config.passes = get_preset_passes(choice)

    config.seed = seed if seed is not None else random.randint(1, 2**31 - 1)

    return config


def config_to_command(config: XollvmConfig, input_file: str, output_file: Optional[str] = None, multi_file: bool = False) -> str:
    """Convert configuration to a xollvm obfuscation command.

    Two things the raw opt pipeline needs that are easy to miss:
      1. The plugin MUST be loaded (``-load-pass-plugin=Obfuscator.so``) or opt
         rejects both ``-passes=obfuscation`` and ``-obf-seed``.
      2. xollvm is annotation-driven — passes only fire on functions carrying
         ``__attribute__((annotate("obf: ...")))``. The command therefore starts
         by running xollvm_prep.py to inject that annotation before the target
         function (default: main).

    For multi-file projects (multi_file=True), outputs only the annotation prep
    step and CFLAGS, allowing the build system to compile all sources with the
    obfuscation flags.
    """
    # Annotation spec reflects the selected passes (consumed by xollvm_prep.py).
    passes = sorted(config.passes) if config.passes else ["mba"]
    spec = ",".join(passes)

    seed = config.seed if config.seed is not None else 42

    if multi_file:
        # For multi-file projects: inject annotations and return CFLAGS for the build
        prep_cmd = f"python3 {XOLLOVM_PREP} {input_file} \"{spec}\""
        cflags = f"-fpass-plugin={XOLLOVM_PLUGIN_PATH} -mllvm -obf-seed={seed} -mllvm -obf-deterministic"
        return f"{prep_cmd} && XOLLVM_CFLAGS=\"{cflags}\""
    else:
        # Determine output filename (strip a trailing .c so main.c -> main_xollvm, not main.c_xollvm)
        out = output_file or config.output_file
        if not out:
            base = input_file[:-2] if input_file.endswith(".c") else input_file
            out = base + "_xollvm"

        stages = [
            f"python3 {XOLLOVM_PREP} {input_file} \"{spec}\"",
            f"clang -S -emit-llvm -O0 {input_file} -o /tmp/input.ll",
            f"opt -load-pass-plugin={XOLLOVM_PLUGIN_PATH} -passes=obfuscation "
            f"/tmp/input.ll -S -o /tmp/output.ll -obf-seed={seed} -obf-deterministic",
            f"clang /tmp/output.ll -O2 -o {out}",
            "rm -f /tmp/input.ll /tmp/output.ll",
        ]
        return " && ".join(stages)


def generate_commands(
    count: int = 1,
    input_file: str = "program.c",
    preset: Optional[str] = None,
    passes: Optional[str] = None,
    seed: Optional[int] = None,
    multi_file: bool = False
) -> List[str]:
    """
    Generate random xollvm obfuscation command(s)

    Args:
        count: Number of commands to generate
        input_file: Input C file
        preset: Optional preset (light, heavy, maximum)
        passes: Comma-separated pass names (overrides preset)
        seed: Random seed for reproducibility

    Returns:
        List of command strings
    """
    # Seed the RNG here too: with --preset given, the preset choice is fixed,
    # but random_* pass variations (and the random seed used in the command
    # when --seed is absent) must still be reproducible per --seed.
    if seed is not None:
        random.seed(seed)

    commands = []
    for i in range(count):
        config = generate_random_config(preset, seed)

        # Override with explicit passes if provided
        if passes:
            config.passes = set()
            for pass_name in passes.split(","):
                pass_name = pass_name.strip()
                config.passes.add(pass_name)

        base = input_file[:-2] if input_file.endswith(".c") else input_file
        output = f"{base}_xollvm_{i}"
        cmd = config_to_command(config, input_file, output, multi_file)
        commands.append(cmd)

    return commands


def main():
    parser = argparse.ArgumentParser(
        description="xollvm Random Command Generator - LLVM 22 obfuscation with zero source edits"
    )
    parser.add_argument(
        "-n", "--count",
        type=int,
        default=1,
        help="Number of commands to generate (default: 1)"
    )
    parser.add_argument(
        "-i", "--input",
        type=str,
        default="program.c",
        help="Input C file (default: program.c)"
    )
    parser.add_argument(
        "--passes",
        type=str,
        default=None,
        help="Comma-separated obfuscation passes (default: random)"
    )
    parser.add_argument(
        "--preset",
        type=str,
        choices=["light", "heavy", "maximum"],
        default=None,
        help="Use preset: light (expression), heavy (structural), maximum (VM)"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Random seed for reproducibility"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output file (print to stdout if not specified)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
    )
    parser.add_argument(
        "--multi-file",
        action="store_true",
        help="Multi-file mode: output annotation prep + CFLAGS instead of full compilation"
    )

    args = parser.parse_args()

    commands = generate_commands(
        count=args.count,
        input_file=args.input,
        preset=args.preset,
        passes=args.passes,
        seed=args.seed,
        multi_file=args.multi_file
    )

    if args.json:
        output = json.dumps({"commands": commands}, indent=2)
    else:
        output = "\n\n".join(commands)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
    else:
        print(output)


if __name__ == "__main__":
    main()
