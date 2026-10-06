#!/usr/bin/env python3
"""
Ensia (OLLVM-Next) Random Command Generator for C/C++ Binaries
Generates randomized Ensia obfuscation commands using modern LLVM

Ensia is OLLVM-Next - a modern LLVM-based obfuscator continuing the
lineage of Hikari and OLLVM projects, supporting LLVM 21 and 22.

================================================================================
USAGE EXAMPLES
================================================================================

# Generate a single command with default settings:
./ensia.py -i program.c

# Generate commands with specific obfuscation passes:
./ensia.py -i program.c --passes strcry,csmobf,mbaobf

# Use preset configurations:
./ensia.py -i program.c --preset medium
./ensia.py -i program.c --preset maximum

# Generate multiple variants:
./ensia.py -i program.c -n 5

# Use seed for reproducible results:
./ensia.py -i program.c --seed 42

# Output to file:
./ensia.py -i program.c -n 10 -o commands.txt
./ensia.py -i program.c -n 10 --json -o commands.json

================================================================================
ENSIA OPTIONS
================================================================================

OBFUSCATION PASSES (via -mllvm flag):
  -ensia                    Enable Ensia obfuscation (required)

PRESETS:
  medium                    Medium protection (production-ready)
                            Includes: math complexity, flattening
                            Avoids: slowest passes
  maximum                   Maximum protection
                            Enables: all passes at max settings
                            Warning: very slow, large binary size

INDIVIDUAL PASSES (via environment variables):
  STRCRY=1                  String Encryption (XOR, GF8, Feistel)
  CSMOBF=1                  Chaos State Machine (logistic-map flattening)
  MBAOBF=1                  Mixed Boolean-Arithmetic (math complexity)
  SUBOBF=1                  Instruction Substitution
  CONSTOBF=1                Constant Encryption
  VECOBF=1                  Vectorization (SIMD confusion)
  SYMOBF=1                  Symbol Obfuscation
  INDOBF=1                  Indirect Branching
  FCNOBF=1                  Function Call Obfuscation
  FUNCOBF=1                 Function Obfuscation
  ANTIHOOK=1                Anti-Hook protection
  ANTIDBG=1                 Anti-Debug protection
  ANTIDUMP=1                Anti-Dump protection

COMPILATION PIPELINE:
  clang -mllvm -ensia [-mllvm -enable-medobf|-enable-maxobf] input.c -o output

  Or with environment variables:
  STRCRY=1 CSMOBF=1 MBAOBF=1 clang -mllvm -ensia input.c -o output

OBFUSCATION ORDER (Ensia pipeline):
  1. Environment Checks (debugger, hook, metadata detection)
  2. Data Hiding (string/constant encryption)
  3. Control Flow (Chaos State Machine / Flattening)
  4. Instruction Complexity (Substitution, MBA)
  5. Vectorization (SIMD lifting)
  6. Cleanup (debug strip, symbol rename)

================================================================================
COMMAND LINE OPTIONS
================================================================================

  -h, --help            Show help message
  -n COUNT              Number of commands to generate (default: 1)
  -i INPUT              Input C file (default: program.c)
  --preset PRESET       Use preset: medium, maximum (default: random)
  --seed SEED           Random seed for reproducibility
  -o OUTPUT             Output file (print to stdout if not specified)
  --json                Output in JSON format

================================================================================
"""

import random
import argparse
import json
from typing import List, Optional, Set
from dataclasses import dataclass, asdict


# ensia is built as an LLVM pass plugin (libEnsia.so) and installed to
# /usr/local/lib by the Dockerfile. clang only registers the `-mllvm -ensia`
# option (and consumes the STRCRY/CSMOBF/... env vars) ONCE the plugin is
# loaded; without this flag clang errors "Unknown command line argument
# '-ensia'" and emits no binary.
ENSIA_PLUGIN_PATH = "/usr/local/lib/libEnsia.so"


class ObfuscationPass:
    """Ensia obfuscation passes (environment variables)"""
    STRCRY = ("STRCRY=1", "String Encryption - XOR, GF8, Feistel")
    CSMOBF = ("CSMOBF=1", "Chaos State Machine - logistic-map flattening")
    MBAOBF = ("MBAOBF=1", "Mixed Boolean-Arithmetic - math complexity")
    SUBOBF = ("SUBOBF=1", "Instruction Substitution")
    CONSTOBF = ("CONSTOBF=1", "Constant Encryption")
    VECSOB = ("VECOBF=1", "Vectorization - SIMD confusion")
    SYMOBF = ("SYMOBF=1", "Symbol Obfuscation")
    INDOBF = ("INDOBF=1", "Indirect Branching")
    FCNOBF = ("FCNOBF=1", "Function Call Obfuscation")
    FUNCOBF = ("FUNCOBF=1", "Function Obfuscation")
    ANTIHOOK = ("ANTIHOOK=1", "Anti-Hook protection")
    ANTIDBG = ("ANTIDBG=1", "Anti-Debug protection")
    ANTIDUMP = ("ANTIDUMP=1", "Anti-Dump protection")


@dataclass
class EnsiaConfig:
    """Ensia obfuscation configuration"""
    passes: Set[str] = None
    preset: Optional[str] = None
    output_file: Optional[str] = None

    def __post_init__(self):
        if self.passes is None:
            self.passes = set()


def get_preset_passes(preset: str) -> Set[str]:
    """Get environment variables for a preset"""
    if preset == "medium" or preset == "medobf":
        # Medium protection: math complexity + flattening
        return {ObfuscationPass.MBAOBF[0], ObfuscationPass.CSMOBF[0],
                ObfuscationPass.STRCRY[0]}
    elif preset == "strong":
        # Strong obfuscation: every obfuscation pass WITHOUT the anti-*
        # trio (ANTIDBG / ANTIDUMP / ANTIHOOK). Those belong to the D
        # (anti-debug) dimension: emitting them from the O dimension would
        # put anti-debug code in D0 tasks and falsify the ground truth.
        excluded = {"ANTIDBG", "ANTIDUMP", "ANTIHOOK"}
        return {getattr(ObfuscationPass, attr)[0]
                for attr in dir(ObfuscationPass)
                if not attr.startswith('_')
                and isinstance(getattr(ObfuscationPass, attr), tuple)
                and attr not in excluded}
    elif preset == "maximum" or preset == "maxobf":
        # Maximum protection: all passes (including the anti-* trio — use
        # only when the D dimension is allowed to overlap)
        return {getattr(ObfuscationPass, attr)[0]
                for attr in dir(ObfuscationPass)
                if not attr.startswith('_') and isinstance(getattr(ObfuscationPass, attr), tuple)}
    return set()


def random_medium_passes() -> Set[str]:
    """Generate random medium obfuscation passes (production-ready)"""
    # Core medium passes
    passes = {ObfuscationPass.MBAOBF[0], ObfuscationPass.CSMOBF[0],
              ObfuscationPass.STRCRY[0]}
    # Maybe add others
    if random.random() < 0.3:
        passes.add(ObfuscationPass.SUBOBF[0])
    if random.random() < 0.2:
        passes.add(ObfuscationPass.INDOBF[0])
    return passes


def random_maximum_passes() -> Set[str]:
    """Generate random maximum obfuscation passes"""
    return {getattr(ObfuscationPass, attr)[0]
            for attr in dir(ObfuscationPass)
            if not attr.startswith('_') and isinstance(getattr(ObfuscationPass, attr), tuple)}


def generate_random_config(use_preset: Optional[str] = None) -> EnsiaConfig:
    """
    Generate a random Ensia configuration

    Args:
        use_preset: Optional preset name (medium, maximum)

    Returns:
        EnsiaConfig object with random settings
    """
    config = EnsiaConfig()

    if use_preset:
        config.passes = get_preset_passes(use_preset)
        config.preset = use_preset
    else:
        # Randomly choose between medium and maximum
        if random.random() < 0.7:
            config.passes = random_medium_passes()
            config.preset = "medium"
        else:
            config.passes = random_maximum_passes()
            config.preset = "maximum"

    return config


def config_to_command(config: EnsiaConfig, input_file: str, output_file: Optional[str] = None, multi_file: bool = False) -> str:
    """Convert configuration to Ensia obfuscation command.

    For multi-file projects (multi_file=True), outputs CFLAGS that can be
    integrated into the build command instead of a full compilation.
    """
    # Build environment variables
    env_vars = " ".join(sorted(config.passes))

    # Build mllvm flags
    mllvm_flags = "-mllvm -ensia"
    if config.preset:
        if config.preset == "medium" or config.preset == "medobf":
            mllvm_flags += " -mllvm -enable-medobf"
        elif config.preset == "maximum" or config.preset == "maxobf":
            mllvm_flags += " -mllvm -enable-maxobf"

    # -fpass-plugin loads libEnsia.so so that `-mllvm -ensia` is recognized
    plugin_flag = f"-fpass-plugin={ENSIA_PLUGIN_PATH}"

    if multi_file:
        # For multi-file projects: output CFLAGS for the build system.
        # The pass-enable variables (STRCRY=1 ...) are ENV VARS, not compiler
        # flags — putting them inside CFLAGS makes cc treat them as input
        # files ("cc: error: STRCRY=1: No such file or directory"). They go
        # into ENSIA_ENV, which the Dockerfile snippet exports next to the
        # build command; ENSIA_CFLAGS carries only real flags.
        cflags = f"{plugin_flag} {mllvm_flags}"
        return f"ENSIA_ENV=\"{env_vars}\" && ENSIA_CFLAGS=\"{cflags}\""
    else:
        # Determine output filename
        out = output_file or config.output_file
        if not out:
            if input_file.endswith(".c"):
                out = input_file[:-2] + "_ensia"
            else:
                out = input_file + "_ensia"

        # Generate the obfuscation command
        if env_vars:
            cmd = f"{env_vars} clang {plugin_flag} {mllvm_flags} {input_file} -o {out}"
        else:
            cmd = f"clang {plugin_flag} {mllvm_flags} {input_file} -o {out}"

        return cmd


def generate_commands(
    count: int = 1,
    input_file: str = "program.c",
    preset: Optional[str] = None,
    seed: Optional[int] = None,
    multi_file: bool = False
) -> List[str]:
    """
    Generate random Ensia obfuscation command(s)

    Args:
        count: Number of commands to generate
        input_file: Input C file
        preset: Optional preset (medium, maximum)
        seed: Random seed for reproducibility

    Returns:
        List of command strings
    """
    if seed is not None:
        random.seed(seed)

    commands = []
    for i in range(count):
        config = generate_random_config(preset)
        base = input_file[:-2] if input_file.endswith(".c") else input_file
        output = f"{base}_ensia_{i}"
        cmd = config_to_command(config, input_file, output, multi_file)
        commands.append(cmd)

    return commands


def main():
    parser = argparse.ArgumentParser(
        description="Ensia (OLLVM-Next) Random Command Generator - Modern LLVM obfuscation"
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
        "--preset",
        type=str,
        choices=["medium", "medobf", "strong", "maximum", "maxobf"],
        default=None,
        help="Use preset: medium (production), strong (all obfuscation, no "
             "anti-debug/anti-dump/anti-hook — keeps O independent of D), "
             "maximum (everything)"
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
        help="Multi-file mode: output CFLAGS instead of full compilation"
    )

    args = parser.parse_args()

    commands = generate_commands(
        count=args.count,
        input_file=args.input,
        preset=args.preset,
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
