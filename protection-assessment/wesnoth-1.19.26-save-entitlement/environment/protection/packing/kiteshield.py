#!/usr/bin/env python3
"""
Kiteshield Random Command Generator for ELF/Linux Binaries
Generates randomized Kiteshield packing commands specifically for Linux x86-64 ELF targets

================================================================================
USAGE EXAMPLES
================================================================================

# Generate a single command with default settings:
./kiteshield.py -i program

# Generate commands with specific build type:
./kiteshield.py -i program --build-type debug

# Generate multiple variants:
./kiteshield.py -i program -n 5

# Always include layer 2 encryption:
./kiteshield.py -i program --force-layer2

# Use seed for reproducible results:
./kiteshield.py -i program --seed 42

# Output to file:
./kiteshield.py -i program -n 10 -o commands.txt
./kiteshield.py -i program -n 10 --json -o commands.json

================================================================================
KITESHIELD OPTIONS
================================================================================

BUILD TYPES:
  release             Standard release build with all optimizations (default)
  debug               Debug build with verbose logging, anti-debug disabled
  debug-antidebug     Debug build with anti-debugging enabled

ENCRYPTION LAYERS:
  Layer 1             Whole-binary RC4 encryption (always applied)
  Layer 2             Per-function RC4 encryption with ptrace runtime engine
                      - Requires unstripped binary (symbol table needed)
                      - Use -n flag to disable for stripped binaries

ANTI-DEBUGGING:
  --no-anti-debug     Disable anti-debugging features (debug builds only)

OTHER OPTIONS:
  -n                  Disable layer 2 encryption (for stripped binaries)
  -o FILE             Write output to FILE

================================================================================
COMMAND LINE OPTIONS
================================================================================

  -h, --help            Show help message
  -n COUNT              Number of commands to generate (default: 1)
  -i INPUT              Input filename (default: program)
  --build-type TYPE     Build type: release, debug, debug-antidebug (default: random)
  --force-layer2        Force layer 2 encryption (don't use -n flag)
  --seed SEED           Random seed for reproducibility
  -o OUTPUT             Output file (print to stdout if not specified)
  --json                Output in JSON format

================================================================================
"""

import random
import argparse
from typing import List, Optional
from dataclasses import dataclass
from enum import Enum


class BuildType(Enum):
    """Kiteshield build type options"""
    RELEASE = ("release", "Standard release build with all optimizations")
    DEBUG = ("debug", "Debug build with verbose logging, anti-debug disabled")
    DEBUG_ANTIDEBUG = ("debug-antidebug", "Debug build with anti-debugging enabled")


class Layer2Option(Enum):
    """Layer 2 encryption options"""
    ENABLED = ("", "Enable layer 2 encryption (default, requires unstripped binary)")
    DISABLED = ("-n", "Disable layer 2 encryption (for stripped binaries)")


class AntiDebugOption(Enum):
    """Anti-debugging options"""
    DEFAULT = ("", "Use default anti-debugging for build type")
    DISABLED = ("--no-anti-debug", "Disable anti-debugging features")


@dataclass
class KiteshieldConfig:
    """Kiteshield configuration for ELF/Linux binaries"""
    build_type: BuildType = BuildType.RELEASE
    layer2: Layer2Option = Layer2Option.ENABLED
    anti_debug: AntiDebugOption = AntiDebugOption.DEFAULT
    output_file: Optional[str] = None


def random_build_type() -> BuildType:
    """Select the build type.

    Defaults to RELEASE: the debug variants disable kiteshield's anti-debug
    and enable verbose logging (packer internals — and potentially key
    material — leak straight into the Docker build log). Debug builds remain
    reachable via the explicit --build-type flag.
    """
    return BuildType.RELEASE


def random_layer2_option(force_layer2: bool = False) -> Layer2Option:
    """Select the layer 2 option.

    Layer 2 (per-function / inner encryption) needs an UNSTRIPPED binary
    (kiteshield reads the symbol table). The protection pipeline always ships
    STRIPPED binaries (``gcc -O2 -s``), and on a stripped binary kiteshield
    SILENTLY writes no output file (exit 0) unless ``-n`` is passed. So the
    default is ``-n`` (Layer2Option.DISABLED). Pass ``force_layer2=True`` only
    when the input binary is known to be unstripped.
    """
    if force_layer2:
        return Layer2Option.ENABLED
    return Layer2Option.DISABLED


def random_anti_debug(build_type: BuildType) -> AntiDebugOption:
    """
    Select anti-debug option based on build type

    Args:
        build_type: The selected build type

    Note: --no-anti-debug only makes sense for debug builds
    """
    if build_type == BuildType.DEBUG:
        # For debug builds, randomly disable anti-debug
        return AntiDebugOption.DISABLED if random.random() < 0.3 else AntiDebugOption.DEFAULT
    elif build_type == BuildType.DEBUG_ANTIDEBUG:
        # debug-antidebug explicitly enables anti-debug
        return AntiDebugOption.DEFAULT
    else:
        # Release builds always have anti-debug
        return AntiDebugOption.DEFAULT


def generate_random_config(
    force_layer2: bool = False
) -> KiteshieldConfig:
    """
    Generate a Kiteshield configuration for ELF/Linux

    Args:
        force_layer2: Whether to force layer 2 encryption

    Returns:
        KiteshieldConfig object with settings (release build by default)
    """
    config = KiteshieldConfig()

    config.build_type = random_build_type()
    config.layer2 = random_layer2_option(force_layer2)
    config.anti_debug = random_anti_debug(config.build_type)

    return config


def config_to_command(config: KiteshieldConfig, input_file: str, output_file: Optional[str] = None) -> str:
    """Convert configuration to Kiteshield command string"""
    cmd_parts = ["kiteshield"]

    # Layer 2 option
    if config.layer2.value[0]:
        cmd_parts.append(config.layer2.value[0])

    # Anti-debug option
    if config.anti_debug.value[0]:
        cmd_parts.append(config.anti_debug.value[0])

    # Input file
    cmd_parts.append(input_file)

    # Output file
    out = output_file or config.output_file
    if out:
        cmd_parts.append(out)
    else:
        # Generate default output name
        cmd_parts.append(f"{input_file}_packed")

    return " ".join(cmd_parts)


def generate_commands(
    count: int = 1,
    input_file: str = "program",
    force_layer2: bool = False,
    seed: Optional[int] = None
) -> List[str]:
    """
    Generate random Kiteshield command(s) for ELF/Linux

    Args:
        count: Number of commands to generate (default: 1)
        input_file: Input filename
        force_layer2: Whether to force layer 2 encryption
        seed: Random seed for reproducibility

    Returns:
        List of command strings
    """
    if seed is not None:
        random.seed(seed)

    commands = []
    for i in range(count):
        config = generate_random_config(force_layer2)
        output = f"{input_file}_packed_{i}"
        cmd = config_to_command(config, input_file, output)
        commands.append(cmd)

    return commands


def main():
    parser = argparse.ArgumentParser(
        description="Kiteshield Random Command Generator for ELF/Linux - Generate randomized Kiteshield packing commands"
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
        default="program",
        help="Input filename (default: program)"
    )
    parser.add_argument(
        "--build-type",
        type=str,
        choices=["release", "debug", "debug-antidebug"],
        help="Build type (default: release — debug disables anti-debug and "
             "logs verbosely, leaking packer internals into build logs)"
    )
    parser.add_argument(
        "--force-layer2",
        action="store_true",
        help="Force layer 2 encryption (don't use -n flag)"
    )
    parser.add_argument(
        "-s", "--seed",
        type=int,
        help="Random seed for reproducibility"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output file (print to stdout if not specified)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
    )

    args = parser.parse_args()

    # Handle seed first
    if args.seed is not None:
        random.seed(args.seed)

    commands = []
    for i in range(args.count):
        config = generate_random_config(args.force_layer2)

        # Override build type if specified. BuildType members carry TUPLE
        # values ("release", "desc"), so a plain BuildType("release")
        # construction raises ValueError — look the member up instead.
        if args.build_type:
            config.build_type = next(
                bt for bt in BuildType if bt.value[0] == args.build_type
            )

        output = f"{args.input}_packed_{i}"
        cmd = config_to_command(config, args.input, output)
        commands.append(cmd)

    if args.json:
        import json
        output = json.dumps(commands, indent=2)
    else:
        output = "\n".join(commands)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Generated {args.count} commands, saved to {args.output}")
    else:
        print(output)


if __name__ == "__main__":
    main()
