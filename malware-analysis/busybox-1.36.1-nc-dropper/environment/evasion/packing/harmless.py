#!/usr/bin/env python3
"""
hARMless Random Command Generator for ELF/Linux Binaries
Generates randomized hARMless packing commands specifically for Linux x86-64 ELF targets

================================================================================
USAGE EXAMPLES
================================================================================

# Generate a single command with default settings:
./harmless.py -i program

# Generate commands with specific architecture:
./harmless.py -i program --arch x86_64

# Generate multiple variants (polymorphic - each is unique):
./harmless.py -i program -n 5

# Use seed for reproducible results:
./harmless.py -i program --seed 42

# Output to file:
./harmless.py -i program -n 10 -o commands.txt
./harmless.py -i program -n 10 --json -o commands.json

================================================================================
HARMLESS OPTIONS
================================================================================

ARCHITECTURES:
  x86_64             x86-64 (AMD64) Linux binaries
  arm64              ARM64 (AArch64) Linux binaries

ENCRYPTION LAYERS:
  Layer 1            AES-256-ECB encryption
  Layer 2            ChaCha20 stream cipher
  Layer 3            RC4 stream cipher

FEATURES:
  memfd_create       In-memory execution via memfd_create
  polymorphic        Every packed binary is bytewise unique
  anti-debug         Built-in anti-debugging and anti-sandbox
  crc32              Integrity verification
  direct_syscalls    Bypasses userland hooks

MEMORY WRITE METHODS:
  io_uring           Use io_uring (default, kernel >= 5.1)
  mmap               Use mmap
  write              Use write(2)

OTHER OPTIONS:
  -n                 Number of commands to generate
  -i INPUT           Input filename
  -o OUTPUT          Output file (print to stdout if not specified)

================================================================================
COMMAND LINE OPTIONS
================================================================================

  -h, --help            Show help message
  -n COUNT              Number of commands to generate (default: 1)
  -i INPUT              Input filename (default: program)
  --arch ARCH           Target architecture: x86_64, arm64 (default: x86_64)
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


class Architecture(Enum):
    """Target architecture options"""
    X86_64 = ("x86_64", "x86-64 (AMD64) Linux binaries")
    ARM64 = ("arm64", "ARM64 (AArch64) Linux binaries")


@dataclass
class HarmlessConfig:
    """hARMless configuration for ELF/Linux binaries"""
    architecture: Architecture = Architecture.X86_64
    output_file: Optional[str] = None


def generate_random_config(architecture: Optional[str] = None) -> HarmlessConfig:
    """
    Generate a hARMless configuration for ELF/Linux

    Architecture defaults to x86_64 and is only overridden by an explicit
    --arch: the challenge containers are x86-64, so emitting an arm64 stub
    (the old random picker did ~20% of the time) produced non-runnable
    binaries. arm64 remains selectable by hand for cross-arch use.

    Returns:
        HarmlessConfig object
    """
    config = HarmlessConfig()
    config.architecture = Architecture.X86_64
    if architecture:
        if architecture.lower() == "arm64":
            config.architecture = Architecture.ARM64
        else:
            config.architecture = Architecture.X86_64
    return config


def _abs_path(p: str) -> str:
    """Make a WORKDIR-relative path absolute under /src.

    hARMless is driven via ``make -C /opt/harmless``, so make resolves relative
    INPUT/OUTPUT paths against /opt/harmless (NOT the Docker WORKDIR). The
    protection pipeline always builds under WORKDIR /src, so prefix the path
    with /src. Already-absolute paths are returned unchanged.
    """
    return p if p.startswith("/") else f"/src/{p}"


def config_to_command(config: HarmlessConfig, input_file: str, output_file: Optional[str] = None) -> str:
    """Convert configuration to hARMless build command string.

    hARMless packs through its Makefile's ``pack`` target, which runs the
    packer AND stubgen (packer alone emits a non-runnable intermediate blob).
    That Makefile lives at /opt/harmless, so the command must (1) run there via
    ``-C /opt/harmless`` and (2) name the ``pack`` target — the default ``all``
    target only BUILDS the tools and ignores INPUT/OUTPUT. INPUT/OUTPUT must be
    absolute (see _abs_path).
    """
    out = output_file or config.output_file or f"{input_file}_packed"
    return (
        f"make pack -C /opt/harmless ARCH={config.architecture.value[0]} "
        f"INPUT={_abs_path(input_file)} OUTPUT={_abs_path(out)}"
    )


def generate_commands(
    count: int = 1,
    input_file: str = "program",
    architecture: Optional[str] = None,
    seed: Optional[int] = None
) -> List[str]:
    """
    Generate hARMless command(s) for ELF/Linux

    Args:
        count: Number of commands to generate (default: 1)
        input_file: Input filename
        architecture: Explicit architecture (x86_64 or arm64; default x86_64)
        seed: Random seed for reproducibility

    Returns:
        List of command strings
    """
    if seed is not None:
        random.seed(seed)

    commands = []
    for i in range(count):
        config = generate_random_config(architecture)
        output = f"{input_file}_packed_{i}"
        cmd = config_to_command(config, input_file, output)
        commands.append(cmd)

    return commands


def main():
    parser = argparse.ArgumentParser(
        description="hARMless Random Command Generator for ELF/Linux - Generate randomized hARMless packing commands"
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
        "--arch",
        type=str,
        choices=["x86_64", "arm64"],
        help="Target architecture (default: x86_64 — the challenge containers "
             "are x86-64; arm64 only for explicit cross-arch use)"
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

    commands = generate_commands(
        count=args.count,
        input_file=args.input,
        architecture=args.arch,
        seed=args.seed
    )

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
