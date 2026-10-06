#!/usr/bin/env python3
"""
Tigress Random Command Generator for C Obfuscation
Generates randomized Tigress obfuscation commands for Linux/ELF targets

================================================================================
USAGE EXAMPLES
================================================================================

# List all obfuscation categories and their transformations:
./tigress.py --list

# Generate a single command with default settings (data + control obfuscation):
./tigress.py -i program.c

# Generate commands for specific obfuscation categories:
./tigress.py -i program.c -c data              # Data-based only
./tigress.py -i program.c -c control           # Control-flow only
./tigress.py -i program.c -c virtualize        # Virtualization only
./tigress.py -i program.c -c anti              # Anti-analysis only
./tigress.py -i program.c -c runtime           # Runtime/JIT only

# Combine multiple categories:
./tigress.py -i program.c -c data,control
./tigress.py -i program.c -c control,virtualize,anti
./tigress.py -i program.c -c data,control,virtualize,anti,runtime  # Full protection

# Specify target functions:
./tigress.py -i app.c -f main encrypt decrypt

# Generate multiple variants:
./tigress.py -i program.c -n 10 --seed 42

# Output to file:
./tigress.py -i program.c -o commands.txt
./tigress.py -i program.c --json -o commands.json

================================================================================
OBFUSCATION CATEGORIES
================================================================================

DATA-BASED: constant expansion, encoding, dead code, arithmetic replacement
  - EncodeLiterals      Encode integer/string literals
  - EncodeData          Encode integer variables
  - EncodeArithmetic    Encode arithmetic operations
  - EncodeExternal      Hide API calls
  - RndArgs             Randomize function arguments

CONTROL-BASED: locality breaking, indirect jumps, opaque predicates, flattening
  - Flatten             Remove control flow (flattening)
  - Split               Split function into parts
  - Merge               Merge multiple functions
  - Inline              Inline functions
  - AddOpaque           Add opaque branches (opaque predicates)
  - EncodeBranches      Make branch targets harder to determine

VIRTUALIZATION: VM protection
  - Virtualize          Turn function into interpreter

ANTI-ANALYSIS: disrupt static/dynamic analysis tools
  - AntiAliasAnalysis   Disrupt alias analysis
  - AntiTaintAnalysis   Disrupt taint analysis
  - AntiBranchAnalysis  Disrupt branch analysis

RUNTIME: dynamic transformations
  - Jit                 Runtime code generation
  - JitDynamic          Continuous self-modification
  - SelfModify          Function modifies own code
  - Checksum            Integrity checkers

================================================================================
COMMAND LINE OPTIONS
================================================================================

  -h, --help            Show help message
  -n COUNT              Number of commands to generate (default: 1)
  -i INPUT              Input C file (default: program.c)
  -f FUNCTIONS [FUNCS...] Functions to obfuscate (default: main)
  --init-func NAME      Initialization function name (default: init_tigress)
  -c CATEGORIES         Obfuscation categories: data,control,virtualize,anti,runtime
  -s SEED               Random seed for reproducibility
  -o OUTPUT             Output file (print to stdout if not specified)
  --json                Output in JSON format
  --list                List all obfuscation categories and transformations

================================================================================
"""

import random
import argparse
from typing import List, Optional, Dict
from dataclasses import dataclass, field
from enum import Enum


# =============================================================================
# ENUMS - Tigress Options
# =============================================================================

class Environment(Enum):
    """Target environment options"""
    X86_64_LINUX = ("x86_64:Linux:Gcc:4.6", "64-bit Linux with GCC")
    X86_64_LINUX_CLANG = ("x86_64:Linux:Clang:10.0", "64-bit Linux with Clang")
    I386_LINUX = ("i386:Linux:Gcc:4.6", "32-bit Linux with GCC")
    ARM64_LINUX = ("arm64:Linux:Gcc:8.0", "ARM64 Linux with GCC")
    WASM = ("wasm:Linux:Emcc:4.6", "WebAssembly with Emscripten")


class Verbosity(Enum):
    QUIET = ("0", "no output")
    NORMAL = ("1", "normal output")
    VERBOSE = ("2", "verbose output")
    DEBUG = ("3", "debug output")


class VirtualizeDispatch(Enum):
    """Valid --VirtualizeDispatch values for tigress 4.0.11.

    Each value was verified end-to-end against tigress 4.0.11: the four values
    below produce functional binaries (correct output for both valid/invalid
    inputs). 'call' and 'linear' are intentionally OMITTED — 'call' fails at
    link time and 'linear' hits a tigress codegen bug (``struct has no member
    named ...``), so neither can be emitted by a generic generator.

    Note: 'goto' is valid for Flatten but NOT for Virtualize, so the two
    transforms use separate enums.
    """
    SWITCH = ("switch", "dispatch via while-switch")
    DIRECT = ("direct", "direct threading dispatch")
    INDIRECT = ("indirect", "indirect threading dispatch")
    IFNEST = ("ifnest", "if-based nesting dispatch")


class FlattenDispatch(Enum):
    SWITCH = ("switch", "switch-based dispatch")
    GOTO = ("goto", "goto-based dispatch")


class EncodeLiteralsKinds(Enum):
    """Valid --EncodeLiteralsKinds values for tigress 4.0.11."""
    INTEGER = ("integer", "encode integer literals")
    STRING = ("string", "encode string literals")
    ALL = ("*", "encode all literals")


class EncodeDataKinds(Enum):
    """Valid --EncodeDataKinds values for tigress 4.0.11."""
    INTEGER = ("integer", "encode integer variables")
    ALL = ("*", "encode all data")


class EncodeArithmeticKinds(Enum):
    """Valid --EncodeArithmeticKinds values for tigress 4.0.11."""
    BUILTIN = ("builtin", "builtin arithmetic operations")
    PLUGINS = ("plugins", "plugin arithmetic operations")
    ALL = ("*", "all arithmetic operations")


class AntiBranchAnalysisKind(Enum):
    GOTO2PUSH = ("goto2push", "replace gotos with push")
    GOTO2CALL = ("goto2call", "replace gotos with calls")
    BRANCHFUNS = ("branchFuns", "use branch functions")


# =============================================================================
# CATEGORIES - Obfuscation Classification
# =============================================================================

class ObfuscationCategory(Enum):
    """M2 Complication Obfuscation Categories"""
    DATA = ("data", "Data-Based: constants, encoding, dead code, arithmetic")
    CONTROL = ("control", "Control-Based: locality, indirect jumps, opaque predicates, flattening")
    VIRTUALIZE = ("virtualize", "Virtualization: VM protection")
    INIT = ("init", "Initialization: setup transformations")
    CLEANUP = ("cleanup", "Cleanup: final transformations")
    ANTI_ANALYSIS = ("anti", "Anti-Analysis: disrupt analysis tools")
    RUNTIME = ("runtime", "Runtime: JIT, self-modification")


# =============================================================================
# TRANSFORMATIONS BY CATEGORY
# =============================================================================

TRANSFORMATIONS_BY_CATEGORY = {
    # Data-Based Obfuscation (M2): constant expansion, encoding, dead code, arithmetic replacement
    ObfuscationCategory.DATA: [
        "EncodeLiterals",      # Encode integer/string literals
        # NOTE: "EncodeData" is intentionally omitted — tigress 4.0.11 requires
        # --EncodeDataVars=<names> (source-specific variable names) which a
        # generic command generator cannot supply. It errors with
        # NOT-ENOUGH-VARS without them.
        "EncodeArithmetic",   # Encode arithmetic operations
        "EncodeExternal",     # Hide API calls
        "RndArgs",            # Randomize arguments
    ],

    # Control-Based Obfuscation (M2): locality breaking, indirect jumps, opaque predicates, flattening
    ObfuscationCategory.CONTROL: [
        "Flatten",            # Remove control flow
        "Split",              # Split function into parts
        "Merge",              # Merge multiple functions
        "Inline",             # Inline functions
        "AddOpaque",          # Add opaque branches (opaque predicates)
        "EncodeBranches",     # Make branch targets harder to determine
    ],

    # Virtualization: VM protection
    ObfuscationCategory.VIRTUALIZE: [
        "Virtualize",         # Turn function into interpreter
    ],

    # Initialization: required setup
    ObfuscationCategory.INIT: [
        "InitEntropy",        # Initialize randomness
        "InitOpaque",         # Initialize opaque predicates
        "InitBranchFuns",     # Initialize branch functions
    ],

    # Cleanup: final transformations
    ObfuscationCategory.CLEANUP: [
        "CleanUp",            # Clean up generated code
        "Optimize",           # Optimize code
    ],

    # Anti-Analysis: disrupt static/dynamic analysis
    ObfuscationCategory.ANTI_ANALYSIS: [
        "AntiAliasAnalysis",   # Disrupt alias analysis
        "AntiTaintAnalysis",   # Disrupt taint analysis
        "AntiBranchAnalysis",  # Disrupt branch analysis
    ],

    # Runtime: dynamic transformations
    ObfuscationCategory.RUNTIME: [
        "Jit",                # Runtime code generation
        "JitDynamic",         # Continuous self-modification
        "SelfModify",         # Function modifies own code
        "Checksum",           # Integrity checkers
    ],
}


# =============================================================================
# TRANSFORMATION CREATOR FUNCTIONS
# =============================================================================

@dataclass
class TigressTransformation:
    """Represents a single Tigress transformation with options"""
    name: str
    options: Dict[str, str] = field(default_factory=dict)
    skip: bool = False

    def to_command_args(self) -> str:
        """Convert transformation to command line arguments"""
        if self.skip:
            return f"--Transform={self.name} --Skip=true"

        args = [f"--Transform={self.name}"]
        for key, value in self.options.items():
            args.append(f"--{key}={value}")
        return " ".join(args)


def create_init_transformations(init_func: str) -> List[TigressTransformation]:
    """Create standard init transformations"""
    return [
        TigressTransformation("InitEntropy", {"Functions": init_func, "InitEntropyKinds": "vars"}),
        TigressTransformation("InitOpaque", {"Functions": init_func, "InitOpaqueStructs": "list,array,env"}),
        TigressTransformation("InitBranchFuns", {"InitBranchFunsCount": str(random.randint(1, 3))}),
    ]


def create_virtualize_transformation(functions: str) -> TigressTransformation:
    """Create a Virtualize transformation"""
    dispatch = random.choice(list(VirtualizeDispatch))
    return TigressTransformation("Virtualize", {
        "Functions": functions,
        "VirtualizeDispatch": dispatch.value[0],
    })


def create_flatten_transformation(functions: str) -> TigressTransformation:
    """Create a Flatten transformation"""
    dispatch = random.choice(list(FlattenDispatch))
    return TigressTransformation("Flatten", {
        "Functions": functions,
        "FlattenDispatch": dispatch.value[0],
        "FlattenRandomizeBlocks": "true",
        "FlattenObfuscateNext": str(random.choice([True, False])).lower(),
    })


def create_add_opaque_transformation(functions: str) -> TigressTransformation:
    """Create an AddOpaque transformation"""
    structs = random.choice(["list", "array", "list,array"])
    return TigressTransformation("AddOpaque", {
        "Functions": functions,
        "AddOpaqueStructs": structs,
        "AddOpaqueKinds": "true",
    })


def create_encode_arithmetic_transformation(functions: str) -> TigressTransformation:
    """Create an EncodeArithmetic transformation"""
    kinds = random.choice(list(EncodeArithmeticKinds))
    return TigressTransformation("EncodeArithmetic", {
        "Functions": functions,
        "EncodeArithmeticKinds": kinds.value[0]
    })


def create_encode_literals_transformation(functions: str) -> TigressTransformation:
    """Create an EncodeLiterals transformation"""
    kinds = random.choice(list(EncodeLiteralsKinds))
    return TigressTransformation("EncodeLiterals", {
        "Functions": functions,
        "EncodeLiteralsKinds": kinds.value[0]
    })


def create_encode_data_transformation(functions: str) -> TigressTransformation:
    """Create an EncodeData transformation"""
    kinds = random.choice(list(EncodeDataKinds))
    return TigressTransformation("EncodeData", {
        "Functions": functions,
        "EncodeDataKinds": kinds.value[0]
    })


def create_anti_branch_analysis_transformation(functions: str) -> TigressTransformation:
    """Create an AntiBranchAnalysis transformation"""
    kind = random.choice(list(AntiBranchAnalysisKind))
    return TigressTransformation("AntiBranchAnalysis", {
        "Functions": functions,
        "AntiBranchAnalysisKinds": kind.value[0],
        "AntiBranchAnalysisObfuscateBranchFunCall": str(random.choice([True, False])).lower(),
        "AntiBranchAnalysisBranchFunFlatten": str(random.choice([True, False])).lower(),
    })


def create_merge_transformation(functions: str) -> TigressTransformation:
    """Create a Merge transformation"""
    return TigressTransformation("Merge", {
        "Functions": functions,
        "MergeFlatten": "false",
        "MergeName": f"MERGED_{random.randint(100, 999)}",
    })


def create_jit_dynamic_transformation(functions: str) -> TigressTransformation:
    """Create a JitDynamic transformation"""
    codecs = random.choice(["xor", "xtea", "aes"])
    fraction = random.choice([100, 75, 50, 25, 10])
    return TigressTransformation("JitDynamic", {
        "Functions": functions,
        "JitDynamicCodecs": codecs,
        "JitDynamicBlockFraction": f"%{fraction}",
    })


def create_self_modify_transformation(functions: str) -> TigressTransformation:
    """Create a SelfModify transformation"""
    return TigressTransformation("SelfModify", {
        "Functions": functions,
        "SelfModifySubExpressions": str(random.choice([True, False])).lower(),
        "SelfModifyBogusInstructions": str(random.randint(5, 20)),
    })


def create_checksum_transformation(functions: str) -> TigressTransformation:
    """Create a Checksum transformation"""
    return TigressTransformation("Checksum", {
        "Functions": functions,
        "ChecksumPrefix": f"TIGRESS_CHECKSUM_{random.randint(100, 999)}",
    })


def create_cleanup_transformation() -> TigressTransformation:
    """Create a CleanUp transformation.

    NOTE: the `names` kind (identifier renaming) is deliberately EXCLUDED. tigress
    CleanUp `names` renames *all* identifiers in the obfuscated translation unit,
    including externally-visible globals/functions exported to other .c files
    (e.g. redis server.c's `server` global and `mstime()`). Other translation
    units still reference the original names, so the link fails with
    `undefined reference`. This breaks every multi-file target (redis, bash,
    curl, binutils, ...); single-file targets merely lose cosmetic renaming.
    `annotations` (strip tigress metadata) and `fold` (constant folding) are
    symbol-stable and safe for both."""
    kinds = random.choice([
        "annotations",
        "annotations,fold",
        "fold",
        "annotations"
    ])
    return TigressTransformation("CleanUp", {"CleanUpKinds": kinds})


# Transformation creators by name
TRANSFORMATION_CREATORS: Dict[str, callable] = {
    "Virtualize": create_virtualize_transformation,
    "Flatten": create_flatten_transformation,
    "AddOpaque": create_add_opaque_transformation,
    "EncodeArithmetic": create_encode_arithmetic_transformation,
    "EncodeLiterals": create_encode_literals_transformation,
    "EncodeData": create_encode_data_transformation,
    "AntiBranchAnalysis": create_anti_branch_analysis_transformation,
    "Merge": create_merge_transformation,
    "JitDynamic": create_jit_dynamic_transformation,
    "SelfModify": create_self_modify_transformation,
    "Checksum": create_checksum_transformation,
}


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class TigressObfuscationConfig:
    """Tigress obfuscation configuration"""
    seed: int = 0
    statistics: bool = False
    verbosity: Verbosity = Verbosity.QUIET
    environment: Environment = Environment.X86_64_LINUX

    # Transformations
    transformations: List[TigressTransformation] = field(default_factory=list)

    # Common settings
    init_function: str = "init_tigress"
    target_functions: List[str] = field(default_factory=lambda: ["main"])
    output_file: Optional[str] = None

    def to_command(self, input_file: str) -> str:
        """Convert configuration to Tigress command"""
        cmd_parts = [
            "tigress",
            f"--Seed={self.seed}",
            f"--Statistics={1 if self.statistics else 0}",
            f"--Verbosity={self.verbosity.value[0]}",
        ]

        if self.environment != Environment.X86_64_LINUX:
            cmd_parts.append(f"--Environment={self.environment.value[0]}")

        for transform in self.transformations:
            cmd_parts.append(transform.to_command_args())

        if self.output_file:
            cmd_parts.append(f"--out={self.output_file}")
        cmd_parts.append(input_file)

        return " ".join(cmd_parts)


def generate_obfuscation_config(
    categories: List[ObfuscationCategory],
    init_func: str = "init_tigress",
    target_functions: List[str] = None,
    seed: int = 0
) -> TigressObfuscationConfig:
    """Generate obfuscation config from selected categories"""
    if target_functions is None:
        target_functions = ["main"]

    config = TigressObfuscationConfig(
        seed=seed,
        verbosity=Verbosity.QUIET,
        init_function=init_func,
        target_functions=target_functions,
    )

    functions_str = ",".join(target_functions)

    # Transforms that require more than one target function (e.g. Merge combines
    # several functions into one). Skip them when only a single function is targeted.
    multi_function_transforms = {"Merge"}

    # Virtualize is incompatible with EncodeLiterals on the SAME function in
    # tigress 4.0.11: Flatten + EncodeLiterals + Virtualize miscompiles (the
    # encoded literals survive flattening but the VM emits wrong bytecode,
    # producing binaries that return wrong results or no output). Verified
    # empirically — Flatten + AddOpaque + EncodeArithmetic + Virtualize works at
    # full strength, so dropping only EncodeLiterals keeps VM configs strong.
    # EncodeArithmetic still provides data encoding when VM is selected.
    has_virtualize = ObfuscationCategory.VIRTUALIZE in categories
    vm_incompatible_with_virtualize = {"EncodeLiterals"}

    # Always add init transformations
    config.transformations.extend(create_init_transformations(init_func))

    # Add transformations from selected categories
    for category in categories:
        for transform_name in TRANSFORMATIONS_BY_CATEGORY.get(category, []):
            creator = TRANSFORMATION_CREATORS.get(transform_name)
            if not creator:
                continue
            if has_virtualize and transform_name in vm_incompatible_with_virtualize:
                continue
            if random.random() <= 0.2:  # 80% chance to include
                continue
            if transform_name in multi_function_transforms and len(target_functions) < 2:
                continue
            config.transformations.append(creator(functions_str))

    # Always add cleanup
    config.transformations.append(create_cleanup_transformation())

    return config


def list_categories():
    """Print all obfuscation categories and their transformations"""
    print("Tigress Obfuscation Categories (M2 Complication):")
    print("=" * 60)

    for cat in ObfuscationCategory:
        print(f"\n{cat.value[1].upper()}")
        print("-" * 40)
        for trans in TRANSFORMATIONS_BY_CATEGORY.get(cat, []):
            print(f"  - {trans}")
    print()


def generate_commands(
    count: int = 1,
    input_file: str = "program.c",
    categories: Optional[List[ObfuscationCategory]] = None,
    init_func: str = "init_tigress",
    target_functions: Optional[List[str]] = None,
    seed: Optional[int] = None
) -> List[str]:
    """Generate Tigress obfuscation commands"""
    if categories is None:
        categories = [ObfuscationCategory.DATA, ObfuscationCategory.CONTROL]

    commands = []
    for i in range(count):
        use_seed = seed + i if seed is not None else 0
        # Seed Python's RNG so transform SELECTION (dispatch, which transforms
        # are included, option values) is reproducible per --seed. The seed is
        # also passed to tigress-the-tool via --Seed= below, which makes the
        # tool's own output reproducible too. Without this, two runs with the
        # same --seed emit different commands.
        random.seed(use_seed)
        output = f"{input_file.rsplit('.', 1)[0]}_obf_{i}.c"

        config = generate_obfuscation_config(
            categories=categories,
            init_func=init_func,
            target_functions=target_functions,
            seed=use_seed
        )
        config.output_file = output
        commands.append(config.to_command(input_file))

    return commands


def parse_categories(arg: str) -> List[ObfuscationCategory]:
    """Parse category argument string to list of categories"""
    cat_map = {cat.value[0]: cat for cat in ObfuscationCategory}
    names = arg.split(",")
    return [cat_map[name.strip()] for name in names if name.strip() in cat_map]


def main():
    parser = argparse.ArgumentParser(
        description="Tigress Random Command Generator - Generate randomized Tigress obfuscation commands"
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
        "-f", "--functions",
        type=str,
        nargs="+",
        default=["main"],
        help="Functions to obfuscate (default: main)"
    )
    parser.add_argument(
        "--init-func",
        type=str,
        default="init_tigress",
        help="Initialization function name (default: init_tigress)"
    )
    parser.add_argument(
        "-c", "--categories",
        type=str,
        default="data,control",
        help="Obfuscation categories: data,control,virtualize,anti,runtime (default: data,control)"
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
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all obfuscation categories and transformations"
    )

    args = parser.parse_args()

    if args.list:
        list_categories()
        return

    categories = parse_categories(args.categories)

    commands = generate_commands(
        count=args.count,
        input_file=args.input,
        categories=categories,
        init_func=args.init_func,
        target_functions=args.functions,
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
