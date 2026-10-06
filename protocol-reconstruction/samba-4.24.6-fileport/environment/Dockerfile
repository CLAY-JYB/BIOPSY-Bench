# ============================================================================================
# PARALLEL BUILD LAYOUT (BuildKit)
#
# BuildKit builds stages with no FROM / COPY --from edge between them CONCURRENTLY.
# The classic builder (DOCKER_BUILDKIT=0) serializes this file back into one long
# chain — build with `docker buildx build` (Docker 23+ default).
#
# Stage graph (edges = FROM / COPY --from):
#
#   ubuntu:22.04
#     └─ apt-build ─┬─ dl-cmake43 ──────────────┐(COPY into ensia /
#     │             │                           └─ target-deps; + /usr/bin links at runtime)
#     │             ├─ dl-llvm22 ──► ensia (the challenge-binary clang/plugin
#     │             │                 COPYs are added per-task when the O axis
#     │             │                 names an LLVM tool)
#     │             ├─ dl-ghidra / dl-retdec / dl-dynamorio / dl-die / dl-rules / dl-checksec
#     │             ├─ pip-re ──► msynth
#     │             ├─ capstone ──► triton        (+own apt: llvm-15/z3/boost)
#     │             ├─ radare2 ──► r2ghidra
#     │             ├─ pwndbg / kiteshield / harmless
#     │             └─ target-deps ──┬─► origin-binary ────► gt-export
#     │                              └─► challenge-binary ─► runtime
#     └─ apt-runtime (full agent-world apt; runs alongside the whole tree)
#
# Critical path: apt-build → target-deps → challenge-binary → runtime tail. The RE
# toolchain branches (pip / triton / r2ghidra / downloads) overlap it instead of
# gating it, and the two full target compiles (origin vs challenge) run in parallel.
#
# Build:
#   docker buildx build --target gt-export -t <gt-image> .   # only the origin chain
#   docker buildx build -t <agent-image> .                   # runtime (default target)
# ============================================================================================

# ============================================================================================
# APT-BUILD — minimal compile/download base shared by every build branch: compilers,
# build tools, fetch tools, python3. Deliberately excludes the heavy agent-world
# packages (java, Qt5, gdb, llvm-15, libboost-all-dev, ...) so the target chain
# does not wait behind them.
# ============================================================================================
FROM ubuntu:22.04@sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982 AS apt-build
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build Tools
    autoconf \
    automake \
    libtool \
    make \
    cmake \
    meson \
    ninja-build \
    pkg-config \
    patch \
    # Compilers
    gcc \
    g++ \
    binutils \
    file \
    # Fetch / archive
    curl \
    wget \
    ca-certificates \
    git \
    unzip \
    # Python (transforms, pwndbg/msynth installs, sdist fallbacks)
    python3 \
    python3-pip \
    python3-dev \
    # Text Processing (build parity with the original toolchain env)
    bison \
    flex \
    gettext \
    autopoint \
    # Packer (challenge binary stage)
    upx-ucl \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================================
# DOWNLOAD BRANCHES — pure fetch+verify+extract, all mutually independent
# ============================================================================================

# Newer CMake (required by ensia which needs CMake 4.3+; also used to configure the target dep tree and both target builds, matching the original where /usr/bin/cmake was already the 4.3.1 symlink by then)
FROM apt-build AS dl-cmake43
RUN wget -qO /tmp/cmake.tar.gz "https://cmake.org/files/v4.3/cmake-4.3.1-linux-x86_64.tar.gz" && \
    echo "208d76804009cbe8ec9aea0aa052c857c6e59bd289b43b9941c99324dc78b1d8  /tmp/cmake.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/cmake.tar.gz -C /opt && \
    rm /tmp/cmake.tar.gz

# LLVM 22 (for ensia, xollvm, and the challenge clang build) - official prebuilt release binaries. Includes clang, lld, headers and CMake configs needed for out-of-tree plugin builds. Verified compatible with ubuntu:22.04 (built against GLIBC 2.34; the distro's 2.35 is newer, so it runs)
FROM apt-build AS dl-llvm22
RUN curl -fL --retry 3 "https://github.com/llvm/llvm-project/releases/download/llvmorg-22.1.5/LLVM-22.1.5-Linux-X64.tar.xz" \
        -o /tmp/llvm-22.tar.xz && \
    echo "04dfa3ab6f1c332dd73a057daeb8f48cdaacdef24178f8eccddf2cbfa8944aa4  /tmp/llvm-22.tar.xz" | sha256sum -c - && \
    tar -xJf /tmp/llvm-22.tar.xz -C /opt && \
    mv /opt/LLVM-22.1.5-Linux-X64 /opt/llvm-22 && \
    rm /tmp/llvm-22.tar.xz

# LLVM 22 environment (same as the original toolchain's): children (ensia, xollvm) need clang + libLLVM discoverable — xollvm's CMakeLists aborts without an external clang on PATH
ENV LLVM22_DIR=/opt/llvm-22
ENV PATH="${LLVM22_DIR}/bin:${PATH}"
ENV LD_LIBRARY_PATH="${LLVM22_DIR}/lib"

# Ghidra (headless analyzeHeadless)
FROM apt-build AS dl-ghidra
RUN wget -c --read-timeout=60 --tries=10 -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip" \
        -O /tmp/ghidra.zip && \
    echo "b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d  /tmp/ghidra.zip" | sha256sum -c - && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_* /opt/ghidra && \
    rm /tmp/ghidra.zip

# RetDec (decompiler) - v5.0 prebuilt release Tarball extracts flat (bin/, lib/, share/); built against GLIBC 2.34
FROM apt-build AS dl-retdec
RUN wget -c --read-timeout=60 --tries=10 -q "https://github.com/avast/retdec/releases/download/v5.0/RetDec-v5.0-Linux-Release.tar.xz" \
        -O /tmp/retdec.tar.xz && \
    echo "e5a7dd82987ff52b8c714892277d0b1d0190ab778c03036d01eb69c7658ab1a5  /tmp/retdec.tar.xz" | sha256sum -c - && \
    mkdir -p /opt/retdec && \
    tar -xJf /tmp/retdec.tar.xz -C /opt/retdec && \
    rm /tmp/retdec.tar.xz

# DynamoRIO (dynamic binary instrumentation) - release_11.2.0 release_11.3.0 has no prebuilt assets; 11.2.0 is the newest stable with tarballs
FROM apt-build AS dl-dynamorio
RUN wget -c --read-timeout=60 --tries=10 -q "https://github.com/DynamoRIO/dynamorio/releases/download/release_11.2.0/DynamoRIO-Linux-11.2.0.tar.gz" \
        -O /tmp/dynamorio.tar.gz && \
    echo "46997695d17ef7be182f503cdf3d697784e8379b7817b7b43501f8ecb4625f53  /tmp/dynamorio.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/dynamorio.tar.gz -C /opt && \
    mv /opt/DynamoRIO-Linux-11.2.0 /opt/dynamorio && \
    rm /tmp/dynamorio.tar.gz

# Detect It Easy (DIE) - packer/protector identification (CLI version) Tolerant tail: a failed download must not fail the image (DIE is optional tooling), so the dir is guaranteed to exist for the runtime COPY --from.
FROM apt-build AS dl-die
RUN wget -c --read-timeout=60 --tries=10 -q "https://github.com/horsicq/DIE-engine/releases/download/3.21/die_3.21_portable_Ubuntu_20.04_amd64.tar.gz" \
        -O /tmp/die.tar.gz && \
    echo "4d85614dd169c0d23f52084f86e05a503c30429df5fb5ec14de50f23808bc2d4  /tmp/die.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/die.tar.gz -C /opt && \
    rm -rf /tmp/die.tar.gz || echo "Warning: DIE installation failed, continuing..." ; \
    mkdir -p /opt/die_linux_portable

# Install Checksec - v2.7.0
FROM apt-build AS dl-checksec
RUN curl -fL https://raw.githubusercontent.com/slimm609/checksec.sh/2.7.0/checksec \
    -o /usr/local/bin/checksec && \
    echo "6745a5816fe8ba2c5f0aaaae67274cf6a262b17c74f0f96241fe18080b30d662  /usr/local/bin/checksec" | sha256sum -c && \
    chmod +x /usr/local/bin/checksec

# ============================================================================================
# PYTHON BRANCH — angr goes first ON PURPOSE: a single resolve would hit
# ResolutionImpossible — angr==9.2.102 wants a newer capstone, the list force-pins
# capstone==4.0.2 (Triton v0.9 requires 4.x), so angr installs first and the second
# call pins capstone back down.
# ============================================================================================
FROM apt-build AS pip-re
RUN pip3 install --no-cache-dir --retries 10 --timeout 90 angr==9.2.102 && \
    pip3 install --no-cache-dir --retries 10 --timeout 90 \
    # Binary Analysis Frameworks
    pwntools==4.12.0 \
    z3-solver==4.13.2.0 \
    # Disassembly and Emulation
    keystone-engine==0.9.2 \
    miasm==0.1.5 \
    # ELF and Binary Manipulation
    cle==9.2.102 \
    pyelftools==0.31 \
    lief==0.14.1 \
    r2pipe==0.9.4 \
    # Exploit Development
    ropper==1.13.13 \
    ROPgadget==6.6 \
    # Cryptography and Analysis
    pycryptodome==3.20.0 \
    python-magic==0.4.27 \
    cryptography==42.0.8 \
    flare-floss==3.1.1 \
    unipacker==1.0.8 \
    frida==16.2.4 \
    frida-tools==12.3.0 \
    # SMT Solvers (z3 above; alternatives much faster on bitwise license-check constraints)
    bitwuzla==0.9.1 \
    pyboolector==3.2.4.19342042739 \
    cvc5==1.3.4 \
    # Emulation Framework (ELF loader + syscall layer, survives anti-debug/anti-vm)
    qiling==1.4.6 \
    # Pattern Matching
    yara-python==4.5.4 \
    # Utilities
    tqdm==4.66.4 \
    pyyaml==6.0.1 \
    capstone==4.0.2 \
    unicorn==2.1.4 \
    # Pinned: angr 9.2.102 is incompatible with pycparser >= 2.22 (cffi pulls latest)
    pycparser==2.21
    # NOTE: Triton Python bindings are installed from source below (v0.9);
    # the PyPI "triton" package is a different project (OpenAI's GPU compiler)

# Install Msynth - commit 661a5e3 (no releases available) — layered ON TOP of the pinned pip stack (same install order as the original), so its /usr/local is the final state of the stack and runtime copies it in one piece.
FROM pip-re AS msynth
RUN git clone https://github.com/mrphrazer/msynth.git /tmp/msynth && \
    cd /tmp/msynth && \
    git checkout 661a5e3d7c0358950cf48b27ae422450c3064966 && \
    pip3 install . && \
    rm -rf /tmp/msynth

# ============================================================================================
# CAPSTONE → TRITON CHAIN
# ============================================================================================

# Install Capstone (for Triton) - v4.0.2 (Triton v0.9 requires Capstone 4.x)
FROM apt-build AS capstone
RUN cd /tmp && \
    git clone --branch 4.0.2 --depth 1 https://github.com/capstone-engine/capstone.git && \
    cd capstone && \
    ./make.sh && \
    ./make.sh install && \
    cd .. && \
    rm -rf capstone

# Install Triton (use LLVM 15 for API compatibility) - v0.9
# Triton-only build deps installed here (kept out of apt-build so the target chain
# does not wait behind libboost-all-dev etc.). Python bindings are installed via
# make install, no pip install needed.
#
# PATCH (v0.9 upstream bug): xPyDict_SetItemString() consumes (decrefs) the value
# reference, but initVersionNamespace.cpp passes borrowed singletons Py_True/Py_False.
# Each *_INTERFACE dict entry therefore steals a reference from the singleton; at
# interpreter shutdown the module dict drops refs it never owned, Py_True's refcount
# hits zero, and CPython calls free() on the static _PyTrueStruct -> abort with
# "free(): invalid pointer" on every `import triton` exit. Fix: incref before the
# helper consumes the reference (upstream rewrote this in later releases).
FROM capstone AS triton
RUN apt-get update && apt-get install -y --no-install-recommends \
    llvm-15 \
    llvm-15-dev \
    clang-15 \
    python3-dev \
    libpython3-stdlib \
    libboost-all-dev \
    libz3-dev \
    libzstd-dev \
    libgmp-dev \
    libmpfr-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone --branch v0.9 --depth 1 https://github.com/JonathanSalwan/Triton.git /tmp/triton && \
    cd /tmp/triton && \
    sed -i -E 's/xPyDict_SetItemString\(versionDict, ("(Z3|BITWUZLA|LLVM)_INTERFACE"), (Py_True|Py_False)\);/Py_INCREF(\3); xPyDict_SetItemString(versionDict, \1, \3);/' \
        src/libtriton/bindings/python/namespaces/initVersionNamespace.cpp && \
    grep -c "Py_INCREF(Py_True); xPyDict_SetItemString\|Py_INCREF(Py_False); xPyDict_SetItemString" \
        src/libtriton/bindings/python/namespaces/initVersionNamespace.cpp | grep -q "^6$" && \
    mkdir build && cd build && \
    PATH="/usr/lib/llvm-15/bin:${PATH}" \
    cmake -DCMAKE_INSTALL_PREFIX=/usr/local \
          -DPYTHON_BINDINGS=ON \
          -DZ3_INTERFACE=ON \
          -DLLVM_DIR=/usr/lib/llvm-15/lib/cmake/llvm \
          -DLLVM_INTERFACE=ON .. && \
    PATH="/usr/lib/llvm-15/bin:${PATH}" \
    make -j$(nproc) && \
    make install && \
    rm -rf /tmp/triton

# ============================================================================================
# RADARE2 → R2GHIDRA CHAIN
# ============================================================================================

# Install Radare2 - v6.1.8
# INSTALL_TARGET=install: real install (copy binaries). The default "symstall"
# creates symlinks into the build tree, which breaks when /tmp/radare2 is removed.
FROM apt-build AS radare2
RUN git clone --branch 6.1.8 --depth 1 https://github.com/radareorg/radare2.git /tmp/radare2 && \
    cd /tmp/radare2 && \
    MAKE_JOBS=$(nproc) INSTALL_TARGET=install WITHOUT_PULL=1 ./sys/install.sh && \
    rm -rf /tmp/radare2

# Install r2ghidra (Ghidra decompiler as an r2 plugin) - 6.1.8 (matches radare2 version) "make -C subprojects" fetches ghidra-native 0.6.4 (pinned in the 6.1.8 tag's wrap files), applies its patch set, and builds pugixml/zlib deps before the plugin itself compiles.
FROM radare2 AS r2ghidra
RUN git clone --branch 6.1.8 --depth 1 https://github.com/radareorg/r2ghidra.git /tmp/r2ghidra && \
    cd /tmp/r2ghidra && \
    ./configure --prefix=/usr/local && \
    make -C subprojects && \
    make -j$(nproc) && \
    make install && \
    rm -rf /tmp/r2ghidra

# ============================================================================================
# STANDALONE TOOL BRANCHES
# ============================================================================================

# Install pwndbg (GDB enhancement for exploit development) - v2024.08.29 setup.sh installs its own system deps (gdb, python3-venv, ...) exactly as it did inside the original toolchain stage; everything stays under /opt/pwndbg.
FROM apt-build AS pwndbg
RUN git clone https://github.com/pwndbg/pwndbg.git /opt/pwndbg && \
    cd /opt/pwndbg && \
    git checkout 2024.08.29 && \
    ./setup.sh && \
    rm -rf /opt/pwndbg/.git

# Install Kiteshield - Packer/Protector for x86-64 ELF binaries on Linux (commit 3c6aace - no releases available)
FROM apt-build AS kiteshield
RUN git clone https://github.com/GunshipPenguin/kiteshield.git /tmp/kiteshield && \
    cd /tmp/kiteshield && \
    git checkout 3c6aaceda5aa7b4317138eb20ce365e1527e1e62 && \
    git submodule update --init && \
    cd packer/bddisasm && \
    mkdir build && cd build && \
    cmake .. && \
    make && \
    cd /tmp/kiteshield && \
    make && \
    cp packer/kiteshield /usr/local/bin/kiteshield && \
    rm -rf /tmp/kiteshield

# Install hARMless - Packer/Loader for ARM64 and x86-64 Linux ELF binaries (commit 46b3630 - no releases available) Disable anti-sandbox checks and io_uring for Docker compatibility libssl-dev: the packer links OpenSSL (packer/crypto.c includes openssl/evp.h) — in the original this came implicitly from the big toolchain apt list
FROM apt-build AS harmless
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/litemars/hARMless.git /opt/harmless && \
    cd /opt/harmless && \
    git checkout 46b3630e3b0e0983c33f2e256436926a1e2089aa && \
    sed -i 's/if (comprehensive_anti_debug_check()) {/if (0) { \/\/ DISABLED FOR TEST/g' loader/loader.c && \
    sed -i 's/return 1; \/\/ anti-debug/return 0; \/\/ anti-debug DISABLED/g' loader/loader.c && \
    sed -i 's/unlink(argv\[0\]);/\/\/ unlink(argv[0]); \/\/ DISABLED - preserve binary/g' loader/loader.c && \
    sed -i 's/-DCOPY_WITH_IO_URING//g' Makefile && \
    make all ARCH=x86_64 && \
    ln -sf /opt/harmless/build/packer /usr/local/bin/harmless_packer && \
    ln -sf /opt/harmless/build/stubgen /usr/local/bin/harmless_stubgen && \
    ln -sf /opt/harmless/build/loader /usr/local/bin/harmless_loader && \
    rm -rf /opt/harmless/.git

# Install ensia (OLLVM-Next, LLVM 22) - v0.1.0 Build from source to ensure compatibility with LLVM 22.1.5. CMake >= 4.3 comes from dl-cmake43 via /usr/local/bin (PATH-preferred over the distro cmake).
FROM dl-llvm22 AS ensia
COPY --from=dl-cmake43 /opt/cmake-4.3.1-linux-x86_64 /opt/cmake-4.3.1-linux-x86_64
COPY --from=dl-checksec /usr/local/bin/checksec /usr/local/bin/checksec
RUN ln -sf /opt/cmake-4.3.1-linux-x86_64/bin/cmake /usr/local/bin/cmake && \
    ln -sf /opt/cmake-4.3.1-linux-x86_64/bin/ctest /usr/local/bin/ctest && \
    cd /tmp && \
    git clone --branch v0.1.0 --depth 1 https://github.com/Apich-Organization/ensia.git ensia && \
    cd ensia && \
    mkdir build && cd build && \
    cmake -DCMAKE_PREFIX_PATH=/opt/llvm-22 \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_CXX_FLAGS="-fno-rtti" \
          .. && \
    make -j$(nproc) && \
    cp obfuscation/libEnsia.so /usr/local/lib/ && \
    rm -rf /tmp/ensia

# ============================================================================================
# TARGET-DEPS — shared dependency stack both target binaries build against.
FROM apt-build AS target-deps
COPY --from=dl-cmake43 /opt/cmake-4.3.1-linux-x86_64 /opt/cmake-4.3.1-linux-x86_64
RUN ln -sf /opt/cmake-4.3.1-linux-x86_64/bin/cmake /usr/local/bin/cmake && \
    ln -sf /opt/cmake-4.3.1-linux-x86_64/bin/ctest /usr/local/bin/ctest

# Single compressed copy of the source tree (the bare tree is not shipped).
COPY testdata/ /tmp/testdata/
# step 3.5 sample capture rides beside the binary (emit_testdata.py)
COPY src.tar.gz /tmp/src.tar.gz
RUN mkdir -p /src && tar xzf /tmp/src.tar.gz -C /src --strip-components=1 && rm /tmp/src.tar.gz

RUN mkdir -p /opt/target-deps /app
# samba-4.24.6 carrier deps (codebase/build.yaml samba-4.24.6 recipe,
# jammy pins; waf needs python3 from the base image, pidl codegen needs
# perl + Parse::Yapp) + patchelf (RUNPATH rewrite on the challenge ELF).
# Installed HERE so both descendant stages (origin-binary,
# challenge-binary) share one apt span. Samba builds every internal
# library itself into bin/shared/ — no custom-lib prefix builds — so the
# ${TARGET_DEPS} prefix stays empty until the challenge-binary stage's
# closure step stages bin/shared/*.so there.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libacl1-dev \
        libparse-yapp-perl \
        libpam0g-dev \
        zlib1g-dev \
        libgnutls28-dev \
        libjansson-dev \
        libarchive-dev \
        bison \
        flex \
        patchelf \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src

# ============================================================================================
# ORIGIN-BINARY — everything compile-time lives in the binary stages (src tree,
# protection toolchain, both binaries). The runtime stage copies OUT only finished
# artifacts, so neither /src nor the ground truth ever enters the agent image's
# layers.
# ============================================================================================
FROM target-deps AS origin-binary
# ORACLE: the SAME generated protocol, unconcealed, server mode with
# milestone logging — test.sh scores the interop ladder from it.
# ANTI-CHEAT: ONLY oracle_server here; the reference client never
# enters the verifier image (solve side only).
#
# TEMPLATE: customize per task (SKILL.md Step 8.05). Build the oracle PAIR
# from the injected protocol engine (engine artifacts:
# reference/injection.md): oracle_server stays in the image export path;
# ref_client rides along in /gt ONLY so the export step can copy it out
# solution-side (it never enters the verifier image).
RUN mkdir -p /gt/binaries && cc -O2 -o /gt/binaries/oracle_server /src/proto/oracle_server.c \
       /src/proto/protocol.c -lpthread && \
    cc -O2 -o /gt/binaries/ref_client /src/proto/ref_client.c \
       /src/proto/proto_client.c /src/proto/protocol.c -lpthread

# ============================================================================================
# CHALLENGE-BINARY — full protection chain (O4 + D3), runs IN PARALLEL with
# origin-binary: identical deps stage, own build tree, Tigress toolchain.
# This stage's /src snapshot is PRIVATE — the D3 source injection and the
# Tigress prep edits below never reach origin-binary's copy, so the oracle
# pair stays unconcealed.
# ============================================================================================
FROM target-deps AS challenge-binary
# COPY concealment/ /concealment/   (O0P0D0: tree not staged)
# Tigress 4.0.11 from the staged deb (gen_concealment.py stages it at O3+;
# the runtime stage installs its own copy for the agent world)
# make the ldd closure resolve smbd's custom libs under ${TARGET_DEPS}/lib
ENV LD_LIBRARY_PATH=/opt/target-deps/lib
WORKDIR /src

# Pristine engine snapshot for the post-concealment smoke client: compile
# the PLAIN object from the UNEDITED sources before any concealment edit
# lands (the post-prep protocol.c carries the tigress dummy main + boot
# references and cannot link standalone).
RUN cp -r /src/proto /tmp/proto_plain_src && \
    cc -O2 -c /tmp/proto_plain_src/protocol.c -o /tmp/protocol_plain.o && \
    cc -O2 -c /tmp/proto_plain_src/proto_client.c -o /tmp/proto_client_plain.o

# D3 binary concealment (seeded plan, concealment_config.json): inject the
# advanced anti-debug check set (TracerPid, parent-process name, SIGTRAP
# handling, timing, breakpoint scan, /proc/self/maps injection + frida
# fingerprints, anti-dump, self-ptrace tracer-slot occupation — ACTION_EXIT)
# into proto_server_entry — anchored at the pc_full_tcp_listen() call so the
# checks run ONLY on the hidden --proto-server path, never on a normal smbd
# invocation. proto_server_entry is defined in proto_core.c (which protocol.c
# amalgamates); adbg.c rides in via #include from the same proto/ dir (assets
# staged there by gen_concealment.py Step 6). The guards matter: the injector
# edits the file even when anchor matching FAILS, so verify the check landed
# in proto_core.c and nothing stray landed in protocol.c.
# O4 prep — three source edits on the engine, each idempotent with a
# hard assert (a missed edit fails the build, never ships quietly):
#   1. pointer LNot rewrite: CIL's TreeCode converter crashes on `!ptr`
#      ("Internal Tigress error: vUnop.arithmeticVersionOf") — the
#      equivalent `p == NULL` form is accepted. 12 sites, 4 modules.
#   2. tigress_prep wiring: declares the empty init_tigress() stub and
#      calls it first inside proto_server_entry (InitEntropy/InitOpaque/
#      InitBranchFuns instrument the stub; without the runtime call the
#      opaque state is never initialised and the VM segfaults).
#   3. whole-program boot: Tigress requires a main(), and CIL relocates
#      every non-constant global-table initialiser into it. A dummy main
#      is appended to protocol.c; its object symbol is renamed
#      proto_tigress_boot at link time and the engine calls it first
#      inside proto_server_entry, so the relocated tables (x25519 curve
#      points, RC4 tables, ...) exist before any virtualised code runs.
# O4 binary concealment — Tigress Virtualize: 59 wire-path functions (the
# serve/client session ladder, framing reader/writer, codec,
# state machine, protocol concealment, crypto) are compiled into VM
# bytecode executed by per-function generated interpreters
# (--VirtualizeDispatch=switch) — the O-ladder's virtualization rung,
# far beyond flattening: no recovered control flow exists, only
# interpreter dispatch loops over encoded operand stacks. EncodeLiterals
# hides the constants of the primary codecs. proto_server_entry stays
# entirely un-transformed (see the NOTE above); InitEntropy/
# InitOpaque/InitBranchFuns seed the opaque-predicate infrastructure the
# VM dispatchers consume. --Seed=4233 fixes the transformation RNG (the
# internal _TIG_* name suffixes stay run-random; R1 determinism covers
# the engine, not the concealment layer — same contract as the sibling
# skills' tigress tasks). The size + symbol guards turn a silent
# tigress no-op or a lost entry symbol into a build failure.
# NOTE proto_server_entry stays OUT of the Virtualize set (plain code +
# EncodeLiterals only): the VM dispatcher preamble evaluates an
# array-division opaque predicate BEFORE any statement runs, and the
# opaque array is only initialised by init_tigress() — which lives
# INSIDE proto_server_entry. Virtualizing the entry is a
# chicken-and-egg SIGFPE (verified: gdb shows divl on
# init_tigress_1__opaque_array+44 with rax=rdx=0). The entry's own
# logic is trivial arg-parsing; every function it calls stays
# virtualized.
# O4 compile: the CIL-normalised output compiles with gcc (the int<->ptr
# cast noise of the VM's unified registers is expected — hence -w, the
# sibling skills' tigress contract), then the dummy main's object symbol
# is renamed proto_tigress_boot so the object links into smbd (whose own
# main is the real one). The differ-check proves tigress actually
# transformed the TU (a silent no-op fails the build instead of shipping
# an unprotected challenge). NOTE the if-form: an `A && B || echo` chain
# would let a failed compile fall through the || and fake a pass.
# -fvisibility=hidden: smbd links -rdynamic for its VFS modules; hidden
# visibility keeps the engine's px_/pf_/pc_/ps_/proto_ names out of
# .dynsym while the carrier's cross-TU reference to proto_server_entry
# still resolves (static-link scope)
# UNPROTECTED BUILD (construction contract: at most two protected
# comprehensive tasks per batch; this one is O0P0D0). The engine
# compiles plainly into the carrier link; hidden visibility keeps the
# engine symbols out of .dynsym and the host-material externs resolve
# against the site-B object
RUN cd /src/proto && \
    cc -O2 -w -fvisibility=hidden -DPROTO_HOST_MATERIAL -c protocol.c -o proto_engine.o && \
    nm proto_engine.o | grep -qw proto_server_entry && \
    nm proto_engine.o | grep -qw ast_proto_boot && \
    nm proto_engine.o | grep -q ' U PROTO_AUTH_SECRET' && \
    if nm proto_engine.o | grep -qE 'proto_client_(session|converse)'; then \
        echo "FATAL: reference client engine leaked into the challenge TU"; exit 1; \
    fi && \
    echo "engine object ready (plain, host-material externs by design)"
# Site B concealment -- Tigress EncodeLiterals+Flatten on the glue TU
# (host-bound construction, reference/host-binding.md): masked material
# blobs + the loadparm boot glue; entry UNTRANSFORMED (opaque-hoist
# SIGFPE contract); symbol-collision dedupe vs the engine object.
# site B compiles plainly at O0P0D0: the masked blobs stay masked in
# the object, so the anti-plaintext assertion below still applies.
# The stub defines the dummy-boot symbol the tigress main-rename
# provided in the protected build (the boot call site stays intact)
RUN cd /src/proto && \
    cp ast_defaults.c ast_defaults_plain.c && \
    printf '\nint adef_dummy_boot(int argc, char **argv, char **envp) { (void)argc; (void)argv; (void)envp; return 0; }\n' >> ast_defaults_plain.c && \
    cc -O2 -w -fvisibility=hidden -c ast_defaults_plain.c -o ast_defaults_ensia.o && \
    nm ast_defaults_ensia.o | grep -qw ast_proto_boot && \
    nm ast_defaults_ensia.o | grep -qw PROTO_AUTH_SECRET && \
    python3 - <<'PYEOF'
import re
t = open('ast_defaults_plain.c').read()
def blob(sym):
    m = re.search(r"adef_%s\[[0-9 +]+\]\s*=\s*\{([^}]*)\}" % sym, t)
    return bytes(int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", m.group(1)))
mask = blob('mask')
data = open('ast_defaults_ensia.o', 'rb').read()
for sym in ('blob_a', 'blob_b'):
    v = blob(sym)
    plain = bytes(b ^ mask[i & 31] ^ ((i * 33) & 0xFF) for i, b in enumerate(v))
    if plain[:12] in data:
        print("FATAL: site-B %s decodes to contiguous PLAINTEXT" % sym)
        raise SystemExit(1)
print("site-B data assertion passed")
PYEOF
# Host-bound wire state (site C): the carrier's boot reads
# /etc/samba/smb.conf through samba's REAL loadparm parser
# (lp_load_global, the testparm-standalone surface); three [global]
# parametric rows carry the wire constants.
RUN mkdir -p /out /etc/samba && cp /src/host-state/smb.conf /etc/samba/smb.conf

# CHALLENGE: carrier build (samba-4.24.6 recipe verbatim: waf configure —
# --disable-python requires --without-ad-dc per wscript line 214 — with
# the LDAP/LMDB/ADS cuts and the !vfs_snapper module filter, then make).
# source3/wscript_build links the prebuilt proto_engine.o AND the
# concealed site-B object into bin/smbd via the smbd/smbd target's
# ldflags ('../../proto/proto_engine.o ../../proto/ast_defaults_ensia.o
# -lpthread -lm' — the VM engine's float
# handler needs libm); source3/smbd/server.c main() carries the hidden
# --proto-server mode. waf embeds an absolute RUNPATH
# (/src/bin/shared:...) — rewritten to the fixed ${TARGET_DEPS} overlay
# prefix where the closure step below stages the custom libs. The ldd
# assertion runs in the closure step, after those libs land in the
# prefix. bin/smbd is a symlink into bin/default — address the real ELF.
RUN test -s proto/proto_engine.o && test -s proto/ast_defaults_ensia.o && \
    ./configure --disable-python --without-ad-dc --without-ldap \
        --without-ldb-lmdb --without-ads \
        "--with-shared-modules=!vfs_snapper" \
        CFLAGS="-O2" CXXFLAGS="-O2" && \
    make -j$(nproc) && \
    strip --strip-all bin/default/source3/smbd/smbd && \
    patchelf --set-rpath /opt/target-deps/lib bin/default/source3/smbd/smbd && \
    cp bin/default/source3/smbd/smbd /app/binary && \
    mkdir -p /out && cp /app/binary /out/challenge_ldd

# Role-named staging + runtime library closure. Split by the export
# machinery's contract:
#   - CUSTOM libs (everything under bin/shared/ — built from source,
#     absent from the distro) land under the fixed ${TARGET_DEPS} prefix
#     where the ldd-resolver sees them via the rewritten RUNPATH;
#     deps.tar.gz packages exactly those (kept lean).
#   - The FULL resolved ldd closure (customs + distro runtime libs the
#     agent apt set does not carry, e.g. libgnutls/libjansson) goes to
#     /out/challenge_libs — the runtime stage overlays it onto the same
#     prefix so /app/binary runs; distro libs there also feed the
#     verifier's pinned-apt derivation (sys_pkgs stays non-empty).

# HOST-BINDING ASSERTIONS: the challenge binary must NOT contain the
# wire secrets anywhere (masked site-B blobs, smb.conf parametrics, VM
# operand streams only). Derives expected sequences from proto_config.h.
RUN python3 - <<'PYEOF'
import re
t = open('/src/proto/proto_config.h').read()
def blob(sym):
    m = re.search(r"static const uint8_t %s\[[A-Za-z0-9_]+\]\s*=\s*\{([^}]*)\}" % sym, t)
    return bytes(int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", m.group(1)))
secrets = {sym: blob(sym) for sym in
           ("PROTO_MAGIC", "PROTO_XOR_KEY", "PROTO_RC4_KEY",
            "PROTO_AUTH_SECRET", "PROTO_SERVER_PRIV", "PROTO_HOST_KEX_SALT")}
vw = int(re.search(r"#define PROTO_F3_VER_W\s+(\d+)", t).group(1))
if vw >= 4:
    # a sub-4-byte field zero-pads the needle and collides with chance
    # byte runs in any large carrier binary -- only a full-width version
    # is assertable by raw substring search
    m = re.search(r"#define PROTO_VERSION\s+(0x[0-9A-Fa-f]+)u", t)
    secrets["PROTO_VERSION_BE"] = int(m.group(1), 16).to_bytes(4, "big")
    secrets["PROTO_VERSION_LE"] = int(m.group(1), 16).to_bytes(4, "little")
data = open('/app/binary', 'rb').read()
hits = [(n, data.find(v)) for n, v in secrets.items() if data.find(v) >= 0]
if hits:
    print("FATAL: wire secrets present in the stripped challenge binary:", hits)
    raise SystemExit(1)
print("host-binding assertions passed (no secret byte-sequence in binary)")
PYEOF

# ENGINE-LEAK ASSERTIONS (leak-audit fix 2026-08): the challenge binary
# must ship NO engine internals. The reference client engine lives in
# proto_client.c -- a TU the carrier build never links (a MITM'd argv +
# code cave used to reproduce the whole session for free); engine
# symbols are compiled hidden (-fvisibility=hidden below) so waf's
# -rdynamic module link cannot carry px_/pf_/pc_/ps_/pe_/proto_/adbg_
# names into .dynsym; strip removes .symtab. Any regression fails the
# build loudly instead of shipping a farmable challenge.
RUN if nm -D /app/binary | awk '$2 ~ /^[TtWw]$/ && $3 ~ /^(px_|pf_|pc_|ps_|pe_|proto_|PROTO_|ast_proto_|adbg_)/ {print $3}' | grep -q .; then \
        echo "FATAL: engine symbols exported in .dynsym:"; \
        nm -D /app/binary | awk '$2 ~ /^[TtWw]$/ && $3 ~ /^(px_|pf_|pc_|ps_|pe_|proto_|PROTO_|ast_proto_|adbg_)/ {print $3}'; \
        exit 1; \
    fi && \
    if readelf -SW /app/binary | grep -q '\.symtab'; then \
        echo "FATAL: .symtab survived the strip"; exit 1; \
    fi && \
    echo "engine-leak assertions passed (dynsym clean, no .symtab)"
RUN mkdir -p /out /out/challenge_libs /opt/target-deps/lib && \
    find /src/bin/shared -name '*.so*' -exec cp -an {} /opt/target-deps/lib/ \; && \
    if ldd /out/challenge_ldd | grep -q 'not found'; then \
        echo "FATAL: unresolved runtime deps"; ldd /out/challenge_ldd; exit 1; \
    fi && \
    ldd /out/challenge_ldd | awk '/=> \// {print $3} /^\// {print $1}' | \
        sort -u > /tmp/closure.txt && \
    xargs -r -I{} cp -n {} /out/challenge_libs/ < /tmp/closure.txt && \
    cp /app/binary /out/challenge_final && chmod 755 /out/challenge_final && \
    mkdir -p /out/host-state && cp /src/host-state/smb.conf /out/host-state/ && \
    ldd /out/challenge_ldd | grep 'libsmbd-base' | grep -q /opt/target-deps/

# Post-concealment protocol smoke test: the protected smbd must still
# serve the full protocol session (flag round-trip through the D3 checks
# and the O4-virtualised engine) — a broken concealment layer fails the
# build here, not in the verifier. The client links the PLAIN engine
# object: a genuine black-box interop, not a shared-concealment loopback.
RUN cc -O2 -I/src/proto -o /tmp/ref_client /src/proto/ref_client.c \
        /tmp/proto_client_plain.o /tmp/protocol_plain.o -lpthread -lm && \
    ( /app/binary --proto-server 17999 > /tmp/proto.out 2>&1 & echo $! > /tmp/proto.pid; sleep 2; \
      timeout 45 /tmp/ref_client 127.0.0.1 17999 > /tmp/proto.out2 2>&1; rc=$?; \
      kill $(cat /tmp/proto.pid) 2>/dev/null; \
      grep -q 'flag{' /tmp/proto.out2 || rc=1; \
      rm -f /tmp/proto.pid; \
      if [ $rc -ne 0 ]; then echo "FATAL: host-bound smoke failed (no flag)"; cat /tmp/proto.out2; exit 1; fi ) && \
    mv /etc/samba/smb.conf /etc/samba/smb.conf.hidden && \
    ( /app/binary --proto-server 17998 > /tmp/proto.out3 2>&1 & echo $! > /tmp/proto.pid; sleep 2; \
      timeout 25 /tmp/ref_client 127.0.0.1 17998 > /tmp/proto.out4 2>&1; rc=$?; \
      kill $(cat /tmp/proto.pid) 2>/dev/null; \
      mv /etc/samba/smb.conf.hidden /etc/samba/smb.conf; \
      rm -f /tmp/proto.pid; \
      if [ $rc -eq 0 ] && grep -q 'flag{' /tmp/proto.out4; then \
          echo "FATAL: poison path failed -- decoy dialect served the flag"; \
          cat /tmp/proto.out4; exit 1; fi ) && \
    rm -f /tmp/ref_client /tmp/proto.out /tmp/proto.out2 /tmp/proto.out3 /tmp/proto.out4 && \
    echo "interop smoke passed (host-bound session ok, decoy poison ok)"


# ============================================================================================
# GT-EXPORT STAGE — `docker buildx build --target gt-export`, then create/cp
# extracts ONLY the ground-truth files (a scratch image holding nothing else).
# In the parallel layout this target no longer drags the challenge chain: it
# builds apt-build → dl-cmake43 → target-deps → origin-binary and nothing else.
# ============================================================================================

# step 3.5 testdata staging: always create /out/testdata
# (populated when the sample capture exists, empty otherwise)
RUN mkdir -p /out/testdata && cp /tmp/testdata/* /out/testdata/ 2>/dev/null || true
FROM scratch AS gt-export
COPY --from=origin-binary /gt /gt

# ============================================================================================
# APT-RUNTIME — the full agent-world package set (verbatim from the original
# toolchain list, plus the target -dev set). No dependency on any build branch,
# so it runs alongside the whole tree and is ready when the merge point needs it.
# ============================================================================================
FROM ubuntu:22.04@sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982 AS apt-runtime
ENV DEBIAN_FRONTEND=noninteractive QT_QPA_PLATFORM=offscreen

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build Tools
    autoconf \
    automake \
    libtool \
    make \
    cmake \
    meson \
    ninja-build \
    pkg-config \
    patch \
    # Compilers and Assemblers
    gcc \
    g++ \
    gcc-multilib \
    binutils \
    nasm \
    # Debugging and Analysis Tools
    gdb \
    lldb-15 \
    ltrace \
    strace \
    valgrind \
    # Binary Analysis Tools
    binwalk \
    ssdeep \
    hexedit \
    qemu-user-static \
    ent \
    yara \
    # Binary Patching Tools
    patchelf \
    prelink \
    checksec \
    socat \
    tcpdump \
    tshark \
    python3-scapy \
    # Development Libraries
    libffi-dev \
    libglib2.0-dev \
    libncursesw5-dev \
    python3-dev \
    libssl-dev \
    libruby \
    libc6-dev-i386 \
    libevent-dev \
    # Text Processing and Localization
    bison \
    flex \
    gettext \
    autopoint \
    texinfo \
    # Network Tools
    curl \
    wget \
    netcat-openbsd \
    # Version Control
    git \
    # Python and Ruby
    python3 \
    python3-pip \
    python3-lldb-15 \
    ruby \
    # Java (for Ghidra)
    openjdk-21-jdk \
    # Utilities
    bc \
    bsdmainutils \
    ca-certificates \
    file \
    libc-bin \
    unzip \
    util-linux \
    vim \
    xxd \
    vbindiff \
    jq \
    upx-ucl \
    # Extra Build Dependencies
    dejagnu \
    software-properties-common \
    # Triton and Obfuscator Build Dependencies
    libboost-all-dev \
    libcapstone-dev \
    libgmp-dev \
    libmpfr-dev \
    libpython3-stdlib \
    libz3-dev \
    libzstd-dev \
    # LLVM 15 (for Triton)
    llvm-15 \
    llvm-15-dev \
    clang-15 \
    # Qt5 (for DIE)
    libqt5core5a \
    libqt5gui5 \
    libqt5widgets5 \
    libqt5svg5 \
    libqt5opengl5 \
    libqt5dbus5 \
    libqt5script5 \
    libqt5scripttools5 \
    libqt5network5 \
    libqt5sql5 \
    libqt5concurrent5 \
    libqt5x11extras5 \
    && rm -rf /var/lib/apt/lists/*


# ============================================================================================
# RUNTIME STAGE (default build target) — the agent's world: full RE toolchain,
# target runtime deps, the finished challenge binary. No /src, no /protection,
# no ground truth anywhere in this stage's layer ancestry. This is the merge
# point: every parallel branch lands here via COPY --from.
# ============================================================================================
FROM apt-runtime AS runtime

# --- /opt merges (each branch keeps whole tools under its own prefix) ---
COPY --from=dl-cmake43 /opt/cmake-4.3.1-linux-x86_64 /opt/cmake-4.3.1-linux-x86_64
COPY --from=dl-llvm22 /opt/llvm-22 /opt/llvm-22
COPY --from=dl-ghidra /opt/ghidra /opt/ghidra
COPY --from=dl-retdec /opt/retdec /opt/retdec
COPY --from=dl-dynamorio /opt/dynamorio /opt/dynamorio
COPY --from=dl-die /opt/die_linux_portable /opt/die_linux_portable
COPY --from=pwndbg /opt/pwndbg /opt/pwndbg
COPY --from=harmless /opt/harmless /opt/harmless
COPY --from=target-deps /opt/target-deps /opt/target-deps

# --- /usr/local merges (directory overlays union cleanly; the pinned pip stack
# rides in via msynth, whose stage is pip-re + msynth — same final state as the
# original install order) ---
COPY --from=capstone /usr/local /usr/local
COPY --from=triton /usr/local /usr/local
COPY --from=radare2 /usr/local /usr/local
COPY --from=r2ghidra /usr/local /usr/local
COPY --from=kiteshield /usr/local /usr/local
COPY --from=harmless /usr/local /usr/local
COPY --from=pwndbg /usr/local /usr/local
COPY --from=msynth /usr/local /usr/local
COPY --from=ensia /usr/local /usr/local

# Finished challenge binary from the builder stage
COPY --from=challenge-binary /out/challenge_final /app/binary
COPY --from=challenge-binary /out/testdata /app/testdata
# Runtime library-closure overlay (leak-audit fix 2026-09-11): the
# challenge stage resolves the carrier's CUSTOM shared libs (libfrr,
# libsamba-*, libstrongswan/libcharon) into /out/challenge_libs; without
# this overlay /app/binary cannot even load in the agent box (the
# 2026-09-11 frr trial: the agent concluded "binary can't run" and
# reversed the REAL carrier protocol instead of the injected engine).
# /opt/target-deps/lib is already on LD_LIBRARY_PATH.
COPY --from=challenge-binary /out/challenge_libs/ /opt/target-deps/lib/
# Host-bound wire state (site C): the carrier reads /etc/samba/smb.conf at
# boot through samba's real loadparm parser -- /app/binary speaks the true
# dialect only with it present.
COPY --from=challenge-binary /out/host-state /tmp/host-state
RUN mkdir -p /etc/samba && cp /tmp/host-state/smb.conf /etc/samba/smb.conf && \
    rm -rf /tmp/host-state

# Environment parity with the original runtime (same final PATH/LD_LIBRARY_PATH/PYTHONPATH strings; LLVM22/LLVM15/TARGET_DEPS resolve as before)
ENV LLVM15_DIR=/usr/lib/llvm-15
ENV LLVM22_DIR=/opt/llvm-22
ENV TARGET_DEPS=/opt/target-deps
ENV PATH="/opt/retdec/bin:/opt/dynamorio/bin64:${LLVM22_DIR}/bin:${LLVM15_DIR}/bin:${PATH}"
ENV LD_LIBRARY_PATH="${TARGET_DEPS}/lib:${TARGET_DEPS}/lib/x86_64-linux-gnu:${LLVM22_DIR}/lib"
ENV PYTHONPATH="/usr/lib/llvm-15/lib/python3/dist-packages:/usr/lib/llvm-15/lib/python3.10/dist-packages"

# /usr/bin & /usr/local/bin symlinks that the original stages created in-place; ldconfig refreshes the loader cache for the merged /usr/local/lib libraries (same effect the original got from dpkg's post-install trigger)
RUN ldconfig && \
    ln -sf /usr/bin/lldb-15 /usr/bin/lldb && \
    ln -sf /opt/cmake-4.3.1-linux-x86_64/bin/cmake /usr/bin/cmake && \
    ln -sf /opt/cmake-4.3.1-linux-x86_64/bin/ctest /usr/bin/ctest && \
    ln -sf /opt/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless && \
    ln -sf /opt/die_linux_portable/base/diec /usr/local/bin/die || echo "Warning: DIE symlink failed, continuing..."

# Install Tigress from local .deb file — gen_concealment.py stages the deb into concealment/obfuscation/ AND uncomments these lines when the O level needs it (O3/O4/O5); they stay commented (and unstaged) otherwise. THE THREE LINES BELOW ARE MACHINE-PARSED ANCHORS (gen_concealment.py exact-string replace) — never reflow, merge, or reword them.
# COPY concealment/obfuscation/tigress_4.0.11-1_all.deb /tmp/tigress_4.0.11-1_all.deb
# RUN dpkg --force-architecture -i /tmp/tigress_4.0.11-1_all.deb && \
#     rm /tmp/tigress_4.0.11-1_all.deb

# Install one_gadget (Ruby gem for finding one-shot ROP gadgets)
RUN gem install one_gadget -v 1.9.0 --no-document && \
    echo 'source /opt/pwndbg/gdbinit.py' > /root/.gdbinit

# Permissions for harbor artifact collection + agent user (same tail as the original image; nothing to clean in this stage — it never had /src)
RUN chmod 755 /app/binary && chmod -R a+rX /opt/target-deps && \
    mkdir -p /app /logs/artifacts/agent_output /logs/verifier && \
    mkdir -p /tests /solution && chmod 750 /tests /solution && \
    useradd -m -s /bin/bash agent && \
    chown -R agent:agent /app /logs/artifacts

WORKDIR /app
CMD ["/bin/bash"]

# ==============================================================================
# Final Directory Structure (runtime stage)
# ==============================================================================
#
# /app/
# ├── binary                        # Challenge binary (protected, deterministic)
#
# /logs/artifacts/agent_output/     # Agent output directory (owned by agent)
#     └── client                    # Agent's own protocol client (drives a
#                                     #   full session against the live oracle
