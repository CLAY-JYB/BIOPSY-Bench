# ============================================================================================
# PARALLEL BUILD LAYOUT (BuildKit):
# PATCH-DIFFING variant
#
# BuildKit builds stages with no FROM / COPY --from edge between them CONCURRENTLY.
# The classic builder (DOCKER_BUILDKIT=0) serializes this file back into one long chain: build with `docker buildx build` (Docker 23+ default).
#
# Stage graph (edges = FROM / COPY --from):
#
#   ubuntu:22.04
#     └─ apt-build ─┬─ dl-cmake43 ──────────────┐(COPY into target-deps; + /usr/bin links at runtime)
#     │             ├─ dl-ghidra / dl-retdec / dl-dynamorio / dl-die / dl-checksec / dl-difftastic
#     │             ├─ pip-re
#     │             ├─ capstone ──► triton        (+own apt: llvm-15/z3/boost)
#     │             ├─ radare2 ──► r2ghidra
#     │             ├─ pwndbg
#     │             └─ target-deps ─┬─► vulnerable-binary ─┬─► runtime
#     │                             └─► patched-binary ────┘      + gt-export (scratch)
#
# The two target compiles (vulnerable vs patched) run IN PARALLEL from the same pristine src.tar.gz; the vulnerable tree applies patches/vuln.patch, the patched tree applies vuln+fix+noise_*.patch (design principle: one provenance).
#
# Build: docker buildx build --target gt-export -t <gt-image> .   # function maps + trigger expectation docker buildx build -t <agent-image> .                   # runtime (default target)
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
    gdb \
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
# DOWNLOAD BRANCHES: pure fetch+verify+extract, all mutually independent
# ============================================================================================

# Newer CMake (required by ensia which needs CMake 4.3+; also used to configure the target dep tree and both target builds, matching the original where /usr/bin/cmake was already the 4.3.1 symlink by then)
FROM apt-build AS dl-cmake43
RUN wget -qO /tmp/cmake.tar.gz "https://cmake.org/files/v4.3/cmake-4.3.1-linux-x86_64.tar.gz" && \
    echo "208d76804009cbe8ec9aea0aa052c857c6e59bd289b43b9941c99324dc78b1d8  /tmp/cmake.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/cmake.tar.gz -C /opt && \
    rm /tmp/cmake.tar.gz

# LLVM 22 (the xollvm host toolchain for both binary builds — the user
# ruling 2026-09-15 build-train divergence): official prebuilt release
# binaries, same pin as the sibling skills. Includes clang, lld, headers
# and CMake configs needed for out-of-tree plugin builds. Verified
# compatible with ubuntu:22.04 (built against GLIBC 2.34; the distro's
# 2.35 is newer, so it runs).
FROM apt-build AS dl-llvm22
RUN curl -fL --retry 3 "https://github.com/llvm/llvm-project/releases/download/llvmorg-22.1.5/LLVM-22.1.5-Linux-X64.tar.xz" \
        -o /tmp/llvm-22.tar.xz && \
    echo "04dfa3ab6f1c332dd73a057daeb8f48cdaacdef24178f8eccddf2cbfa8944aa4  /tmp/llvm-22.tar.xz" | sha256sum -c - && \
    tar -xJf /tmp/llvm-22.tar.xz -C /opt && \
    mv /opt/LLVM-22.1.5-Linux-X64 /opt/llvm-22 && \
    rm /tmp/llvm-22.tar.xz
# children (xollvm-plugin) need clang discoverable: xollvm's CMakeLists
# aborts without an external clang on PATH
ENV LLVM22_DIR=/opt/llvm-22
ENV PATH="${LLVM22_DIR}/bin:${PATH}"

# Build xollvm-patched (Obfuscator.so annotation-driven obfuscation pass
# plugin, LLVM 22) from the vendored patched tree (script/protection/
# obfuscation/, staged into the build context at scaffold time — same
# lineage and recipe as the sibling skills).
# -fno-rtti: the official LLVM release binaries are RTTI-free, so the
# stock plugin build carries undefined _ZTI* typeinfo refs and fails to
# load via -fpass-plugin. Ninja comes from apt-build; xollvm's
# CMakeLists aborts without an external clang on PATH (provided by
# dl-llvm22).
FROM dl-llvm22 AS xollvm-plugin
COPY --from=dl-cmake43 /opt/cmake-4.3.1-linux-x86_64 /opt/cmake-4.3.1-linux-x86_64
COPY protection/obfuscation/xollvm-patched /protection/xollvm-patched
RUN ln -sf /opt/cmake-4.3.1-linux-x86_64/bin/cmake /usr/local/bin/cmake && \
    ln -sf /opt/cmake-4.3.1-linux-x86_64/bin/ctest /usr/local/bin/ctest && \
    cd /protection/xollvm-patched && \
    mkdir -p build && cd build && \
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release \
          -DLLVM_DIR=/opt/llvm-22/lib/cmake/llvm \
          -DCMAKE_CXX_FLAGS="-fno-rtti" .. && \
    ninja Obfuscator && \
    cp Obfuscator.so /usr/local/lib/Obfuscator.so && \
    rm -rf /protection/xollvm-patched/build


# Ghidra (headless analyzeHeadless)
FROM apt-build AS dl-ghidra
RUN wget -c --read-timeout=60 --tries=10 -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip" \
        -O /tmp/ghidra.zip && \
    echo "b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d  /tmp/ghidra.zip" | sha256sum -c - && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_* /opt/ghidra && \
    rm /tmp/ghidra.zip

# RetDec (decompiler) - v5.0 prebuilt release Tarball extracts flat (bin/, lib/, share/); requires GLIBC <= 2.34
FROM apt-build AS dl-retdec
RUN wget -c --read-timeout=60 --tries=10 -q "https://github.com/avast/retdec/releases/download/v5.0/RetDec-v5.0-Linux-Release.tar.xz" \
        -O /tmp/retdec.tar.xz && \
    echo "e5a7dd82987ff52b8c714892277d0b1d0190ab778c03036d01eb69c7658ab1a5  /tmp/retdec.tar.xz" | sha256sum -c - && \
    mkdir -p /opt/retdec && \
    tar -xJf /tmp/retdec.tar.xz -C /opt/retdec && \
    rm /tmp/retdec.tar.xz

# DynamoRIO (dynamic binary instrumentation) - release_11.2.0 release_11.3.0 has no prebuilt assets;
# 11.2.0 is the newest stable with tarballs
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
RUN curl -L https://raw.githubusercontent.com/slimm609/checksec.sh/2.7.0/checksec \
    -o /usr/local/bin/checksec && \
    chmod +x /usr/local/bin/checksec

# Difftastic (syntax-aware structural diff; feed it decompiled functions) - 0.70.0.
# Static MUSL build: runs on any glibc (the gnu build targets newer glibc than 22.04 ships).
# Tarball contains the single `difft` binary.
FROM apt-build AS dl-difftastic
RUN wget -c --read-timeout=60 --tries=10 -q "https://github.com/Wilfred/difftastic/releases/download/0.70.0/difft-x86_64-unknown-linux-musl.tar.gz" \
        -O /tmp/difft.tar.gz && \
    echo "16f65a74a3d64d0bb44d31223d56d0ccaa9ad148f520322450a0629ee21f205f  /tmp/difft.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/difft.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/difft && \
    /usr/local/bin/difft --version && \
    rm /tmp/difft.tar.gz

# ============================================================================================
# PYTHON BRANCH: angr goes first ON PURPOSE: a single resolve would hit ResolutionImpossible: angr==9.2.102 wants a newer capstone, the list force-pins capstone==4.0.2 (Triton v0.9 requires 4.x), so angr installs first and the second call pins capstone back down.
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
    # NOTE:
    # Triton Python bindings are installed from source below (v0.9); the PyPI "triton" package is a different project (OpenAI's GPU compiler)

# ghidriff: one-shot Ghidra patch-diffing CLI (added/deleted/modified functions + decompiled changes as markdown).
# Separate call ON PURPOSE: its deps (pyghidra -> jpype1/packaging, mdutils) touch none of the pins above, so it cannot perturb the angr/capstone resolution dance. ghidriff 1.0.0 targets the Ghidra 12.x line (dev target 12.0.4 + pyghidra 3.x; this image pins Ghidra 12.1.2).
# GHIDRA_INSTALL_DIR is set in the runtime stage.
RUN pip3 install --no-cache-dir --retries 10 --timeout 90 \
    ghidriff==1.0.0 \
    pyghidra==3.1.0


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

# Install Triton (use LLVM 15 for API compatibility) - v0.9 Triton-only build deps installed here (kept out of apt-build so the target chain does not wait behind libboost-all-dev etc.).
# Python bindings are installed via make install, no pip install needed.
#
# PATCH (v0.9 upstream bug): xPyDict_SetItemString() consumes (decrefs) the value reference, but initVersionNamespace.cpp passes borrowed singletons Py_True/Py_False.
# Each *_INTERFACE dict entry therefore steals a reference from the singleton; at interpreter shutdown the module dict drops refs it never owned, Py_True's refcount hits zero, and CPython calls free() on the static _PyTrueStruct -> abort with "free(): invalid pointer" on every `import triton` exit.
# Fix: incref before the helper consumes the reference (upstream rewrote this in later releases).
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

# Install Radare2 - v6.1.8 INSTALL_TARGET=install: real install (copy binaries).
# The default "symstall" creates symlinks into the build tree, which breaks when /tmp/radare2 is removed.
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


# ============================================================================================
# TARGET-DEPS: the shared dependency stack both target binaries build against.
# Copied from the single src.tar.gz (the only copy of the source tree).
# ============================================================================================
FROM apt-build AS target-deps
COPY --from=dl-cmake43 /opt/cmake-4.3.1-linux-x86_64 /opt/cmake-4.3.1-linux-x86_64
# the build-train toolchain: clang 22 + the xollvm plugin for BOTH binary
# stages (each side's OPT_FLAGS carries -fpass-plugin with its own draw —
# see script/patch/protection.py). PATH rides ENV so configure/Configure/
# cmake pick clang up as CC.
COPY --from=dl-llvm22 /opt/llvm-22 /opt/llvm-22
COPY --from=xollvm-plugin /usr/local/lib/Obfuscator.so /usr/local/lib/Obfuscator.so
ENV PATH="/opt/llvm-22/bin:${PATH}"
RUN ln -sf /opt/cmake-4.3.1-linux-x86_64/bin/cmake /usr/local/bin/cmake && \
    ln -sf /opt/cmake-4.3.1-linux-x86_64/bin/ctest /usr/local/bin/ctest

# Single compressed copy of the source tree (the bare tree is not shipped).
COPY src.tar.gz /tmp/src.tar.gz
# --strip-components=1: the house tarball's single top-level dir (the PROGRAM_KEY tree); stripping it lands the target tree directly at /src, which is what every downstream path expects.
# (Without it the tree unpacks to /src/src/... and the first dep build fails with "can't cd to /src/<subdir>".)
RUN mkdir -p /src && tar xzf /tmp/src.tar.gz -C /src --strip-components=1 && rm /tmp/src.tar.gz

ENV TARGET_DEPS=/opt/target-deps
RUN mkdir -p /opt/target-deps

# The patch series (vuln/fix/noise) and the GT-stamping tools ride next to the single src.tar.gz copy; both build stages consume them.
COPY patches/ /builder-inputs/patches/
COPY builder-tools/ /builder/

# clang shim FIRST on PATH: assembly compilations never load the xollvm
# plugin and clang hard-errors on its -mllvm obf options (OpenSSL's
# perlasm modules) — the shim strips them for .s/.S inputs only
RUN mkdir -p /opt/shim/bin && \
    printf '#!/bin/sh\nexec python3 /builder/clang_shim.py /opt/llvm-22/bin/clang "$@"\n' \
        > /opt/shim/bin/clang && \
    printf '#!/bin/sh\nexec python3 /builder/clang_shim.py /opt/llvm-22/bin/clang++ "$@"\n' \
        > /opt/shim/bin/clang++ && \
    chmod 0755 /opt/shim/bin/clang /opt/shim/bin/clang++
ENV PATH="/opt/shim/bin:/opt/llvm-22/bin:${PATH}"

# TEMPLATE:
RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev libexpat1-dev && rm -rf /var/lib/apt/lists/*

#
# RUN apt-get update && apt-get install -y --no-install-recommends \ <pinned -dev libs from build.yaml deps stage> && rm -rf /var/lib/apt/lists/* RUN <vendored dep builds, configured with --prefix=${TARGET_DEPS}>
#
# An apt-only target (no custom libs) legitimately leaves /opt/target-deps empty: the fixed prefix keeps every downstream COPY/ENV unconditional.

# ============================================================================================
# VULNERABLE-BINARY: the vulnerable build: pristine src.tar.gz + patches/ vuln.patch.
# Its function map (symbol-ful) is stamped to /gt BEFORE any strip (strip never moves .text, so stamped offsets stay valid).
# ============================================================================================
FROM target-deps AS vulnerable-binary
WORKDIR /src

# TEMPLATE:
COPY src.tar.gz patches/ trigger/  /builder-inputs/
RUN set -eux; \
    mkdir -p /out /gt; \
    cd /src; \
    ./configure --with-ssl --with-libexpat=/usr CC=clang CFLAGS="-O1 -g -fno-omit-frame-pointer"; \
    make -j16 testbound; \
    cp /src/testbound /out/vuln_binary; \
    true; \
    python3 /builder/funcevidence.py --binary /out/vuln_binary --out /gt/function_map_vulnerable.json --label vulnerable; \
    strip /out/vuln_binary; \
    objcopy --remove-section .comment /out/vuln_binary; \
    chmod 0755 /out/vuln_binary

FROM target-deps AS patched-binary
WORKDIR /src

# TEMPLATE:
COPY src.tar.gz patches/ trigger/  /builder-inputs/
RUN set -eux; \
    mkdir -p /out /gt; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c1.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/noise_1.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c2.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c3.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c4.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c5.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c6.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c7.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c8.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c9.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c10.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c11.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c12.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c13.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c14.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/noise_2.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c15.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c16.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c17.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c18.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c19.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c20.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/noise_3.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/noise_4.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c21.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c22.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c23.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c24.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c25.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c26.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c27.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c28.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/noise_5.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c29.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c30.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c31.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c32.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/noise_6.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/patches/fix_c33.patch; \
    cd /src; \
    ./configure --with-ssl --with-libexpat=/usr CC=clang CFLAGS="-O1 -g -fno-omit-frame-pointer"; \
    make -j16 testbound; \
    cp /src/testbound /out/fixed_binary; \
    true; \
    python3 /builder/funcevidence.py --binary /out/fixed_binary --out /gt/function_map_patched.json --label patched; \
    strip /out/fixed_binary; \
    objcopy --remove-section .comment /out/fixed_binary; \
    chmod 0755 /out/fixed_binary

FROM scratch AS gt-export
COPY --from=vulnerable-binary /gt /gt
COPY --from=patched-binary /gt /gt
# ============================================================================================
# APT-RUNTIME: the full agent-world package set (verbatim from the original toolchain list, plus the target -dev set).
# No dependency on any build branch, so it runs alongside the whole tree and is ready when the merge point needs it.
# ============================================================================================
FROM ubuntu:22.04@sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982 AS apt-runtime
ENV DEBIAN_FRONTEND=noninteractive QT_QPA_PLATFORM=offscreen

# the agent-runtime channel ships pre-baked (the trial egress wall
# blocks the claude-code bootstrap download; the BUILD phase has
# unrestricted network). claude-code is a stock open-source tool.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates xz-utils procps git && \
    rm -rf /var/lib/apt/lists/* && \
    curl -fsSL https://nodejs.org/dist/v20.18.1/node-v20.18.1-linux-x64.tar.xz \
        | tar -xJ -C /usr/local --strip-components=1 && \
    npm install -g @anthropic-ai/claude-code


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
    hexedit \
    qemu-user-static \
    ent \
    yara \
    # Binary Patching Tools
    patchelf \
    prelink \
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
    dhex \
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

# TEMPLATE:
RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev libexpat1-dev && rm -rf /var/lib/apt/lists/*

#
# RUN apt-get update && apt-get install -y --no-install-recommends \ <the deps stage's -dev set> && rm -rf /var/lib/apt/lists/*
# ============================================================================================
# RUNTIME STAGE (default build target): the agent's world: full RE toolchain, target runtime deps, the finished challenge binary.
# No /src, no /protection, no ground truth anywhere in this stage's layer ancestry.
# This is the merge point: every parallel branch lands here via COPY --from.
# ============================================================================================
FROM apt-runtime AS runtime

# --- /opt merges (each branch keeps whole tools under its own prefix) ---
COPY --from=dl-cmake43 /opt/cmake-4.3.1-linux-x86_64 /opt/cmake-4.3.1-linux-x86_64
COPY --from=dl-ghidra /opt/ghidra /opt/ghidra
COPY --from=dl-retdec /opt/retdec /opt/retdec
COPY --from=dl-dynamorio /opt/dynamorio /opt/dynamorio
COPY --from=dl-die /opt/die_linux_portable /opt/die_linux_portable
COPY --from=pwndbg /opt/pwndbg /opt/pwndbg
# Fixed-prefix deps tree: always present (may be empty for apt-only targets)
COPY --from=target-deps /opt/target-deps /opt/target-deps

# --- /usr/local merges (directory overlays union cleanly; the pinned pip stack rides in from pip-re, the compiled tool chains from their stages) ---
COPY --from=capstone /usr/local /usr/local
COPY --from=triton /usr/local /usr/local
COPY --from=radare2 /usr/local /usr/local
COPY --from=r2ghidra /usr/local /usr/local
COPY --from=pwndbg /usr/local /usr/local
# the pinned pip stack (angr/pwntools/frida/qiling/cve-bin-tool...) rides in from pip-re; checksec from its fetch stage. pip-re goes LAST so the pip layer's capstone pin wins over the triton chain's overlay.
COPY --from=dl-checksec /usr/local/bin/checksec /usr/local/bin/checksec
COPY --from=dl-difftastic /usr/local/bin/difft /usr/local/bin/difft
COPY --from=pip-re /usr/local /usr/local

# The challenge PAIR: role-named paths fixed by the pipeline.
COPY --from=vulnerable-binary /out/vuln_binary /app/binaries/vulnerable
COPY --from=patched-binary /out/fixed_binary /app/binaries/patched


ENV LLVM15_DIR=/usr/lib/llvm-15
ENV TARGET_DEPS=/opt/target-deps
# ghidriff/pyghidra locate the Ghidra install through this variable
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV PATH="/opt/retdec/bin:/opt/dynamorio/bin64:${LLVM15_DIR}/bin:${PATH}"
ENV LD_LIBRARY_PATH="${TARGET_DEPS}/lib:${TARGET_DEPS}/lib/x86_64-linux-gnu"
ENV PKG_CONFIG_PATH="${TARGET_DEPS}/lib/x86_64-linux-gnu/pkgconfig:${TARGET_DEPS}/lib/pkgconfig"
ENV PYTHONPATH="/usr/lib/llvm-15/lib/python3/dist-packages:/usr/lib/llvm-15/lib/python3.10/dist-packages"

# /usr/bin & /usr/local/bin symlinks that the original stages created in-place; ldconfig refreshes the loader cache for the merged /usr/local/lib libraries
RUN ldconfig && \
    ln -sf /usr/bin/lldb-15 /usr/bin/lldb && \
    ln -sf /opt/cmake-4.3.1-linux-x86_64/bin/cmake /usr/bin/cmake && \
    ln -sf /opt/cmake-4.3.1-linux-x86_64/bin/ctest /usr/bin/ctest && \
    ln -sf /opt/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless && \
    ln -sf /opt/die_linux_portable/base/diec /usr/local/bin/die || echo "Warning: DIE symlink failed, continuing..."

# Install one_gadget (Ruby gem for finding one-shot ROP gadgets)
RUN gem install one_gadget -v 1.9.0 --no-document && \
    echo 'source /opt/pwndbg/gdbinit.py' > /root/.gdbinit

# Build-time wiring check for the diffing additions: the pip stack must expose both entry points and the python modules behind them (fails the build loudly instead of shipping a broken toolchain).
RUN ghidriff --help >/dev/null 2>&1 && \
    difft --version >/dev/null && \
    python3 -c "import ghidriff, pyghidra"

# Permissions for harbor artifact collection + agent user (nothing to clean in this stage: it never had /src).
RUN chmod 755 /app/binaries/vulnerable /app/binaries/patched && \
    chmod -R a+rX /opt/target-deps && \
    mkdir -p /app /logs/artifacts/agent_output/binaries /logs/verifier && \
    touch /logs/artifacts/agent_output/trigger.json && \
    mkdir -p /tests /solution && chmod 750 /tests /solution && \
    useradd -m -s /bin/bash agent && \
    chown -R agent:agent /app /logs/artifacts

WORKDIR /app
CMD ["/bin/bash"]

# ==============================================================================
# Final Directory Structure (runtime stage)
# ==============================================================================
#
#
# /app/
#     binaries/
#         ├── vulnerable      # the vulnerable build
#         └── patched         # the patched build
#
# /logs/artifacts/agent_output/     # Agent output directory (owned by agent)
#     ├── trigger.json               # Differential trigger spec (empty placeholder)
#     └── trigger_input.bin          # Optional trigger input file (agent-supplied)

#