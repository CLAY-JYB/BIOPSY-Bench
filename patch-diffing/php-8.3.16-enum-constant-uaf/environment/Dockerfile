# ============================================================================================
# PARALLEL BUILD LAYOUT (BuildKit):
# PATCH-DIFFING variant
#
# BuildKit builds stages with no FROM / COPY --from edge between them CONCURRENTLY.
# The classic builder (DOCKER_BUILDKIT=0) serializes this file back into one long chain. Build with `docker buildx build` (Docker 23+ default).
#
# Stage graph (edges = FROM / COPY --from):
#
#   ubuntu:22.04
#     └─ apt-build ─┬─ dl-cmake43 ──────────────┐(COPY into target-deps. + /usr/bin links at runtime)
#     │             ├─ dl-ghidra / dl-retdec / dl-dynamorio / dl-die / dl-checksec / dl-difftastic
#     │             ├─ pip-re
#     │             ├─ capstone ──► triton        (+own apt: llvm-15/z3/boost)
#     │             ├─ radare2 ──► r2ghidra
#     │             ├─ pwndbg
#     │             └─ target-deps ─┬─► vulnerable-binary ─┬─► runtime
#     │                             └─► patched-binary ────┘      + gt-export (scratch)
#
# The two target compiles (vulnerable vs patched) run IN PARALLEL from the same pristine src.tar.gz. The vulnerable tree IS the pristine source, the patched tree applies the whole update series, fix fragments plus release-drift noise plus decoy guards (design principle: one provenance).
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

# Newer CMake (required by ensia which needs CMake 4.3+. Also used to configure the target dep tree and both target builds, matching the original where /usr/bin/cmake was already the 4.3.1 symlink by then)
FROM apt-build AS dl-cmake43
RUN wget -qO /tmp/cmake.tar.gz "https://cmake.org/files/v4.3/cmake-4.3.1-linux-x86_64.tar.gz" && \
    echo "208d76804009cbe8ec9aea0aa052c857c6e59bd289b43b9941c99324dc78b1d8  /tmp/cmake.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/cmake.tar.gz -C /opt && \
    rm /tmp/cmake.tar.gz

# LLVM 22 (the xollvm host toolchain for both binary builds, the user
# ruling 2026-09-15 build-train divergence): official prebuilt release
# binaries, same pin as the sibling skills. Includes clang, lld, headers
# and CMake configs needed for out-of-tree plugin builds. Verified
# compatible with ubuntu:22.04 (built against GLIBC 2.34. The distro's
# 2.35 is newer, so it runs).
FROM apt-build AS dl-llvm22
RUN curl -fL --retry 3 "https://github.com/llvm/llvm-project/releases/download/llvmorg-22.1.5/LLVM-22.1.5-Linux-X64.tar.xz" \
        -o /tmp/llvm-22.tar.xz && \
    echo "04dfa3ab6f1c332dd73a057daeb8f48cdaacdef24178f8eccddf2cbfa8944aa4  /tmp/llvm-22.tar.xz" | sha256sum -c - && \
    tar -xJf /tmp/llvm-22.tar.xz -C /opt && \
    mv /opt/LLVM-22.1.5-Linux-X64 /opt/llvm-22 && \
    rm /tmp/llvm-22.tar.xz
# children (xollvm-plugin) need clang discoverable. xollvm's CMakeLists
# aborts without an external clang on PATH
ENV LLVM22_DIR=/opt/llvm-22
ENV PATH="${LLVM22_DIR}/bin:${PATH}"

# Build xollvm-patched (Obfuscator.so annotation-driven obfuscation pass
# plugin, LLVM 22) from the vendored patched tree (script/protection/
# obfuscation/, staged into the build context at scaffold time, same
# lineage and recipe as the sibling skills).
# -fno-rtti: the official LLVM release binaries are RTTI-free, so the
# stock plugin build carries undefined _ZTI* typeinfo refs and fails to
# load via -fpass-plugin. Ninja comes from apt-build. xollvm's
# CMakeLists aborts without an external clang on PATH (provided by
# dl-llvm22).


# Ghidra (headless analyzeHeadless)
FROM apt-build AS dl-ghidra
RUN wget -c --read-timeout=60 --tries=10 -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip" \
        -O /tmp/ghidra.zip && \
    echo "b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d  /tmp/ghidra.zip" | sha256sum -c - && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_* /opt/ghidra && \
    rm /tmp/ghidra.zip

# RetDec (decompiler), v5.0 prebuilt release Tarball extracts flat (bin/, lib/, share/). Requires GLIBC <= 2.34
FROM apt-build AS dl-retdec
RUN wget -c --read-timeout=60 --tries=10 -q "https://github.com/avast/retdec/releases/download/v5.0/RetDec-v5.0-Linux-Release.tar.xz" \
        -O /tmp/retdec.tar.xz && \
    echo "e5a7dd82987ff52b8c714892277d0b1d0190ab778c03036d01eb69c7658ab1a5  /tmp/retdec.tar.xz" | sha256sum -c - && \
    mkdir -p /opt/retdec && \
    tar -xJf /tmp/retdec.tar.xz -C /opt/retdec && \
    rm /tmp/retdec.tar.xz

# DynamoRIO (dynamic binary instrumentation), release_11.2.0 release_11.3.0 has no prebuilt assets.
# 11.2.0 is the newest stable with tarballs
FROM apt-build AS dl-dynamorio
RUN wget -c --read-timeout=60 --tries=10 -q "https://github.com/DynamoRIO/dynamorio/releases/download/release_11.2.0/DynamoRIO-Linux-11.2.0.tar.gz" \
        -O /tmp/dynamorio.tar.gz && \
    echo "46997695d17ef7be182f503cdf3d697784e8379b7817b7b43501f8ecb4625f53  /tmp/dynamorio.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/dynamorio.tar.gz -C /opt && \
    mv /opt/DynamoRIO-Linux-11.2.0 /opt/dynamorio && \
    rm /tmp/dynamorio.tar.gz

# Detect It Easy (DIE), packer/protector identification (CLI version) Tolerant tail: a failed download must not fail the image (DIE is optional tooling), so the dir is guaranteed to exist for the runtime COPY --from.
FROM apt-build AS dl-die
RUN wget -c --read-timeout=60 --tries=10 -q "https://github.com/horsicq/DIE-engine/releases/download/3.21/die_3.21_portable_Ubuntu_20.04_amd64.tar.gz" \
        -O /tmp/die.tar.gz && \
    echo "4d85614dd169c0d23f52084f86e05a503c30429df5fb5ec14de50f23808bc2d4  /tmp/die.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/die.tar.gz -C /opt && \
    rm -rf /tmp/die.tar.gz || echo "Warning: DIE installation failed, continuing..." ; \
    mkdir -p /opt/die_linux_portable

# Install Checksec, v2.7.0
FROM apt-build AS dl-checksec
RUN curl -L https://raw.githubusercontent.com/slimm609/checksec.sh/2.7.0/checksec \
    -o /usr/local/bin/checksec && \
    chmod +x /usr/local/bin/checksec

# Difftastic (syntax-aware structural diff. Feed it decompiled functions), 0.70.0.
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
    # SMT Solvers (z3 above. Alternatives much faster on bitwise license-check constraints)
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
    # Triton Python bindings are installed from source below (v0.9). The PyPI "triton" package is a different project (OpenAI's GPU compiler)

# ghidriff: one-shot Ghidra patch-diffing CLI (added/deleted/modified functions + decompiled changes as markdown).
# Separate call ON PURPOSE: its deps (pyghidra -> jpype1/packaging, mdutils) touch none of the pins above, so it cannot perturb the angr/capstone resolution dance. ghidriff 1.0.0 targets the Ghidra 12.x line (dev target 12.0.4 + pyghidra 3.x. This image pins Ghidra 12.1.2).
# GHIDRA_INSTALL_DIR is set in the runtime stage.
RUN pip3 install --no-cache-dir --retries 10 --timeout 90 \
    ghidriff==1.0.0 \
    pyghidra==3.1.0


# ============================================================================================
# CAPSTONE → TRITON CHAIN
# ============================================================================================

# Install Capstone (for Triton), v4.0.2 (Triton v0.9 requires Capstone 4.x)
FROM apt-build AS capstone
RUN cd /tmp && \
    git clone --branch 4.0.2 --depth 1 https://github.com/capstone-engine/capstone.git && \
    cd capstone && \
    ./make.sh && \
    ./make.sh install && \
    cd .. && \
    rm -rf capstone

# Install Triton (use LLVM 15 for API compatibility), v0.9 Triton-only build deps installed here (kept out of apt-build so the target chain does not wait behind libboost-all-dev etc.).
# Python bindings are installed via make install, no pip install needed.
#
# PATCH (v0.9 upstream bug): xPyDict_SetItemString() consumes (decrefs) the value reference, but initVersionNamespace.cpp passes borrowed singletons Py_True/Py_False.
# Each *_INTERFACE dict entry therefore steals a reference from the singleton. At interpreter shutdown the module dict drops refs it never owned, Py_True's refcount hits zero, and CPython calls free() on the static _PyTrueStruct -> abort with "free(): invalid pointer" on every `import triton` exit.
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

# Install Radare2, v6.1.8 INSTALL_TARGET=install: real install (copy binaries).
# The default "symstall" creates symlinks into the build tree, which breaks when /tmp/radare2 is removed.
FROM apt-build AS radare2
RUN git clone --branch 6.1.8 --depth 1 https://github.com/radareorg/radare2.git /tmp/radare2 && \
    cd /tmp/radare2 && \
    MAKE_JOBS=$(nproc) INSTALL_TARGET=install WITHOUT_PULL=1 ./sys/install.sh && \
    rm -rf /tmp/radare2

# Install r2ghidra (Ghidra decompiler as an r2 plugin), 6.1.8 (matches radare2 version) "make -C subprojects" fetches ghidra-native 0.6.4 (pinned in the 6.1.8 tag's wrap files), applies its patch set, and builds pugixml/zlib deps before the plugin itself compiles.
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

# Install pwndbg (GDB enhancement for exploit development), v2024.08.29 setup.sh installs its own system deps (gdb, python3-venv, ...) exactly as it did inside the original toolchain stage. Everything stays under /opt/pwndbg.
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
# stages (each side's OPT_FLAGS carries -fpass-plugin with its own draw.
# see script/protection/xollvm/). PATH rides ENV so configure/Configure/
# cmake pick clang up as CC.
COPY --from=dl-llvm22 /opt/llvm-22 /opt/llvm-22
ENV PATH="/opt/llvm-22/bin:${PATH}"
RUN ln -sf /opt/cmake-4.3.1-linux-x86_64/bin/cmake /usr/local/bin/cmake && \
    ln -sf /opt/cmake-4.3.1-linux-x86_64/bin/ctest /usr/local/bin/ctest

# Single compressed copy of the source tree (the bare tree is not shipped).
COPY src.tar.gz /tmp/src.tar.gz
# --strip-components=1: the house tarball's single top-level dir (the PROGRAM_KEY tree). Stripping it lands the target tree directly at /src, which is what every downstream path expects.
# (Without it the tree unpacks to /src/src/... and the first dep build fails with "can't cd to /src/<subdir>".)
RUN mkdir -p /src && tar xzf /tmp/src.tar.gz -C /src --strip-components=1 && rm /tmp/src.tar.gz

ENV TARGET_DEPS=/opt/target-deps
RUN mkdir -p /opt/target-deps

# The commit series rides next to the single src.tar.gz copy. Both
# build stages consume it.
COPY commits/ /builder-inputs/commits/



# TEMPLATE:
RUN apt-get update && apt-get install -y --no-install-recommends autoconf bison re2c pkg-config libasan5 && rm -rf /var/lib/apt/lists/*

#
# RUN apt-get update && apt-get install -y --no-install-recommends \ <pinned -dev libs from build.yaml deps stage> && rm -rf /var/lib/apt/lists/* RUN <vendored dep builds, configured with --prefix=${TARGET_DEPS}>
#
# An apt-only target (no custom libs) legitimately leaves /opt/target-deps empty. The fixed prefix keeps every downstream COPY/ENV unconditional.

# ============================================================================================
# VULNERABLE-BINARY: the vulnerable build, the pristine source itself.
# Its function map (symbol-ful) is stamped to /gt BEFORE any strip (strip never moves .text, so stamped offsets stay valid).
# ============================================================================================
FROM target-deps AS vulnerable-binary
WORKDIR /src

# TEMPLATE:
COPY src.tar.gz commits/ gh12366.inc /builder-inputs/
RUN set -eux; \
    mkdir -p /out /gt; \
    cd /src; \
    ./buildconf --force >/dev/null 2>&1 && ./configure --disable-all --enable-opcache --enable-cli --without-pear --disable-cgi --enable-address-sanitizer CC=clang CFLAGS="-O1 -fno-omit-frame-pointer -fstack-protector-strong -D_FORTIFY_SOURCE=2"; \
    make -j16; \
    cp /src/sapi/cli/php /out/vuln_binary; \
    cp /out/vuln_binary /out/vuln_binary.unstripped; \
    cp $(find /src -name opcache.so | head -1) /usr/local/lib/opcache.so && cp /builder-inputs/gh12366.inc /usr/local/lib/gh12366.inc; \
    strip /out/vuln_binary; \
    objcopy --remove-section .comment /out/vuln_binary; \
    chmod 0755 /out/vuln_binary

FROM target-deps AS patched-binary
WORKDIR /src

# TEMPLATE:
COPY src.tar.gz commits/ gh12366.inc /builder-inputs/
RUN set -eux; \
    mkdir -p /out /gt; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p1.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n1.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n2.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n3.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n4.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n5.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p2.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n6.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n7.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n8.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n9.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p3.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d1.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n10.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n11.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p4.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p5.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n12.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d2.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d3.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n13.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n14.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p6.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n15.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n16.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n17.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n18.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n19.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d4.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n20.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p7.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n21.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p8.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n22.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n23.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n24.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n25.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n26.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p9.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n27.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n28.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n29.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n30.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p10.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n31.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n32.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n33.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d5.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n34.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n35.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d6.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n36.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n37.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n38.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n39.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n40.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n41.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n42.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p11.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d7.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n43.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n44.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n45.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n46.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n47.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n48.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n49.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n50.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n51.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n52.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n53.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n54.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n55.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n56.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n57.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n58.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d8.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n59.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p12.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n60.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n61.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n62.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n63.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n64.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n65.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n66.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n67.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p13.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n68.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d9.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p14.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n69.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n70.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n71.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n72.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d10.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n73.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n74.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n75.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n76.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n77.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n78.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n79.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n80.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n81.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n82.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n83.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n84.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n85.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n86.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n87.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n88.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n89.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n90.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n91.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n92.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n93.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d11.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n94.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n95.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n96.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n97.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n98.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n99.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n100.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n101.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n102.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n103.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n104.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n105.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p15.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d12.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d13.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n106.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n107.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n108.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n109.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d14.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n110.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n111.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n112.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n113.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n114.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n115.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n116.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n117.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n118.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n119.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n120.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n121.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n122.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n123.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n124.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n125.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n126.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n127.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n128.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n129.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n130.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n131.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n132.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n133.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n134.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p16.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n135.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n136.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p17.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n137.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n138.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n139.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p18.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n140.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n141.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n142.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d15.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n143.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n144.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p19.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n145.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n146.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p20.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n147.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n148.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n149.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p21.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n150.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n151.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n152.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n153.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n154.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n155.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n156.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d16.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n157.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n158.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d17.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n159.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n160.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n161.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n162.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n163.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p22.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n164.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n165.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n166.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n167.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n168.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n169.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n170.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n171.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n172.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n173.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n174.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p23.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n175.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n176.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n177.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d18.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n178.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n179.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d19.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n180.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n181.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n182.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d20.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n183.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n184.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n185.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n186.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n187.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n188.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n189.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n190.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n191.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n192.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n193.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n194.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n195.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n196.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n197.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d21.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n198.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n199.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n200.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n201.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n202.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n203.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n204.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n205.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n206.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n207.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n208.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n209.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n210.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n211.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n212.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n213.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d22.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n214.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n215.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n216.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n217.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p24.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n218.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n219.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d23.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n220.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n221.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n222.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n223.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n224.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n225.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n226.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n227.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n228.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n229.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n230.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d24.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p25.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n231.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n232.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n233.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n234.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n235.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n236.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n237.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n238.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n239.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n240.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n241.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n242.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n243.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n244.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n245.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d25.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n246.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p26.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n247.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n248.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n249.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n250.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d26.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n251.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d27.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n252.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n253.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p27.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n254.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n255.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n256.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p28.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p29.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n257.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d28.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n258.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n259.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n260.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n261.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n262.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n263.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n264.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n265.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p30.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n266.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n267.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n268.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n269.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n270.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n271.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p31.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n272.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p32.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n273.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n274.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n275.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n276.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n277.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n278.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n279.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n280.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n281.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n282.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n283.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d29.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n284.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n285.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p33.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n286.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n287.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d30.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n288.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d31.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n289.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d32.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n290.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n291.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n292.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n293.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n294.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n295.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p34.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n296.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p35.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n297.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n298.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n299.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n300.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n301.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n302.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n303.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n304.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n305.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n306.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p36.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p37.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n307.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n308.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p38.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n309.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n310.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n311.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n312.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n313.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n314.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n315.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n316.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n317.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n318.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n319.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d33.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n320.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n321.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p39.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n322.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n323.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n324.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d34.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n325.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n326.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n327.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n328.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n329.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n330.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n331.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n332.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n333.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n334.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n335.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n336.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n337.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n338.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n339.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n340.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n341.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n342.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p40.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d35.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p41.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n343.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n344.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n345.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n346.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n347.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n348.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n349.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p42.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n350.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n351.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n352.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n353.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n354.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p43.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n355.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n356.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n357.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n358.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n359.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n360.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n361.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n362.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n363.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n364.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n365.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n366.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n367.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n368.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p44.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n369.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n370.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n371.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n372.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n373.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n374.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n375.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n376.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n377.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p45.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n378.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n379.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d36.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n380.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n381.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n382.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n383.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d37.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n384.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n385.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n386.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n387.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n388.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n389.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n390.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n391.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n392.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n393.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n394.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n395.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n396.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n397.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n398.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n399.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n400.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n401.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n402.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n403.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d38.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n404.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n405.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p46.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n406.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n407.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n408.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n409.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n410.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n411.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n412.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n413.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n414.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d39.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n415.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n416.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n417.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n418.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n419.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n420.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n421.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n422.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n423.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n424.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n425.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n426.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p47.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n427.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n428.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n429.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n430.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n431.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n432.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n433.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n434.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n435.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p48.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n436.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n437.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n438.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p49.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n439.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n440.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n441.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/decoy/d40.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n442.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p50.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n443.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n444.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/noise/n445.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p51.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p52.patch; \
    patch -d /src -p1 --fuzz=0 --silent < /builder-inputs/commits/patch/p53.patch; \
    cd /src; \
    ./buildconf --force >/dev/null 2>&1 && ./configure --disable-all --enable-opcache --enable-cli --without-pear --disable-cgi --enable-address-sanitizer CC=clang CFLAGS="-O1 -fno-omit-frame-pointer -fstack-protector-strong -D_FORTIFY_SOURCE=2"; \
    make -j16; \
    cp /src/sapi/cli/php /out/fixed_binary; \
    cp /out/fixed_binary /out/fixed_binary.unstripped; \
    cp $(find /src -name opcache.so | head -1) /usr/local/lib/opcache.so && cp /builder-inputs/gh12366.inc /usr/local/lib/gh12366.inc; \
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
# blocks the claude-code bootstrap download. The BUILD phase has
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
RUN apt-get update && apt-get install -y --no-install-recommends autoconf bison re2c pkg-config libasan5 && rm -rf /var/lib/apt/lists/*

#
# RUN apt-get update && apt-get install -y --no-install-recommends \ <the deps stage's -dev set> && rm -rf /var/lib/apt/lists/*
# ============================================================================================
# RUNTIME STAGE (default build target): the agent's world: full RE toolchain, target runtime deps, the finished challenge binary.
# No /src, no /protection, no ground truth anywhere in this stage's layer ancestry.
# This is the merge point. Every parallel branch lands here via COPY --from.
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

# --- /usr/local merges (directory overlays union cleanly. The pinned pip stack rides in from pip-re, the compiled tool chains from their stages) ---
COPY --from=capstone /usr/local /usr/local
COPY --from=triton /usr/local /usr/local
COPY --from=radare2 /usr/local /usr/local
COPY --from=r2ghidra /usr/local /usr/local
COPY --from=pwndbg /usr/local /usr/local
# the pinned pip stack (angr/pwntools/frida/qiling/cve-bin-tool...) rides in from pip-re. Checksec from its fetch stage. pip-re goes LAST so the pip layer's capstone pin wins over the triton chain's overlay.
COPY --from=dl-checksec /usr/local/bin/checksec /usr/local/bin/checksec
COPY --from=dl-difftastic /usr/local/bin/difft /usr/local/bin/difft
COPY --from=pip-re /usr/local /usr/local

# The challenge PAIR: role-named paths fixed by the pipeline.
COPY --from=vulnerable-binary /out/vuln_binary /app/binaries/vulnerable
COPY --from=vulnerable-binary /usr/local/lib/opcache.so /usr/local/lib/opcache.so
COPY --from=vulnerable-binary /usr/local/lib/gh12366.inc /usr/local/lib/gh12366.inc
COPY --from=patched-binary /out/fixed_binary /app/binaries/patched


ENV LLVM15_DIR=/usr/lib/llvm-15
ENV TARGET_DEPS=/opt/target-deps
# ghidriff/pyghidra locate the Ghidra install through this variable
ENV GHIDRA_INSTALL_DIR=/opt/ghidra
ENV PATH="/opt/retdec/bin:/opt/dynamorio/bin64:${LLVM15_DIR}/bin:${PATH}"
ENV LD_LIBRARY_PATH="${TARGET_DEPS}/lib:${TARGET_DEPS}/lib/x86_64-linux-gnu"
ENV PKG_CONFIG_PATH="${TARGET_DEPS}/lib/x86_64-linux-gnu/pkgconfig:${TARGET_DEPS}/lib/pkgconfig"
ENV PYTHONPATH="/usr/lib/llvm-15/lib/python3/dist-packages:/usr/lib/llvm-15/lib/python3.10/dist-packages"

# /usr/bin & /usr/local/bin symlinks that the original stages created in-place. ldconfig refreshes the loader cache for the merged /usr/local/lib libraries
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

# Permissions for harbor artifact collection + agent user (nothing to clean in this stage. It never had /src).
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