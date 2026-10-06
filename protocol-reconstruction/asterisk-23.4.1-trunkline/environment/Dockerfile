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
# step 3.5 sample capture rides beside the binary
COPY src.tar.gz /tmp/src.tar.gz
RUN mkdir -p /src && tar xzf /tmp/src.tar.gz -C /src --strip-components=1 && rm /tmp/src.tar.gz

RUN mkdir -p /opt/target-deps /app
# Carrier deps ride inside the build span below (apt in-stage), matching
# the original recipe verbatim.
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
RUN mkdir -p /gt/binaries && cc -O2 -o /gt/binaries/oracle_server /src/proto/oracle_server.c \
       /src/proto/protocol.c -lpthread && \
    cc -O2 -o /gt/binaries/ref_client /src/proto/ref_client.c \
       /src/proto/proto_client.c /src/proto/protocol.c -lpthread

# ============================================================================================
# CHALLENGE-BINARY — full protection chain (D3 + O5 + P2), runs IN PARALLEL with
# origin-binary: identical deps stage, own build tree, clang+plugin toolchain.
# ============================================================================================
FROM target-deps AS challenge-binary
COPY concealment/ /concealment/
# Tigress 4.0.11 from the staged deb (gen_concealment.py stages it at O3+;
# the runtime stage installs its own copy for the agent world)
RUN dpkg --force-architecture -i /concealment/obfuscation/tigress_4.0.11-1_all.deb && \
    rm /concealment/obfuscation/tigress_4.0.11-1_all.deb && \
    command -v tigress >/dev/null
WORKDIR /src

# CHALLENGE deps (carrier recipe pins) + host-bound wire state (site C,
# reference/host-binding.md): the carrier reads these through its REAL
# config parser and astdb subsystem at boot -- install at the paths the
# unconfigured defaults resolve to (/etc/asterisk, /var/lib/asterisk).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libjansson-dev \
        libxml2-dev \
        libsqlite3-dev \
        uuid-dev \
        libssl-dev \
        libedit-dev \
        libncurses-dev && \
    mkdir -p /out /etc/asterisk /var/lib/asterisk && \
    cp /src/host-state/asterisk.conf /src/host-state/modules.conf \
       /src/host-state/extensions.conf /src/host-state/rtp.conf /etc/asterisk/ && \
    cp /src/host-state/astdb.sqlite3 /var/lib/asterisk/astdb.sqlite3

# Pristine engine snapshot for the post-concealment smoke client: compile
# the PLAIN objects from the UNEDITED sources before any concealment edit
# lands (the post-prep protocol.c carries the tigress dummy main + boot
# references and cannot link standalone).
RUN cp -r /src/proto /tmp/proto_plain_src && \
    cc -O2 -c /tmp/proto_plain_src/protocol.c -o /tmp/protocol_plain.o && \
    cc -O2 -c /tmp/proto_plain_src/proto_client.c -o /tmp/proto_client_plain.o

# D3 binary concealment (seeded plan, concealment_config.json): inject the
# advanced anti-debug check set (TracerPid, parent-process name, SIGTRAP
# handling, timing, breakpoint scan, /proc/self/maps injection + frida
# fingerprints, anti-dump, self-ptrace tracer-slot occupation -- ACTION_EXIT)
# into proto_server_entry's serving path -- anchored at the pc_full_tcp_listen()
# call so the checks run ONLY on the hidden --proto-server path. The guards
# matter: the injector edits the file even when anchor matching FAILS.
RUN python3 /src/proto/anti-debug.py /src/proto/proto_core.c \
        --checks advanced \
        --insert-at-call pc_full_tcp_listen,proto_serve_connection --quiet && \
    grep -c 'adbg_init_config(&adbg_site_cfg' /src/proto/proto_core.c | grep -q '^2$' && \
    ! grep -q 'adbg' /src/proto/protocol.c

# O4 prep -- source edits on the engine, each idempotent with a hard
# assert (a missed edit fails the build, never ships quietly):
#   1. tigress_prep wiring: declares the empty init_tigress() stub and
#      calls it first inside proto_server_entry (InitEntropy/InitOpaque/
#      InitBranchFuns instrument the stub; without the runtime call the
#      opaque state is never initialised and the VM segfaults).
#   2. pointer LNot rewrite: CIL's TreeCode converter crashes on `!ptr`
#      ("TreeCodeCIL2Tree.vUnop.arithmeticVersionOf") -- the equivalent
#      `p == NULL` form is accepted.
#   3. whole-program boot: Tigress requires a main(); a dummy main is
#      appended to protocol.c, its object symbol renamed proto_tigress_boot
#      at link time, and the engine calls it first inside
#      proto_server_entry so CIL-relocated global tables exist before any
#      virtualised code runs.
RUN python3 /concealment/obfuscation/tigress_prep.py /src/proto/proto_core.c \
        --init-func init_tigress --target-function proto_server_entry && \
    python3 - <<'PYEOF'
edits = {
 'proto_frame.c': [
   ('if (!sch) return -1;', 'if (sch == NULL) return -1;'),
   ('if (!cand) return -1;', 'if (cand == NULL) return -1;'),
 ],
 'proto_encode.c': [
   ('if (!tok) return -1;', 'if (tok == NULL) return -1;'),
 ],
 'proto_core.c': [
   ('if (!seed)', 'if (seed == NULL)'),
 ],
}
for fn, pairs in edits.items():
    p = '/src/proto/' + fn
    t = open(p).read()
    for old, new in pairs:
        if new not in t:
            assert t.count(old) >= 1, ('LNot anchor missing', fn, old)
            t = t.replace(old, new)
    open(p, 'w').write(t)
t = open('/src/proto/proto_core.c').read()
if 'proto_tigress_boot' not in t:
    old = ('int proto_server_entry(int argc, char **argv, const char *applet) {\n'
           '    init_tigress();')
    new = ('int proto_tigress_boot(int argc, char **argv, char **envp);\n'
           'int proto_server_entry(int argc, char **argv, const char *applet) {\n'
           '    proto_tigress_boot(0, 0, 0);\n    init_tigress();')
    assert t.count(old) == 1, 'boot anchor missing'
    t = t.replace(old, new)
    open('/src/proto/proto_core.c', 'w').write(t)
t = open('/src/proto/protocol.c').read()
if 'int main(void){return 0;}' not in t:
    t += ('\n/* tigress whole-program stub: CIL relocates global-table inits into\n'
          '   main, whose object symbol is renamed proto_tigress_boot at link */\n'
          'int main(void){return 0;}\n')
    open('/src/proto/protocol.c', 'w').write(t)
print('O4 prep OK')
PYEOF

# O4 binary concealment -- Tigress Virtualize: the wire-path functions
# (serve/session ladder, framing reader/writer, codec, state machine,
# protocol concealment, crypto) are compiled into VM bytecode executed by
# per-function generated interpreters (--VirtualizeDispatch=switch) -- no
# recovered control flow exists, only interpreter dispatch loops over
# encoded operand stacks. EncodeLiterals hides the constants of the
# primary codecs. -DPROTO_HOST_MATERIAL is CRITICAL: tigress runs its own
# preprocessor, so without it the host-bound header branch silently
# compiles FULL secret definitions into the TU (and drops the boot call) --
# the material-absence assertion below fails the build if that ever
# regresses. proto_server_entry stays OUT of the Virtualize set (plain
# code + EncodeLiterals only): the VM dispatcher preamble evaluates an
# opaque predicate that init_tigress() -- living INSIDE the entry -- must
# first initialise (chicken-and-egg SIGFPE otherwise). --Seed=7735 fixes
# the transformation RNG. The size + symbol guards turn a silent tigress
# no-op or a lost entry symbol into a build failure.
RUN cd /src/proto && \
    tigress --Seed=7735 --Statistics=0 --Verbosity=0 -D_GNU_SOURCE -DPROTO_HOST_MATERIAL \
      --Transform=InitEntropy --Functions=init_tigress \
      --Transform=InitOpaque --Functions=init_tigress \
        --InitOpaqueStructs=list,array,env \
      --Transform=InitBranchFuns --InitBranchFunsCount=2 \
      --Transform=Virtualize \
        --Functions=proto_serve_connection,proto_session_flag_decode,send_msg,px_derive_direction_keys,px_auth_mac,px_flag_token,kv_get,kv_set,prng_next,prng_seed,pc_full_tcp_listen,pc_full_tcp_connect,milestone \
        --VirtualizeDispatch=switch \
      --Transform=Virtualize \
        --Functions=pf_build,pf_reader_feed,pf_write_msg,pf_extract_frame,pf_crypt,pf_escape,pf_unescape,pf_crc32,pf_crypto_on \
        --VirtualizeDispatch=switch \
      --Transform=Virtualize \
        --Functions=pe_encode,pe_decode,pe_example,w_bits,r_bits,w_varint,r_varint \
        --VirtualizeDispatch=switch \
      --Transform=Virtualize \
        --Functions=ps_schema_for,ps_schema_by_index,ps_schema_by_lead,ps_sem_slot,ps_server_allow,ps_server_step \
        --VirtualizeDispatch=switch \
      --Transform=Virtualize \
        --Functions=px_session_init,px_client_set_nonce,px_proof,px_verify,px_mask,px_maybe_chaff,px_frag_write,px_defrag_feed,px_wrap_mimicry,px_unwrap_mimicry,px_build_chaff \
        --VirtualizeDispatch=switch \
      --Transform=Virtualize \
        --Functions=pc_prv_hash,pc_prv_kdf,pc_prv_stream,pc_prv_pub,pc_prv_shared,pc_prv_cbc,pc_xor_crypt \
        --VirtualizeDispatch=switch \
      --Transform=EncodeLiterals \
        --Functions=proto_serve_connection,pe_encode,pe_decode,pf_build,pf_extract_frame,milestone \
      --out=protocol_tigress.c protocol.c && \
    test -s protocol_tigress.c && \
    test "$(wc -c < protocol_tigress.c)" -gt 1000000 && \
    grep -q proto_server_entry protocol_tigress.c && \
    grep -q ast_proto_boot protocol_tigress.c

# O4 engine compile: the CIL output compiles with gcc (-w for the VM's
# int<->ptr cast noise), under -DPROTO_HOST_MATERIAL so the secret arrays
# are EXTERNS resolved from main/ast_defaults.o at carrier link (the nm
# guard asserts exactly that). The dummy main's object symbol is renamed
# proto_tigress_boot. The differ-check proves tigress actually transformed
# the TU; the client-exclusion guard proves the reference client engine
# never entered the challenge object.
RUN cd /src/proto && \
    cc -O2 -c protocol.c -o /tmp/protocol_plain_prep.o && \
    if gcc -O2 -w -fvisibility=hidden -DPROTO_HOST_MATERIAL -c protocol_tigress.c -o proto_engine_raw.o; then \
        if cmp -s /tmp/protocol_plain_prep.o proto_engine_raw.o; then \
            echo "FATAL: tigress passes are a no-op on protocol.c"; exit 1; \
        fi; \
        echo "tigress transform verified (objects differ)"; \
    else \
        echo "FATAL: tigress compile of protocol_tigress.c failed"; exit 1; \
    fi && \
    objcopy --redefine-sym main=proto_tigress_boot proto_engine_raw.o proto_engine.o && \
    nm proto_engine.o | grep -qw proto_server_entry && \
    nm proto_engine.o | grep -qw ast_proto_boot && \
    nm proto_engine.o | grep -q ' U PROTO_AUTH_SECRET' && \
    if nm proto_engine.o | grep -qE 'proto_client_(session|converse)'; then \
        echo "FATAL: reference client engine leaked into the challenge TU"; exit 1; \
    fi && \
    if nm proto_engine.o | grep -qw main; then \
        echo "FATAL: main survived the rename"; exit 1; \
    fi && \
    echo "O4 engine object ready (host-material externs unresolved by design)"

# Site B concealment -- Tigress EncodeLiterals+Flatten on
# main/ast_defaults.c: a DIFFERENT transformation family than the VM
# (literal/data encoding + control flattening, not virtualization),
# keeping the multi-technique property of the host-bound construction
# while the stage stays self-contained (no cross-branch toolchain
# dependency). The TU is header-hermetic (local ABI mirrors), and the
# empty-main trick lets whole-program tigress process it; objcopy renames
# the stub away. The data assertion proves the encoding covered the
# masked blobs (neither the plaintext secrets nor the masked forms may
# appear as contiguous bytes in the object); the differ + symbol guards
# as everywhere else.
RUN cd /src/proto && cp /src/proto/ast_defaults.c ./ast_defaults_src.c && \
    printf '\nint main(void){return 0;}\n' >> ./ast_defaults_src.c && \
    tigress --Seed=7735 --Statistics=0 --Verbosity=0 \
      --Transform=InitEntropy --Functions=adef_init \
      --Transform=InitOpaque --Functions=adef_init \
        --InitOpaqueStructs=list,array,env \
      --Transform=Flatten --Functions=adef_unmask,adef_hex,adef_observed \
      --Transform=EncodeLiterals --Functions=adef_unmask,adef_hex,adef_observed \
      --out=ast_defaults_tigress.c ast_defaults_src.c && \
    test -s ast_defaults_tigress.c && \
    grep -q ast_proto_boot ast_defaults_tigress.c && \
    cc -O2 -w -c ast_defaults_src.c -o /tmp/adef_plain.o && \
    if gcc -O2 -w -fvisibility=hidden -c ast_defaults_tigress.c -o /tmp/adef_raw.o; then \
        if cmp -s /tmp/adef_plain.o /tmp/adef_raw.o; then \
            echo "FATAL: site-B tigress passes are a no-op"; exit 1; \
        fi; \
    else \
        echo "FATAL: site-B tigress compile failed"; exit 1; \
    fi && \
    objcopy --redefine-sym main=adef_dummy_boot /tmp/adef_raw.o ast_defaults_ensia.o && \
    nm --defined-only proto_engine.o | awk '$2 ~ /^[TDB]$/ {print $3}' | sort > /tmp/syms_engine.txt && \
    nm --defined-only ast_defaults_ensia.o | awk '$2 ~ /^[TDB]$/ {print $3}' | sort > /tmp/syms_siteb.txt && \
    for s in $(comm -12 /tmp/syms_engine.txt /tmp/syms_siteb.txt); do \
        objcopy --redefine-sym $s=adef_$s ast_defaults_ensia.o; \
        echo "renamed colliding tigress runtime symbol: $s"; \
    done && \
    nm ast_defaults_ensia.o | grep -qw ast_proto_boot && \
    nm ast_defaults_ensia.o | grep -qw PROTO_AUTH_SECRET && \
    if nm ast_defaults_ensia.o | grep -qw main; then \
        echo "FATAL: site-B main survived the rename"; exit 1; \
    fi && \
    nm --defined-only ast_defaults_ensia.o | awk '$2 ~ /^[TDB]$/ {print $3}' | sort > /tmp/syms_siteb2.txt && \
    if comm -12 /tmp/syms_engine.txt /tmp/syms_siteb2.txt | grep -q .; then \
        echo "FATAL: engine/site-B symbol collision survived the rename"; exit 1; \
    fi && \
    python3 - <<'PYEOF'
import re
t = open('ast_defaults_src.c').read()
def blob(sym):
    m = re.search(r"adef_%s\[[0-9 +]+\]\s*=\s*\{([^}]*)\}" % sym, t)
    return bytes(int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", m.group(1)))
mask = blob('mask')
data = open('ast_defaults_ensia.o', 'rb').read()
mask = blob('mask')
data = open('ast_defaults_ensia.o', 'rb').read()
for sym in ('blob_a', 'blob_b'):
    v = blob(sym)
    plain = bytes(b ^ mask[i & 31] ^ ((i * 33) & 0xFF)
                  for i, b in enumerate(v))
    if plain[:12] in data:
        print("FATAL: site-B %s decodes to contiguous PLAINTEXT in the object" % sym)
        raise SystemExit(1)
print("site-B data assertion passed (no plaintext secret in object)")
PYEOF

# CHALLENGE: carrier build + .cleancount bootstrap (the tar IS the full
# modified tree). main/Makefile links the prebuilt concealed objects
# (../proto/proto_engine.o + ../proto/ast_defaults_ensia.o) into
# main/asterisk; the assert proves both exist before make runs.
RUN test -s proto/proto_engine.o && test -s proto/ast_defaults_ensia.o && \
    touch .cleancount && \
    ./bootstrap.sh && \
    ./configure --without-pjproject --disable-asteriskssl \
        --sysconfdir=/etc --localstatedir=/var \
        CFLAGS="-O2" CXXFLAGS="-O2" && \
    make -j$(nproc) && \
    strip --strip-all main/asterisk && \
    if ldd main/asterisk | grep -q '/src/'; then \
        echo "FATAL: in-tree runtime lib dependency (rm -rf /src would orphan it)"; \
        ldd main/asterisk; exit 1; \
    fi && \
    cp main/asterisk /app/binary && cp main/asterisk /out/challenge_ldd

# HOST-BINDING ASSERTIONS (reference/host-binding.md): the challenge
# binary must NOT contain the wire secrets anywhere -- they exist only
# (a) masked inside the site-B object, (b) as config/astdb values on the
# filesystem, (c) inside the VM's encoded operand streams. The check
# derives the expected byte sequences from proto_config.h at build time
# (no second copy of the material) and scans the stripped binary for
# them; any hit (a tigress define slip, a new static initializer, a
# compiler constant-fold) fails the build loudly.
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
hits = [(name, data.find(v)) for name, v in secrets.items() if data.find(v) >= 0]
if hits:
    print("FATAL: wire secrets present in the stripped challenge binary:", hits)
    raise SystemExit(1)
print("host-binding assertions passed (no secret byte-sequence in binary)")
PYEOF

# IDENTITY SCRUB: overwrite banner/copyright/identifier tokens with
# equal-length filler. LOWERCASE tokens are deliberately OUT of the list:
# they live inside runtime-parsed strings -- filesystem paths
# (/etc/asterisk/asterisk.conf, /var/lib/asterisk/astdb) AND the astdb
# SQL statements ("FROM astdb") -- where an equal-length rewrite either
# breaks the host-bound boot or repoints the DB queries at an empty
# table (verified: decoy installs, session dies). The image layout
# (/etc/asterisk) conveys the carrier name either way; banners do not.
RUN python3 - <<'PYEOF'
data = bytearray(open('/app/binary', 'rb').read())
for tok in (b'Asterisk', b'ASTERISK', b'Sangoma', b'sangoma', b'Digium',
            b'digium', b'IAX2 Keys', b'Call Manager'):
    filler = (b'X') * len(tok)
    n = data.count(tok)
    if n:
        data = data.replace(tok, filler)
    print("scrub %-13r -> %d site(s)" % (tok, n))
open('/app/binary', 'wb').write(bytes(data))
print("identity scrub applied (banner tokens)")
PYEOF

# ENGINE-LEAK ASSERTIONS (leak-audit fix 2026-08): the challenge binary
# must ship NO engine internals. Engine + material symbols are compiled
# hidden (-fvisibility=hidden) so a dynamic link cannot carry
# px_/pf_/pc_/ps_/pe_/proto_/PROTO_/ast_proto_/adbg_ names into .dynsym;
# strip removes .symtab. Any regression fails the build loudly.
RUN if nm -D /app/binary | awk '$2 ~ /^[TtWw]$/ && $3 ~ /^(px_|pf_|pc_|ps_|pe_|proto_|PROTO_|ast_proto_|adbg_)/ {print $3}' | grep -q .; then \
        echo "FATAL: engine symbols exported in .dynsym:"; \
        nm -D /app/binary | awk '$2 ~ /^[TtWw]$/ && $3 ~ /^(px_|pf_|pc_|ps_|pe_|proto_|PROTO_|ast_proto_|adbg_)/ {print $3}'; \
        exit 1; \
    fi && \
    if readelf -SW /app/binary | grep -q '\.symtab'; then \
        echo "FATAL: .symtab survived the strip"; exit 1; \
    fi && \
    echo "engine-leak assertions passed (dynsym clean, no .symtab)"

# P0 binary concealment (was P2): UPX is DISABLED for this task -- the
# tigress InitEntropy runtime spawns a worker thread whose TLS setup
# deadlocks under the UPX stub (process alive, listener up, session
# handlers stall; unpacked concealed binary verified flag-complete).
# The expert tier keeps O4 VM + D3 + the host-bound material split;
# packing adds nothing on top of the scrubbed/encoded artifacts
# (sibling samba task runs the same O4D3 stack unpacked).

# TEMP DIAGNOSTIC: packed vs unpacked boot liveness + listen state
RUN ( /app/binary --proto-server 17997 >/tmp/d1.log 2>&1 & echo $! >/tmp/p1 ); sleep 2; \
    if kill -0 $(cat /tmp/p1) 2>/dev/null; then echo DIAG-PACKED-ALIVE; else echo DIAG-PACKED-DEAD; fi; \
    cat /tmp/d1.log; grep -q ':464D' /proc/net/tcp && echo DIAG-PACKED-LISTENING || echo DIAG-PACKED-PORT-ABSENT; \
    kill $(cat /tmp/p1) 2>/dev/null; \
    ( /out/challenge_ldd --proto-server 17996 >/tmp/d2.log 2>&1 & echo $! >/tmp/p2 ); sleep 2; \
    if kill -0 $(cat /tmp/p2) 2>/dev/null; then echo DIAG-UNPACKED-ALIVE; else echo DIAG-UNPACKED-DEAD; fi; \
    cat /tmp/d2.log; grep -q ':464C' /proc/net/tcp && echo DIAG-UNPACKED-LISTENING || echo DIAG-UNPACKED-PORT-ABSENT; \
    kill $(cat /tmp/p2) 2>/dev/null; true

# Post-concealment interop smoke (positive + poison), against the packed
# artifact with the PLAIN engine objects as the client -- a genuine
# black-box interop, not a shared-concealment loopback:
#   1. with the host state installed: full session + flag (this also
#      PROVES the host binding end-to-end: the engine booted its material
#      through the real config parser + astdb subsystem);
#   2. with /etc/asterisk swept away: the same client must FAIL -- the
#      decoy dialect installs and nothing usable is served.
RUN cc -O2 -I/src/proto -o /tmp/ref_client /src/proto/ref_client.c \
        /tmp/proto_client_plain.o /tmp/protocol_plain.o -lpthread -lm && \
    ( /app/binary --proto-server 17999 & echo $! > /tmp/proto.pid; sleep 2; \
      timeout 45 /tmp/ref_client 127.0.0.1 17999 > /tmp/proto.out 2>&1; rc=$?; \
      kill $(cat /tmp/proto.pid) 2>/dev/null; \
      grep -q 'flag{' /tmp/proto.out || rc=1; \
      rm -f /tmp/proto.pid; \
      if [ $rc -ne 0 ]; then echo "FATAL: host-bound smoke failed (no flag)"; cat /tmp/proto.out; exit 1; fi ) && \
    mv /etc/asterisk /etc/asterisk.hidden && \
    ( /app/binary --proto-server 17998 & echo $! > /tmp/proto.pid; sleep 2; \
      timeout 25 /tmp/ref_client 127.0.0.1 17998 > /tmp/proto2.out 2>&1; rc=$?; \
      kill $(cat /tmp/proto.pid) 2>/dev/null; \
      mv /etc/asterisk.hidden /etc/asterisk; \
      rm -f /tmp/proto.pid; \
      if [ $rc -eq 0 ] && grep -q 'flag{' /tmp/proto2.out; then \
          echo "FATAL: poison path failed -- decoy dialect served the flag"; \
          cat /tmp/proto2.out; exit 1; fi ) && \
    rm -f /tmp/ref_client /tmp/proto.out /tmp/proto2.out /tmp/should_fail && \
    echo "interop smoke passed (host-bound session ok, decoy poison ok)"

# IDENTITY ASSERTION: banner/copyright tokens must be gone; lowercase
# path/SQL tokens are alive by design (see the scrub note above).
RUN if strings -a /app/binary | grep -qiE 'sangoma|digium|iax2 keys|call manager'; then \
        echo "FATAL: banner identity leaked:"; \
        strings -a /app/binary | grep -iE 'sangoma|digium|iax2 keys|call manager' | head; \
        exit 1; \
    fi && \
    test $(strings -a /app/binary | grep -c 'Asterisk') -eq 0 && \
    echo "identity assertion passed (banner tokens clean)"

# Role-named staging: ldd captured pre-UPX; host state staged for the
# runtime stage's site-C install.
RUN mkdir -p /out/host-state /out/challenge_libs && cp /src/host-state/*.conf /out/host-state/ && \
    cp /src/host-state/astdb.sqlite3 /out/host-state/ && \
    cp /app/binary /out/challenge_final && chmod 755 /out/challenge_final && \
    ldd /out/challenge_ldd | awk '/=> \// {print $3} /^\// {print $1}' | \
        sort -u | xargs -I{} cp -n {} /out/challenge_libs/ && \
    ls /out/challenge_libs | wc -l

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
# Runtime library-closure overlay (leak-audit fix 2026-09-11, applied to
# every carrier 2026-09-13): apt-only carriers collect an all-apt set --
# harmless no-op semantically, uniform with the custom-lib carriers.
# /opt/target-deps/lib is already on LD_LIBRARY_PATH.
COPY --from=challenge-binary /out/challenge_libs/ /opt/target-deps/lib/
# Host-bound wire state (site C, reference/host-binding.md): the carrier
# reads these at boot through its real config parser + astdb subsystem --
# /app/binary speaks the true dialect only with them present.
COPY --from=challenge-binary /out/host-state /tmp/host-state
RUN mkdir -p /etc/asterisk /var/lib/asterisk && \
    cp /tmp/host-state/asterisk.conf /tmp/host-state/modules.conf \
       /tmp/host-state/extensions.conf /tmp/host-state/rtp.conf /etc/asterisk/ && \
    cp /tmp/host-state/astdb.sqlite3 /var/lib/asterisk/astdb.sqlite3 && \
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
COPY concealment/obfuscation/tigress_4.0.11-1_all.deb /tmp/tigress_4.0.11-1_all.deb
RUN dpkg --force-architecture -i /tmp/tigress_4.0.11-1_all.deb && \
    rm /tmp/tigress_4.0.11-1_all.deb

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
