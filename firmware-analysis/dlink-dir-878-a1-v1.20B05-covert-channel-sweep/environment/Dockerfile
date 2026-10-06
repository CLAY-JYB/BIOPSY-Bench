# Agent running environment.
# BuildKit runs stages with no FROM/COPY --from edge concurrently; every branch hangs off apt-build (cve-db off pip-re, its python stack) and lands in runtime via COPY --from: dl-retdec/dl-die/dl-ghidra/firmwalker/fmk/pwndbg -> /opt, sasquatch/binwalk3/radare2-r2ghidra/checksec/pip-re -> /usr/local, cve-db -> /var/lib/cve-bin-tool, gt-export -> verifier artifacts.
# The firmware arrives PRE-BUILT by gen_firmware.py (pinned OpenWrt Image Builder + SDK, outside Docker; never unpack/repack surgery in-image). firmware.bin is the agent-facing challenge; assembled.bin is the pre-concealment image gt-export derives the oracle tree from.

FROM ubuntu:22.04@sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982 AS apt-build
ENV DEBIAN_FRONTEND=noninteractive QT_QPA_PLATFORM=offscreen

# Agent toolchain: instruction.md "AVAILABLE TOOLS" must match what ships here.
# Base mirrors the sibling skills; FIRMWARE additions marked inline.
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build Tools
    autoconf \
    automake \
    libtool \
    make \
    cmake \
    ninja-build \
    pkg-config \
    patch \
    # Compilers and Assemblers
    gcc \
    g++ \
    binutils \
    # Debugging and Analysis Tools
    gdb \
    # FIRMWARE: multiarch gdb (stock gdb is x86-target-only; pwndbg works)
    gdb-multiarch \
    lldb-15 \
    ltrace \
    strace \
    valgrind \
    # Binary Analysis Tools (+ FIRMWARE: binwalk signature/entropy scanning)
    file \
    binwalk \
    hexedit \
    qemu-user-static \
    ent \
    yara \
    ssdeep \
    # Binary Patching Tools
    patchelf \
    # FIRMWARE: filesystem / flash / container tooling
    squashfs-tools \
    mtd-utils \
    u-boot-tools \
    cpio \
    # FIRMWARE: all-arch readelf/objdump + transparent foreign-ELF exec
    binutils-multiarch \
    binfmt-support \
    # FIRMWARE: full-system boot per arch family (each pkg = whole family)
    qemu-system-mips \
    qemu-system-arm \
    qemu-system-x86 \
    qemu-efi-aarch64 \
    # FIRMWARE: dtc, ext4/x86 tooling, compression CLIs, squashfs-tools-ng.
    # gcc-multilib DROPPED: jammy conflicts it with every cross toolchain but aarch64
    device-tree-compiler \
    e2fsprogs \
    fdisk \
    parted \
    p7zip-full \
    xz-utils \
    zstd \
    lz4 \
    squashfs-tools-ng \
    # FIRMWARE: bzip2/lzop CLIs; userspace FAT/EFI (mtools; no mounts in-container); genromfs
    bzip2 \
    lzop \
    mtools \
    genromfs \
    # FIRMWARE: cross toolchains for target-arch PoCs (arm = future armsr/armv7); libc6-dev-*-cross is Recommends-only, must be explicit or no libc headers ship
    gcc-mipsel-linux-gnu \
    gcc-mips-linux-gnu \
    gcc-aarch64-linux-gnu \
    gcc-arm-linux-gnueabi \
    libc6-dev-mipsel-cross \
    libc6-dev-mips-cross \
    libc6-dev-arm64-cross \
    libc6-dev-armel-cross \
    # FIRMWARE: emulated-device recon (hostfwd -> 127.0.0.1); rg/tree sweeps
    nmap \
    dnsutils \
    tree \
    ripgrep \
    # Development Libraries
    libffi-dev \
    libglib2.0-dev \
    libncursesw5-dev \
    python3-dev \
    libssl-dev \
    libruby \
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
    socat \
    tcpdump \
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
    bsdextrautils \
    ca-certificates \
    libc-bin \
    unzip \
    util-linux \
    vim \
    xxd \
    vbindiff \
    jq \
    upx-ucl \
    openssl \
    zlib1g-dev \
    liblzma-dev \
    liblzo2-dev \
    libzstd-dev \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================================
# PARALLEL TOOL BRANCHES: nothing lands in the image until the runtime merge COPYs it in.
# ============================================================================================

# --- prebuilt downloads (fetch + verify only) ---
FROM apt-build AS dl-retdec
# RetDec v5.0 prebuilt (tarball extracts flat; linked against GLIBC 2.34, so the base needs >= 2.34; jammy ships 2.35)
RUN wget -q "https://github.com/avast/retdec/releases/download/v5.0/RetDec-v5.0-Linux-Release.tar.xz" \
        -O /tmp/retdec.tar.xz && \
    echo "e5a7dd82987ff52b8c714892277d0b1d0190ab778c03036d01eb69c7658ab1a5  /tmp/retdec.tar.xz" | sha256sum -c - && \
    mkdir -p /opt/retdec && \
    tar -xJf /tmp/retdec.tar.xz -C /opt/retdec && \
    rm /tmp/retdec.tar.xz
ENV PATH="/opt/retdec/bin:${PATH}"

FROM apt-build AS dl-die
# Detect It Easy - packer/protector identification (CLI)
RUN wget -q "https://github.com/horsicq/DIE-engine/releases/download/3.21/die_3.21_portable_Ubuntu_20.04_amd64.tar.gz" \
        -O /tmp/die.tar.gz && \
    echo "4d85614dd169c0d23f52084f86e05a503c30429df5fb5ec14de50f23808bc2d4  /tmp/die.tar.gz" | sha256sum -c - && \
    tar -xzf /tmp/die.tar.gz -C /opt && \
    ln -sf /opt/die_linux_portable/base/diec /usr/local/bin/die && \
    rm -rf /tmp/die.tar.gz

FROM apt-build AS dl-ghidra
# Ghidra (headless) - multi-arch disassembly/decompilation
RUN wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip" \
        -O /tmp/ghidra.zip && \
    echo "b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d  /tmp/ghidra.zip" | sha256sum -c - && \
    unzip -q /tmp/ghidra.zip -d /opt && \
    mv /opt/ghidra_* /opt/ghidra && \
    rm /tmp/ghidra.zip && \
    ln -sf /opt/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless

# --- Python RE stack (angr first: the big set conflicts with its capstone pin) ---
FROM apt-build AS pip-re
RUN pip3 install --no-cache-dir angr==9.2.102
RUN pip3 install --no-cache-dir \
    pwntools==4.12.0 \
    z3-solver==4.13.2.0 \
    keystone-engine==0.9.2 \
    miasm==0.1.5 \
    cle==9.2.102 \
    pyelftools==0.31 \
    lief==0.14.1 \
    r2pipe==0.9.4 \
    ropper==1.13.13 \
    ROPgadget==6.6 \
    pycryptodome==3.20.0 \
    python-magic==0.4.27 \
    cryptography==42.0.8 \
    flare-floss==3.1.1 \
    frida==16.2.4 \
    frida-tools==12.3.0 \
    qiling==1.4.6 \
    yara-python==4.5.4 \
    tqdm==4.66.4 \
    pyyaml==6.0.1 \
    capstone==4.0.2 \
    unicorn==2.1.4 \
    pycparser==2.21 \
    # FIRMWARE: flash fs parsers; version floor set by unblob below
    ubi_reader==0.8.10 \
    jefferson==0.4.7 \
    && rm -rf /root/.cache/pip

# FIRMWARE: unblob, cve-bin-tool (version->CVE; offline DB below),
# vmlinux-to-elf, SMT backends, uefi-firmware (PyPI name of theopolis/uefi-firmware-parser, CLI uefi-firmware-parser)
RUN pip3 install --no-cache-dir \
    unblob==26.6.4 \
    cve-bin-tool==3.4 \
    vmlinux-to-elf==1.3.6 \
    uefi-firmware==1.16 \
    && rm -rf /root/.cache/pip
RUN pip3 install --no-cache-dir \
    bitwuzla==0.9.1 \
    pyboolector==3.2.4.19342042739 \
    cvc5==1.3.4 \
    && rm -rf /root/.cache/pip

# --- FIRMWARE: offline CVE snapshot ---
# Fetch the NVD json-mirror DB once at build time (non-NVD sources disabled; 2GB+ otherwise) into globally readable /var/lib/cve-bin-tool; the agent's ~/.cache/cve-bin-tool symlinks there so `cve-bin-tool --offline <dir>` needs no network.
# Best-effort: on failure a SNAPSHOT-ABSENT marker lands and the
# instruction documents the no-snapshot path.
# The -s guard accepted a schema-only ~520K db (all tables, 0 rows) as a valid
# snapshot; the guard is now a cve_range row count. NB: cve-bin-tool==3.4 fetches
# mirror.cveb.in's 1.1 json feed, which the mirror retired (2.0 path still live);
# until the pin is bumped this stage will land SNAPSHOT-ABSENT honestly.
FROM pip-re AS cve-db
RUN mkdir -p /var/lib/cve-bin-tool && \
    ( timeout 1500 cve-bin-tool -u now -n json-mirror --nvd-api-key no \
        --disable-data-source CURL,EPSS,GAD,OSV,PURL2CPE,REDHAT,RSD \
        /bin >/tmp/cvebt-fetch.log 2>&1 || \
      echo "WARN: cve snapshot fetch failed" ) ; \
    if [ -s "$HOME/.cache/cve-bin-tool/cve.db" ] && \
       python3 -c "import sqlite3,sys; sys.exit(0 if sqlite3.connect('$HOME/.cache/cve-bin-tool/cve.db').execute('select count(*) from cve_range').fetchone()[0] > 0 else 1)" 2>/dev/null; then \
        mv "$HOME/.cache/cve-bin-tool/cve.db" /var/lib/cve-bin-tool/cve.db ; \
        du -h /var/lib/cve-bin-tool/cve.db ; \
    else \
        echo "cve snapshot unavailable at build time (schema-only or empty db rejected)" \
            > /var/lib/cve-bin-tool/SNAPSHOT-ABSENT ; \
        rm -f "$HOME/.cache/cve-bin-tool/cve.db" ; \
        tail -20 /tmp/cvebt-fetch.log || true ; \
    fi

# --- source-built tools ---
FROM apt-build AS sasquatch
# FIRMWARE: sasquatch: patched unsquashfs for non-standard squashfs (the F2 variants); installs to /usr/local/bin/unsquashfs, shadowing stock on PATH (how binwalk finds it). build.sh steps inlined: squashfs 4.3's Makefile carries -Werror and gcc>=10 warnings (misleading-indentation) fail the build on jammy, so -Werror is stripped and -fcommon restored (gcc>=10 defaults to -fno-common; error.h's 'int verbose' then breaks the link) before make. The patched binary installs as /usr/local/bin/sasquatch; unsquashfs is symlinked onto it so it shadows stock on PATH. The || echo fallback had masked all of this since the first build.
RUN git clone https://github.com/devttys0/sasquatch.git /tmp/sasquatch && \
    cd /tmp/sasquatch && \
    wget -q "https://downloads.sourceforge.net/project/squashfs/squashfs/squashfs4.3/squashfs4.3.tar.gz" && \
    tar -zxf squashfs4.3.tar.gz && \
    cd squashfs4.3 && \
    patch -p0 < ../patches/patch0.txt && \
    cd squashfs-tools && \
    sed -i 's/-Werror//g; s/-Wall/-Wall -fcommon/' Makefile && \
    make -j$(nproc) && \
    make install && \
    ln -sf /usr/local/bin/sasquatch /usr/local/bin/unsquashfs && \
    ln -sf /usr/local/bin/sasquatch /usr/local/bin/sasquatch-unsquashfs && \
    rm -rf /tmp/sasquatch

FROM apt-build AS binwalk3
# FIRMWARE: binwalk v3 (Rust) as /usr/local/bin/binwalk3 (apt 2.3.3 stays
# for extraction); cargo install --locked at v3.1.0 (positional crate name: the repo also ships a fuzz bin; libfontconfig1-dev feeds yeslogic-fontconfig-sys), rustup removed after
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends libfontconfig1-dev libfreetype6-dev && \
    curl -fsS https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain 1.97.1 && \
    . "$HOME/.cargo/env" && \
    cargo install --locked --git https://github.com/ReFirmLabs/binwalk --tag v3.1.0 binwalk && \
    cp /root/.cargo/bin/binwalk /usr/local/bin/binwalk3 && \
    rustup self uninstall -y && \
    rm -rf /root/.cargo/registry

FROM apt-build AS firmwalker
# FIRMWARE: firmwalker: sensitive-data sweep (credentials, keys, certs).
# upstream craigz28/firmwalker is gone (GitHub 404, seen 2026-09-09);
# zhibx/firmwalker_pro is its continuation — firmwalker.sh byte-identical
# (md5 490e1504ba0aa44d1787dbe9b15dc61a), data lists mildly extended.
# Pinned to the 2026-08-08 merge commit.
RUN git clone https://github.com/zhibx/firmwalker_pro.git /opt/firmwalker && \
    cd /opt/firmwalker && \
    git checkout 76d80300d3e0c1b0a509bd8e69c85d4e6e178294 && \
    rm -rf /opt/firmwalker/.git && \
    chmod 755 /opt/firmwalker/firmwalker.sh

FROM apt-build AS fmk
# FIRMWARE: Firmware Mod Kit: whole-image extract/rebuild. No top-level Makefile: build under src/ with CFLAGS="-O2 -w" -k; bundled squashfs-2.x/ 3.x and python2 binwalk intentionally left unbuilt (superseded).
RUN git clone https://github.com/rampagex/firmware-mod-kit.git /opt/firmware-mod-kit && \
    cd /opt/firmware-mod-kit/src && \
    make -k -j$(nproc) CFLAGS="-O2 -w"; \
    rm -rf /opt/firmware-mod-kit/.git && \
    ln -sf /opt/firmware-mod-kit/extract-firmware.sh /usr/local/bin/fmk-extract && \
    ln -sf /opt/firmware-mod-kit/build-firmware.sh /usr/local/bin/fmk-build

FROM apt-build AS radare2
# Install Radare2 - v6.1.8 (sibling pin; real install, not symstall)
RUN git clone --branch 6.1.8 --depth 1 https://github.com/radareorg/radare2.git /tmp/radare2 && \
    cd /tmp/radare2 && \
    MAKE_JOBS=$(nproc) INSTALL_TARGET=install WITHOUT_PULL=1 ./sys/install.sh && \
    rm -rf /tmp/radare2

FROM radare2 AS r2ghidra
# r2ghidra 6.1.8 (Ghidra decompiler as an r2 plugin; needs r2 in-stage)
RUN git clone --branch 6.1.8 --depth 1 https://github.com/radareorg/r2ghidra.git /tmp/r2ghidra && \
    cd /tmp/r2ghidra && \
    ./configure --prefix=/usr/local && \
    make -C subprojects && \
    make -C src subprojects-zlib && \
    make -j$(nproc) && \
    make install && \
    rm -rf /tmp/r2ghidra

FROM apt-build AS pwndbg
# Install pwndbg - v2024.08.29
RUN git clone https://github.com/pwndbg/pwndbg.git /opt/pwndbg && \
    cd /opt/pwndbg && \
    git checkout 2024.08.29 && \
    ./setup.sh && \
    echo 'source /opt/pwndbg/gdbinit.py' > /root/.gdbinit && \
    rm -rf /opt/pwndbg/.git

FROM apt-build AS checksec
# Install Checksec - v2.7.0
RUN curl -L https://raw.githubusercontent.com/slimm609/checksec.sh/2.7.0/checksec \
    -o /usr/local/bin/checksec && \
    chmod +x /usr/local/bin/checksec

# ============================================================================================
# GT-EXPORT: `buildx build --target gt-export`; the construct pipeline exports these verifier artifacts (oracle tree + challenge image only; the GT config and oracle binaries are host-side export products) into tests/ + solution/.
# ============================================================================================
FROM apt-build AS gt-export
# the copy list = "firmware.bin assembled.bin" (+ firmware_v1.1.bin + its pre-F2 assembled_v1.1.bin on chain (I6/I7) tasks; the overlay tree derives from the PRE-CONCEALMENT v1.1, whose superblock is still a plain hsqs)
COPY firmware.bin assembled.bin firmware_v1.1.bin /work/

# Oracle tree derivation only: this stage never sees the GT config (the
# integrity gate and the oracle-binary staging run host-side in the export
# script); it carves the standard squashfs out of the pre-concealment images
# and overlays the chain's v1.1 tree when present
RUN python3 - <<'PYEOF'
import os, shutil, subprocess, sys

os.makedirs("/gt", exist_ok=True)
shutil.copy("/work/firmware.bin", "/gt/firmware.bin")

# oracle tree: carve the squashfs from the pre-concealment assembled image (always standard LE hsqs; F2/X transforms never touch assembled.bin); same magic scan + superblock validation as the old host-side pack
asm = open("/work/assembled.bin", "rb").read()
off = None
for magic in (b"hsqs", b"shsq"):  # f2_squashfs.MAGIC_LE/MAGIC_BE
    pos = asm.find(magic)
    while pos != -1:
        import struct
        # squashfs v4 superblock: s_major at +28, bytes_used at +40
        s_major = struct.unpack_from("<H", asm, pos + 28)[0]
        bu = struct.unpack_from("<Q", asm, pos + 40)[0]
        if s_major == 4 and 0 < bu <= len(asm) - pos:
            off = pos
            break
        pos = asm.find(magic, pos + 1)
    if off is not None:
        break
if off is None:
    # tree-less tier (F0 initramfs/dry fixture): empty tree, coverage N/A
    os.makedirs("/gt/tree", exist_ok=True)
if off is not None:
    open("/work/rootfs.bin", "wb").write(asm[off:])
    # unsquashfs exits nonzero without CAP_MKNOD but still extracts regular files; the oracle is the FILE set; device nodes carry no coverage
    subprocess.run(["unsquashfs", "-f", "-d", "/gt/tree", "/work/rootfs.bin"],
                   capture_output=True)
    n_files = sum(len(f) for _, _, f in os.walk("/gt/tree"))
    if n_files < 100:
        sys.exit("FATAL: oracle tree extraction produced only %d files" % n_files)

# chain (I6/I7): overlay the v1.1 tree onto the oracle set (v1.2 wins same-name conflicts; v1.1-only files (the decryptor) survive)
v11_src = "/work/assembled_v1.1.bin" if os.path.exists("/work/assembled_v1.1.bin") else "/work/firmware_v1.1.bin"
if os.path.exists(v11_src) and off is not None:
    v11 = open(v11_src, "rb").read()
    off11 = None
    for magic in (b"hsqs", b"shsq"):
        pos = v11.find(magic)
        while pos != -1:
            s_major = struct.unpack_from("<H", v11, pos + 28)[0]
            bu = struct.unpack_from("<Q", v11, pos + 40)[0]
            if s_major == 4 and 0 < bu <= len(v11) - pos:
                off11 = pos
                break
            pos = v11.find(magic, pos + 1)
        if off11 is not None:
            break
    if off11 is None:
        sys.exit("FATAL: no squashfs in firmware_v1.1.bin (chain overlay)")
    open("/work/v11_rootfs.bin", "wb").write(v11[off11:])
    subprocess.run(["unsquashfs", "-f", "-d", "/gt/tree",
                    "/work/v11_rootfs.bin"], capture_output=True)
    # re-run v1.2 extraction last: unsquashfs overwrites same-name files and v1.2 must win the conflicts
    subprocess.run(["unsquashfs", "-f", "-d", "/gt/tree", "/work/rootfs.bin"],
                   capture_output=True)

PYEOF
RUN chmod -R a+rX /gt

# ============================================================================================
# RUNTIME: agent-facing merge point; COPY --from overlays union cleanly
# ============================================================================================
FROM apt-build AS runtime

# --- /opt merges (each branch keeps whole tools under its own prefix) ---
COPY --from=dl-retdec /opt/retdec /opt/retdec
COPY --from=dl-die /opt/die_linux_portable /opt/die_linux_portable
COPY --from=dl-ghidra /opt/ghidra /opt/ghidra
COPY --from=firmwalker /opt/firmwalker /opt/firmwalker
COPY --from=fmk /opt/firmware-mod-kit /opt/firmware-mod-kit
COPY --from=pwndbg /opt/pwndbg /opt/pwndbg

# --- /usr/local merges (directory overlays union cleanly) ---
COPY --from=sasquatch /usr/local /usr/local
COPY --from=binwalk3 /usr/local /usr/local
COPY --from=radare2 /usr/local /usr/local
COPY --from=r2ghidra /usr/local /usr/local
COPY --from=checksec /usr/local /usr/local
COPY --from=pip-re /usr/local /usr/local

# FIRMWARE: offline CVE snapshot (agent cache lookup wired below)
COPY --from=cve-db /var/lib/cve-bin-tool /var/lib/cve-bin-tool

ENV PATH="/opt/retdec/bin:${PATH}"

# re-create stage symlinks; ldconfig picks up merged /usr/local/lib
RUN ldconfig && \
    ln -sf /opt/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless && \
    ln -sf /opt/die_linux_portable/base/diec /usr/local/bin/die && \
    printf '%s\n' '#!/bin/sh' \
        '# firmwalker.sh reads data/ relative to its own dir; resolve caller-relative args first' \
        'a="$1"; case "$a" in /*) ;; *) a="$PWD/$a";; esac' \
        'o="${2:-firmwalker.txt}"; case "$o" in /*) ;; *) o="$PWD/$o";; esac' \
        'cd /opt/firmwalker && exec ./firmwalker.sh "$a" "$o"' \
        > /usr/local/bin/firmwalker && \
    chmod 755 /usr/local/bin/firmwalker && \
    ln -sf /opt/firmware-mod-kit/extract-firmware.sh /usr/local/bin/fmk-extract && \
    ln -sf /opt/firmware-mod-kit/build-firmware.sh /usr/local/bin/fmk-build && \
    echo 'source /opt/pwndbg/gdbinit.py' > /root/.gdbinit

# ============================================================================================
# Challenge artifact: generated outside Docker by gen_firmware.py, arrives via the build context (never built inside this image)
# ============================================================================================
# the copy list = firmware.bin to /app (+ firmware_v1.1.bin on chain (I6/I7) tasks: the agent receives BOTH images)
COPY firmware.bin firmware_v1.1.bin /app/
RUN chmod 0444 /app/*.bin

RUN mkdir -p /app /logs/artifacts/agent_output /logs/verifier && \
    rm -rf /tmp/*

# Set permissions for Harbor artifact collection
RUN mkdir -p /tests /solution
RUN chmod 750 /tests /solution

# Create agent user and set ownership
RUN useradd -m -s /bin/bash agent && \
    chown -R agent:agent /app /logs/artifacts && \
    chmod -R a+rX /var/lib/cve-bin-tool && \
    mkdir -p /home/agent/.cache && \
    ln -sfn /var/lib/cve-bin-tool /home/agent/.cache/cve-bin-tool && \
    chown -h agent:agent /home/agent/.cache/cve-bin-tool && \
    if grep -q "pwndbg" /root/.gdbinit 2>/dev/null; then \
        echo "source /opt/pwndbg/gdbinit.py" >> /home/agent/.gdbinit && \
        chown agent:agent /home/agent/.gdbinit; \
    fi

WORKDIR /app

# Set default command
CMD ["/bin/bash"]

# ==============================================================================
# Runtime layout: /app/firmware.bin (+ firmware_v1.1.bin on chain tasks) and /logs/artifacts/agent_output/{extracted_fs/, firmware_repacked.bin, activation.keys, decrypted.bin (encrypted engagements)}
# ==============================================================================
