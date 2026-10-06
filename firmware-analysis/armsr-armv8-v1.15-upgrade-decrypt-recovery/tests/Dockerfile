# Verifier environment.
# The thin consumer image never inherits environment/ and never builds anything: every ground-truth artifact (tree from the gt-export stage, report from pack's serialization, binaries staged host-side, challenge image) is exported at construction time by script/pipeline/export_verifier_artifacts.sh.
# The verifier exercises: qemu-user-static (agent binaries under the target arch, explicit invocation; no binfmt needed), strace + setpriv (observable capture + privilege drop), squashfs-tools (oracle-tree probe + the reference solve's mksquashfs repack), binwalk/mkimage/file (carve/repack re-parse gates), python3 (the scorer itself).

FROM ubuntu:22.04@sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982
ENV DEBIAN_FRONTEND=noninteractive QT_QPA_PLATFORM=offscreen

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    file \
    binwalk \
    squashfs-tools \
    u-boot-tools \
    qemu-user-static \
    strace \
    util-linux \
    qemu-system-arm qemu-efi-aarch64 ipxe-qemu \
    && rm -rf /var/lib/apt/lists/*
# The VERIFY_EXTRA_PKGS token on the install line above expands to the full-system-rehost tooling on --system-boot tasks (qemu-system-arm + qemu-efi-aarch64; the verifier boots the agent's rebuilt disk under qemu-system-aarch64) and to nothing otherwise.
# The export step's gate asserts the packages are present when the GT declares a system_boot contract, so the "tool missing -> denominator removed" fallback never silently fires.

# Copy test script for harbor verifier
RUN mkdir -p /tests /app/ground_truth /logs/verifier
COPY test.sh /tests/test.sh
RUN chmod 700 /tests/test.sh  # the inlined GT_CONFIG is the answer key: root-only (the verifier runs it as root; agent code runs as nobody)

# Ground truth (construction-time exports from the environment image):
#   ground_truth/tree.tar.gz   the extracted reference file tree: the hash-coverage oracle for Property Validation (order-/naming-free: scored by content hash, never by path)
#   firmware.bin               the challenge image (reference point for the repack gate; byte-identical to the environment image's copy)
#   Oracle BINARIES stay solution-side only: the verifier runs the AGENT's own extracted copies (anti-cheat).
COPY ground_truth/tree.tar.gz /tmp/tree.tar.gz
RUN tar xzf /tmp/tree.tar.gz -C /app/ground_truth/ && rm /tmp/tree.tar.gz
#   assembled.bin             the pre-encryption image (P0 head reference
#   + verbatim-copy void on encrypted engagements; root-only)
COPY ground_truth/assembled.bin /app/ground_truth/assembled.bin
COPY firmware.bin /app/firmware.bin

# Diagnosis graph (assembled at pack time from the same GT config that produced the report): the attribution engine embedded in test.sh walks it over the scorers' ledger and writes /logs/verifier/diagnosis.json.
COPY diagnosis_graph.json /app/diagnosis_graph.json

# Ground truth is root-only: the analyzed binaries run as 'nobody' during verification (test.sh setpriv drop) and must not be able to read the report, the marker UUIDs, or the oracle tree out of this directory.
RUN chmod -R go-rwx /app/ground_truth && chmod go-rwx /app/diagnosis_graph.json

WORKDIR /app

CMD ["/tests/test.sh"]

# ==============================================================================
# Final Directory Structure (this VERIFIER image)
# ==============================================================================
#
# Build-time (this image):
# /app/
#  ├── firmware.bin            # the challenge image (byte-identical to the environment image's copy)
#  ├── diagnosis_graph.json    # pack-time attribution graph (root-only; the diagnosis engine in test.sh walks it)
#  └── ground_truth/           # ground truth (root-only: the analyzed binaries run as nobody and cannot read it)
#      └── tree/
# /tests/test.sh               # verifier entrypoint (CMD)
# /logs/verifier/              # verifier output (empty at build time; test.sh writes reward.json + reward-details.json + diagnosis.json)
#
# Runtime (shared /logs volume; populated by the agent):
# /logs/artifacts/agent_output/
#  ├── binaries/               # the agent's executed component copies
#  ├── extracted_fs/           # the agent's unpacked file tree
#  ├── firmware_repacked.bin   # the agent's rebuilt image
#  └── ...                     # poc/, rehost/ where the engagement asks for them
