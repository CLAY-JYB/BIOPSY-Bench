FROM ubuntu:22.04@sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982
ENV DEBIAN_FRONTEND=noninteractive

# Thin verifier image: pure consumer — never inherits environment/, never compiles. oracle_server / ground_truth / deps.tar.gz are construction-time exports from the environment build (script/pipeline/export_verifier_artifacts.sh, SKILL.md Step 8.05). Only the tools test.sh drives: python3 (the verifier's scoring engine), strace (observation), file (type probes), setpriv (privilege drop), timeout (coreutils).

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    strace \
    file \
    util-linux \
    # BEGIN RUNTIME CLOSURE (generated — do not edit)
    # END RUNTIME CLOSURE
    && rm -rf /var/lib/apt/lists/*

# Custom-target shared libs (construction-time export; the ldd closure of
# oracle_server + the packer-free challenge ELF). the deps-dirs token is the
# space-separated ld.so search list filled by the same export step.
COPY deps.tar.gz /tmp/deps.tar.gz
RUN tar xzf /tmp/deps.tar.gz -C / && rm /tmp/deps.tar.gz && \
    printf '%s\n' "/opt/target-deps/lib" > /etc/ld.so.conf.d/target.conf && ldconfig

# Oracle server (unconcealed protocol engine; milestone logging). ANTI-CHEAT: the reference client NEVER enters this image (solve side only — solution/ground_truth/binaries/).


# Verifier-side ground truth: the oracle/ tree only (the verifier's levels/messages/states config is inlined in test.sh as GT_CONFIG). The live oracle ships INSIDE the ground-truth export (single copy): the verifier executes it as root (it is verifier-side, not agent code), so the baseline's go-rwx on /app/ground_truth does not affect it
COPY ground_truth/ /app/ground_truth/
# the GT is root-only by contract (the privilege drop is the second
# layer, not the only one): strip group/world bits at image build
RUN chmod -R go-rwx /app/ground_truth
RUN chmod 755 /app/ground_truth/oracle/oracle_server

COPY test.sh /tests/test.sh
RUN chmod 700 /tests/test.sh  # the inlined GT_CONFIG is the answer key: root-only (the verifier runs it as root; agent code runs as nobody) && mkdir -p /logs/verifier

# Verifier entrypoint (harbor runs the image with no command override)
CMD ["/tests/test.sh"]

# ==============================================================================
# Final Directory Structure
# ==============================================================================
#
# /app/ground_truth/oracle/oracle_server  # the live oracle (random port per run; root-exec)
# /tests/test.sh                       # verifier entrypoint (driven by harbor)
# /logs/verifier/                      # reward.json + reward-details.json
#
# Construction-time prerequisites: scaffold copies the template (tests/test.sh); fill_report.py stamps the inline GT config into test.sh; the export step materializes tests/deps.tar.gz and tests/ground_truth/oracle/oracle_server plus the RUNTIME CLOSURE library injection (oracle ships ONCE, inside the ground-truth export)
