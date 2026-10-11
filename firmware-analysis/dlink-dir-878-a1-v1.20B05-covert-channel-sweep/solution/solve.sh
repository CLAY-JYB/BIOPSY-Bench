#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════════════════════════════════
# SOLUTION SCRIPT: reference solve (scores 1.0000 against tests/test.sh)
# ═══════════════════════════════════════════════════════════════════════════
#
# The reference solution is the generator's own knowledge, staged into the
# PURE-DYNAMIC output contract (instruction.md OUTPUT CONTRACT — no report
# exists; every artifact is verified by execution or bytes):
#   extracted_fs/         = the oracle file tree (B/C/D/H carriers; the
#                           graded components live at their in-image paths)
#   firmware_repacked.bin = a TRUE mksquashfs rebuild from the tree (F; on
#                           system-boot tasks spliced onto the boot-chain
#                           prefix so the rebuilt disk boots, G)
#   activation.keys       = the true activation keys (root-only GT oracle
#                           block; the verifier only ever runs them)
#   decrypted.bin         = the decrypt chain's output (P0, encrypted
#                           engagements): the pre-encryption image bytes
#
# Mounted layout (Harbor convention, same as the sibling skills):
#   $0                      this script
#   ground_truth/           tree.tar.gz (+ assembled.bin)
# ═══════════════════════════════════════════════════════════════════════════

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="/logs/artifacts/agent_output"
GT_DIR="$SCRIPT_DIR/ground_truth"
GT_CONFIG='{"image":{"sha256":"fb6781628ffe645a1b56d4686bea8ad8142e6fc216f417411981fd3d4897e879","size":7715702,"format":"syn1-encrypted","image_encrypted":true,"partitions":[]},"filesystem":{"type":"squashfs","compression":"xz","offset":null,"headerless":false,"block_log":18,"block_size":262144,"inodes":792},"architecture":{"arch":"mipsel"},"components":[{"path":"/usr/sbin/dropbear","arch":"mipsel","version":"2025.89","banner_args":["-V"],"banner_obs":"Dropbear v2025.89"},{"path":"/usr/sbin/synbmark","arch":"mipsel","version":"1.0"}],"contracts":[{"binary":"/usr/sbin/synbmark","argv_template":["-k","{KEY}"],"key_slot":"token","observable":"bytes:5ae34dba8b80650faecb9bd6b22b6ce4"},{"binary":"/usr/sbin/synbmark","argv_template":["-k","{KEY:token}","-a","{KEY}"],"key_slot":"account","observable":"stdout:svc_c82d0b"},{"binary":"/usr/sbin/synbmark","argv_template":["-k","{KEY}","-l","{PORT}"],"key_slot":"token","observable":"chain:59128:5ae34dba8b80650faecb9bd6b22b6ce4","chain":true,"chain_material":{"uuid":"7a590b2c-90bd-51e9-cf06-d9e0c6014471","salt":"482a3501cd6530df","psha":"3a30bc57"}}],"protections":{"image_encryption":{"present":true,"techniques":["syn-ctr"],"key_location":"boot-embedded"},"layout_obfuscation":{"present":false,"techniques":[]},"filesystem_obfuscation":{"present":false,"techniques":[]},"packing":{"present":false,"techniques":[]},"anti_debug":{"present":true,"techniques":["int3_check","proc_maps_check","frida_detection","time_delta_check"]},"anti_tamper":{"present":false,"techniques":[]},"obfuscation":{"present":false,"techniques":[]}},"system_boot":null,"trigger":{"kind":"covert","component":"/usr/sbin/synbmark","feed":"chain","key_slot":"token","argv_template":["-k","{KEY}","-l","{PORT}"],"chain_material":{"uuid":"7a590b2c-90bd-51e9-cf06-d9e0c6014471","salt":"482a3501cd6530df","psha":"3a30bc57"},"expect_observable":"5ae34dba8b80650faecb9bd6b22b6ce4","control_max_ring":2,"stability_runs":5,"control_input_b64":""},"checkpoints":{"/usr/sbin/dropbear":{"phoff":52,"phdr_vaddr":4194356,"et":"exec","link":"dynamic","entry":4221296,"psize":4,"endian":"little","pad_auxv":true,"banner":[{"name":"main","vaddr":4221008}]},"/usr/sbin/synbmark":{"phoff":52,"phdr_vaddr":4194356,"et":"exec","link":"static","entry":4197568,"psize":4,"endian":"little","pad_auxv":true,"keychain":[{"name":"syn_ring_argv","vaddr":4199124},{"name":"syn_ring_provision","vaddr":4199132},{"name":"syn_ring_derive","vaddr":4199140},{"name":"syn_ring_validate","vaddr":4199148},{"name":"syn_ring_emit","vaddr":4199156}],"chain":[{"name":"syn_ring_ch_nonce","vaddr":4199164},{"name":"syn_ring_ch_derive","vaddr":4199172},{"name":"syn_ring_ch_answer","vaddr":4199180},{"name":"syn_ring_ch_advance","vaddr":4199188}]}},"scoring":{"extraction":{"tree":{"recall":4,"precision":2,"sample":4},"banner":{"process":2,"banner":1,"version":1},"token":{"process":2,"observable":4.0},"p0":{"size":2,"head":2,"exact":2},"account":{"process":2,"observable":4.0},"chain":{"round":1.6}},"reconstruction":{"tools":{"one":3,"two":6},"unpack":{"ok":3,"selftree":3},"spec":{"blog":1,"comp":1,"bs":1,"inodes":1},"battery":14},"triggering":{"process":{"per_ring":3.75},"stability":{"runs":5,"per_run":1},"result":{"rounds":10}},"buckets":{"extraction":40,"reconstruction":30,"triggering":30}},"oracle":{"activation_keys":{"token":"26c0b0c70d5b8e18","account":"3161cd22bfc11d01"},"perfile":{"family":"pbkdf2-aes-cbc","halves":["bba18898fecff41f167b9ee89eb8c437","62720b0e2e57bdd793ea041c18c83809"]}},"decrypted_sha256":"6b067d0197a9a23c4ace06ca04fcb08fba29385fbd45089f6c4223e085cc7d58","decrypted_size":7342003}'
export GT_CONFIG

mkdir -p "$OUTPUT_DIR"

# 1. the extracted tree: the oracle file tree at its original in-image
#    paths. The graded components are byte-checked HERE (in tree context)
#    and every gated execution runs from inside it.
if [ -d "$GT_DIR/tree" ]; then
    mkdir -p "$OUTPUT_DIR/extracted_fs"
    cp -a "$GT_DIR/tree/." "$OUTPUT_DIR/extracted_fs/"
elif [ -f "$GT_DIR/tree.tar.gz" ]; then
    # compact layout: the oracle tree ships as the construction-time export
    # tree.tar.gz (single archive, identical on both sides)
    mkdir -p "$OUTPUT_DIR/extracted_fs"
    tar xzf "$GT_DIR/tree.tar.gz" -C "$OUTPUT_DIR/extracted_fs" --strip-components=1
else
    echo "warning: ground_truth/tree missing -- task assembly must stage" \
         "the oracle file tree (SKILL.md Step 8)" >&2
fi

# 2. activation.keys: the true keys from the root-only oracle block. These
#    are never string-compared by the verifier -- they only pay through the
#    gated executions they unlock inside the extracted tree.
python3 - "$GT_CONFIG" "$OUTPUT_DIR" <<'PYEOF'
import json, os, sys
gt = json.loads(sys.argv[1])
keys = (gt.get("oracle") or {}).get("activation_keys") or {}
lines = []
for slot in ("token", "account"):
    if keys.get(slot):
        lines.append("%s=%s" % (slot, keys[slot]))
open(os.path.join(sys.argv[2], "activation.keys"), "w").write(
    "\n".join(lines) + "\n")
print("activation.keys: %d slot(s)" % len(lines))
PYEOF

# 3. firmware_repacked.bin: a TRUE rebuild from the extracted tree
#    (mksquashfs the recovered rootfs with the original geometry) -- a
#    fresh image with identical content, rebuilt bytes. This is
#    deliberately NOT a byte-copy of the challenge image or the decrypted
#    original: the verifier rejects verbatim embeds and positional splices.
#    On system-boot tasks the rebuilt rootfs is spliced onto the boot-chain
#    prefix of the pre-encryption disk (the bootloader/kernel chain is not
#    what the rebuild axis grades; the filesystem is), so the rebuilt disk
#    genuinely boots.
python3 - "$GT_CONFIG" "$OUTPUT_DIR" "$GT_DIR" <<'PYEOF'
import json, os, shutil, struct, subprocess, sys

gt = json.loads(sys.argv[1])
outdir = sys.argv[2]
gt_dir = sys.argv[3]
tree = os.path.join(outdir, "extracted_fs")
target = os.path.join(outdir, "firmware_repacked.bin")
fs = gt.get("filesystem") or {}
geo = []
if fs.get("compression") and fs["compression"] != "none":
    geo += ["-comp", str(fs["compression"])]
if fs.get("block_size"):
    geo += ["-b", str(fs["block_size"])]
ok = False
if os.path.isdir(tree) and shutil.which("mksquashfs"):
    # -no-fragments on the DIVERGENCE-GRADED tasks (the shipped stream
    # must not be reproducible positionally); the boot-splice task keeps
    # default fragments so the rebuilt filesystem stays inside the
    # original fs region (a no-fragments rebuild of a fragment-packed
    # original overflows the partition and costs the boot tail)
    flags = [] if gt.get("system_boot") else ["-no-fragments"]
    r = subprocess.run(["mksquashfs", tree, "/tmp/solve-rootfs.bin"]
                       + geo + flags
                       + ["-noappend", "-no-xattrs", "-no-progress"],
                       capture_output=True)
    built = r.returncode == 0 and \
        os.path.getsize("/tmp/solve-rootfs.bin") > 4096
    if built:
        if gt.get("system_boot") and os.path.isfile(
                os.path.join(gt_dir, "assembled.bin")):
            # boot-chain splice: prefix (bootloader/kernel) from the
            # pre-encryption disk + the REBUILT rootfs, PADDED to the
            # original filesystem region's length so every later
            # structure (overlay partition, GPT backup) keeps its exact
            # offset -- the disk boots with the recovered tree inside.
            asm = open(os.path.join(gt_dir, "assembled.bin"), "rb").read()
            off = None
            tail = b""
            fs_len = None
            # stream-scan for the standard superblock (compression xz + a
            # sane bytes_used), same anchor the verifier's boot phase uses
            for chunk_start in range(0, len(asm), 8 * 1024 * 1024):
                buf = asm[chunk_start:chunk_start + 8 * 1024 * 1024]
                win = tail + buf
                pos = win.find(b"hsqs")
                while pos != -1:
                    try:
                        if struct.unpack_from("<H", win, pos + 20)[0] == 4 \
                                and 0 < struct.unpack_from(
                                    "<Q", win, pos + 40)[0]:
                            off = chunk_start - len(tail) + pos
                            fs_len = struct.unpack_from(
                                "<Q", win, pos + 40)[0]
                            break
                    except struct.error:
                        pass
                    pos = win.find(b"hsqs", pos + 1)
                if off is not None:
                    break
                tail = win[-3:]
            if off is None:
                off = asm.find(b"hsqs")
            rebuilt = open("/tmp/solve-rootfs.bin", "rb").read()
            if off and off > 0:
                # keep the original tail (overlay partition, GPT backup)
                # from max(fs end, rebuilt end) onward: the rootfs
                # PARTITION is far larger than the filesystem it holds,
                # so a rebuilt fs a little past bytes_used still fits --
                # the disk keeps its exact partition layout and boots
                with open(target, "wb") as t:
                    t.write(asm[:off])
                    t.write(rebuilt)
                    if fs_len and len(rebuilt) < fs_len:
                        t.write(b"\x00" * (fs_len - len(rebuilt)))
                    keep_from = off + max(fs_len or 0, len(rebuilt))
                    if keep_from < len(asm):
                        t.write(asm[keep_from:])
            else:
                shutil.copyfile("/tmp/solve-rootfs.bin", target)
        else:
            shutil.copyfile("/tmp/solve-rootfs.bin", target)
        ok = os.path.getsize(target) > 4096
if not ok:
    print("warning: rebuild unavailable (no mksquashfs or empty output)"
          " -- repack skipped" )
    sys.exit(1)
print("firmware_repacked.bin: genuine rebuild (%d bytes)"
      % os.path.getsize(target))
PYEOF

# 4. decrypted.bin (encrypted engagements): the decrypt chain's output --
#    the pre-encryption image, which is exactly what a correct decrypt of
#    the shipped image reproduces.
if python3 -c "
import json, os, sys
gt = json.loads(os.environ['GT_CONFIG'])
sys.exit(0 if gt.get('decrypted_sha256') else 1)" 2>/dev/null && \
   [ -f "$GT_DIR/assembled.bin" ]; then
    # L4 tasks: the decrypt chain's output still carries the per-file
    # layer (region-decrypted, file-encrypted) -- that variant IS the
    # decrypt delivery target
    if [ -f "$GT_DIR/assembled_perfile.bin" ]; then
        cp "$GT_DIR/assembled_perfile.bin" "$OUTPUT_DIR/decrypted.bin"
    else
        cp "$GT_DIR/assembled.bin" "$OUTPUT_DIR/decrypted.bin"
    fi
    echo "decrypted.bin: decrypt-chain output staged"
fi

# 5. poc_input.bin (agent-fed trigger engagements): the crafted trigger
#    bytes from the root-only oracle block (the attack request / packet
#    the verifier feeds verbatim to the byte-verified component).
if python3 -c "
import json, os, sys
gt = json.loads(os.environ['GT_CONFIG'])
sys.exit(0 if (gt.get('oracle') or {}).get('poc_input_b64') else 1)" \
   2>/dev/null; then
    python3 - "$GT_CONFIG" "$OUTPUT_DIR" <<'PYEOF2'
import base64, json, os, sys
gt = json.loads(sys.argv[1])
blob = base64.b64decode((gt.get("oracle") or {}).get("poc_input_b64"))
open(os.path.join(sys.argv[2], "poc_input.bin"), "wb").write(blob)
print("poc_input.bin: %d trigger bytes staged" % len(blob))
PYEOF2
fi

# 6. world-readable output.
#    Harbor downloads agent_output to the host and re-uploads it into the
#    verifier container; cp -a above preserves the oracle tree's
#    restrictive modes (etc/shadow 600, root/ 700, sbin/* 700), which
#    breaks that transfer whenever the artifact owner cannot be re-mapped
#    to the host user (rootless docker). The verifier itself chmods a+rX
#    before dropping to nobody, so this changes nothing there.
chmod -R a+rX "$OUTPUT_DIR"

echo "reference solve staged (pure-dynamic contract):"
echo "  $OUTPUT_DIR/extracted_fs/          (oracle file tree)"
echo "  $OUTPUT_DIR/firmware_repacked.bin  (genuine mksquashfs rebuild)"
echo "  $OUTPUT_DIR/activation.keys        (true activation keys)"
[ -f "$OUTPUT_DIR/decrypted.bin" ] && \
    echo "  $OUTPUT_DIR/decrypted.bin           (decrypt-chain output)"
[ -f "$OUTPUT_DIR/poc_input.bin" ] && \
    echo "  $OUTPUT_DIR/poc_input.bin           (crafted trigger bytes)"
echo "expected score: 1.0000"
