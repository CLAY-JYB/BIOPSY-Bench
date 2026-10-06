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
GT_CONFIG='{"image":{"sha256":"31c926f564dc56b429c0a0079af6459763bd804975bbbdf731caa02be6dde08c","size":18325358,"format":"ring-chain-hardened","image_encrypted":false,"partitions":[]},"filesystem":{"type":"squashfs","compression":"xz","offset":null,"headerless":false,"block_log":18,"block_size":262144,"inodes":796},"architecture":{"arch":"mipsel"},"components":[{"path":"/usr/sbin/pppd","arch":"mipsel","version":"2.4.8","banner_args":["--version"],"banner_obs":"pppd version 2.4.8"},{"path":"/usr/sbin/synbmark","arch":"mipsel","version":"1.0"}],"contracts":[{"binary":"/usr/sbin/synbmark","argv_template":["-k","{KEY}"],"key_slot":"token","observable":"bytes:5bb8d0f25b6daefdc80d527cfdb5df52"},{"binary":"/usr/sbin/synbmark","argv_template":["-k","{KEY:token}","-a","{KEY}"],"key_slot":"account","observable":"stdout:svc_f3c238"}],"protections":{"image_encryption":{"present":false,"techniques":[]},"layout_obfuscation":{"present":true,"techniques":["decoy_partitions"],"decoy_count":1},"filesystem_obfuscation":{"present":true,"techniques":["endianness_swap"],"magic":"0x73687371"},"packing":{"present":true,"techniques":["upx_packing","nrv_compression","runtime_decompression"]},"anti_debug":{"present":false,"techniques":[]},"anti_tamper":{"present":false,"techniques":[]},"obfuscation":{"present":false,"techniques":[]}},"system_boot":null,"poc_trigger":null,"impact_trigger":null,"scoring":{"B":{"b1":8,"b2":5,"b3":7},"C":{"c1":3,"c2_run":2,"c2_banner":2,"c2_ver":2,"c3":3},"D":{"d1a_run":1,"d1a_gate":1,"d1b_fmt":2,"d1b":14,"d2a_run":1,"d2a_gate":1,"d2b_fmt":2,"d2b":10},"F":{"f1_1tool":2,"f1_2tools":4,"f4_hi":8,"f4_mid":3,"f2":8,"f3_blog":2,"f3_comp":2,"f3_bs":3,"f3_inodes":1},"P0":{"size":2,"head":2,"exact":4},"buckets":{"extraction_emulation":72,"reconstruction":28,"demonstration":0}},"oracle":{"activation_keys":{"token":"5c0c8f3289ec5847","account":"cae34efaa19db31b"},"perfile":{"family":"sha3mix","halves":["44629feafbd25f10b207b1b295308632","d7a215ac7354d3aaf8547e16dfc68787"]}},"decrypted_sha256":"97e95da51dd2b46179013526538c0ba07203f8a51cab3f2873e6f9c79e32dad8","decrypted_size":13711200}'
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

# 5. world-readable output.
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
echo "expected score: 1.0000"
