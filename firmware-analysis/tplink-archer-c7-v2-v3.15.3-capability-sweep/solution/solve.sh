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
GT_CONFIG='{"image":{"sha256":"5181448eefda418eb772eb5809ab414ab93146ca64639d283c95fe04859ce006","size":14281096,"format":"vendor-bespoke-chain","image_encrypted":false,"gr2_windows":["f68e0bc8ef23fa32cc6d28b9c42a6e2cf3406e86e7e47bb03c0519ed6c56fe95","6aece62f5b4585515e4acc5249267e00f801bf98f9125bccfad1bb83a430bc76","431fcee1314157c0cca378108bf94c8ec385072f7a2ece5870da604e22dbbee4","6ed4cbbedba9a0bed953810771f24c50b34175f3b8302f08eb28cdfc7ce935d1","7160d420cc95dfc26f9b20cc82189eb0b1c41cb71dad801f55fae6159844d7ce","7e088af60fbd18c283ac394f006c8841be488fb07f459dc52f95030802734a8a","1f9442a52c5c73e02ce083b3162e239b0c60def30e17b1d9e954b1bc1521c9eb","ca35ffe48f3b0f7d3a747301e9377407e45e80a5203e8384f6a1574bb041ba31"],"partitions":[{"name":"pad","offset":8258,"length":1088,"sha256":"769b7cd9026948adacd8471bc117a9a1ebb2cd7ed9c4fbfdfcd71a61c604ff48"},{"name":"decoy:raw","offset":9346,"length":8010,"sha256":"8087da25de94bd1fcbf380cfd1e566a470c677643b08c426ca4bcacb624ff901"},{"name":"gap","offset":17356,"length":136,"sha256":"b707241545a346265aab1ffb32ff64b55bf8f8dc1b56a46ef33ce3d15db11d33"},{"name":"decoy:raw","offset":17492,"length":7074,"sha256":"b2384bcdbd631122cf53ab99d2d28dd0aed4f1b8e1c12b18e99693c058f69509"},{"name":"gap","offset":24566,"length":572,"sha256":"0fcf40c74177936605ea861fa5eac3ab108c9ecaa13c579cf3f6846389b113a1"},{"name":"decoy:raw","offset":25138,"length":5919,"sha256":"2411e6f768882d7ea6497867b8f0edeb3bf9457db4f76caef67ecf252727122a"},{"name":"gap","offset":31057,"length":108,"sha256":"77133f431d5e12dd850002c0d3d4e0fecbe3a7a699d604dc8c5eae9976e1d260"},{"name":"decoy:squashfs","offset":31165,"length":7462,"sha256":"bdb48331f9fa12573a75aa0514429381cf3ce8b5467d19ae55384eacbf3a0996"},{"name":"gap","offset":38627,"length":884,"sha256":"6ca83adefc47fc9ab71637c150b95b33083e61e507dff2ee5f2692aa27e1453e"},{"name":"decoy:raw","offset":39511,"length":2509,"sha256":"eef21084e06b7ce2d9eb0928c3edff3ac4786a91e8c0564e102f374f7cfa2304"},{"name":"gap","offset":42020,"length":148,"sha256":"3b18c58c739716e76429634a61375c45b3b5cd470c22ab6d3e14cee23dd992e1"},{"name":"decoy:squashfs","offset":42168,"length":7081,"sha256":"ce41be114458271a0c0fe8d8575bb51a499d3aa52cab278583fb2d3f51a074ed"},{"name":"gap","offset":49249,"length":912,"sha256":"d2710a3a6574fc3d509a62191d8933226f0046f7ffcd83fd8de6866684c5f73e"},{"name":"decoy:squashfs","offset":50161,"length":6281,"sha256":"a47d5b3c8fdcb51f72b1bff05a78ba550f778f6bdc86ee100ad36d747ac71526"},{"name":"gap","offset":56442,"length":20,"sha256":"de47c9b27eb8d300dbb5f2c353e632c393262cf06340c4fa7f1b40c4cbd36f90"},{"name":"decoy:uimage","offset":56462,"length":6926,"sha256":"c69e4f8e856b70ac1b9b0c26bfbcf88e3c6f16f699d60b59e0335a41c37735c6"},{"name":"gap","offset":63388,"length":92,"sha256":"62b14867e4e79d50673d2f7474335229f54c478f56d2a910235e1953c6d29206"},{"name":"decoy:uimage","offset":63480,"length":3773,"sha256":"d7e769cf6825f68b61e11a0be0ddf5f79c1ba2e6a7fcc31674f79f7a62c8790d"},{"name":"gap","offset":67253,"length":868,"sha256":"60b2789a68bdcbb6bbda951c3a24854e64d8f51ccdaad0d7db302b5123af1cbb"},{"name":"gap","offset":68121,"length":524,"sha256":"c1dcdd7d8c2a5d273f73cca0b55d798344bf94f5834c1a6b852cb0ee709278d7"},{"name":"decoy:squashfs_honey","offset":68645,"length":3792896,"sha256":"f35ff7e8441de091b450fc8c79157ed1306859179779d6cca95d713ae72e0738","poison":[{"package":"ppp","component":"/usr/sbin/pppd","stanza":"P:ppp-fw","bumped_version":"2.4.9-r1","true_version":"2.4.8"}]},{"name":"kernel","offset":3861541,"length":2742568,"sha256":"733ef7fa5d74f97cb34a250033d448a667bbece99521d57388761b1eda193c19"},{"name":"rootfs","offset":6604109,"length":3846144,"sha256":"69a6a3442ad949617181824889246e159b5381bc1ea30816afbe62b270549cb5"},{"name":"gap","offset":10450253,"length":864,"sha256":"0ed9e26c3f1435e498beb2369bdf5a04a7fe4f0e302068ef2c308e1ff872b5f7"},{"name":"decoy:raw","offset":10451117,"length":4177,"sha256":"a7033018dc3e73311eb2535848db27acfbc158824da19d5e8dd4cd373becbc2f"},{"name":"gap","offset":10455294,"length":312,"sha256":"6287e17fe5efcb191aec8a2578e685d0a1040a0ab53bd1f02c7f49cc6c8fced7"},{"name":"decoy:raw","offset":10455606,"length":5207,"sha256":"f36c80707cd41c0875e5774ba1724d20e7f15cecddc4a8c31bc3cf48e8e253c9"},{"name":"gap","offset":10460813,"length":788,"sha256":"3e84c247e11701fb5451865acb6262c8495d47c5f397a772a7bc01c9ce9f5b12"},{"name":"decoy:raw","offset":10461601,"length":5481,"sha256":"eb61725f3beea4df35db585df5d8d9becc2a94aaf3a6533d033c46bb05e0001c"},{"name":"gap","offset":10467082,"length":752,"sha256":"cb92b2277c7e07535d3df05479d7f0fa8a2f5f920ba92ed4acbcbc58a7b14227"},{"name":"decoy:raw","offset":10467834,"length":1318,"sha256":"f033677e83bd54cf3c4d5e34f066eee9f7e3f0cab3d9a30e360ddd9cd0d4b564"},{"name":"gap","offset":10469152,"length":660,"sha256":"213e3a2ae54f25b06fa2c6712c23310e8cea297ecc0d77c984cf1372e8c115f3"},{"name":"decoy:squashfs","offset":10469812,"length":1653,"sha256":"e15c4d526213b827da5e7957d54ae07842511268177e2cae96495773e7e23105"},{"name":"gap","offset":10471465,"length":1004,"sha256":"fa16c3b03c75c0d2a74b01ab8bd3806b53f82abc36bbcc29ae987898f56f5544"},{"name":"decoy:squashfs","offset":10472469,"length":8177,"sha256":"9e78d9a2181d50a26295bea1b232c61d7e306f12bdd739bf7b0ad3fd0fab42bc"},{"name":"gap","offset":10480646,"length":192,"sha256":"5d89f056865052bcb89c910d2d62872e029fb273c3db03f8968a52a41593c1b5"},{"name":"decoy:uimage","offset":10480838,"length":621,"sha256":"54514f679a2c890f3a3cbd4f7e75e444a781eed72d2d9f0d438dbc9051544aa4"},{"name":"gap","offset":10481459,"length":40,"sha256":"2c34ce1df23b838c5abf2a7f6437cca3d3067ed509ff25f11df6b11b582b51eb"},{"name":"decoy:uimage","offset":10481499,"length":3946,"sha256":"14bccb1bdb01827d746321767001d056e1b7fee0e31558042650d603944aedff"},{"name":"gap","offset":10485445,"length":612,"sha256":"fea95ee6654315a11e31ce972ff371fc74f2ad8dc02dd7439dafe6ceff383e9a"},{"name":"decoy:squashfs","offset":10486057,"length":1379,"sha256":"229d2a5bf8f79139e51c0bf9df1f3c853150ed226b57529e1b74093dcc98d3cd"},{"name":"gap","offset":10487436,"length":764,"sha256":"f13cb867dec47196cbc9e31b6e9b13831c4febfb9b822f5fcc265557364d1cdb"},{"name":"decoy:squashfs_honey","offset":10488200,"length":3792896,"sha256":"f35ff7e8441de091b450fc8c79157ed1306859179779d6cca95d713ae72e0738","poison":[{"package":"ppp","component":"/usr/sbin/pppd","stanza":"P:ppp-fw","bumped_version":"2.4.9-r1","true_version":"2.4.8"}]}]},"filesystem":{"type":"squashfs","compression":"xz","offset":6604109,"headerless":false,"block_log":18,"block_size":262144,"inodes":792},"architecture":{"arch":"mips"},"components":[{"path":"/usr/sbin/pppd","arch":"mips","version":"2.4.8","banner_args":["--version"],"banner_obs":"pppd version 2.4.8"},{"path":"/usr/sbin/synbmark","arch":"mips","version":"1.0"}],"contracts":[{"binary":"/usr/sbin/synbmark","argv_template":["-k","{KEY}"],"key_slot":"token","observable":"bytes:5bb8d0f25b6daefdc80d527cfdb5df52"},{"binary":"/usr/sbin/synbmark","argv_template":["-k","{KEY:token}","-a","{KEY}"],"key_slot":"account","observable":"stdout:svc_f3c238"}],"protections":{"image_encryption":{"present":false,"techniques":[]},"layout_obfuscation":{"present":true,"techniques":["bespoke_header","offset_shift","decoy_partitions"],"magic":"0x44564f50","real_offset":3853283,"decoy_count":20},"filesystem_obfuscation":{"present":true,"techniques":["endianness_swap"],"magic":"0x73687371"},"packing":{"present":false,"techniques":[]},"anti_debug":{"present":false,"techniques":[]},"anti_tamper":{"present":false,"techniques":[]},"obfuscation":{"present":false,"techniques":[]}},"system_boot":null,"trigger":{"kind":"backdoor","component":"/usr/sbin/synbmark","feed":"argv_kv","key_slot":"account","argv_template":["-k","{KEY:token}","-a","{KEY}"],"expect_observable":"svc_f3c238","control_max_ring":4,"stability_runs":5,"control_input_b64":""},"checkpoints":{"/usr/sbin/pppd":{"phoff":52,"phdr_vaddr":4194356,"et":"exec","link":"dynamic","entry":4224544,"psize":4,"endian":"big","pad_auxv":true,"banner":[{"name":"main","vaddr":4219824}]},"/usr/sbin/synbmark":{"phoff":52,"phdr_vaddr":4194356,"et":"exec","link":"static","entry":4197312,"psize":4,"endian":"big","pad_auxv":true,"keychain":[{"name":"syn_ring_argv","vaddr":4199156},{"name":"syn_ring_provision","vaddr":4199164},{"name":"syn_ring_derive","vaddr":4199172},{"name":"syn_ring_validate","vaddr":4199180},{"name":"syn_ring_emit","vaddr":4199188}],"chain":[{"name":"syn_ring_ch_nonce","vaddr":4199196},{"name":"syn_ring_ch_derive","vaddr":4199204},{"name":"syn_ring_ch_answer","vaddr":4199212},{"name":"syn_ring_ch_advance","vaddr":4199220}]}},"scoring":{"extraction":{"tree":{"recall":4,"precision":2,"sample":4},"banner":{"process":2,"banner":1,"version":1},"token":{"process":2,"observable":12},"account":{"process":2,"observable":10}},"reconstruction":{"tools":{"one":3,"two":6},"unpack":{"ok":3,"selftree":3},"spec":{"blog":1,"comp":1,"bs":1,"inodes":1},"battery":14},"triggering":{"process":{"per_ring":3.0},"stability":{"runs":5,"per_run":1},"result":{"observable":10}},"buckets":{"extraction":40,"reconstruction":30,"triggering":30}},"oracle":{"activation_keys":{"token":"0445402f9bb09da0","account":"8f51032d3ec984e6"},"perfile":{"family":"iterhash-md5","halves":["c5d97c9ef7786dbf94a1adea622544dd","299fa9d83578d525b38cb8cee7d19d0a"]}}}'
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
