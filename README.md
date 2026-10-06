# BIOPSY

**Reverse-engineering benchmarks that remain difficult as agents become more capable.**

BIOPSY is a benchmark of realistic diagnostic reverse-engineering tasks built end-to-end from real open-source software. Each task seeds a security property into the source of a pinned real program, builds the program, and packages the result as a runnable [Harbor](https://github.com/harbor-framework/harbor) task that agents must solve from the binary alone.

## Motivation

A fixed benchmark eventually becomes too easy. When nearly every agent solves the same tasks, scores cluster near the top, the benchmark stops discriminating, and we can no longer tell which agents are stronger or which parts of reverse engineering still challenge them.

Our research question is how to keep constructing tasks that reveal those remaining bottlenecks.

We utilize **agent performance to provide actionable feedback for constructing harder tasks**. Scores tell us when a task may have become too easy. Execution trajectories explain why, since they show which clues agents rely on and which analysis steps they manage to skip.

## Workflow

BIOPSY turns this feedback into an iterative construction loop.

1. **Construct.** The Task Agent builds verifiable tasks grounded in real software and documented cases.
2. **Evaluate.** Evaluation agents attempt the tasks while we collect scores and trajectories.
3. **Propose.** The Task Agent mines the trajectories for candidate *hardness patterns*, which are changes to the task structure that might require more substantial analysis.
4. **Reconstruct and re-evaluate.** The analysis subjects are rebuilt under those patterns and the agents are evaluated again.

Hardness patterns are hypotheses rather than guaranteed improvements. Each pattern is tested on two questions, namely whether it makes the tasks harder and whether it helps distinguish agents.

## Scenarios

BIOPSY covers five scenarios. Across all five, we require **verifiable outcomes rather than explanations alone**. For example, a patch-diffing solution supplies a triggering input, a protocol-reconstruction solution supplies an executable client, and a firmware-analysis solution supplies a verdict backed by recovered artifacts and observed behavior.

| Scenario                | Agent objective                                                                                                                                                                                                    |
|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Protection assessment   | defeat protection layers on a binary to recover license-verification logic and derive a valid key                                                                                                                  |
| Malware analysis        | reverse a trojanized build on an already-compromised host, deliver a patched binary that no longer detonates but keeps the carrier's genuine behavior, and a cleanup script that removes the infection's artifacts |
| Protocol reconstruction | reconstruct an undocumented wire protocol from a stripped binary and prove the reconstruction by interoperating with the binary                                                                                    |
| Firmware analysis       | unpack a real OpenWrt firmware image with concealed squashfs and SDK-injected anchors, identify the components and architecture, and analyze the embedded software                                                 |
| Patch diffing           | diff two builds of the same program, localize the security-relevant change, characterize the root cause, produce a differential trigger that cleanly separates the pair                                            |

## Evaluation

All tasks and agents share a single Claude Code scaffold. Performance is reported as pass@5 under a budget of two hours per attempt. Scoring is fully automated, with an oracle solution earning 1.0, a no-op solution earning 0.0, and anti-cheating invariants keeping the ground truth out of plaintext.

On the initial task set, agents score between **0.84 and 0.96**. After reconstruction under the mined hardness patterns, scores fall to between **0.03 and 0.15**, which shows that the reconstructed tasks are substantially harder.

![BIOPSY leaderboard](assets/leaderboard.png)

## Hardness patterns

The table below summarizes representative patterns mined from agent trajectories, one for each scenario.

| Pattern                                                              | Scenario                | Effect on the agent                                                                                                                        |
|----------------------------------------------------------------------|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| Interdependent protections                                           | Protection assessment   | protection layers must be defeated jointly rather than peeled one at a time, and no single unwrap exposes the license logic                |
| Malicious behavior distributed across similar benign features        | Malware analysis        | no single code site reads as malicious, so the campaign must be reconstructed from behavior that resembles the carrier's own               |
| Patch commits interleaved with decoys                                | Patch diffing           | the security-relevant change is buried among plausible neutral commits, so localization cannot rely on surface diff signals                |
| Proprietary protocol format combined with complex session state      | Protocol reconstruction | format recovery alone is insufficient, since the client must also reproduce stateful session dynamics to interoperate                      |
| Firmware behavior spread across components and runtime configuration | Firmware analysis       | the verdict hinges on correlating several components with configuration that is visible only at runtime rather than on any single artifact |

Together, these patterns illustrate the core idea of BIOPSY, which is to use agent performance to construct and test new challenges as agents grow more capable.

## Task catalog

Each scenario directory holds its finished and verified task instances.

### Protection assessment

Five protected builds of real programs, each requiring the full protection chain to be defeated.

| Task                                                                                         | Created    | Difficulty | Objective                                                                                                                                   |
|----------------------------------------------------------------------------------------------|------------|------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| [`ddnet-19.9-license-gate`](protection-assessment/ddnet-19.9-license-gate)                   | 2026-09-19 | hard       | defeat the packed, anti-debug-hardened, interlock-guarded chain to recover the headless server's startup entitlement key                    |
| [`stk-code-1.5-premium-unlock`](protection-assessment/stk-code-1.5-premium-unlock)           | 2026-09-19 | expert     | defeat the packed, anti-debug-hardened, interlock-guarded chain to unlock premium story, challenge, kart, and track content in SuperTuxKart |
| [`wesnoth-1.19.26-save-entitlement`](protection-assessment/wesnoth-1.19.26-save-entitlement) | 2026-09-19 | hard       | defeat the VM-obfuscated, packed, anti-debug-hardened chain to recover save-data entitlement in Battle for Wesnoth                          |
| [`ffmpeg-9.0.1-transcode-unlock`](protection-assessment/ffmpeg-9.0.1-transcode-unlock)       | 2026-09-19 | hard       | defeat the PageGuard-packed, anti-debug-hardened chain to unlock the commercial transcoding tier of the protected tool                      |
| [`nginx-1.31.3-tier-license`](protection-assessment/nginx-1.31.3-tier-license)               | 2026-09-19 | hard       | defeat the UPX, Tigress, and interlock chain on the protected web server to forge the load-balancing tier's activation key                  |

### Malware analysis

Five trojanized builds of real network-facing carriers, each hiding its payload behind layered evasion such as stealth packing, anti-debug, anti-VM, anti-emulation, and obfuscation. The deliverable is a patched binary that keeps the carrier's genuine behavior but no longer detonates, plus a cleanup script that removes the infection's artifacts.

| Task                                                                            | Created    | Difficulty | Objective                                                                                                                                                                             |
|---------------------------------------------------------------------------------|------------|------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [`httpd-2.4.68-cred-exfil`](malware-analysis/httpd-2.4.68-cred-exfil)           | 2026-10-05 | hard       | defeat stealthed UPX packing, anti-debug, and string obfuscation to strip the credential exfiltration from the trojanized shared-hosting web daemon while keeping it a working server |
| [`busybox-1.36.1-nc-dropper`](malware-analysis/busybox-1.36.1-nc-dropper)       | 2026-10-06 | hard       | defeat UPX-stealth packing, anti-VM, anti-emulation, and timing evasion to strip the netcat dropper from the trojanized BusyBox while keeping the multi-tool working                  |
| [`openssh-9.9p2-sshkey-harvest`](malware-analysis/openssh-9.9p2-sshkey-harvest) | 2026-10-06 | expert     | defeat a custom page-encrypted packer and obfuscated payload to strip the key harvest from the trojanized SSH client while keeping genuine behavior                                   |
| [`socat-1.8.0.2-covert-relay`](malware-analysis/socat-1.8.0.2-covert-relay)     | 2026-10-06 | expert     | defeat custom-VM virtualization, stealth packing, and anti-analysis layers to strip the covert relay from the trojanized network tool while keeping genuine behavior                  |
| [`stunnel-5.80-tls-beacon`](malware-analysis/stunnel-5.80-tls-beacon)           | 2026-10-06 | hard       | defeat whole-binary packing, trigger-point anti-debug, and environment fingerprinting to strip the TLS beacon from the trojanized tunnel while keeping genuine behavior               |

### Protocol reconstruction

Five carriers spanning multi-envelope, bit-packed, and TLV wire formats. Every task is host-bound, with wire material split across a Tigress-VM engine, a masked second translation unit, and the real configuration state of the carrier, together with per-connection frame-material rolling. The deliverable is an interoperating client judged by a 26-element session ladder and a 13-probe robustness battery.

| Task                                                                               | Created    | Difficulty | Objective                                                                                     |
|------------------------------------------------------------------------------------|------------|------------|-----------------------------------------------------------------------------------------------|
| [`mosh-1.4.0-roamlink`](protocol-reconstruction/mosh-1.4.0-roamlink)               | 2026-09-07 | expert     | reverse the VM-carried multi-envelope protocol with X25519 sessions and then interoperate     |
| [`asterisk-23.4.1-trunkline`](protocol-reconstruction/asterisk-23.4.1-trunkline)   | 2026-09-07 | expert     | reverse the bit-packed multi-envelope protocol over a VM engine and then interoperate         |
| [`samba-4.24.6-fileport`](protocol-reconstruction/samba-4.24.6-fileport)           | 2026-09-07 | expert     | reverse the bit-packed protocol with HTTP-mimicking chaff and then interoperate               |
| [`strongswan-6.0.7-tunnelkey`](protocol-reconstruction/strongswan-6.0.7-tunnelkey) | 2026-09-07 | hard       | reverse the TLV protocol with X25519 and HKDF sessions behind a settings-parser material site |
| [`mariadb-12.3.3-binlatch`](protocol-reconstruction/mariadb-12.3.3-binlatch)       | 2026-09-16 | expert     | reverse the single-checksum bit-packed protocol with a static keystream and no key exchange   |

### Firmware analysis

Five images across four device classes (arm64 virtual hub and camera, marvell-armada NAS, SOHO router, and 32-bit x86 industrial), each requiring the agent to unpack, inventory, and analyze the image, with a scenario verdict that must be backed by emulation-proven findings.

| Task                                                                                                                 | Created    | Difficulty | Objective                                                                                                                                                                                                                       |
|----------------------------------------------------------------------------------------------------------------------|------------|------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [`tplink-archer-a6-v3-v1.0.16-capability-sweep`](firmware-analysis/tplink-archer-a6-v3-v1.0.16-capability-sweep)     | 2026-08-31 | hard       | sweep the UPX-layered factory image for an undocumented maintenance capability (a hidden account and helper) and rule PRESENT or ABSENT with image-backed evidence                                                              |
| [`dlink-dir-878-a1-v1.20B05-covert-channel-sweep`](firmware-analysis/dlink-dir-878-a1-v1.20B05-covert-channel-sweep) | 2026-09-04 | hard       | sweep the obfuscated-layout image for an undocumented listener, beacon, or magic-port responder and rule PRESENT or ABSENT with image-backed evidence                                                                           |
| [`armsr-armv8-v1.15-upgrade-decrypt-recovery`](firmware-analysis/armsr-armv8-v1.15-upgrade-decrypt-recovery)         | 2026-09-28 | expert     | recover the upgrade-chain key material from an older plaintext update, decrypt and inventory the newest encrypted arm64 image, and deliver an emulation-proven verdict                                                          |
| [`buffalo-ls220de-v1.86-exploitability-review`](firmware-analysis/buffalo-ls220de-v1.86-exploitability-review)       | 2026-09-28 | hard       | prove that CVE-2026-22903 is exploitable as shipped on the NAS image, requiring vulnerable code to be present and a trigger to be demonstrated, not merely vulnerability on paper                                               |
| [`x86-generic-v1.11-advisory-impact-triage`](firmware-analysis/x86-generic-v1.11-advisory-impact-triage)             | 2026-09-28 | hard       | triage the six-CVE dnsmasq May-2026 wave (CVE-2026-2291, CVE-2026-4890, CVE-2026-4891, CVE-2026-4892, CVE-2026-4893, and CVE-2026-5172) against the shipped 2.91 build, with the verdict backed by image-verified version facts |

### Patch diffing

Six stripped build pairs under six distinct engagement scenarios, covering backport check, fuzzer regression triage, staged-rollout audit, exploit replay, embargo response, and bounty audit. The required deliverable is always a differential trigger, a single crafted input that cleanly separates the two builds under the canonical invocation of the task.

| Task                                                                                         | Created    | Difficulty | Objective                                                                                                                                                                                                    |
|----------------------------------------------------------------------------------------------|------------|------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [`git-2.49.0-push-remoteref-leak`](patch-diffing/git-2.49.0-push-remoteref-leak)             | 2026-10-05 | hard       | in a backport check, decide whether the shipped git build already carries the just-published upstream fix for the push remote-ref leak, and demonstrate any gap with a differential trigger                  |
| [`php-8.3.16-enum-constant-uaf`](patch-diffing/php-8.3.16-enum-constant-uaf)                 | 2026-10-05 | hard       | in a bounty adjudication, decide whether the submitted crash report of the enum-constant use-after-free is a genuine in-scope vulnerability that the update actually closes, and rule out a coincidental fix |
| [`qemu-10.0.0-sriov-vf-overflow`](patch-diffing/qemu-10.0.0-sriov-vf-overflow)               | 2026-10-05 | hard       | for rollout sign-off, produce the differential-risk evidence, with one input demonstrating the SR-IOV VF overflow gap between the fleet build and the about-to-ship build                                    |
| [`ruby-3.4.1-pattern-parse-leak`](patch-diffing/ruby-3.4.1-pattern-parse-leak)               | 2026-10-05 | hard       | in an embargo response, provide go or no-go evidence on whether the release candidate is exploitable through the pattern-parse leak that the about-to-lift advisory will name                                |
| [`sqlite-3.53.4-window-recursion-crash`](patch-diffing/sqlite-3.53.4-window-recursion-crash) | 2026-10-05 | hard       | in fuzzer triage, decide whether the flagged window-recursion crash is a known-fixed issue resurfacing through a bad backport or a genuinely new defect, and prove the call                                  |
| [`unbound-1.22.0-keytrap-ds-grind`](patch-diffing/unbound-1.22.0-keytrap-ds-grind)           | 2026-10-05 | hard       | in an exploit replay, carry the KeyTrap technique from a public write-up onto the fleet's shipped-versus-fixed pair as a trigger that misbehaves only on the build the fleet still runs                      |

## Task package layout

Every task directory shares the same core shape, with a category-specific extra under environment/ where needed (for example protection/ in protection-assessment or patches/ in patch-diffing).

```text
<scenario>/<task>/
├── task.toml              # Harbor manifest with name, description, difficulty, verifier limits, and agent limits
├── instruction.md         # the brief that the solving agent reads
├── README.md              # per-challenge README
├── agent_third_party.py   # adapter for running third-party agents inside the environment
├── config/                # agent configs for cc, codex, and gemini-cli
├── environment/           # agent-side Dockerfile and, outside patch diffing, docker-compose.yaml
├── solution/              # held-out oracle with solve.sh and ground_truth/
└── tests/                 # verifier side with Dockerfile, docker-compose.yaml, and test.sh
```

## License

The benchmark's own content (task scaffolding and evaluation data) is licensed under [**GPL-3.0**](LICENSE). Commercial use is permitted under its copyleft terms, so recipients must receive corresponding source and modifications carry the same license.

Third-party software keeps its upstream license. The carrier programs and embedded libraries inside each task environment are redistribution builds of their upstream releases (GPL-2, GPL-3, LGPL, MIT, BSD, Apache-2.0, zlib, and similar), and corresponding sources ship alongside every task. Upstream names and trademarks belong to their projects. The benchmark is provided "AS IS", without warranty of any kind.
