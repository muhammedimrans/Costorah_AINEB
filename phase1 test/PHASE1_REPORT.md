# Phase 1 — Co-Resident Agent Experiment: Results

**Run date:** 26 August 2026
**Host:** Linux 6.18.44 x86_64, root, cgroup v1 + v2, `kernel.pid_max = 32768`
**Code:** `exp/` (rerunnable: `python3 run_experiment.py`, `run_counterfactuals.py`, `run_refined.py`)
**Raw output:** `results.json`, `results_counterfactual.json`, `results_refined.json`

---

## 1. Verdict

**G1 (agent instance individuation) is real, and it is worse than the v2 document states.**

The document asks whether co-resident identical agents can be individuated. The answer is no — but the more important finding is *why*, and it is structural rather than an implementation gap:

> **A workload attestor selector must be (a) different between instances, (b) not forgeable by the workload, and (c) knowable before the workload starts, because registration entries are authored in advance. On a standard Linux host, the set of process attributes satisfying all three is empty.**

That is a provable statement, it was empirically confirmed, and it is not something SPIRE can fix by adding a plugin. It is a consequence of the registration model.

**G2 (instance-to-flow binding) is real but needs restating.** The kernel *does* hold the mapping and it resolved correctly in every process-per-instance trial. It collapses entirely in the deployment model that actually matters. The correct anchor is the socket, not the process — see §6.

**G3 (verdict to enforcement) was not testable here.** It requires real enforcement points.

---

## 2. Method

Four agent instances (`A`–`D`), each acting for a different delegating human, launched from the same interpreter, same script path, same uid/gid, same cwd, same cgroup, same network namespace, connecting to the same destination. Two conditions: byte-identical argv, and argv differing only by a principal label.

A mock SPIRE Workload API reproduces the real control flow — accept on a Unix socket, obtain the caller PID via `SO_PEERCRED`, run workload attestors against that PID, match the resulting selectors against pre-authored registration entries, return the matching SVID.

Selector derivation is a faithful reimplementation of SPIRE's `unix` attestor (`unix:uid`, `unix:user`, `unix:gid`, `unix:group`, `unix:supplementary_gid`, `unix:path`, `unix:sha256`) plus the container-id extraction the `docker`/`k8s` attestors perform on `/proc/<pid>/cgroup`. The registration entry was authored from a reference process *before* the agents under test existed, matching the real operator workflow.

---

## 3. E1 — Selector collision

| | strict identical argv | differ by label only |
|---|---|---|
| co-resident instances | 4 | 4 |
| distinct SPIRE selector sets | **1** | **1** |
| indistinguishable group | A, B, C, D | A, B, C, D |
| SVIDs issued | 4 × `spiffe://example.org/agent/research-agent` | same |
| distinct PIDs seen by `SO_PEERCRED` | 4 (527–530) | 4 (542–545) |

All four instances received the same SPIFFE ID. Adding a distinguishing argv changed nothing, because the `unix` attestor does not read `cmdline`.

**The sharpest detail:** `SO_PEERCRED` returned four *different, kernel-authoritative, unforgeable* PIDs. The attestation pipeline then used each PID solely as a handle for gathering selectors and discarded it. The one discriminator the kernel hands over for free is thrown away — necessarily, because a PID cannot appear in a registration entry authored before the process exists.

## 4. E2 — Discriminator inventory

17 per-process facts examined, classified on three axes.

| Fact | varies | kernel-authoritative | admissible in reg. entry | usable |
|---|---|---|---|---|
| `uid`, `gid`, `supplementary_gids` | no | yes | yes | — |
| `exe_path`, `exe_sha256` | no | yes | yes | — |
| `cgroup`, `netns`, `pidns`, `mntns`, `userns`, `ppid` | no | yes | partly | — |
| `cmdline` | yes (cond. B) | **no** | yes | — |
| `environ_hash` | yes | **no** | no | — |
| `pid` | yes | yes | **no** | — |
| `starttime_ticks` | yes | yes | **no** | — |
| `pid_starttime_pair` | yes | yes | **no** | — |
| `socket_inodes` | yes | yes | **no** | — |

**Intersection of all three properties: empty, in both conditions.**

The two columns fail for different and irreducible reasons. `cmdline` and `environ` live in writable process memory — SPIRE rejected an `environ` selector for the `unix` attestor on precisely this ground (spiffe/spire#1198: `/proc/[pid]/environ` "is mutable by the workload"). `pid`, `starttime`, and socket inodes are kernel-authoritative but allocated at runtime, so no operator can write them into a registration entry in advance.

## 5. E3 — Flow attribution

All four agents connected to the same destination from the same source IP.

```
127.0.0.1:56716 -> :9443  inode=935  pid=[527]  agent=[A]
127.0.0.1:56730 -> :9443  inode=940  pid=[530]  agent=[D]
127.0.0.1:56744 -> :9443  inode=945  pid=[528]  agent=[B]
127.0.0.1:56754 -> :9443  inode=950  pid=[529]  agent=[C]
```

4/4 flows attributed to the correct process by matching the `/proc/net/tcp` inode column against `/proc/<pid>/fd` — the mechanism `ss -p` uses.

**The information exists in the kernel and is exact.** It is simply never lifted into the identity plane, and it is only available to something with local `/proc` access on that host. A gateway one hop away sees four flows from one IP with nothing to separate them. The destination received only a self-asserted JSON claim of which principal it was acting for.

## 6. E6 — The case that breaks everything

Four concurrent agent sessions as threads inside **one** process, each with its own socket and its own delegating human. This is how real agent runtimes are built.

| | |
|---|---|
| concurrent sessions | 4 |
| distinct delegating principals | 4 |
| distinct OS PIDs | **1** |
| distinct thread ids | 4 |
| distinct SPIRE selector sets | **1** |
| flows observed | 4 |
| distinct PIDs behind those flows | **1** |
| socket inodes | 4 — all distinct |

Here the E3 result collapses. Every flow resolves to the same PID, so even the kernel-level attribution path that worked in §5 returns one answer for four different principals. `SO_PEERCRED` would also return one PID.

**One discriminator survives: the socket.** Socket inodes were distinct in every trial, including this one. This is the single most useful design output of the experiment:

> **Bind identity to the socket, not to the process.** A socket is created at a known instant, is 1:1 with a flow, is kernel-authoritative, cannot be forged by the workload, and survives the in-process multi-session case that defeats every process-level approach. `bpf_get_socket_cookie` gives exactly this handle at `cgroup/connect4` time.

This reframes G2 from "process → flow" to "session → socket → flow," and it makes the architecture strictly simpler.

## 7. E5 / E5b — Does one container per instance fix it?

Partly, and the boundary is precise. Per-instance cgroups were created and populated; `/proc/<pid>/cgroup` varied across all four instances. SPIRE's selector set still showed **1 distinct value**, because stock attestors only lift a container id out of cgroup paths matching known runtime patterns:

| cgroup shape | becomes a selector |
|---|---|
| bare host | no |
| operator-invented per-instance cgroup (`/agent-A`) | **no** |
| systemd scope per instance | **no** |
| docker container per instance | yes |
| k8s cri-containerd per instance | yes |

**Consequence:** one *real container* per agent instance does individuate, via `docker:container_id`. An arbitrary per-instance cgroup does not, without a custom attestor plugin.

So the honest scoping of G1 is three tiers:

| Deployment | Individuation |
|---|---|
| one container per agent instance | **solved today** — but forces container-per-instance on a runtime whose sessions are cheap and short-lived, and still says nothing about *which human* delegated |
| many processes, one container/host | **unsolved by stock SPIRE**; needs a custom attestor and still hits the registration-entry constraint |
| many sessions, one process | **unsolved by any current mechanism** |

Your research must state this tiering explicitly. A reviewer will otherwise say "just run one container per agent."

Also noted: a privileged writer moved a process into a peer's cgroup successfully. Cgroup membership is only as trustworthy as the privilege boundary around the cgroup tree.

## 8. E7 / E7b — PID stability

SPIRE's documentation warns that PIDs are not stable identifiers and that a delegate must guarantee PID stability across the call. Quantified:

| | |
|---|---|
| `kernel.pid_max` | 32,768 (default) |
| fork/exit rate achieved | 2,721 /s |
| first PID reuse observed | after 32,435 spawns |
| **elapsed time to first reuse** | **≈ 11.9 seconds** |

**The PID space recycles in about twelve seconds under sustained process churn on a default-configured host.** Any delegated attestation that passes a PID and attests it asynchronously has a TOCTOU window on that order. This is a concrete, citable number for the threat model, and it directly constrains any design built on SPIRE's Delegated Identity API PID mode.

## 9. E4 — Adversarial

An impostor process claiming a different principal was launched. It received **the same SVID**, and its attested selector set was **identical to the victim's**. There is no impersonation to defend against because there is no distinction to violate — every instance is the same security subject.

---

## 10. Threats to validity

These matter and should be closed before publication.

1. **Attestor logic is a reimplementation, not SPIRE itself.** Faithful to the documented selector sets, but must be confirmed against a real `spire-agent`. This is the single most important thing to redo in a proper lab.
2. **No eBPF.** No `clang` or `bpftool` in this environment, so the socket-cookie approach in §6 is argued from `/proc` evidence rather than demonstrated at the `cgroup/connect4` hook. Must be built.
3. **No real containers, no Cilium, no Envoy/agentgateway, no Kubernetes.** E5 used synthetic cgroups; the container-per-instance tier is inferred from the regex behaviour, not observed end to end.
4. **Loopback only.** No NAT, no proxy, no shared egress gateway, no multiplexed HTTP/2. The "network-side observer" had local `/proc` access, which a real enforcement point does not.
5. **`pid_max` is the default 32,768.** Hosts running many containers often raise it to 4,194,304, extending the reuse window by ~128×. Re-measure at the target configuration; report both.
6. **Single host, single kernel version.** Namespace and cgroup behaviour varies across distributions and kernel configs.

---

## 11. What this changes in the research plan

**Keep, strengthened:** G1. It is real, it is structural, and §4 gives it a crisp formal statement that no vendor product addresses. Lead with the empty-intersection result — it is the paper's central claim and it fits in one sentence.

**Restate:** G2. Not "process to flow" but "session to socket to flow." §6 shows the process is the wrong anchor. This is a better result than the one you set out to find.

**Add:** the in-process multi-session case (§6) is not in the v2 document and it is the strongest single argument for the whole research programme. Promote it from a footnote to the motivating example.

**Scope explicitly:** §7's three tiers. Concede the container-per-instance case up front rather than being told about it in review.

**Drop:** any framing that says SPIRE "cannot" individuate. It can, in one deployment tier. The claim is that no mechanism individuates in the tier that agent runtimes actually use.

### Immediate next steps

1. Reproduce E1/E2 against a real `spire-agent` + `spire-server`, container-per-instance and processes-in-one-container. **Highest priority — it either confirms or kills the central claim.**
2. Build the eBPF socket-cookie prototype at `cgroup/connect4` and `sock_ops`; demonstrate socket → session mapping for the E6 case. Measure overhead against the ~50–80 ns/packet TC baseline.
3. Re-run E7b at `pid_max = 4194304`.
4. Only then move to G3, using agentgateway as the enforcement point.

Do not begin protocol design until step 1 is done.
