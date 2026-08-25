# Phase 2 — Falsification and Prior-Art Report

**Date:** 26 August 2026
**Brief:** `Claude_Phase2_AI_Agent_Binding_Research_Query.md`
**Instruction followed:** *"Do not simply validate our hypothesis. Try to destroy it."*
**New experimental code:** `exp2/falsify_socket_anchor.py` · `exp2/results_falsification.json`

---

## 1. Executive conclusion

I attacked the hypothesis on three fronts. Two of them broke it.

| Claim | Verdict |
|---|---|
| **G1** — co-resident identical agents cannot be individuated by stock SPIRE | **Survives**, but the novelty is largely gone (§4) |
| **"Socket is the correct security anchor"** (Phase 1's headline design output) | **FALSIFIED** (§3) — do not build on it |
| **G2** — bind instance to flow at the kernel | **Falsified as stated.** Reframed, it becomes an impossibility argument, which is more interesting (§3.6) |
| **G3** — verdict channel to enforcement points | **Survives**, but there is 20 years of prior art you have not cited (§5) |
| Phase 1's E2 "empty intersection" result | **Holds, and is the most defensible thing you have** (§2) |

**The single most important finding:** Phase 1's E6 result — four sessions, four sockets — was **an artifact of my own test harness**. I gave each thread its own socket. Real agent runtimes pool connections. When I redid it the way `httpx`, `aiohttp`, and every LLM SDK actually behave, four sessions with four different delegating humans shared **one socket**. The socket-as-anchor recommendation I gave you last round was wrong, and I should have tested it before recommending it.

**The second most important finding:** a company called **Riptides** is shipping a commercial product that does kernel-level SPIFFE issuance bound to the process at syscall level, kTLS credential injection, and per-connection kernel-enforced egress policy. Their own marketing describes <cite index="129-1">a composite identity binding the agent process and the delegating human, attested at the kernel</cite>. That is a substantial portion of G1+G2+G3, already productized.

**What survives is narrower and better:** not a protocol, but a **characterization of where network-layer enforcement of agent identity is possible and where it provably is not**, plus the minimal interface for the region where it is. See §8.

---

## 2. Verification of Phase 1

### What holds

**The empty-intersection result is sound.** A selector must simultaneously vary between instances, be unforgeable by the workload, and be knowable before the workload starts. The third constraint is confirmed by SPIRE's own documentation: <cite index="122-1">a selector is a native property of a node or workload that SPIRE can verify before issuing an identity</cite>, and entries are authored via `spire-server entry create` or the Entry API in advance. The second is confirmed by SPIRE's own reasoning — the project rejected an `environ` selector for the unix attestor because <cite index="112-1">`/proc/[pid]/environ` is mutable by the workload</cite>, and routed it to the docker attestor instead, where values are set by the daemon at container creation and are not mutable by the workload.

**Third-party confirmation of the gap.** Riptides independently describes the same constraint: <cite index="127-1">SPIRE requires that every workload be pre-registered with the SPIRE server — a registration entry mapping a SPIFFE ID to a set of selectors — before the workload can be attested and issued an SVID. For dynamic sub-agents that are created on the fly, this means either pre-registering every possible agent variant ahead of time or building an external automation pipeline that races to create registration entries as processes spawn</cite>. The word "races" is theirs, and it matches the ~12-second PID wraparound window measured in Phase 1 E7b.

### What does NOT hold, or needs qualification

**1. The registration-entry constraint is softer than I implied.** The Entry API supports runtime entry creation, and Kubernetes deployments already do this automatically — Istio's SPIRE integration notes that <cite index="125-1">new entries will be automatically registered for each new pod that matches the selector defined in a ClusterSPIFFEID custom resource</cite>. So "predictable in advance" is really "predictable by the *registrar*, in advance of the *attestation call*." A controller that creates an entry at spawn time, keyed on a selector its own custom attestor will emit, defeats the impossibility argument as I stated it. The argument survives only against **stock attestors**; against a custom attestor plus a spawn-time registrar, it does not. Phase 1 overstated this. Correct it.

**2. E6 was invalid.** See §3.

**3. E5 conflated two things.** Arbitrary cgroups produce no selector, which is true — but that is a statement about stock attestor *regexes*, not about cgroups being unusable. A custom attestor reading `/proc/<pid>/cgroup` and emitting the path as a selector is ~50 lines of Go.

### Stock vs. custom vs. architectural vs. new protocol

| Approach | Solves instance individuation? |
|---|---|
| **Stock SPIRE** | No, for co-resident identical processes. Yes, for one container per instance (`docker:container_id`). |
| **Custom SPIRE attestor plugin + spawn-time registrar** | **Yes**, for process-per-instance. This is the honest answer, and it is engineering, not research. |
| **Architectural workaround** (container or netns per instance) | Yes, at real operational cost. |
| **New mechanism** | Only required for the **in-process multi-session** case — and §3 shows that case cannot be solved at the network layer at all. |

---

## 3. Falsification of the socket-anchor hypothesis

Five tests. The hypothesis failed four of them.

### F1 — Connection pooling

Four sessions, four different delegating principals, through one pooled HTTP client:

```
sessions                        : 4
distinct principals             : 4
sockets used                    : 1
principals seen on that ONE sock: [alice, bob, carol, dave]
socket:session ratio            : 1:4
```

`socket_is_1to1_with_session = False`.

### F2 — Concurrent stream multiplexing

Four concurrent logical streams interleaved on one TCP socket, each carrying a different principal. All four principals observed on one socket cookie. `per_socket_verdict_sufficient = False`. This is HTTP/2 and HTTP/3 semantics — the normal case for MCP over Streamable HTTP and for every major LLM API.

### F5 — Pooled socket reused across principals

One keep-alive socket served `alice@corp`, then `bob@corp`. `socket_served_multiple_principals = True`. A verdict cached against that socket cookie authorizes the wrong principal on the second request.

### F3 — Socket cookie stability

The cookie itself is well-behaved and matches the kernel documentation — <cite index="130-1">once generated, the socket cookie remains stable for the life of the socket, providing a global socket identifier that can be assumed unique</cite>:

| property | result |
|---|---|
| distinct sockets → distinct cookies | true |
| cookie stable across 50 reads | true |
| cookie survives `dup()` | true |
| **forked child sees the same cookie** | **true** |

The last row matters: after `fork()`, two processes hold the same socket and therefore the same socket identity. Socket identity does not track process identity.

### F4 — SCM_RIGHTS handover

A live socket was passed to an unrelated process over a Unix socket:

```
cookie in original owner        : 5
cookie seen by receiving process: 5
cookie UNCHANGED after handover : True
receiver could write on socket  : True
```

Any process that can receive a file descriptor inherits the socket's identity intact. A socket cookie is a **capability**, not an identity — possession is authority, and possession is transferable.

### 3.6 — What this actually means

The failure is not an implementation detail. It is structural:

> **The security subject (an agent session, tied to one delegating human) is finer-grained than any kernel-observable network object (socket, flow, 5-tuple) whenever connections are pooled or multiplexed. No purely kernel-level mechanism can attribute traffic at session granularity, because at the moment the kernel sees the bytes, the session distinction has already been erased by the client library.**

This is a stronger and more publishable statement than "we need a new protocol." It says the G2 objective *as originally posed* is unachievable, and explains exactly why. Corollaries:

- Any correct design needs a **cooperating runtime** that declares the session→request mapping. There is no way around this.
- Once you accept a cooperating runtime, you are at the application layer — which is where WIMSE already operates.
- The remaining trust question becomes: **how do you make a runtime's session declaration trustworthy?** That is an attestation problem, not a networking problem.

**Recommendation: abandon "socket as security anchor." The correct primitive is the (authenticated request, attested runtime) pair, not the socket.**

---

## 4. The commercial falsifier: Riptides

Riptides (riptides.io, Riptides Labs) ships:

- SPIFFE-compliant X.509 issued **inside the kernel**, bound to the process initiating communication, injected into the TLS handshake via kTLS — the application never loads a certificate
- <cite index="128-1">Per-process identity binding tied to the specific process, identified at the syscall level — not to a pod, not to a node, not to a proxy</cite>
- Kernel-level policy evaluated at connection time: <cite index="128-1">when an agent process opens a socket to a destination, the kernel module checks the agent's identity against the configured policy before the connection is established</cite>
- Continuous posture re-attestation, and on-the-wire credential swapping so the agent never holds the real OAuth token
- Solution pages named "Agent Identity" and "Attribution"

**Impact on your claims:**

| Your gap | Riptides status |
|---|---|
| G1, process-per-instance | **Solved commercially** |
| G1, in-process multi-session | **Not solved** — theirs is explicitly per-process |
| G2, process→flow | **Solved commercially** (kernel, at connect time) |
| G3, verdict→enforcement | **Solved for their own enforcement point**, not as an interoperable standard |
| Human↔agent composite identity | **Claimed** in their agent-identity product |

You must cite them, obtain or trial the product, and verify these claims yourself. "We didn't know about it" is not survivable in review. Note also two US patents on **Identity-Based Internet Protocol networking** (US 9,948,675 and US 10,630,725) covering identity-bound network traffic with enforceable authorization — run a proper patent search before filing anything.

---

## 5. Prior art you have not cited: labeled networking

Your G3 — "get a verified identity verdict to a network enforcement point" — has roughly twenty years of prior art in Linux that appears nowhere in your documents.

| Mechanism | In-kernel since | What it does |
|---|---|---|
| **SECMARK / CONNSECMARK** | 2.6.18 (2006) | Netfilter targets that attach an LSM security label to packets and connections, so <cite index="142-1">SELinux enforces policy based on those labels</cite> |
| **NetLabel / CIPSO** | 2.6.19 | <cite index="144-1">A mechanism to put CIPSO information into outgoing packets and examine incoming packets for their tags, using LSM hooks, interfacing with SELinux to provide label information based on the SELinux context</cite> |
| **CALIPSO** | later | The IPv6 equivalent |
| **Labeled IPsec** | 2.6.x | Peer label transmitted by the peer itself inside the SA |
| **Cisco TrustSec SGT** | — | Numeric group tag propagated in the data plane and enforced on by L3 devices |

This is the same shape as your Binding Verdict: derive a label from local security context, carry it with the flow, enforce on it downstream.

**How you are still different — state this explicitly:**

1. These carry a **sensitivity label from a static MAC policy**, not a cryptographically verifiable identity with a delegating human and a lifetime.
2. CIPSO/CALIPSO are IP options — stripped or dropped by most middleboxes, useless across NAT, proxies, or the internet.
3. Labeled IPsec requires an IPsec SA end to end.
4. None of them survive TLS-terminating L7 proxies, which is the environment agents actually run in.
5. None address session-granularity within a process.

That is a real differentiation, but you have to make it in writing, because a reviewer from the SELinux community will raise it in the first five minutes.

---

## 6. What WIMSE already solves

The WIMSE charter is broader than your documents assume. It covers <cite index="164-1">the unique identity and access management aspects of workloads at runtime and their execution context, particularly focusing on the propagation, representation, and processing of workload identities</cite>. The architecture draft has sections on security context establishment and propagation, delegation and impersonation, and AI/ML-based intermediaries.

Critically, for the session problem: WIMSE's WIT+WPT is scoped to **a single HTTP request-and-response pair**, and Transaction Tokens exist precisely so that <cite index="167-1">the security context associated with the authorization can be passed along the call chain</cite>. Together these give you **per-request, per-transaction identity that is independent of which socket carried the bytes**.

**So the in-process multi-session problem is already solved — at layer 7.** Four sessions on one pooled socket each carry their own WPT. Your F1/F2/F5 scenario is exactly what WPT was designed for.

What remains unsolved is making that L7 fact **actionable at an L3/L4 enforcement point** — which is G3, and only G3.

---

## 7. Threat model — what the architecture can and cannot assume

| Attacker | Consequence |
|---|---|
| **Unprivileged, separate process** | Cannot forge PID/uid/exe. **But** F4 shows that if it can receive an FD over `SCM_RIGHTS`, it inherits socket identity completely. Any design binding authority to a socket must treat FD passing as a privilege transfer. |
| **Code execution inside the agent process** | Game over for session separation. All sessions share an address space; session keys are readable. This is the prompt-injection case, and it is the one that matters most for agents. **No kernel mechanism helps here.** |
| **Container escape** | Cgroup membership becomes untrustworthy. Phase 1 E5 showed a privileged writer moving a process into a peer's cgroup successfully. |
| **Host root** | Can write eBPF maps, load programs, read kernel memory. Kernel-resident identity assumes root is not hostile. |
| **Kernel compromise** | Everything fails. Out of scope; say so. |

**State this plainly:** the architecture's security boundary is *the process address space*. It provides no separation between sessions co-resident in one process against an attacker with code execution in that process. Since the primary agent threat is prompt injection leading to rogue tool calls **within** the agent process, this is a serious scope limitation and reviewers will find it. Address it head-on rather than hoping it goes unnoticed.

---

## 8. Recommended research boundary

Of your five options in §15, **none is right as written.**

- Option 1 "AI agent instance identity" — Riptides ships this.
- Option 2 "AI agent session identity" — WIMSE WPT + Transaction Tokens cover it at L7.
- Option 3 "Runtime-to-socket identity binding" — **falsified in §3.** Do not use.
- Option 5 "Agent Network Binding Protocol" — premature; §3 shows a protocol may not be the answer.

**Option 4 is closest, but sharpen it to:**

> **The session-granularity attribution boundary: characterizing where network-layer enforcement of AI-agent identity is achievable, proving where it is not, and specifying the minimal interface by which an application-layer verifier conveys an enforceable, cryptographically-grounded session verdict to a network enforcement point that cannot itself parse layer-7 proofs.**

Three contributions, in descending confidence:

1. **A negative result.** Session-granularity attribution is unachievable below L7 under connection reuse (§3.6), plus the selector-admissibility constraint (§2). Both are empirically demonstrated. Negative results with clean experiments are publishable and hard to scoop.
2. **The verdict interface.** Differentiated from SECMARK/CIPSO/SGT by §5's five points. This is the standardizable piece.
3. **A taxonomy** of deployment tiers (container-per-instance / process-per-instance / session-in-process) with what is achievable in each.

**Drop the protocol ambition until (1) and (2) are done.** On the name: `AIBP` appears unused in networking and security — the nearest collisions are SIP's Authenticated Identity Body (AIB) and unrelated ticker symbols. It is available, but do not commit to it yet; if the contribution is a negative result plus an interface, "protocol" is the wrong word.

---

## 9. What would kill this entirely

Watch for these. Any one is fatal:

1. **Riptides (or Cisco/Palo Alto/Zscaler) ships session-granularity attribution.** Currently they are per-process. If that changes, contribution 1 and 3 die.
2. **WIMSE adopts a session/execution-context token with a network-enforcement binding.** The WG charter covers execution context explicitly. Monitor the mailing list weekly.
3. **A real SPIRE deployment with a custom attestor plus spawn-time registrar individuates process-per-instance cleanly** — which I expect it will. That removes the process tier from your gap entirely, leaving only the in-process tier.
4. **Someone shows the in-process tier is adequately solved by WPT.** §6 suggests it largely is, at L7. If enforcement points start consuming WPT directly, G3 closes.
5. **An SELinux-community reviewer demonstrates SECMARK+CONNSECMARK with a custom LSM achieves the verdict channel.** Test this yourself before someone tests it for you.

---

## 10. Recommended next experiments

In priority order. Do not write protocol text until 1–3 are done.

1. **Real SPIRE, not my reimplementation.** Deploy `spire-server` + `spire-agent`. Reproduce E1/E2 in three tiers. Then *attempt to defeat your own gap*: write a custom attestor emitting a per-instance selector plus a spawn-time registrar, and see how cleanly it works. **If it works well, the process tier is gone and you should say so.**
2. **Trial Riptides.** Determine empirically whether it separates two sessions inside one process. This single test decides how much of your gap remains.
3. **WPT end-to-end through a pooled connection.** Four sessions, one socket, four WPTs, verified at agentgateway. Confirm §6 — that L7 already solves it. Then measure what an L3/L4 enforcement point can and cannot do with that verified result. **This is where your actual contribution begins.**
4. **eBPF verdict channel prototype.** `cgroup/connect4` + `sock_ops`, writing verdicts into a BPF map, consumed by Cilium. Measure against the ~50–80 ns/packet TC baseline. Compare directly to SECMARK.
5. **SECMARK/CONNSECMARK baseline.** Build the labeled-networking version of your verdict channel and document precisely what it cannot do. This becomes your related-work section.
6. **SCM_RIGHTS / FD-passing threat test** against whatever binding you design.

---

## 11. Bottom line

You asked me to try to destroy it. I destroyed the socket-anchor design, substantially eroded G1 on commercial grounds, and found that G2 as posed is unachievable in principle.

What is left is real but different from what you set out to build: **a negative result with clean experimental support, a taxonomy, and a narrow interface specification.** That is a legitimate systems-security paper. It is not a new protocol, and it is not a product.

The most valuable thing in this entire program remains Phase 1's E2 result, now supplemented by §3.6. Two clean impossibility-shaped findings, both demonstrated on real kernels, is a better paper than a protocol nobody adopts.

Before anything else: run experiment 2. If Riptides separates in-process sessions, most of what remains disappears, and you should know that within a week rather than after six months of protocol design.
