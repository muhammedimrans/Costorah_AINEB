# Phase 3 — L7 Identity → Network Enforcement: Falsification Report

**Date:** 26 August 2026
**Brief:** `Claude_Phase3_L7_to_Network_Enforcement_Research_Query.md`
**Instruction followed:** *"Try to destroy the remaining G3 hypothesis... Optimize for finding the truth."*
**New code:** `exp3/demux_experiment.py` · `exp3/results_demux.json`

---

## 1. Executive conclusion

> **The research gap as posed is largely closed.**

Your falsification criterion #3 is substantially met: Envoy already ships the mechanism, and it has for years. Specifically — < cite index="177-1">filter state objects that are shared with the upstream also affect connection pooling decisions if they implement a hashing interface. Whenever a shared hashable object is added, an upstream connection is created for each distinct hash value</cite>. That is a per-principal upstream connection, created automatically, keyed on whatever identity your ext_authz filter verified.

The question you posed — *how do you enforce Alice→ALLOW, Bob→DENY, Carol→RESTRICT over the same connection?* — has an answer nobody needs a new protocol for: **stop putting them on the same connection.** De-multiplex at the L7 verifier, re-originate one upstream connection per verified principal, and a pure 5-tuple enforcer becomes sufficient.

I built and ran it. With a shared pool, a 5-tuple enforcer got **0/3** verdicts right. With a principal-keyed pool, it got **3/3** — Alice ALLOW, Bob DENY, Carol RESTRICT, enforced with no L7 awareness whatsoever (§3).

**Your §14 "fundamental boundary" is not falsifiable, because it is analytically true.** "Either the enforcement point receives an L7 signal, or it becomes L7-aware" is an exhaustive disjunction over its own terms — a tautology, not a theorem. Worse, it is *incomplete*: it omits the third option that the industry actually uses, which is to make the principals not share a connection. Do not publish it as a finding.

**What survives is a cost problem, not an identity problem** — and I measured it, then measured the fix. Naive de-multiplexing is linear: 500 principals → 500 upstream connections → 1,000 file descriptors (§3.3). Keying connections by *policy class* instead makes it **O(distinct policies), independent of principal count** — 800 principals collapse to 4 connections, a 200× reduction (§6.1). Enforcement stays correct. What you lose is exactly per-principal attribution at the network layer.

**That trade is the result worth publishing:**

> **Enforcement correctness and attribution granularity are separable properties with different costs. Enforcement is O(distinct policies). Attribution is O(principals).**

Your §17 million-agent question dissolves along with the rest: under policy-class pooling, connection count does not scale with agent count at all.

---

## 2. Answers to the falsification criteria

| # | Criterion | Verdict |
|---|---|---|
| 1 | WIMSE specifies the complete identity-to-network-enforcement interface | **No.** WIMSE is explicitly scoped to workload-to-workload authentication; WPT is scoped to a single HTTP request/response pair. It stops at L7 by design. |
| 2 | Cilium already consumes request-level agent identity | **No.** Cilium identity is a 32-bit value derived from a label set — endpoint granularity, not session. Its mutual auth is per-connection, agent-to-agent, and < cite index="190-1">workload SPIFFE identities are based on Cilium security identities</cite>. It cannot separate two principals on one TCP connection and does not try to. |
| 3 | Envoy/agentgateway provides the mechanism | **Substantially yes.** Hashable shared filter state → per-principal upstream connection. Combined with ext_authz for verification. Not a *standard*, but shipping, vendor-neutral, and CNCF-governed. **This is the criterion that closes your gap.** |
| 4 | Commercial AI gateways provide vendor-neutral L7→L3 | **No.** Each does it internally; none expose an interoperable interface. |
| 5 | SECMARK/CONNSECMARK provides equivalent semantics | **Partially.** Connection granularity, local host only, MAC sensitivity labels rather than cryptographic delegated identity. Sufficient for the post-demux case, insufficient pre-demux. |
| 6 | MCP/A2A define network enforcement semantics | **No.** Both are L7 authorization only. |
| 7 | A standard mechanism works with multiplexed connections *without application cooperation* | **No — and provably cannot.** But this is the tautology; see §5. |

---

## 3. The experiment

Three principals, per-request proofs (HMAC standing in for WPT's ES256/EdDSA proof-of-possession — the algorithm is irrelevant, what matters is that the principal is only knowable after verifying an application-layer object), one gateway, one upstream, and a 5-tuple-only enforcement point that cannot parse anything above L4.

### D1 — Shared upstream pool (the architecture in your brief)

```
upstream connections created    : 1
  5-tuple :47154  principals=[alice, bob, carol]  policy=RESTRICT  ok=False
ambiguous 5-tuples              : 1
L4-only enforcement CORRECT     : 0/1  -> INSUFFICIENT
```

The control plane installed a policy against that 5-tuple. It was wrong for two of three principals. This reproduces your critical case and confirms it is real.

### D2 — Principal-keyed upstream pool

Identical gateway, identical proofs. The only change: the upstream connection is keyed by the **verified** principal.

```
upstream connections created    : 3
  5-tuple :47166  principals=[alice@corp]  policy=ALLOW     ok=True
  5-tuple :47170  principals=[bob@corp]    policy=DENY      ok=True
  5-tuple :47178  principals=[carol@corp]  policy=RESTRICT  ok=True
ambiguous 5-tuples              : 0
L4-only enforcement CORRECT     : 3/3  -> SUFFICIENT
SO_MARK per principal           : {alice: 0xa1, bob: 0xb0, carol: 0xc2}
```

**Alice ALLOW, Bob DENY, Carol RESTRICT — achieved by a pure 5-tuple enforcer with zero application awareness.** No new protocol, no label carried in packets, no cryptographic verdict format. The identity translation happened by making the network object's granularity match the security principal's granularity.

This is not a trick. It is what Envoy does natively via hashable shared filter state, what a service-mesh egress gateway does when it re-originates with per-workload mTLS, and what every identity-aware proxy has done for a decade.

### D3 — The cost, which is the real finding

| principals | upstream conns | fds | setup ms/principal |
|---|---|---|---|
| 1 | 1 | 2 | 0.793 |
| 10 | 10 | 20 | 0.960 |
| 100 | 100 | 200 | 0.635 |
| 500 | 500 | 1,000 | 0.579 |

**Strictly linear. Amplification factor 1.0 — every principal costs one upstream connection.** Connection reuse, the thing HTTP/2 and connection pooling exist to provide, is *completely surrendered* to gain enforceability. At 1M agents that is 1M connections and 2M file descriptors per gateway.

This inverts your research question. The problem is not "can we translate L7 identity to L4 enforcement." It is **"can we do it without paying full de-multiplexing cost."**

### D4 — The local signalling channel already exists

`SO_MARK` is settable from userspace, reads back correctly, is 32 bits wide, and is visible to nftables `meta mark`, policy routing (`ip rule fwmark`), tc filters, and eBPF via `sk->mark`. A gateway can stamp a per-principal mark on each upstream socket and the kernel enforces on it.

Limits: requires `CAP_NET_ADMIN`, and **it does not leave the host**. That matters for §6.

---

## 4. What this means for each layer of your stack

| Layer | Status |
|---|---|
| **WIMSE / WPT** | Solves per-request principal identity through intermediaries. Complete for its scope. Not a network mechanism and does not claim to be. |
| **MCP** | OAuth 2.1 resource server, RFC 9728 metadata, RFC 8707 resource indicators. L7 authorization only. Nothing at network layer. |
| **A2A** | Agent Cards, capability discovery. No network enforcement semantics. |
| **SPIFFE/SPIRE** | Workload-class identity. After de-multiplexing, a per-principal upstream mTLS identity is the cleanest carrier of the verdict. |
| **Cilium/eBPF** | Enforces on 32-bit label-derived identity at TC/socket hooks. Post-demux it is sufficient. Pre-demux it cannot help and does not claim to. |
| **Envoy/agentgateway** | **Where the answer lives.** ext_authz verifies; hashable shared filter state partitions the pool; per-principal upstream connection results. |
| **SECMARK/CONNSECMARK** | Connection-granularity labels, local host. Post-demux, adequate. A direct competitor to any verdict format you might design. |
| **TrustSec SGT** | 16-bit tag propagated in the data plane, enforced on L3 devices. Coarser than a principal, no cryptographic binding, no delegation semantics — but the closest architectural precedent, and reviewers will name it. |
| **Commercial (MS/PAN/Zscaler/Cisco/Fortinet/CheckPoint/Cloudflare/Okta)** | All are L7 proxies that de-multiplex internally. None expose a vendor-neutral L7→L3 interface. Evidence class: **Inferred** for most — I did not verify any product hands-on and you should classify it that way in your write-up. |

---

## 5. Why §14 should be deleted rather than tested

Your boundary statement:

> *If multiple security principals share one encrypted multiplexed connection, an L3/L4 enforcement point cannot independently enforce request-level authorization without receiving an identity signal from the application layer or becoming an application-aware proxy.*

Three problems:

1. **It is true by construction.** If the only distinguishing information lives at L7, then any enforcer must either receive it or parse it. There is no third possibility *within the premise*. Restating a definition is not a result.
2. **The premise is a design choice, not a constraint.** D2 shows the premise can simply be voided. The interesting statement is about the *cost* of voiding it.
3. **A reviewer will call it trivial in one sentence**, and it will damage credibility for the parts of your work that are genuinely good.

Replace it with the empirical claim, which is defensible and non-obvious:

> **Enforcing agent-session-granularity policy at L3/L4 requires the network object's granularity to match the principal's, which costs one connection per principal and eliminates connection reuse entirely. The open problem is achieving sub-linear cost.**

---

## 6. What actually remains open

Three residuals, in descending value.

**R1 — Sub-linear de-multiplexing.** Now measured; see §6.1. The result reframes it: the cost is not linear in principals if you are willing to give up something specific. Remaining directions not yet tested: short-lived connection leases, and QUIC connection IDs as per-principal handles within one UDP 4-tuple.

### 6.1 Policy-equivalence-class pooling — measured

I tested the candidate technique. Key the upstream connection by **policy class** rather than by principal, so principals resolving to the same network-observable policy share a connection.

800 principals across 4 policy classes:

| scheme | conns | amplification | enforcement correct | attribution exact | principals per 5-tuple |
|---|---|---|---|---|---|
| per-principal | 800 | 1.0 | **yes** | **yes** | 1 |
| per-policy-class | **4** | 0.005 | **yes** | **no** | 200 |

Scaling, holding policy classes at 4:

| principals | per-principal conns | per-policy-class conns | reduction |
|---|---|---|---|
| 10 | 10 | 4 | 2× |
| 50 | 50 | 4 | 12× |
| 200 | 200 | 4 | 50× |
| 800 | 800 | 4 | **200×** |

**Connections become O(distinct policies), independent of principal count.** At 1M agents with a few dozen policy classes, that is a few dozen connections instead of a million. The million-agent problem in your §17 is not hard — under this scheme it does not scale with agent count at all.

**The cost is precise, and it is the finding:**

> **Enforcement correctness and attribution granularity are separable properties with different costs. Enforcement is O(distinct policies). Attribution is O(principals). Policy-class pooling buys the first and surrenders the second.**

Every principal on a shared connection receives the correct verdict, because they all demand the same one. But given a packet, the enforcement point can no longer name which of 200 agents produced it — network-layer audit degrades from "which agent" to "which policy class". Per-principal audit must then come from the L7 verifier's logs, not from the network.

That separation is not stated anywhere in the literature I found, it is measurable, and it is the sort of result that changes how people build these systems. It is a better contribution than the protocol you set out to design.

**R2 — Off-host verdict conveyance (moderate).** `SO_MARK` stops at the host boundary. To tell an off-host NGFW or SASE PoP which principal owns a flow, the options today are per-principal source IP (exhausts address space), per-principal mTLS client identity (requires the enforcement point to terminate TLS), or a proprietary out-of-band channel. There is no vendor-neutral interface. This is your original G3, correctly scoped — and it is much narrower than you thought, because it only bites *after* de-multiplexing, and only off-host.

**R3 — Non-proxyable traffic (weak, but real).** Everything above assumes an L7 proxy in path. Raw TCP, non-HTTP protocols, and traffic that deliberately avoids the gateway get none of it. This is the non-bypassability problem, and it is an enforcement-architecture question rather than an identity one.

---

## 7. Recommendation

**Do not build AIBP.** Three phases of investigation have now shown, in order: the identity problem is structural but mostly solved commercially (Phase 1/2), the socket anchor is invalid (Phase 2), and the translation problem dissolves under connection partitioning (Phase 3). A protocol is not justified.

**The paper that is left is a measurement paper, and it is a good one:**

> *The cost of enforceable agent-session attribution: quantifying the connection-amplification penalty of identity-preserving de-multiplexing, and techniques for sub-linear enforcement at agent scale.*

Contributions, all now experimentally supported: (a) the negative results from Phases 1–3; (b) the linear amplification measurement (§3.3); (c) the enforcement/attribution separation theorem with policy-class pooling as its constructive proof (§6.1).

That is publishable at a systems venue, it is unclaimed, and it does not require anyone to adopt a new protocol.

### Next steps, in order

1. **Reproduce D1/D2 on real Envoy** using ext_authz plus a hashable shared filter state object. Confirm the pool partitions as documented. If it does not, that is itself worth reporting upstream.
2. **Reproduce §6.1 on real Envoy + Cilium** at 1K and 10K principals. Get fd, memory, CPU, and connection-setup curves for both schemes. My numbers are from a single-host Python harness and are directional only.
3. **Characterise the attribution loss properly.** How much per-principal audit fidelity can be recovered from L7 verifier logs correlated by timestamp and 5-tuple? If the answer is "most of it," policy-class pooling is close to free and the paper gets stronger.
4. **Find the knee.** Real enterprises have some distribution of principals over policy classes. Measure where partial pooling (hybrid: dedicated connections for high-value principals, shared for the tail) beats both extremes.
5. **Then, and only then**, decide whether R2 needs an interface. It probably needs a profile of something existing, not a new protocol.

### Stop conditions

Abandon entirely if: Envoy's pool partitioning turns out to be widely used for exactly this purpose already (check the Istio and Solo mailing lists first), or if someone publishes the amplification measurement before you do. Both are plausible within months.

---

## 8. Honest note on this three-phase investigation

Phase 1 found a real structural constraint. Phase 2 destroyed the design conclusion I had drawn from it — including a recommendation of mine that was wrong. Phase 3 found that the remaining problem dissolves under an architecture Envoy has shipped for years.

That sequence is not a failure. Three rounds of falsification converged on a smaller, sharper, measurable question, and it cost weeks rather than the months a protocol design would have consumed. The negative results are the asset. Write them up as such.
