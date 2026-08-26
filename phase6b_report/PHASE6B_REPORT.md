# Phase 6B — Full-Scale Validation and Research-Gap Check

**Date:** 26 August 2026
**Environment:** Envoy 1.31.0 · Linux 6.18.44 (BTF) · clang 18.1.3 + libbpf 1.3 · OpenSSL 3.0.13 · **1× Xeon @ 2.10 GHz, single core**
**Artifacts:** `p6b/` — `ed25519_bench.c`, `policy_class.py`, `policy_enforce.bpf.c`, `test_policy_ebpf.py`, `control_plane.py`, `results_phase6b.json`

---

## 1. Executive conclusion

**Two Phase 6 claims were wrong, one attack got through, and the architecture survives with corrections.**

**Correction 1 — my native-crypto guidance was wrong.** Phase 6 said the Python figure (6,376 verify/s/core) was a floor and native would be 3–5× faster. I wrote a C benchmark against OpenSSL EVP: **8,726 raw verifies/s/core, 9,189 with SHA-256**. That is **1.44×**, not 3–5×. I then isolated where the time goes: reusing the EVP context instead of allocating per operation gained 5%, and context setup alone runs at 432,911/s. **98% of the time is the curve operation itself.** Language choice buys almost nothing; this is CPU-bound elliptic-curve work. Anyone who took my Phase 6 multiplier into a capacity plan would have under-provisioned by ~3×.

**Correction 2 — destination-only eBPF keying is insufficient, exactly as the brief suspected.** Phase 6 said "key the verdict map by destination, which makes it O(destinations)." That is wrong. A `(daddr, dport)` key holds one verdict, and the whole point is that Agent A and Agent B reach the *same* destination needing different answers. I rebuilt the datapath keyed on `(enforcement_identity, daddr, dport)` and demonstrated it on real kernel:

```
policy class A cgroup id = 21    agent in class A -> :19201  =>  ALLOWED
policy class B cgroup id = 36    agent in class B -> :19201  =>  BLOCKED errno 1
differentiated on one destination : True
```

**The attack that got through — RQ3.** Eleven of twelve token manipulations were blocked. The twelfth was not:

```
11_delegation_swapped            ALLOW     nc01   <-- REVIEW
```

I minted a token with `act.human = "attacker@corp.example"`, signed with the *legitimate agent's own key*. Signature valid, `sub` correct, tenant correct, audience correct, not expired, not replayed — **accepted**. The signature proves the agent's identity; it says nothing about who authorized the agent. See §5; this has an architectural fix and it changes the Phase 6 design.

**What held up, and decisively:** policy classes do not explode (§4), the control plane at 1M agents is a non-issue (§6), and the eBPF map reaches 10M entries with flat lookup (§7).

---

## 2. RQ2 — Real crypto capacity

| measurement | value |
|---|---|
| raw Ed25519 verify | **8,726 /s/core** |
| verify + SHA-256 (realistic JWT path) | **9,189 /s/core** |
| Ed25519 sign (issuance path) | 21,790 /s/core |
| verify p50 / p99 / p99.9 | 111.98 / 155.48 / 188.78 µs |
| signing input | 340 bytes (422-byte token) |

Where the time goes:

| variant | ops/s |
|---|---|
| fresh EVP context per operation | 8,648 |
| reused context | 9,106 (+5%) |
| context setup only, no curve op | 432,911 |
| **curve operation share of total time** | **98.0%** |

**Revised capacity model** (verify is the only cost that scales with load; the 2.1 GHz virtualized core here is slow — a 3 GHz bare-metal core with AVX2 paths should do better, so re-measure on target hardware):

| agents | req/agent/s | total req/s | cores @ 9,189/s |
|---|---|---|---|
| 1,000,000 | 0.01 | 10,000 | **2** |
| 1,000,000 | 0.1 | 100,000 | **11** |
| 1,000,000 | 1.0 | 1,000,000 | **109** |

Issuance is cheaper: at 60 s token TTL and 1M agents, ~16,700 signatures/s ≈ **1 core**.

---

## 3. RQ9 — What the eBPF map must actually be keyed by

**Resolved: `(enforcement_identity, daddr, dport)`.** Destination-only is provably insufficient.

Phase 5 established that at `cgroup/connect4` the kernel sees no L7 principal — `connect()` precedes every byte. So the enforcement identity must be something the kernel can read *and* the control plane can bind to a policy class. Carriers available at that hook:

| carrier | usable | notes |
|---|---|---|
| **cgroup id** | yes — demonstrated | one cgroup per policy class; `bpf_get_current_cgroup_id()` |
| **socket mark** | yes | gateway stamps `SO_MARK` before connect; needs `CAP_NET_ADMIN`, so not forgeable by an unprivileged workload |
| source address | yes | only if the gateway re-originates from a class-specific address |
| L7 principal | **no** | does not exist yet at connect time |

The map key grows from `O(destinations)` to `O(policy_classes × destinations)`. §4 shows why that stays bounded.

---

## 4. RQ4 — Does P explode? No, and here is the bound

This was the question that could have killed the architecture. It does not, but the reason matters and it forces a restatement of the safety condition.

Modelling all 14 policy dimensions the brief lists, **6 are network-enforceable** (destination set, ports, protocol, network zone, tenant, geography) and 8 are not (rate limit, data class, time window, risk, user/agent privilege, runtime/device posture).

| | theoretical max |
|---|---|
| P_policy (all 14 dimensions) | 2,239,488,000 |
| **P_network (6 enforceable dimensions)** | **86,400** |

Measured across agent populations:

| scenario | N=1K | N=10K | N=100K | **N=1M** |
|---|---|---|---|---|
| independent random (worst case) | 992 | 9,440 | 59,284 | **86,400** |
| structured templates (realistic) | 40 | 40 | 40 | **40** |
| structured + 5% network exceptions | 50 | 208 | 1,031 | **1,761** |

Network-exception sensitivity at N=100,000:

| exception rate | 0% | 1% | 5% | 10% | 25% | 50% | 100% |
|---|---|---|---|---|---|---|---|
| P_network | 40 | 327 | 1,027 | 1,348 | 1,687 | 1,772 | **1,788** |

**P_network is bounded above by the product of network-enforceable dimension cardinalities — a property of the policy schema, not of agent count.** Even adversarially (every dimension independent), it saturates at 86,400 and stops. Even at 100% exception rate it saturates at ~1,788. It never approaches N.

**The safety condition must be restated.** The brief says agents may share a class only when `EffectivePolicy(A) == EffectivePolicy(B)`. That is too strong and would give P_policy, not P_network. The correct condition:

> Agents may share a **connection** iff their **network-enforceable** policy is identical. Non-network dimensions — rate limit, data classification, time window, posture — are enforced **per request at L7** and do not require connection separation.

And the failure mode to guard against: **never let anything infer policy equivalence from connection membership.** Two agents on one connection are network-equivalent, not policy-equivalent. If an operator or a downstream system reads "same pool" as "same policy," the separation silently disappears.

Note the gap: at 1M agents, P_policy = 2,631 while P_network = 1,761. Keying pools on full policy equivalence would cost 1.5× more connections for zero enforcement benefit.

---

## 5. RQ3 — The delegation-swap finding

| attack | result | reason |
|---|---|---|
| valid baseline | ALLOW | nc01 |
| policy_class tampered | BLOCKED | bad_signature |
| risk downgraded | BLOCKED | bad_signature |
| key substitution | BLOCKED | bad_signature |
| alg confusion (HS256) | BLOCKED | bad_alg |
| alg none | BLOCKED | bad_alg |
| expired | BLOCKED | expired |
| replay | BLOCKED | replay |
| cross-agent (`sub` swapped) | BLOCKED | principal_mismatch |
| cross-tenant | BLOCKED | tenant_mismatch |
| audience confusion | BLOCKED | bad_audience |
| **delegation swapped (`act.human`)** | **ALLOW** | — |

Signing the policy class into the token is sound: tampering with `policy_class`, `network_class`, or `risk` breaks the signature every time. That part of the Phase 6 design is validated.

But **the delegation is not protected by the agent's own signature**, because the agent produced the signature. This is the Phase 5/6 model where the agent holds a key and mints its own WPT. Consequences:

- A compromised or malicious agent can attribute its actions to any human.
- The audit trail — the thing Phases 3–5 concluded was the *only* surviving attribution mechanism — becomes forgeable at the source.

Two fixes, and they are not equivalent:

| fix | delegation integrity | gateway state |
|---|---|---|
| **A. Gateway cross-checks `act.human` against the control plane** | yes | **breaks statelessness** — a control-plane lookup per request |
| **B. Identity service signs the token, agent never mints claims** | yes | **stays stateless** — gateway verifies one service key |

**Take B.** The agent authenticates to the identity service; the service issues a short-lived token with the delegation and policy class baked in, signed with the service key. The agent holds no claim-minting capability. The gateway verifies against a small set of service keys and needs zero per-agent state — preserving the property that made Phase 6's numbers work.

This is a direct correction to the Phase 5 and Phase 6 architecture, where agents held their own Ed25519 keys.

---

## 6. RQ1 — Control plane at 1,000,000 agents

Real store, full schema (human, agent, runtime, session, policy class, network class, risk, credential kid, status, timestamps), 1M rows.

| operation | result |
|---|---|
| registration | **188,981 /s** (1M in 5.3 s) |
| index build | 1.8 s |
| database size | 184 MB |
| point lookup | p50 **0.006 ms**, p99 0.03 ms, p99.9 0.042 ms |
| single update | p50 0.024 ms, p99 0.068 ms |
| bulk risk-class migration | 25,140 agents in 0.69 s (**36,446 /s**) |
| revocation insert | **443,001 /s** |
| revocation check | p50 0.003 ms, p99 0.007 ms |
| network-class rollup | 40 classes in 0.79 s |
| 8 concurrent readers | **145,005 lookups/s**, p99 0.018 ms |

This is **SQLite** — deliberately a floor, since production would use PostgreSQL. Even so the control plane is nowhere near being a bottleneck. Note the rollup found exactly **40 network classes**, matching the §4 structured-template prediction.

---

## 7. RQ10 — eBPF map to 10 million, and a memory trap

| entries | segment load | p50 | p99 | p99.9 |
|---|---|---|---|---|
| 1,000,000 | 2.68 s | 1.65 µs | 2.89 µs | 15.01 µs |
| 2,000,000 | 2.55 s | 1.62 µs | 2.54 µs | 14.21 µs |
| 5,000,000 | 7.82 s | 1.88 µs | 6.58 µs | 18.16 µs |
| **10,000,000** | 13.56 s | **1.73 µs** | 6.61 µs | 16.77 µs |

Lookup is flat across a 10× range. **Update churn: 331,715 updates/s single-threaded** — comfortably above the brief's 100,000/s target.

**The trap, which Phase 6 missed: BPF hash maps preallocate at load time.**

| map | memory committed at load | load time |
|---|---|---|
| 1M entries | **87 MB** | 0.29 s |
| 16M entries | **1,508 MB** | **6.19 s** |

That is committed **before a single verdict is written**. Sizing `max_entries` generously costs ~94 bytes/entry of RSS and seconds of gateway startup up front. Size to actual need (from §4, `P_network × destinations`, so thousands not millions), or use `BPF_F_NO_PREALLOC` and accept allocation latency on the hot path.

---

## 8. Research-gap verdict

**Outcome A/B — no research gap. This is engineering.**

Phase 6B asked whether any genuine research contribution remains after six phases. It does not. Every finding here is a bug, a misconfiguration, or a design constraint — valuable for building the product, not for a paper:

- native crypto is 1.44× Python, not 3–5× (a measurement error of mine)
- destination-only eBPF keying is insufficient (a design error of mine)
- delegation is unprotected under agent-held keys (an architecture error of mine)
- BPF maps preallocate (an operational gotcha)
- P_network is schema-bounded (a useful bound, but a straightforward counting argument once stated)

Combined with the earlier phases, the publishable residue remains what Phase 5 identified: **the catalogue of silent fail-opens**, now five items:

| # | failure | symptom | correct configuration |
|---|---|---|---|
| 1 | `envoy.string` filter state not `Hashable` | pool partitioning silently absent | custom C++ object |
| 2 | `%UPSTREAM_STREAM_ID%` unsupported | no wire-to-principal join key | — (file upstream) |
| 3 | RDS in-place write | revocation never propagates, no error | atomic rename (3 ms) |
| 4 | `ext_authz` without `clear_route_cache` | all agents to default class, HTTP 200 | `clear_route_cache: true` |
| 5 | **agent-held signing keys** | **delegation forgeable, audit trail unsound** | **identity-service-signed tokens** |

All five are silent, all five are security-relevant, and all five occur in plausible implementations. That is a solid practitioner paper or engineering write-up, and it is the honest ceiling of this programme.

---

## 9. What was not tested

1. **Single core only.** No multi-core or horizontal-scaling measurement; core counts in §2 are arithmetic, not measured.
2. **2.1 GHz virtualized CPU.** Crypto numbers are hardware-specific — the one figure that must be re-measured on target hardware.
3. **SQLite, not PostgreSQL.** A floor, not a production measurement. No replication, failover, or multi-writer contention.
4. **No 24-hour soak (RQ19), no rolling upgrade (RQ18), no multi-gateway consistency (RQ8).**
5. **Policy-class modelling is a simulation**, with assumed cardinalities and an assumed template structure. The *bound* is real arithmetic; the *typical values* (40, 1,761) depend on those assumptions. Validate against a real enterprise policy corpus.
6. **eBPF churn measured via syscall-per-update** from userspace; a batched `BPF_MAP_UPDATE_BATCH` path would be faster.
7. **Commercial products remain Inferred** across all seven phases. RQ22 was not executed.

---

## 10. Next steps

1. **Move to identity-service-signed tokens.** §5 is the highest-severity finding and it changes the credential architecture. Do this before anything else.
2. **Re-measure Ed25519 on target hardware.** It is the only number that sets fleet size, and mine came from a slow virtualized core.
3. **Rebuild the enforcement datapath on `(enforcement_identity, destination)`**, with cgroup-per-class as the carrier. Size `max_entries` from `P_network × destinations`, not optimistically.
4. **Validate P_network against real policy data.** The bound holds regardless; the operating point determines connection count.
5. **Make all five fail-opens integration tests** before any deployment.
6. Then soak, rolling upgrade, and multi-gateway consistency.
