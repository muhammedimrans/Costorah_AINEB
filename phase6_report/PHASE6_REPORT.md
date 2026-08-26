# Phase 6 — Can This Actually Run at a Million Agents?

**Date:** 26 August 2026
**Question:** Can we build a corporate AI-agent security platform that safely manages millions of agents using existing protocols and enforcement mechanisms, without one network rule or connection per agent?
**Environment:** Envoy 1.31.0 · Linux 6.18.44 · real eBPF (clang 18 / libbpf 1.3) · real Ed25519
**Artifacts:** `p6/` — `route_scale.py`, `capacity.py`, `results_phase6.json`

---

## 1. Answer

**Yes — with one architectural constraint that the Phase 5 prototype got wrong.**

Every per-agent cost can be pushed into the control plane. The data plane can be made completely independent of agent count. But only if you **route on a signed policy-class claim, never on the agent principal**. Phase 5 routed on `x-verified-principal` with one exact-match route per agent. Measured, that design does not reach a million agents:

| | per-principal routing | policy-class routing |
|---|---|---|
| route entries at 1M | 1,000,001 | **3** |
| config size at 1M | ~163 MB | **1,635 B** |
| gateway startup at 1M | ~216 s | **0.25 s** |
| gateway RSS at 1M | ~3.9 GB | **~52 MB** |
| p50 request latency at 1M | ~41 ms | **~0.49 ms** |

The policy-class numbers are not extrapolations. They are **flat and measured identical at N = 1,000, 10,000, and 100,000** — 1,635 bytes of config, 0.25 s startup, ~52 MB RSS, ~0.49 ms p50 every time. Agent count does not appear in the data plane at all.

The per-principal numbers at 1M are extrapolated linearly from a measured 100,000-route gateway (16.3 MB config, 21.6 s startup, 392 MB RSS, 4.1 ms p50). Envoy's header-match route table is a linear scan, so p50 grew 7× from 1K to 100K routes. That extrapolation is the honest part of this report to distrust most — but the trend across three decades of N is unambiguous.

---

## 2. Measured scaling

### Route table (real Envoy, three decades of N)

| N | scheme | routes | config | startup | RSS | p50 | p99 |
|---|---|---|---|---|---|---|---|
| 1,000 | per-principal | 1,001 | 0.2 MB | 0.31 s | 70 MB | 0.589 ms | 1.174 ms |
| 1,000 | policy-class | 3 | 1.6 KB | 0.25 s | 51 MB | 0.483 ms | 0.877 ms |
| 10,000 | per-principal | 10,001 | 1.6 MB | 2.26 s | 115 MB | 0.975 ms | 2.753 ms |
| 10,000 | policy-class | 3 | 1.6 KB | 0.25 s | 51 MB | 0.478 ms | 1.000 ms |
| 100,000 | per-principal | 100,001 | 16.3 MB | 21.59 s | 392 MB | 4.105 ms | 9.296 ms |
| 100,000 | policy-class | 3 | 1.6 KB | 0.25 s | 52 MB | 0.492 ms | 0.779 ms |

Two things matter here beyond the headline. First, **21.6 s startup at 100K routes** means a 1M-agent gateway takes minutes to restart or accept a config push — that is an availability problem, not just a performance one. Second, per-principal RSS at 100K is 392 MB *for route matching alone*, before any connection or buffer memory.

### eBPF verdict map to one million entries

| entries | cumulative load | lookup p50 | lookup p99 |
|---|---|---|---|
| 1,000 | 0.00 s | 1.42 µs | 2.62 µs |
| 10,000 | 0.02 s | 1.43 µs | 2.42 µs |
| 100,000 | 0.24 s | 1.51 µs | 3.03 µs |
| **1,000,000** | **2.31 s** | **2.65 µs** | **9.01 µs** |

A million verdicts load in 2.31 s and lookup stays essentially flat — 1.9× growth across three orders of magnitude. Memory consumption was below the resolution of `MemAvailable` (a 1M-entry hash of 8-byte keys and 24-byte values is tens of MB).

**The kernel enforcement layer is not a bottleneck and does not need to be.** In practice the verdict map should be keyed by *destination*, not by agent, which makes it O(destinations) — smaller still.

### Identity verification (the real bottleneck)

| | |
|---|---|
| token size | 422 bytes |
| raw Ed25519 verify | 7,659 ops/s/core |
| full JWT verify (decode + claims) | **6,376 ops/s/core** |
| per-verify p50 / p99 | 138.9 µs / 178.8 µs |

**Caveat, and it is a large one:** this is Python (`PyJWT` + `cryptography`). Native Ed25519 verification runs 15,000–25,000 ops/s/core, so binding overhead dominates here. Treat 6,376 as a **floor**, and expect roughly 3–5× better from a Rust or C gateway. Do not put my number in a capacity plan without re-measuring on your actual gateway.

---

## 3. The capacity model

Using the measured floor, and noting that agent *count* never enters the data plane — only agent *request rate* does:

```
  gateway cores needed  =  (agents x requests_per_agent_per_second) / 6,376
```

| agents | req/agent/s | total req/s | cores (Python floor) | cores (native, ~4x) |
|---|---|---|---|---|
| 1,000,000 | 0.01 | 10,000 | 2 | ~1 |
| 1,000,000 | 0.1 | 100,000 | 16 | ~4 |
| 1,000,000 | 1.0 | 1,000,000 | 157 | ~40 |

A million mostly-idle agents is a small deployment. A million *busy* agents is a real one — and it is still bounded by ordinary horizontal scaling, because gateways are stateless under this design.

**Why gateways are stateless is the crux.** If the identity service signs the policy class *into the token*, the gateway needs zero per-agent records: it verifies a signature, reads a class claim, and matches one of P routes. Agent registration, delegation, risk scoring, and revocation all live in a control-plane database, which is a solved problem at 10⁶ rows.

```
CONTROL PLANE  (O(N) — a database)        DATA PLANE  (O(P) — flat)
  agent registry, 1M rows                   route table: P entries
  human -> agent -> session delegation      upstream pools: P connections
  risk scoring, revocation lists            eBPF verdict map: O(destinations)
  audit store                               gateway state per agent: ZERO
            |                                        ^
            +--- signs policy_class into token ------+
```

---

## 4. What breaks, and what to do about it

**Revocation is the one thing that genuinely resists this design.** A signed policy-class claim is valid until it expires. Two options, both real:

- Short token TTL (30–60 s) — revocation lands within one TTL, at the cost of re-minting. At 1M agents × 1 mint/min that is ~16,700 signatures/s across the identity service, which is a horizontal-scaling problem, not a design problem.
- A revocation list pushed to gateways — O(revoked), not O(N), and revoked agents are a tiny fraction. Phase 4B measured RDS propagation at **3 ms** with atomic rename.

Use both: short TTL as the floor, revocation list for immediate kills.

**The two silent fail-opens from Phases 4B and 5 are now capacity-critical, not just correctness bugs.** At a million agents, `clear_route_cache: true` being absent means every agent silently lands in the default policy class, and an in-place RDS write means revocation never propagates. Both return HTTP 200. Make them the first two integration tests.

**Policy-class collision is the security cost.** Agents sharing a class share a connection and are mutually indistinguishable at the network layer. That is the Phase 3–5 attribution result restated: per-request audit stays complete in gateway logs; network-layer attribution does not. High-risk agents get dedicated isolation (Phase 5 hybrid, measured working); everyone else pools.

**A note on YAML, since it cost me a debugging cycle:** `node: {id: n}` parses `n` as boolean `false` under YAML 1.1 and Envoy rejects the config with a confusing JSON error. Quote your identifiers in generated configs.

---

## 5. What was not tested

1. **Nothing was run at 10⁶ agents end-to-end.** Route scaling was measured to 100K and extrapolated; the eBPF map was measured at exactly 1M; crypto was measured per-core and extrapolated arithmetically.
2. **Crypto numbers are a Python floor**, not a gateway measurement (§2).
3. **Single host, loopback.** No multi-gateway, no real NAT, no failover, no geographic distribution.
4. **No control-plane implementation.** The O(N) database side is asserted to be tractable, not built.
5. **No sustained load or soak.** All latency figures are from short runs of a few hundred requests.
6. **Revocation at scale untested.** The 3 ms figure is from Phase 4B at trivial scale.
7. **Commercial products remain Inferred** across all six phases.

---

## 6. Bottom line

The platform is buildable on existing components, and the million-agent target is not the hard part — it mostly disappears once the design stops putting agent identity in the data plane. Ranked by what will actually bite:

1. **Identity verification CPU** — the only cost that scales with load. Horizontally scalable, and 3–5× cheaper than measured here in a native gateway.
2. **Revocation latency** — a design choice between TTL and push, both workable.
3. **Attribution loss inside policy classes** — a security trade-off to accept deliberately, with high-risk agents isolated.
4. **The two fail-opens** — configuration bugs that silently defeat the whole thing.
5. **Route table, connections, eBPF map** — all flat in agent count. Non-issues.

The single most important line of the design:

> **Sign the policy class into the token. Route on the class. Never put the agent principal in the route table.**

### Next steps

1. Re-measure Ed25519 throughput on the real gateway. It is the only number in this report that determines fleet size, and mine is a floor.
2. Build the control plane and test 10⁶ registrations, and revocation propagation with a realistic revoked-set size.
3. Make the two fail-opens integration tests before anything else ships.
4. Multi-gateway failover and a 24-hour soak.
