# Phase 4 — Real-World Validation on Envoy 1.31.0

**Date:** 26 August 2026
**Brief:** `Phase_4_Real_World_Validation_and_Testing.md`
**Environment:** Envoy 1.31.0 (`7b8baff…`, BoringSSL), Linux 6.18.44, real binary, real traffic
**Artifacts:** `p4/` — configs, harnesses, `results/phase4_results.json`

---

## 1. Executive conclusion

**Outcome C — systems research opportunity.** Two Phase 3 conclusions were wrong, and correcting them produced a sharper result than the one I set out to validate.

**Correction 1 — the mechanism I cited does not exist as configuration.** Phase 3 claimed "Envoy already ships the mechanism" for principal-based pool partitioning, citing hashable shared filter state. **It does not work.** Three separate configurations produced one shared upstream connection for three principals. Source inspection explains why: the pool key hashes filter-state objects only if they pass `dynamic_cast<const Hashable*>`, and `StringAccessorImpl` — the `envoy.string` factory that `set_filter_state` uses — does not implement `hash()`. Of the common stock filter-state objects, only the destination-address object is hashable. **Partitioning by principal via filter state requires a C++ extension, not configuration.**

**Correction 2 — the attribution loss is governed by upstream protocol, not by pooling.** This is the important one. Holding the pooling policy fixed and changing only the upstream protocol:

| upstream | connections | exact attribution | ambiguity | max principals concurrent per conn |
|---|---|---|---|---|
| HTTP/1.1 | 112 | **1.000** | 0.000 | 1 |
| HTTP/2 | **2** | **0.108** | 0.892 | 4 |

Same 8 principals, same policy classes, same concurrency 16. **HTTP/1.1 pooling loses nothing** — it never multiplexes, so requests serialise and time-windowed log correlation recovers the principal every time. HTTP/2 collapses 112 connections to 2 and destroys 89% of network-layer attributability.

Phase 3's claim that "policy-class pooling sacrifices attribution" is **false for HTTP/1.1 and true for HTTP/2**. The variable is the protocol.

**What held up:** the scaling result, confirmed on real Envoy — connections are O(P), independent of N.

---

## 2. Claims verdict

| Claim | Verdict | Evidence |
|---|---|---|
| **C1** identity-aware partitioning enables correct L4 enforcement | **Confirmed**, mechanism corrected | Positive control: 3 principals → 3 unambiguous connections |
| **C2** per-principal ≈ O(N) | **Confirmed** | N=32,P=32 → 32 conns; N=64,P=64 → 64 conns |
| **C3** policy-class ≈ O(P) | **Confirmed on real Envoy** | N=32,P=4 → 4; N=64,P=4 → 4. Independent of N |
| **C4** enforcement correctness preserved | **Confirmed** | Each cluster carries exactly one policy |
| **C5** attribution sacrificed | **Confirmed only under multiplexing** | 1.0 (H1) vs 0.108 (H2) |
| **C6** L7 logs recover attribution | **Split — see §5** | Audit completeness 1.0 both; network attributability differs 9× |
| **C7** hybrid useful | **Not tested** | Requires xDS; see §7 |
| **C8** not already characterised | **Holds for the protocol-dependence** | §6 |

---

## 3. §20 critical verification — what actually keys the pool

This was flagged in the brief as "a critical verification." It was, and it overturned the Phase 3 finding.

### Runtime evidence (4 configurations, real Envoy, 12 requests, 3 principals)

| configuration | upstream connections | partitioned |
|---|---|---|
| `set_filter_state` `object_key: envoy.string`, `shared_with_upstream: ONCE` | 1 | **no** |
| same, `shared_with_upstream: TRANSITIVE` | 1 | **no** |
| `object_key: envoy.network.upstream_server_name` | 1 | **no** |
| **positive control** — per-principal cluster routing | **3** | **yes** |

The positive control matters: it proves the measurement apparatus detects partitioning when it occurs. The negatives are real negatives.

### Source evidence (Envoy v1.31.0)

Pool key construction, `source/common/upstream/cluster_manager_impl.cc` ≈ L2006–2023, hashes: socket options, transport-socket options, and the downstream connection ID *only if* `connectionPoolPerDownstreamConnection()` is set.

Filter state enters only through the transport-socket path, `source/common/network/transport_socket_options_impl.cc` L47–53:

```cpp
for (const auto& object : options->downstreamSharedFilterStateObjects()) {
  if (auto hashable = dynamic_cast<const Hashable*>(object.data_.get()); hashable != nullptr) {
    if (auto hash = hashable->hash(); hash) {
      pushScalarToByteVector(hash.value(), key);
    }
  }
}
```

`StringAccessorImpl` (`source/common/router/string_accessor_impl.h`) implements `asString()`, `serializeAsProto()`, and `serializeAsString()` — **and nothing else.** No `hash()`, so the `dynamic_cast` fails and the object contributes zero bytes to the key. Audit of common stock objects:

| object | implements `hash()` |
|---|---|
| `string_accessor_impl.h` (`envoy.string`) | **no** |
| `filter_state_proxy_info.h` | no |
| `uint32_accessor_impl.h` | no |
| `bool_accessor_impl.h` | no |
| `filter_state_dst_address.h` | **yes** |

**The documentation is accurate but the ecosystem is empty.** The framework hashes hashable shared filter state; no stock object that can carry an identity string is hashable. This is a genuine, reportable gap in Envoy — and it is worth filing upstream.

### Config-only paths that do work

1. **One cluster per principal or policy class** (used throughout Phase 4). Works, but static config does not scale — dynamic principals need xDS, and cluster count grows with N or P.
2. **`connection_pool_per_downstream_connection`** — partitions by downstream connection. Useless here, because the premise is that principals share a downstream connection.

---

## 4. Scaling — C2 and C3 on real Envoy

HTTP/2 upstream, policy-class routing:

| N principals | P classes | upstream connections |
|---|---|---|
| 32 | 4 | **4** |
| 64 | 4 | **4** |
| 32 | 32 | 32 |
| 64 | 64 | 64 |

Connections track P exactly and are independent of N. Doubling principals at fixed P changed nothing. **C3 confirmed on real infrastructure**, not just the Python harness.

---

## 5. §13–14 attribution — the central result

Method: Envoy access log carries `START_TIME`, `DURATION`, `UPSTREAM_LOCAL_ADDRESS` (identifying the upstream connection), and the principal. A network event at time *T* on connection *C* is **exactly attributed** if precisely one logged request on *C* has `[start, start+duration]` containing *T*.

| metric | HTTP/1.1 upstream | HTTP/2 upstream |
|---|---|---|
| logged requests | 919 | 655 |
| upstream connections | 112 | 2 |
| **exact attribution rate** | **1.0000** | **0.1084** |
| ambiguity rate | 0.0000 | 0.8916 |
| max principals concurrent on one connection | 1 | 4 |
| **audit completeness** | **1.0** | **1.0** |

Two things follow, and they should be stated separately because conflating them is the error Phase 3 made:

> **L7 audit completeness is not network-layer attributability.** The access log contains the principal for 100% of requests under both protocols — per-request audit is never lost. What is lost under HTTP/2 is the ability to map an *observed network event* back to a principal. 89% of events had four candidate principals in flight simultaneously on the same connection.

And the sharper claim:

> **The enforcement/attribution trade-off is a property of the upstream protocol, not of the pooling policy.** HTTP/1.1 pooling gives exact attribution for free, because H1 binds one request per connection at a time. HTTP/2 buys a 56× connection reduction and pays 89% of attribution for it.

Note the H1 cost is not free in a different currency: 112 connections for 8 principals, driven by *concurrency*, not principal count. So the real frontier has three points, not two:

| architecture | connections | attribution |
|---|---|---|
| H1 + policy-class | O(concurrency) — 112 | exact |
| H2 + policy-class | O(P) — 2 | 11% exact |
| H2 + per-principal | O(N) — 32/64 | exact |

---

## 6. Prior art — where C8 stands

The individual pieces are all documented. Envoy documents pool partitioning by hashable shared filter state; Cilium documents endpoint-granularity identity; the connection-amplification cost of per-principal connections is folklore among mesh operators.

What I did not find characterised anywhere: **the protocol-dependence of the attribution loss, measured.** Nobody appears to have published that HTTP/1.1 upstream pooling preserves exact attribution while HTTP/2 destroys it, or quantified the 9× gap. That is the defensible contribution.

Also unclaimed and reportable: **`envoy.string` filter state is not `Hashable`**, so the documented pool-partitioning mechanism has no usable stock object. I could find no issue describing this. Filing it is worth doing regardless of the research outcome — and if maintainers respond "use a custom object," that response is itself citable evidence for the paper.

Evidence classification for the vendor matrix in §19 of your brief: everything I have on Microsoft, Palo Alto, Zscaler, Cisco, Fortinet, Check Point, Cloudflare, and Okta remains **Inferred**. I tested none of them. Do not upgrade those cells without hands-on work.

---

## 7. What I could not test here

Be explicit about these in any write-up.

1. **No Cilium/eBPF.** No `clang` or `bpftool` in this environment. L4 enforcement was modelled by per-cluster routing plus 5-tuple observation, not by a real eBPF datapath. **RQ3 remains open.**
2. **No revocation or churn testing (§15, §16).** Requires xDS for dynamic config change. The question "what happens when Alice goes ALLOW→DENY while sharing a connection with Bob" is unanswered and is a **security-relevant gap** — under cluster-based routing, new requests route to the new cluster, but in-flight requests and pool eviction behaviour are untested.
3. **No TLS.** All upstreams were cleartext. Transport-socket options are where the hashable path actually lives, so a TLS cluster may behave differently — worth one more test.
4. **No real WPT/SPIFFE.** Identity was a trusted header. **RQ2 remains open**, though it is unlikely to change the pooling results since only the verified value matters.
5. **Single host, loopback, small N.** Max 64 principals. The O(P) result is clean but untested at 10⁴.
6. **No hybrid architecture (C7).**

---

## 8. Recommendation

The research question is now well-posed and worth pursuing, but it is not the question you started with:

> **The enforceability/attributability frontier for multiplexed agent traffic: how upstream protocol choice determines what a network enforcement point can attribute, and how to recover attribution under HTTP/2 without surrendering connection reuse.**

That last clause is the open problem. Under HTTP/2 you get O(P) connections and 11% attribution. The question is whether a mechanism exists that gets both — for example, carrying a per-stream principal identifier that an eBPF observer can read without terminating TLS, or exploiting HTTP/2 stream IDs in access logs to disambiguate the 89%.

**Try the second one first — it may close the gap cheaply.** Envoy can log the stream ID. If a network observer can also see stream IDs (it cannot under TLS, but can in cleartext or at the proxy), correlation becomes exact. Establishing precisely where that fails is a one-day experiment and it sharpens the problem statement considerably.

### Next steps

1. **File the `envoy.string` non-hashable finding upstream.** Cheap, useful, and the response is citable.
2. **Retest the filter-state path with a TLS cluster.** One config change. Determines whether the mechanism is genuinely unusable or just unusable for cleartext.
3. **Add HTTP/2 stream IDs to the correlation.** May recover much of the 89%. Decides whether the problem is real.
4. **Then** stand up Cilium and close RQ3.
5. **Then** xDS and the revocation tests — the only remaining security-relevant unknown.

Do not write protocol text. Three phases of falsification and one round of real-world validation have not yet produced a gap that a protocol would fill.
