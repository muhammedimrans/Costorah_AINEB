# Phase 4B — Validation Results on Envoy 1.31.0

**Date:** 26 August 2026
**Brief:** `Phase_4B_Validation_Tests_and_Verification.md`
**Environment:** Envoy 1.31.0 (`7b8baff…`, BoringSSL), Linux 6.18.44, real TLS, real HTTP/2 wire capture
**Artifacts:** `p4b/` — configs, harnesses, `results/phase4b_results.json`

---

## 1. Executive conclusion

**The hypothesis survives, and it is now structural rather than circumstantial.**

> Transport multiplexing, not pooling, determines the loss of network-layer principal attribution.

Confirmed — and Phase 4B closes the escape hatch I flagged at the end of Phase 4. HTTP/2 stream IDs **do** recover attribution, but only under conditions that never hold in production:

| condition | cleartext HTTP/2 | TLS HTTP/2 |
|---|---|---|
| observer parses the byte stream | 100% of bytes | **0%** |
| HEADERS frames extracted | 192 | **0** |
| distinct stream IDs recovered | 192 | **0** |
| attribution recoverable | yes, by order inference | **no** |

Under TLS the observer saw two connections, 192 successful requests, and could not parse a single frame. **The attribution loss is not a tooling artifact. An observer that cannot decrypt cannot attribute, and no amount of stream-ID cleverness changes that.**

Three concrete, reportable defects found along the way:

1. **`%UPSTREAM_STREAM_ID%` does not exist in Envoy 1.31.0.** Config validation rejects it: *"Not supported field in StreamInfo: UPSTREAM_STREAM_ID"*. So even in cleartext there is **no join key** between a wire-observed stream and Envoy's principal record.
2. **`envoy.string` filter state still does not partition the pool with a TLS transport socket present.** This closes the open question from Phase 4 — the mechanism is unusable with stock objects, TLS or not.
3. **Revocation via file-based RDS silently fails on in-place writes.** In-place copy: never propagated in 10 s. Atomic rename: **3 ms**. Same content, same file, same Envoy. This is a fail-open security defect in a plausible operator implementation.

And the scaling model from Phases 3/4 needed correcting: **HTTP/1.1 policy-class pooling is O(concurrency), not O(P).**

---

## 2. Research questions

| RQ | Verdict |
|---|---|
| **RQ1** stream IDs recover attribution | **Cleartext yes, TLS no.** And no join key exists either way (§3) |
| **RQ2** TLS changes pool behaviour | **No.** Still O(P). Filter-state path still broken (§4) |
| **RQ3** real Cilium/eBPF | **NOT TESTED** — no clang/bpftool in this environment |
| **RQ4** real WPT/SPIFFE identity | **NOT TESTED** |
| **RQ5** revocation under shared connection | **Tested — see §6.** Correct behaviour, but fail-open update hazard |
| **RQ6** hybrid pooling | **NOT TESTED** |
| **RQ7** attribution recovery from metadata | **Partially. Order inference works in cleartext (§3.3); nothing works under TLS** |
| **RQ8** novelty | **Narrowed further — see §8** |

Test matrix coverage: A, B, C, D, E tested. F, G, H, I **NOT TESTED** (require Cilium and real identity).

---

## 3. Test 1 — HTTP/2 stream-ID correlation

A TCP observer was placed on the upstream path between two Envoy instances, forwarding bytes while parsing HTTP/2 framing (RFC 9113 §4.1: 3-byte length, 1-byte type, 1-byte flags, 4-byte stream ID).

### 3.1 Test A — cleartext HTTP/2

```
observed connections : 2
conn 1: preface=True  parseable=1.0  HEADERS=96  distinct_stream_ids=96
conn 2: preface=True  parseable=1.0  HEADERS=96  distinct_stream_ids=96
```

192 stream IDs for 192 logged requests — exact one-to-one. Stream identifiers are fully available to a wire observer in cleartext.

### 3.2 The join-key problem

Having the stream ID is useless without a mapping to a principal. Envoy 1.31.0 **cannot log it**:

```
error initializing configuration: Not supported field in StreamInfo: UPSTREAM_STREAM_ID
```

What Envoy *does* expose was verified by running it: `%STREAM_ID%` (a downstream request UUID), `%CONNECTION_ID%`, `%UPSTREAM_CONNECTION_ID%` (integer), `%UPSTREAM_LOCAL_ADDRESS%`. All identify the *connection*, none the upstream *stream*.

### 3.3 Order-based inference — the only fallback

HTTP/2 allocates client-initiated stream IDs in strictly increasing order (RFC 9113 §5.1.1), so the k-th HEADERS frame should correspond to the k-th request Envoy initiated on that connection. For this to work, requests must be totally orderable by their logged start time.

```
logged requests            : 192
tied start timestamps      : 0
totally orderable fraction : 1.0
baseline (5-tuple + time)  : 0.0625 exact attribution
```

**Order inference is viable in cleartext** — it would lift attribution from 6.25% to effectively 100%. Three caveats, all disqualifying in practice:

- It requires the observer to **parse HTTP/2 framing**, which makes it an application-aware proxy — precisely what an L3/L4 enforcement point is defined not to be.
- It is **inference, not measurement.** I did not validate the order mapping against ground truth; it rests on the assumption that Envoy initiates upstream requests in logged-start-time order.
- It is a **post-hoc log join**, not a real-time enforcement input.

### 3.4 Test B — TLS HTTP/2

```
observed connections : 2
conn 1: preface_seen=False  opaque=True  parseable_fraction=0.0  HEADERS=0  stream_ids=0
conn 2: preface_seen=False  opaque=True  parseable_fraction=0.0  HEADERS=0  stream_ids=0
requests: 192 ok, 0 failed
```

**Zero bytes parseable.** Per the brief's own instruction — *do not claim stream IDs solve network attribution unless the enforcement point can obtain them* — they cannot. RQ1 is answered in the negative for every realistic deployment.

---

## 4. Test 2 — TLS validation

Real TLS between Envoy instances, RSA-2048, custom CA, SAN-validated, ALPN `h2`.

| property | cleartext | TLS |
|---|---|---|
| policy-class connections | 2 | **2** |
| requests succeeded | 192 | 192 |
| pool keyed by policy class | yes | yes |

**TLS does not change pool behaviour.** Connections remain O(P).

**Phase 4 open question, now closed.** I had flagged that the hashable filter-state path lives in transport-socket options, so a TLS cluster might behave differently. It does not: with a TLS upstream transport socket, `set_filter_state` with `envoy.string` and `shared_with_upstream: ONCE` gave **3 principals → 1 upstream connection**. The mechanism is unusable with stock objects regardless of transport.

---

## 5. Tests 10 & 11 — concurrency sweeps

8 principals, 2 policy classes, connection counts read from Envoy's own stats.

### HTTP/1.1 upstream

| concurrency | client threads | requests | connections | conns/thread | p50 | p99 |
|---|---|---|---|---|---|---|
| 1 | 8 | 64 | 8 | 1.000 | 3.8 ms | 13.9 ms |
| 4 | 32 | 256 | 20 | 0.625 | 11.4 ms | 26.4 ms |
| 8 | 64 | 512 | 21 | 0.328 | 20.6 ms | 44.4 ms |
| 16 | 128 | 1024 | 65 | 0.508 | 39.5 ms | 78.2 ms |
| 32 | 256 | 2048 | 126 | 0.492 | 85.4 ms | 233.1 ms |
| 64 | 512 | 4096 | **148** | 0.289 | 137.7 ms | 288.3 ms |

**HTTP/1.1 policy-class pooling is O(concurrency), not O(P).** Sub-linear (conns/thread falls from 1.0 to 0.29 as reuse kicks in) but unbounded in concurrency. This corrects the Phase 3 and Phase 4 scaling model, and it matters: the "112 connections" figure from Phase 4 was a concurrency artifact, not a property of pooling.

### HTTP/2 upstream

| concurrency | client threads | requests | new connections |
|---|---|---|---|
| 1 | 8 | 64 | 2 |
| 4 | 32 | 256 | 0 |
| 8 | 64 | 512 | 0 |
| 16 | 128 | 1024 | 0 |
| 32 | 256 | 2048 | 2 |
| 64 | 512 | 4096 | **2** |

**Flat at O(P), independent of both principal count and concurrency.** At 512 concurrent client threads issuing 4096 requests, Envoy opened zero new upstream connections — it multiplexed everything onto the existing two. Latency is comparable to HTTP/1.1 (p50 170 ms vs 138 ms at concurrency 64).

**The corrected trade-off:** at concurrency 64, HTTP/2 uses **74× fewer connections** than HTTP/1.1 (2 vs 148) and gives up essentially all network-layer attribution under TLS.

---

## 6. Test 5 — revocation under a shared policy-class connection

Alice and Bob share one upstream connection in `c_allow`. Alice is then revoked (route changed to `c_deny`) via file-based RDS.

| update method | propagation |
|---|---|
| in-place copy | **never propagated** (10 s, no error) |
| atomic rename | **0.003 s** |

Once propagated, behaviour was correct:

- Bob: `[200, 200, 200, 200, 200]` — unaffected
- Alice: diverted to `c_deny`, new connection created (`deny_cx_total=1`)
- Shared `c_allow` connection **not torn down** (`allow_cx_active=1`) — correct, since Bob still needs it

**The security finding is the update method, not the pooling.** Policy-class pooling handles revocation cleanly and fast. But an operator who implements revocation by writing the RDS file in place gets a system where revocation **never takes effect and emits no error** — a silent fail-open. Envoy's file watcher requires an atomic rename (the pattern Kubernetes ConfigMap symlink swaps and consul-template already use). Any deployment doing agent revocation this way should be audited.

---

## 7. What was not tested

State these plainly in any write-up. Matrix rows F, G, H, I are **NOT TESTED**.

1. **No Cilium/eBPF (RQ3).** No `clang` or `bpftool` available. L4 enforcement remains modelled by routing plus 5-tuple observation. This is the largest remaining gap.
2. **No real WPT/SPIFFE (RQ4).** Identity was a trusted header throughout. Unlikely to change pooling results — only the verified value matters — but unverified.
3. **No hybrid pooling (RQ6).**
4. **No HTTP/3 / QUIC (Test 12).** QUIC moves stream multiplexing inside the encryption envelope and adds connection-ID migration, so TCP results should not be assumed to carry over. Untested.
5. **No non-HTTP traffic (Test 13).** The entire architecture assumes an L7 gateway in path. **This is a scope limitation, not an oversight — document it as such.**
6. **Attack suite (Test 14) only partially covered.** Stale authorization was tested (§6). Pool-key collision, request migration on retry, and stream confusion were not.
7. **Order-inference not validated against ground truth** (§3.3).
8. Single host, loopback, 8 principals, RSA-2048.

---

## 8. Novelty assessment

Honest position: the *phenomenon* is not novel. That TLS blinds a network observer is textbook. That HTTP/2 multiplexes is definitional. A reviewer will say so.

What survives as contribution:

**Strong — the concrete defects.** Three specific, verifiable, unreported findings, each independently useful:
- `envoy.string` filter state is not `Hashable`, so Envoy's documented pool-partitioning mechanism has no usable stock object (confirmed cleartext and TLS)
- `%UPSTREAM_STREAM_ID%` does not exist, so there is no join key from wire observation to principal
- file-based RDS silently fails to propagate on in-place writes — a fail-open revocation hazard

File all three upstream. The maintainer responses are citable either way, and they cost nothing.

**Moderate — the quantified frontier.** The O(concurrency) vs O(P) measurement with matched attribution rates and latency, on real Envoy, is not published anywhere I found. It is a useful engineering result even if the direction is unsurprising.

**Weak — the boundary claim itself.** "Encryption prevents network-layer attribution" will not carry a paper.

**Decision: Outcome B — measurement contribution, scoped down.** Not a protocol. Not a systems-research programme. A short measurement paper or a well-evidenced engineering write-up, anchored on the three defects and the frontier data.

---

## 9. Recommended next steps

1. **File the three defects.** Cheapest possible action, highest certainty of value, and the responses sharpen or close the research question for free.
2. **Close RQ3 with real Cilium.** This is the last structural unknown. If Cilium can consume a per-connection verdict keyed on the post-partition 5-tuple, the enforcement story is complete and the remaining question is purely about attribution.
3. **Validate order inference against ground truth** by decoding HPACK in the observer and extracting the principal header directly. Confirms or kills §3.3, one day of work.
4. **Test HTTP/3.** QUIC changes the shape of the problem — connection IDs, migration, stream IDs inside the encryption envelope. Do not assume the TCP results transfer.
5. **Then** decide whether anything remains beyond the three defects.

Do not write protocol text. Four phases of falsification have produced three bug reports and a scaling curve. That is a real, if modest, outcome — and it is a considerably better use of the work than a specification nobody adopts.
