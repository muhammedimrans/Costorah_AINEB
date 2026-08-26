# Phase 5 — Final Technical Validation

**Date:** 26 August 2026
**Brief:** `Phase_5_Final_Technical_Validation_AI_Agent_Corporate_Network.md`
**Environment:** Envoy 1.31.0 · Linux 6.18.44 with BTF · clang 18.1.3 + libbpf 1.3, **real BPF programs loaded into the kernel** · real Ed25519/EdDSA identity · real HTTP/3 over QUIC v1
**Artifacts:** `p5/` — BPF source, loader, QUIC observer, ext_authz service, configs, `results/phase5_results.json`

---

## 1. Executive conclusion

All three Phase 4B gaps are now closed with real infrastructure. The decision-tree answer is:

> **Existing systems solve the enforcement problem. They do not solve the attribution problem, and Phase 5 shows the attribution problem is unsolvable below L7 rather than merely unsolved. Research closed as a protocol effort; a narrow engineering contribution remains.**

Four findings, in order of value.

**1. The single most useful result is a silent fail-open in identity-based routing.** Envoy's `ext_authz` injects the verified principal as a request header — but route selection has already happened by then. Without `clear_route_cache: true`, every request falls through to the **default route**. Measured A/B, same load, same configs otherwise:

| configuration | correctly routed | clusters actually used |
|---|---|---|
| `ext_authz` without `clear_route_cache` | **0/2** | `c_allow` only |
| `ext_authz` with `clear_route_cache: true` | **2/2** | all four |

In the failing case, high-risk `agent0@corp` — configured for dedicated isolation — was pooled into the shared `c_allow` class, and **the request returned 200**. No error, no warning. Any corporate tool built on ext_authz identity routing without this flag silently assigns every agent to the default policy class.

**2. Real eBPF enforcement works, and proves the limit is structural.** I compiled and loaded a real `cgroup/connect4` program with a userspace-written verdict map. It correctly enforced Alice=ALLOW (connect succeeded) and Bob=DENY (connect refused, EPERM) at the kernel, before any bytes left the host. But at that hook the kernel offers destination IP, destination port, protocol, socket cookie, PID, UID, and cgroup ID — **and nothing else, because `connect()` happens before any request is written.** No L7 principal, no headers, no SNI, no stream ID. The verdict map key is `(daddr, dport)`, which is strictly coarser than the security principal whenever principals share a connection.

**3. QUIC makes attribution worse, not better.** Real HTTP/3, 192 requests, 2 upstream QUIC connections. A UDP observer on the path parsed headers on 1,024 packets:

| | |
|---|---|
| short-header (1-RTT) packets | **98.93%** |
| packets with parseable connection ID | **1.07%** |
| DCID length encoded on the wire (short header) | **no** |
| stream IDs extractable | **no** |
| frame types extractable | **no** |

Under TLS-over-TCP an observer at least gets reliable connection boundaries from the TCP header. Under QUIC it gets ~1% of packets — the handshake — and after that cannot even determine where the connection ID ends, because its length is negotiated during the handshake and never re-transmitted.

**4. Real cryptographic identity changes nothing architecturally.** Swapping the trusted header for real Ed25519 WPT-shaped tokens left pooling, connection counts, and attribution identical. It did exactly what it should at the security layer — all seven attacks blocked — but the routing and network behaviour downstream were unchanged, because the route matches on a verified *string*.

---

## 2. Research questions

| RQ | Verdict |
|---|---|
| **RQ1** Cilium/eBPF makes the attribution problem irrelevant? | **No.** Real eBPF enforces correctly per 5-tuple and cannot see L7 principals at all (§3) |
| **RQ2** Real identity changes the architecture? | **No architectural change.** Security posture improves; network behaviour identical (§4) |
| **RQ3** Does the result generalise to QUIC? | **Yes, and worse** — 1.07% observability vs TCP's connection boundaries (§5) |
| **RQ4** Hybrid enforcement viable? | **Yes** — 8 principals → 4 clusters (2 isolated + 2 pooled), but only with `clear_route_cache` (§6) |
| **RQ5** Meaningful remaining gap? | **Narrow. Engineering, not research.** (§8) |

---

## 3. RQ1 — real eBPF enforcement

Not a simulation. `enforce.bpf.c` compiled with clang 18 for the BPF target, loaded via libbpf, attached to a cgroup v2 with `bpf_program__attach_cgroup`.

### Verdict channel (E1–E2)

Userspace wrote verdicts into a `BPF_MAP_TYPE_HASH` keyed by `(daddr, dport)`; the datapath enforced at `cgroup/connect4`:

```
alice (verdict=ALLOW, port 19101) -> OK
bob   (verdict=DENY,  port 19102) -> BLOCKED errno 1 (EPERM)
enforcement correct               : True
```

**The Phase 3 "G3 verdict channel" is an engineering problem, and a small one.** ~120 lines of BPF C plus a map. It works, at the kernel, pre-connection.

### The structural limit (E3–E4)

With one shared upstream connection carrying three principals, the map key `(daddr, dport)` admits exactly **one** verdict. Fields available at the hook:

| available | not available |
|---|---|
| `user_ip4`, `user_port`, `protocol` | L7 principal — no request written yet |
| `bpf_get_socket_cookie` | HTTP headers — `connect()` precedes all bytes |
| `bpf_get_current_pid_tgid`, `uid_gid` | TLS SNI — handshake not started |
| `bpf_get_current_cgroup_id` | HTTP/2 stream ID — stream does not exist |

This is not a Cilium limitation to be engineered around. It is what a connect-time hook can observe, and it confirms — with a real datapath rather than an argument — that per-principal enforcement below L7 requires the network object's granularity to match the principal's.

### Overhead (E5)

Connect-time hook overhead was **below the measurement noise floor** (p50 10.7 µs hooked vs 17.2 µs bare — a negative delta, i.e. noise dominated at n=300). The honest statement is that a map lookup plus a ring-buffer write is not measurable against `connect()` syscall variance. It is not a performance concern. Note this is per *connect*, not per packet.

---

## 4. RQ2 — real agent identity

Replaced the trusted header with an `ext_authz` service verifying real EdDSA JWTs carrying the full chain:

```
human (act.human) -> agent (iss = spiffe://corp.example/agent/N)
  -> session (sid) -> credential (this token: htm/htu bound, 30s TTL, jti replay window)
```

The gateway verifies signature, audience, expiry, replay, request binding, and delegation consistency, then emits `x-verified-principal`. Client-supplied `x-agent-principal` is discarded.

### Attack results (Test 7 / Test 15)

| attack | result | reason |
|---|---|---|
| header only, no token | **BLOCKED** | `missing_token` |
| tampered signature | **BLOCKED** | `bad_signature` |
| expired token | **BLOCKED** | `expired` |
| replayed `jti` | **BLOCKED** | `replay` |
| request-binding mismatch (different path) | **BLOCKED** | `request_binding_mismatch` |
| cross-principal claim (`sub` swapped) | **BLOCKED** | `principal_mismatch` |
| algorithm confusion (HS256) | **BLOCKED** | `bad_alg` |

7/7 blocked; 147 legitimate requests allowed. **Where identity is established is now precise:** at the gateway, per request, before routing — and nowhere below it. The network layer receives a verified string and a route decision, never the credential.

**Architectural conclusion: real crypto is necessary and sufficient at L7, and irrelevant below it.** It does not move the attribution boundary by one layer.

---

## 5. RQ3 — HTTP/3 / QUIC

Real QUIC v1 (`00000001`), Envoy-to-Envoy, TLS via `QuicUpstreamTransport`/`QuicDownstreamTransport`, ALPN `h3`. 192 requests, 0 failures, **2 upstream QUIC connections for 2 policy classes** — the same O(P) pooling as HTTP/2.

The UDP observer parsed 1,024 packets:

- **11 long-header packets (1.07%)** — the handshake. DCIDs and SCIDs parseable here: 2 distinct DCIDs, 3 distinct SCIDs.
- **1,013 short-header packets (98.93%)** — all application data. The DCID length is **not on the wire**; it is negotiated during the handshake. An observer that did not witness and track the handshake cannot determine where the connection ID ends, let alone read anything after it.
- Stream IDs and frame types: **encrypted, not extractable.**

**Three consequences for a corporate tool:**

1. **QUIC is strictly worse than TLS-over-TCP for network attribution.** TCP at least gives an observer reliable connection framing from an unencrypted header. QUIC gives ~1%.
2. **Connection identity is decoupled from the 5-tuple by design.** QUIC identifies connections by connection ID precisely so they can survive address changes. Any verdict map keyed on a 5-tuple — including the eBPF one in §3 and Cilium's — is keyed on something QUIC explicitly permits to change mid-connection. I did not force a migration end-to-end (**NOT TESTED**), but the design intent is unambiguous and the DCID/SCID asymmetry observed (2 vs 3) is consistent with connection-ID rotation.
3. **Do not assume the TCP results transfer** — they transfer in the pooling dimension and get worse in the observability dimension.

One correction worth recording: I initially read the `192.0.2.2` source addresses as an Envoy placeholder. Checking `/proc/net/fib_trie` showed `192.0.2.0/24` is a real interface subnet on this host. Envoy reported correctly; the hunch was wrong.

---

## 6. RQ4 — hybrid enforcement, and the fail-open

Configuration: `agent0`/`agent1` (high risk) → dedicated clusters; `agent2`–`agent7` → two policy classes. 8 principals → **4 upstream clusters**.

| variant | correctly routed | connections by cluster |
|---|---|---|
| no `clear_route_cache` | **0/2** | `c_allow:1, c_restrict:0, iso_agent0:0, iso_agent1:0` |
| `clear_route_cache: true` | **2/2** | `c_allow:1, c_restrict:1, iso_agent0:1, iso_agent1:1` |

**Hybrid works — conditionally.** The mechanism is sound and the cost model is attractive: isolation only for the principals that need it, pooling for the rest.

But the failure mode deserves emphasis. Envoy selects a route before the `ext_authz` filter runs, so headers the authorizer injects are invisible to route matching unless the route cache is explicitly cleared. The result is not an error — it is a **200 response on the wrong policy class**. Every agent, including the ones specifically marked high-risk, silently lands in the default pool.

This joins the Phase 4B RDS finding as the second silent fail-open discovered in this stack:

| finding | failure | correct configuration |
|---|---|---|
| Phase 4B — RDS revocation | in-place file write never propagates, no error | atomic rename (3 ms) |
| Phase 5 — ext_authz routing | all traffic to default route, HTTP 200 | `clear_route_cache: true` |

Both are silent, both are security-relevant, and both are plausible implementations. **This pair is the most defensible output of the whole programme.**

---

## 7. What was not tested

State these plainly.

1. **Cilium itself was not run.** I built and loaded an equivalent eBPF datapath directly. This is stronger evidence about what the *hook* can see and weaker evidence about Cilium's product behaviour. Cilium's identity is label-derived and endpoint-granular; that claim remains **documented, not demonstrated**.
2. **QUIC connection migration was not forced end-to-end.** The structural argument stands; the empirical demonstration does not exist.
3. **No SPIRE server/agent binaries.** Identity was real Ed25519 with SPIFFE-shaped IDs, not SPIRE-issued SVIDs.
4. **Single host, loopback, 8 principals.** No real NAT, no multi-host, no scale test in Phase 5.
5. **Access-log flushing limited logged request counts** in the A/B (2 rows each). The connection-count evidence across four clusters is the primary evidence and is unambiguous; the log rows corroborate.
6. **Commercial products** (Palo Alto, Zscaler, Cisco, Fortinet, Check Point, Cloudflare, Okta, Microsoft) remain **Inferred**. None were tested in any phase.

---

## 8. RQ5 — the remaining gap, and the recommendation

**Close the protocol effort.** Across five phases: the identity problem is structural but commercially addressed (Riptides), the socket anchor was invalid, the translation problem dissolves under connection partitioning, Envoy's documented partitioning mechanism does not work with stock objects, and now — with a real kernel datapath — the enforcement half is a 120-line BPF program while the attribution half is bounded by what `connect()` can observe. **No missing interoperable interface has appeared in five phases of looking.**

What remains, honestly graded:

**Worth publishing (small).** Two silent fail-opens with reproductions, plus the three Phase 4B defects. A short paper or a well-evidenced engineering write-up: *"Silent fail-open modes in identity-based network policy for AI agents."* Practitioner-relevant, reproducible, unclaimed.

**Worth building (a product, not a paper).** The hybrid architecture in §6 is a real corporate tool: verified per-request identity at an L7 gateway, risk-tiered pooling, eBPF verdict enforcement at connect time, per-request audit from gateway logs. Every component exists; the value is in assembling it correctly and not tripping the fail-opens. That is engineering, and it is legitimate — it is just not research.

**Not worth pursuing.** A new protocol. The interface that would need standardising — "L7 verifier tells L3/L4 enforcement point about a flow" — is a BPF map write when co-located and an unsolvable problem when the principals share an encrypted multiplexed connection. Neither case needs a spec.

### Next steps

1. **File all five defects** (three from Phase 4B, two fail-opens). Cheapest action, highest certainty of value. Maintainer responses are citable.
2. **Write the fail-open paper.** It is done except for prose; every result is reproducible from `p4b/` and `p5/`.
3. **If the corporate tool is the goal**, start from §6's architecture, and make the two fail-opens the first two integration tests in the suite.
4. **Do not** run more phases hoping a protocol gap appears. Five rounds of falsification is a sufficient answer.

---

## 9. Note on the programme

Phase 1 found a real structural constraint. Phase 2 destroyed a design conclusion I had drawn from it, including a recommendation of mine that was wrong. Phase 3 found the problem dissolves under an architecture Envoy already shipped. Phase 4 found the specific mechanism I had cited for that does not actually work. Phase 4B and Phase 5 found four silent failure modes nobody documented.

The programme did not find a protocol. It found five bugs, a scaling model, and a correct architecture — at a cost of weeks rather than the months a specification would have consumed. That is the right outcome from falsification done properly, and it is worth writing up as such.
