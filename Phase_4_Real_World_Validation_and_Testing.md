# Phase 4 — Real-World Validation, Testing & Prior-Art Verification

## Research Objective

Phase 1–3 progressively falsified the original AI-agent network identity hypothesis.

The current research hypothesis is narrower:

> **Enforcement correctness and per-principal attribution are separable properties with different scaling costs.**

Phase 3's controlled experiments found:

- Per-principal connection partitioning preserves exact attribution but scales approximately O(N) in connections.
- Policy-equivalence-class pooling reduces connections to O(P), where P is the number of distinct network policies, while preserving enforcement correctness.
- The trade-off is loss of exact per-principal attribution at the L3/L4 enforcement point.

Phase 4 must determine whether this result survives:

1. real Envoy,
2. real identity verification,
3. real Cilium/eBPF enforcement,
4. realistic multiplexed traffic,
5. realistic policy distributions,
6. larger-scale workloads,
7. audit-log correlation,
8. and a rigorous prior-art challenge.

**Do not assume Phase 3 is correct. Try to falsify it.**

---

# 1. Phase 4 Research Questions

### RQ1 — Real-world reproducibility

Can the Phase 3 D1/D2 results be reproduced using real Envoy rather than the Python harness?

### RQ2 — Real identity

Can a real application-layer identity mechanism such as WIMSE/WPT, SPIFFE/SVID, OAuth/JWT, or an equivalent verified identity be used to partition Envoy's upstream connections?

### RQ3 — Enforcement

Can Cilium/eBPF or another pure L3/L4 enforcement mechanism correctly enforce different policies after Envoy performs identity-aware connection partitioning?

### RQ4 — Scaling

Does per-principal connection amplification remain approximately O(N) with real Envoy?

Does policy-class pooling remain approximately O(P)?

### RQ5 — Attribution

When multiple principals share one policy-class connection, how much per-principal attribution can be recovered from Envoy access logs, gateway logs, WIMSE/WPT verification logs, timestamps, connection IDs, source/destination tuples, request IDs, trace IDs, and OpenTelemetry?

### RQ6 — Hybrid model

Can a hybrid architecture provide exact attribution for high-risk principals, policy-class pooling for ordinary principals, and correct enforcement for both?

### RQ7 — Prior art

Has the enforcement/attribution separation already been described, measured, or implemented by Envoy, Istio, Cilium, service meshes, egress gateways, SASE vendors, AI gateways, academic research, or other systems?

### RQ8 — Novelty

After real-world validation and prior-art review, is there still a meaningful research contribution?

---

# 2. Claims That Must Be Tested

Do NOT treat these as established facts.

### Claim C1

> Identity-aware L7 verification can partition upstream connections so that a pure L4 enforcement point can apply the correct policy without understanding the application identity.

### Claim C2

> Per-principal connection partitioning causes approximately linear connection/resource amplification.

### Claim C3

> Policy-equivalence-class pooling reduces connection count from O(N) principals to O(P) distinct policy classes.

### Claim C4

> Policy-class pooling preserves enforcement correctness when all principals sharing a class have identical network policy.

### Claim C5

> Policy-class pooling sacrifices exact L3/L4 attribution of the individual principal.

### Claim C6

> L7 gateway logs can recover enough principal-level attribution to compensate for the network-layer attribution loss.

### Claim C7

> A hybrid policy-class/per-principal architecture provides a useful security/resource/attribution trade-off.

### Claim C8

> The observed trade-off is not already adequately characterized in existing literature or production systems.

---

# 3. Phase 3 Baseline

Use the Phase 3 results as the baseline, not as proof.

At 800 principals and four policy classes:

| Architecture | Connections | Enforcement | Exact attribution |
|---|---:|---|---|
| Per-principal | 800 | Correct | Yes |
| Policy-class | 4 | Correct | No |

The Phase 3 experiment observed a 200× connection reduction with policy-class pooling.

Relevant Phase 3 artifacts:

- `PHASE3_REPORT.md`
- `demux_experiment.py`
- `eqclass_experiment.py`
- `results_eqclass.json`

These results came from a Python/socket harness and should therefore be treated as directional until reproduced with real Envoy and Cilium.

---

# 4. Experimental Architecture

Build the smallest realistic environment:

```text
                    +---------------------+
                    |  Agent Clients      |
                    |                     |
                    | A1 A2 A3 ... AN     |
                    +----------+----------+
                               |
                               | HTTP / HTTP2
                               v
                    +---------------------+
                    |   Envoy Gateway     |
                    |                     |
                    | ext_authz / auth    |
                    | identity verification|
                    | connection pooling  |
                    +----------+----------+
                               |
                +--------------+--------------+
                |                             |
        Per-principal pool             Policy-class pool
                |                             |
                v                             v
          upstream-A/B/C                upstream classes
                |                             |
                +--------------+--------------+
                               v
                    +---------------------+
                    | Cilium / eBPF       |
                    | L3/L4 enforcement   |
                    +----------+----------+
                               v
                    +---------------------+
                    | Protected Services  |
                    +---------------------+
```

---

# 5. Real Envoy Validation

Configure Envoy to perform external authorization.

The verifier should produce a verified principal such as:

```text
principal = alice@corp
policy_class = ALLOW_ALL
session_id = session-123
```

The identity must be obtained only after successful verification.

Do not use a trusted client-supplied identity without independently verifying it.

---

# 6. Verify Envoy Connection Pool Partitioning

Verify the Phase 3 assumption against the actual Envoy implementation and documentation.

Investigate:

- hashable filter state
- upstream connection pools
- shared filter state
- `ext_authz`
- filter metadata
- dynamic metadata
- connection pool keys
- HTTP/1.1
- HTTP/2
- HTTP/3 if supported
- retries
- connection reuse
- circuit breakers
- outlier detection

Create two tests.

### Test A — Shared pool

```text
Alice --+
Bob   --+--> Envoy ---> one upstream connection
Carol --+
```

### Test B — Principal-keyed pool

```text
Alice --> Envoy --> upstream-A
Bob   --> Envoy --> upstream-B
Carol --> Envoy --> upstream-C
```

Measure actual upstream connection identities.

---

# 7. Test Real L4 Enforcement

Use Cilium/eBPF or another L3/L4-only enforcement mechanism.

The enforcement point must NOT inspect:

- HTTP headers
- WPT
- JWT
- agent identity
- application payload

It should only use network-observable information such as source IP, source port, destination IP, destination port, protocol, network identity, and connection metadata available to the enforcement layer.

Test:

```text
Alice → ALLOW
Bob   → DENY
Carol → RESTRICT
```

Verify that the enforcement result is correct.

---

# 8. Negative Control

Run the same experiment with shared upstream connections.

The L4 enforcement point should be unable to distinguish them.

Record:

- incorrect verdicts
- ambiguous 5-tuples
- connection count
- attribution

This establishes the experimental contrast.

---

# 9. Protocol Tests

Repeat the experiments for:

### HTTP/1.1

Test keep-alive, connection reuse, and sequential requests.

### HTTP/2

Test:

```text
one TCP connection
    +-- stream A → Alice
    +-- stream B → Bob
    +-- stream C → Carol
```

### HTTP/3 / QUIC

If feasible, investigate connection IDs, stream multiplexing, connection reuse, Envoy support, and enforcement observability.

### Non-HTTP

Test or document raw TCP, UDP, and non-proxyable protocols.

Determine whether the architecture depends fundamentally on an L7 gateway.

---

# 10. Scaling Experiment

Run at least:

```text
N = 10
N = 100
N = 1,000
N = 5,000
N = 10,000
```

If resources permit:

```text
N = 50,000
N = 100,000
```

Compare:

### Scheme A

```text
connection key = principal
```

Expected:

```text
connections ≈ N
```

### Scheme B

```text
connection key = policy class
```

Expected:

```text
connections ≈ P
```

Measure upstream connections, open file descriptors, Envoy memory/CPU, Cilium memory/CPU, connection setup rate, connection establishment latency, request latency, throughput, TLS/mTLS overhead if applicable, connection reuse, and failure rate.

---

# 11. Policy Distribution Experiment

Test:

```text
P = 1
P = 2
P = 4
P = 10
P = 50
P = 100
P = 500
```

for increasing:

```text
N = 100
N = 1,000
N = 10,000
```

Measure `connections(N, P)` and determine whether per-principal is approximately O(N) and policy-class pooling approximately O(P).

---

# 12. Hybrid Architecture

Implement:

```text
High-value principals
       ↓
per-principal connection

Normal principals
       ↓
policy-class connection
```

Define at least:

```text
HIGH_RISK
NORMAL
LOW_RISK
```

Test exact attribution for high-risk agents, pooled connections for normal agents, and enforcement correctness across all classes.

Measure total connection count and determine whether the hybrid model produces a useful Pareto frontier between resource cost, attribution fidelity, and security.

---

# 13. Attribution Experiment

Under policy-class pooling, determine whether identity can be reconstructed by correlating:

- Envoy request logs
- principal ID
- session ID
- request ID
- trace ID
- timestamp
- upstream connection ID
- source port
- destination port
- Cilium flow logs

Test whether every network event can be mapped back to principal, session, and request with measurable confidence.

---

# 14. Attribution Metrics

Define:

### Exact attribution rate

```text
exactly attributed events
-------------------------
all network events
```

### Ambiguity rate

```text
ambiguous events
----------------
all network events
```

### Attribution latency

Time between the network event and principal identification.

### Correlation failure rate

Percentage of network events that cannot be mapped to a unique principal.

### Audit completeness

Percentage of requests for which the audit trail contains:

```text
human
agent
session
request
destination
decision
```

---

# 15. Connection Churn

Investigate idle timeout, max connection duration, pool eviction, policy changes, principal revocation, and policy-class membership changes.

Critical question:

> What happens when Alice changes from ALLOW to DENY while sharing a policy-class connection with other principals?

Verify that policy changes cannot accidentally affect principals that should remain in a different policy state.

---

# 16. Revocation Testing

Test:

```text
Alice = ALLOW
```

Then revoke Alice. Measure time until access is blocked, existing connection behavior, new requests, connection reuse, policy cache lifetime, Envoy state, and Cilium state.

Then test:

```text
Alice: ALLOW → DENY
Bob:   remains ALLOW
```

while Alice and Bob initially share a policy-class connection. Determine exactly how the system handles the change.

---

# 17. Policy-Class Safety Condition

Formally define the pooling condition.

Two principals may share an enforcement connection only if:

```text
Policy(A) == Policy(B)
```

for every network-enforced property relevant to that connection.

Test whether this includes destination, source, protocol, port, egress region, data classification, time, risk, device posture, agent posture, user privileges, rate limits, bandwidth, and threat level.

Determine whether a policy class can actually be represented as a stable equivalence relation in real enterprise systems.

---

# 18. Prior-Art Investigation

Search primary sources for:

### Envoy

- hashable filter state
- connection pool partitioning
- ext_authz
- shared filter state

### Istio

- egress gateways
- workload identity
- connection pooling
- per-workload routing

### Cilium

- identity
- policy
- eBPF
- endpoint identity
- socket-level enforcement

### Service meshes

- workload identity
- per-workload connections
- identity-aware routing
- mTLS

### AI gateways

Research Microsoft, Palo Alto, Zscaler, Cisco, Fortinet, Check Point, Cloudflare, Okta, Envoy, agentgateway, Kong, Tyk, and other major gateways.

### Academic literature

Search specifically for:

- connection amplification
- identity-aware connection pooling
- workload identity connection pooling
- principal-aware connection pooling
- policy-equivalence classes
- security policy equivalence
- attribution vs enforcement
- network-flow attribution
- multi-tenant connection pooling
- multiplexed security principals
- per-user connection pooling
- service mesh connection pooling

Do NOT search only for "AI agent security."

---

# 19. Prior-Art Matrix

Create:

| System | Identity verification | Connection partitioning | Policy-class pooling | L4 enforcement | Per-principal attribution | Scale mechanism |
|---|---|---|---|---|---|---|
| Envoy | | | | | | |
| Istio | | | | | | |
| Cilium | | | | | | |
| Tetragon | | | | | | |
| WIMSE | | | | | | |
| SPIFFE/SPIRE | | | | | | |
| Microsoft | | | | | | |
| Palo Alto | | | | | | |
| Zscaler | | | | | | |
| Cisco | | | | | | |
| Fortinet | | | | | | |
| Cloudflare | | | | | | |
| Okta | | | | | | |

Classify each statement as Documented, Demonstrated, Inferred, or Unknown. Do not infer absence from lack of documentation.

---

# 20. Reproduce Envoy's Existing Mechanism

Verify the claim that Envoy supports hashable shared filter state that influences upstream connection pooling from:

1. Envoy documentation
2. Envoy source code
3. Envoy tests
4. actual runtime behavior

Determine exactly which filter state is hashed, when the connection pool key is calculated, whether identity can safely be used, whether ext_authz output can populate the state, whether the state survives retries, whether HTTP/2 streams remain isolated, how connection reuse behaves, how invalidation works, and whether the mechanism is intended for security isolation or routing behavior.

This is a critical verification.

---

# 21. Security Analysis

Attack the policy-class architecture.

Test:

- identity changes while reusing an existing connection
- policy-class changes
- authorization loss while a connection remains open
- forged policy-class metadata
- gateway compromise
- stale policy cache
- connection-pool key collision
- retry onto the wrong connection
- HTTP/2 stream misassociation
- credential expiration with connection reuse

Determine whether the architecture can ever cause Alice's request to receive Bob's policy or Bob's request to receive Alice's privileges.

---

# 22. Failure and Availability Testing

Test Envoy restart, Cilium restart, gateway failure, upstream failure, connection pool exhaustion, policy-service failure, identity-service failure, authorization timeout, stale identity, and partial network partition.

Determine fail-open vs fail-closed behavior.

---

# 23. Performance Experiment

Compare:

### Baseline

No identity verification.

### Identity only

L7 identity verification but shared connection.

### Per-principal

Identity + per-principal connection pooling.

### Policy-class

Identity + policy-class pooling.

### Hybrid

Identity + mixed pooling.

Measure p50/p95/p99 latency, throughput, CPU, memory, connection count, file descriptors, and network overhead.

---

# 24. Expected Result Matrix

Build this table from actual experiments:

| Architecture | Enforcement | Attribution | Connections | CPU | Memory | Latency |
|---|---|---|---:|---:|---:|---:|
| Shared | | | | | | |
| Per-principal | | | | | | |
| Policy-class | | | | | | |
| Hybrid | | | | | | |

Do not fill cells with assumptions.

---

# 25. Decision Criteria

## Outcome A — Research closed

If real Envoy + Cilium demonstrates that existing mechanisms already provide the complete desired behavior and the trade-off is already documented in prior art:

> Stop pursuing the current research contribution.

## Outcome B — Measurement contribution

If the mechanism is known but the connection amplification, policy-class scaling, attribution loss, or hybrid trade-off is not adequately measured or characterized:

> Pursue a measurement/systems paper.

## Outcome C — Systems research opportunity

If real experiments reveal an undocumented or poorly understood scaling/security trade-off:

> Define the exact problem and continue experimental research.

## Outcome D — Protocol opportunity

Only consider a new protocol if:

1. Existing systems cannot communicate the required identity/policy semantics.
2. The missing interface is clearly defined.
3. Real experiments demonstrate the gap.
4. Existing standards do not provide equivalent semantics.
5. The interface is vendor-neutral and broadly applicable.
6. A protocol provides meaningful value over configuration-specific solutions.

**Do not design a protocol before satisfying all six conditions.**

---

# 26. Required Final Report

Produce:

1. Executive conclusion
2. Phase 1 → Phase 2 → Phase 3 evolution
3. Experimental environment
4. Real Envoy configuration
5. Real identity mechanism
6. Real Cilium configuration
7. D1 shared-pool results
8. D2 per-principal results
9. Policy-class results
10. Hybrid results
11. Scaling curves
12. Connection amplification
13. FD amplification
14. CPU results
15. Memory results
16. Latency results
17. Throughput results
18. Attribution results
19. Audit correlation results
20. Revocation results
21. Policy-change results
22. HTTP/1.1 results
23. HTTP/2 results
24. HTTP/3/QUIC analysis
25. Non-HTTP analysis
26. Security attack results
27. Failure-mode results
28. Prior-art matrix
29. Envoy source/documentation verification
30. Cilium verification
31. WIMSE/SPIFFE verification
32. Commercial competitor verification
33. Academic prior-art verification
34. What Phase 3 got right
35. What Phase 3 got wrong
36. Remaining research gap
37. Novelty assessment
38. Publication potential
39. Protocol justification or rejection
40. Recommended Phase 5

---

# 27. Most Important Instruction

**Do not try to prove that our research is novel.**

Try to disprove it.

The desired conclusion may be:

> Existing systems already solve the problem.

That is a successful research result.

If the original problem is closed, identify the smallest remaining measurable problem.

The strongest current candidate is:

> **How should identity-preserving network enforcement balance exact per-principal attribution against connection/resource amplification when millions of principals share a small number of network policy classes?**

But this statement must also be challenged against existing literature and implementations.

---

# 28. Final Research Decision

At the end, provide exactly one of:

```text
RESEARCH CLOSED
```

or

```text
MEASUREMENT PAPER OPPORTUNITY
```

or

```text
SYSTEMS RESEARCH OPPORTUNITY
```

or

```text
PROTOCOL RESEARCH OPPORTUNITY
```

Then provide the evidence supporting that decision.

## Principle

> **Do not invent a protocol because the project started as a protocol idea. Build only what the evidence proves is missing.**
