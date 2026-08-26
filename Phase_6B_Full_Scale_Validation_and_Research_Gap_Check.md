# Phase 6B — Full-Scale Validation, Research-Gap Check & Production Readiness

## Project Scope

This document is for the **corporate AI-agent network security tool**.

**Do not mix this project with Zero Protocol.**

Phase 6A demonstrated that moving agent-specific routing state out of the Envoy data plane and routing on a signed policy class dramatically improves scalability.

The current architecture hypothesis is:

```text
CONTROL PLANE
O(N) agent records
        |
        | signs policy class
        v
DATA PLANE
O(P) policy classes
        |
        +--> Envoy
        |
        +--> eBPF / Cilium
```

The key Phase 6A result was that policy-class routing remained effectively constant from 1K to 100K principals, while per-principal routing grew linearly. The eBPF verdict map also reached 1,000,000 entries with low measured lookup latency.

However, Phase 6A was **not a full million-agent end-to-end validation**.

This phase must determine:

> **Does the architecture remain secure, scalable, correct, and operationally practical when the control plane, identity system, gateways, revocation system, enforcement layer, and audit system operate together at large scale?**

It must also answer:

> **Is there any genuine research problem still remaining, or is the project now primarily an engineering/product opportunity?**

---

# 1. Current Evidence

Phase 6A measured:

### Policy-class routing

At N = 1,000, 10,000, and 100,000:

- 3 route entries
- ~1.6 KB configuration
- ~0.25 s startup
- ~51–52 MB RSS
- ~0.48–0.49 ms p50

### Per-principal routing

At N = 100,000:

- 100,001 routes
- ~16.3 MB configuration
- ~21.59 s startup
- ~392 MB RSS
- ~4.1 ms p50

The 1M per-principal figures are extrapolations and must not be presented as direct measurements.

### eBPF map

Measured:

```text
1,000 entries       → ~1.42 µs p50
10,000              → ~1.43 µs
100,000             → ~1.51 µs
1,000,000           → ~2.65 µs
```

### Identity verification

Measured with Python:

```text
raw Ed25519       ≈ 7,659 verifies/s/core
full JWT EdDSA    ≈ 6,376 verifies/s/core
p50               ≈ 138.9 µs
p99               ≈ 178.8 µs
```

These are **benchmark results, not production capacity numbers**.

---

# 2. What Is Still Unproven?

The following remain open:

1. Real 1M-agent control-plane operation.
2. Real gateway crypto capacity.
3. Revocation at scale.
4. Multi-gateway consistency.
5. Policy propagation at scale.
6. Long-duration stability.
7. Failure recovery.
8. Policy-class security boundaries.
9. Correct eBPF keying for policy enforcement.
10. Audit scalability.
11. Identity-service scalability.
12. Agent registration churn.
13. Risk-class migration at scale.
14. Whether existing products already provide this complete architecture.
15. Whether any genuine research contribution remains.

---

# 3. Phase 6B Research Questions

## RQ1 — Does the control plane scale to 1M agents?

Measure:

- registration,
- lookup,
- updates,
- credential issuance,
- policy-class assignment,
- revocation,
- agent deletion,
- concurrent operations.

Target:

```text
1,000,000 agent records
```

Do not simply insert 1M rows.

Simulate realistic metadata:

```text
human
agent
runtime
session
policy class
risk
credential
status
timestamps
```

---

# 4. RQ2 — Does the identity service scale?

Measure:

```text
credential issuance/s
credential verification/s
key rotation
revocation
concurrent sessions
```

Test:

```text
1K agents
10K
100K
1M
```

Do not use the Python benchmark as the final capacity number.

Implement or benchmark the actual production language/runtime:

- Rust
- Go
- C++
- Java
- or the selected gateway implementation.

Measure:

```text
single-core
multi-core
horizontal scaling
```

---

# 5. RQ3 — Does policy-class signing create a security problem?

The architecture depends on:

```text
signed token
      ↓
policy_class
      ↓
route
```

Test whether an attacker can modify:

```text
policy_class
risk
agent_id
human_id
session_id
expiration
audience
delegation
```

Expected:

```text
modified token → DENY
```

Also test:

- algorithm confusion,
- key substitution,
- expired credentials,
- replay,
- cross-agent token use,
- cross-tenant token use,
- audience confusion.

---

# 6. RQ4 — Is Policy Class Actually Safe?

This is one of the most important remaining research/engineering questions.

Two agents can share a policy class only when:

```text
EffectivePolicy(A) == EffectivePolicy(B)
```

Define the exact policy dimensions.

At minimum:

```text
destination
port
protocol
network
data classification
risk
time restrictions
tenant
user privilege
agent privilege
runtime posture
device posture
geography
rate limit
```

Test:

```text
A ≡ B
```

and:

```text
A ≠ B
```

The system must never put non-equivalent agents into the same enforcement class.

---

# 7. RQ5 — Dynamic Policy-Class Changes

Test:

```text
NORMAL
  ↓
HIGH RISK
  ↓
DEDICATED
```

and:

```text
CLASS_A
  ↓
CLASS_B
```

while the agent has active connections.

Verify:

- old connection behavior,
- new connection behavior,
- policy update,
- route update,
- eBPF enforcement,
- audit trail.

Critical question:

> Can an agent continue using the old policy through an already-established connection after its class changes?

---

# 8. RQ6 — Revocation at Scale

The current architecture proposes:

```text
short token TTL
+
revocation list
```

Validate this.

Test:

```text
1M active agents
10 revoked
100 revoked
1,000 revoked
10,000 revoked
```

Measure:

- revocation propagation,
- gateway update,
- enforcement update,
- stale authorization window,
- memory,
- CPU,
- network traffic.

Determine whether revocation cost is:

```text
O(N)
```

or:

```text
O(revoked)
```

---

# 9. RQ7 — Policy Propagation

Test:

```text
Control Plane
      ↓
Gateway A
Gateway B
Gateway C
...
Gateway N
```

Change a policy and measure:

```text
t0 = control-plane update
t1 = gateway receives update
t2 = gateway activates update
t3 = enforcement changes
```

Report:

```text
propagation p50
propagation p95
propagation p99
maximum stale window
```

---

# 10. RQ8 — Multi-Gateway Consistency

Deploy multiple gateways.

Example:

```text
             Load Balancer
                  |
       +----------+----------+
       |          |          |
   Gateway A  Gateway B  Gateway C
       |          |          |
       +----------+----------+
                  |
              Enforcement
```

Test:

- identity verification,
- policy consistency,
- revocation,
- gateway restart,
- gateway failure,
- network partition,
- delayed configuration,
- partial rollout.

Critical question:

> Can one gateway allow traffic after another gateway has already revoked it?

---

# 11. RQ9 — eBPF Policy-Key Validation

Do not assume the eBPF verdict map can be keyed only by destination.

Determine the real key required by the architecture.

Potential keys:

```text
destination
+
policy class
```

or:

```text
cgroup/workload identity
+
destination
```

or:

```text
network identity
+
destination
```

or another verified enforcement identity.

Test:

```text
Agent A → destination X → ALLOW
Agent B → destination X → DENY
```

If both agents share the same destination but require different decisions, destination-only enforcement is insufficient.

This must be explicitly resolved before production.

---

# 12. RQ10 — eBPF Map Scaling

Repeat the 1M-entry experiment under:

```text
1M
2M
5M
10M
```

if the kernel/environment permits.

Measure:

- memory,
- load time,
- update time,
- lookup p50,
- lookup p99,
- lookup p99.9,
- contention,
- CPU.

Also measure **update churn**, not only initial population.

Example:

```text
100,000 updates/s
```

if feasible.

---

# 13. RQ11 — Agent Registration Churn

One million registered agents is different from one million agents constantly changing.

Test:

```text
agents starting
agents stopping
agents registering
agents revoking
agents rotating credentials
```

Measure:

```text
1K changes/s
10K changes/s
100K changes/s
```

Determine control-plane bottlenecks.

---

# 14. RQ12 — Session Scale

Separate:

```text
agents
```

from:

```text
sessions
```

Test:

```text
1M agents
+
10M sessions
```

if resources permit.

The control plane must not accidentally become:

```text
O(agents × sessions × requests)
```

for persistent state.

---

# 15. RQ13 — Audit Scale

Measure:

```text
requests/s
events/s
audit records/s
```

At large scale:

```text
1M agents × 0.1 req/s
=
100K requests/s
```

Determine:

- event size,
- storage,
- ingestion,
- indexing,
- query latency,
- retention,
- compression.

Audit data should not become the next scaling bottleneck.

---

# 16. RQ14 — Identity and Audit Correlation

Verify that:

```text
human
agent
runtime
session
request
policy
network decision
```

can be correlated.

Example:

```text
Alice
 ↓
Agent-742
 ↓
Session-88321
 ↓
Request-19482
 ↓
CLASS-004
 ↓
ALLOW
 ↓
Network flow
```

Determine which links are cryptographically guaranteed versus log correlation.

---

# 17. RQ15 — Fail-Open Regression #1: Route Cache

This must become a permanent integration test.

Test:

```text
identity verification
        ↓
ext_authz
        ↓
policy class
        ↓
route
```

Compare:

```text
clear_route_cache = false
```

against:

```text
clear_route_cache = true
```

Expected production behavior:

```text
incorrect route
=
DENY / fail-safe
```

Never accept:

```text
incorrect route
=
HTTP 200
```

Repeat with:

- high-risk agent,
- normal agent,
- revoked agent,
- policy-class change.

---

# 18. RQ16 — Fail-Open Regression #2: Policy Propagation

Reproduce the Phase 4B RDS behavior.

Test:

### In-place update

### Atomic rename

Measure:

```text
update detected?
update applied?
time?
old policy still active?
```

If in-place behavior fails, determine:

- whether this is documented,
- whether it is Envoy-version-specific,
- whether the configuration is supported,
- whether the production tool can eliminate the risk by using atomic updates.

Do not label a configuration issue a universal vulnerability without evidence.

---

# 19. RQ17 — Gateway Restart

Test:

```text
1M agents
   ↓
gateway restart
```

Measure:

- startup,
- memory,
- policy load,
- readiness,
- request failure,
- recovery time.

Compare:

```text
policy-class
```

against:

```text
per-principal
```

The objective is to confirm that the data plane remains O(P).

---

# 20. RQ18 — Rolling Upgrade

Run:

```text
Gateway A v1
Gateway B v1
Gateway C v2
```

and gradually migrate.

Test:

- policy compatibility,
- token compatibility,
- configuration compatibility,
- revocation,
- audit schema,
- rollback.

---

# 21. RQ19 — 24-Hour Soak

Run the system continuously for at least:

```text
24 hours
```

Prefer:

```text
72 hours
```

Simulate:

- agent registration,
- requests,
- policy changes,
- revocation,
- credential rotation,
- gateway restarts,
- failures,
- high-risk transitions.

Monitor:

- RSS,
- CPU,
- file descriptors,
- connections,
- memory leaks,
- latency,
- event backlog,
- policy drift.

---

# 22. RQ20 — Multi-Tenant Isolation

Test:

```text
Tenant A
Tenant B
```

with identical agent IDs where necessary.

Ensure:

```text
tenant A token
≠
tenant B authorization
```

Test:

- token replay across tenants,
- policy-class collision,
- route collision,
- audit collision,
- revocation collision.

---

# 23. RQ21 — External Agent Admission

Test the original corporate requirement:

```text
Internal approved agent
       ↓
corporate boundary
       ↓
ALLOW
```

versus:

```text
External unauthorized agent
       ↓
corporate boundary
       ↓
DENY
```

Also test:

```text
valid external identity
+
not approved by corporate policy
=
DENY
```

This separates authentication from admission authorization.

---

# 24. RQ22 — Existing Technology Recheck

Before claiming a product gap, perform a final primary-source review of:

- Envoy
- Cilium
- Tetragon
- SPIFFE/SPIRE
- WIMSE
- Istio
- Linkerd
- service meshes
- SASE
- NGFW
- AI gateways
- Microsoft
- Palo Alto
- Zscaler
- Cisco
- Fortinet
- Check Point
- Cloudflare
- Okta

For each capability:

```text
Agent identity
Human delegation
Session identity
Policy classes
Network enforcement
Revocation
Attribution
Risk escalation
Scaling
Audit
```

Classify:

```text
Demonstrated
Documented
Inferred
Unknown
```

Do not claim a capability is absent simply because it is not advertised.

---

# 25. Final Research-Gap Test

This is the most important section.

Ask:

> After implementing the architecture with existing components, is there still a technically non-trivial problem that existing systems do not solve?

Possible outcomes:

### Outcome A — No research gap

```text
Existing technology + integration
solves the problem.
```

Conclusion:

```text
Research closed.
Product engineering continues.
```

### Outcome B — Measurement opportunity

The system reveals a previously uncharacterized measurable trade-off.

Conclusion:

```text
Systems measurement paper.
```

### Outcome C — Systems opportunity

Existing mechanisms work individually but fail to compose efficiently or safely.

Conclusion:

```text
Systems research.
```

### Outcome D — Protocol opportunity

Only if:

```text
existing standards cannot express
the required interoperable security context
```

and:

```text
multiple independent implementations
would benefit from the missing interface.
```

Only then reopen protocol research.

---

# 26. Research Questions That Must NOT Be Assumed

Do not assume:

```text
1M database rows = 1M-agent scalability
```

Do not assume:

```text
1M eBPF map entries = 1M-agent enforcement
```

Do not assume:

```text
signed policy class = safe policy class
```

Do not assume:

```text
short token TTL = immediate revocation
```

Do not assume:

```text
audit attribution = network attribution
```

Do not assume:

```text
single-host benchmark = production scale
```

Do not assume:

```text
eBPF hook test = Cilium product behavior
```

Do not assume:

```text
Envoy configuration behavior = universal Envoy vulnerability
```

---

# 27. Required Metrics

Every experiment should report:

## Scale

```text
agents
sessions
policy classes
gateways
```

## Performance

```text
throughput
p50
p95
p99
p99.9
```

## Resource

```text
CPU
RSS
file descriptors
connections
map memory
storage
```

## Security

```text
false allow
false deny
revocation delay
stale authorization window
policy mismatch
identity failures
```

## Reliability

```text
restart time
failover time
policy propagation
recovery time
```

---

# 28. Required Final Tables

## Architecture

| Component | Current implementation | Scaling property | Remaining risk |
|---|---|---|---|
| Identity | | | |
| Registration | | | |
| Policy | | | |
| Envoy | | | |
| eBPF | | | |
| Revocation | | | |
| Audit | | | |
| Control plane | | | |

## Security

| Scenario | Expected | Actual | Status |
|---|---|---|---|
| Forged identity | DENY | | |
| Replay | DENY | | |
| Expired token | DENY | | |
| Wrong tenant | DENY | | |
| Policy mismatch | DENY | | |
| Revoked agent | DENY | | |
| Wrong route | DENY | | |
| Stale policy | bounded/fail-safe | | |

## Scale

| Agents | Sessions | Classes | Gateways | RPS | CPU | RSS | p99 |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1K | | | | | | | |
| 10K | | | | | | | |
| 100K | | | | | | | |
| 1M | | | | | | | |

---

# 29. Exit Criteria

Phase 6 should not be considered complete until:

- [ ] 1M control-plane records tested
- [ ] production-language identity verification benchmark completed
- [ ] policy-class signing validated
- [ ] policy-class equivalence tested
- [ ] dynamic class migration tested
- [ ] revocation at scale tested
- [ ] multi-gateway consistency tested
- [ ] eBPF policy-key model proven
- [ ] eBPF update churn tested
- [ ] audit scalability measured
- [ ] multi-tenant isolation tested
- [ ] route-cache regression test automated
- [ ] policy-propagation regression test automated
- [ ] gateway restart tested
- [ ] rolling upgrade tested
- [ ] 24-hour soak completed
- [ ] external-agent admission tested
- [ ] final competitor/prior-art review completed
- [ ] final research-gap decision documented

---

# 30. Final Decision

At the end of Phase 6B, return exactly one:

```text
RESEARCH CLOSED — PRODUCT ENGINEERING
```

or:

```text
MEASUREMENT RESEARCH OPPORTUNITY
```

or:

```text
SYSTEMS RESEARCH OPPORTUNITY
```

or, only with strong evidence:

```text
PROTOCOL RESEARCH REOPENED
```

The default expectation should be:

```text
RESEARCH CLOSED
        ↓
PRODUCT ENGINEERING
```

unless the experiments demonstrate something genuinely new.

---

# 31. What Comes After Phase 6B?

Do not automatically create Phase 7.

If Phase 6B succeeds:

```text
Research
   ↓
Validated architecture
   ↓
Prototype
   ↓
Pilot
   ↓
Production hardening
```

The next work should then be:

```text
Corporate AI-Agent Security Tool
        ↓
MVP
        ↓
Enterprise Pilot
        ↓
Production
```

Only reopen research if implementation reveals a genuinely unresolved technical problem.

---

# 32. Final Principle

The project began with:

> "Can we design a protocol that binds AI agents to corporate network traffic?"

After five phases, the more useful question is:

> **Can we build a scalable corporate security control plane that understands human → AI-agent → session identity and safely translates that context into network policy and enforcement?**

Phase 6B must answer that question with measurements rather than assumptions.

**Do not create another protocol merely because a research gap is interesting.**

If existing standards and systems are sufficient:

> integrate them, harden them, and build the product.

If a genuine gap remains:

> isolate the smallest missing capability and research only that.
