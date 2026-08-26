# Phase 7 — Final Validation, Remediation & Research Closure

**Project:** Corporate AI-Agent Network Security Platform  
**Scope:** Separate project for controlling and monitoring AI-agent access in corporate networks. **Do not mix this work with Zero Protocol.**

## Purpose

Execute the remaining high-value tests identified after Phase 6B. Do not invent positive results. Run tests where the environment permits, record exact evidence, identify failures, fix reproducible issues, rerun affected tests, and determine whether any genuine research gap remains.

## 1. Phase 7 Decision Question

> **Can the corrected architecture be made fail-closed, cryptographically trustworthy, revocable, consistently enforced across gateways, resistant to enforcement-identity spoofing, and operationally stable at enterprise scale?**

Do **not** reopen protocol research merely because an implementation problem is discovered. Only declare **PROTOCOL RESEARCH REOPENED** if testing demonstrates a fundamental limitation that cannot reasonably be addressed through architecture, implementation, configuration, or existing standards/mechanisms.

## 2. Phase 6B Findings to Carry Forward

1. Native Ed25519 verification was about 8.7K/s/core in the tested environment, not 3–5× faster than the previous Python result.
2. Destination-only eBPF enforcement is insufficient when two agents/classes require different decisions for the same destination.
3. Enforcement needs a kernel-visible identity carrier such as cgroup identity, a trusted socket mark, or another securely bound mechanism.
4. Policy classes appear scalable when defined around network-enforceable dimensions, but realistic enterprise distribution remains unvalidated.
5. The agent-held signing-key model allowed a delegation-swap attack: the agent could produce a valid signature while changing the claimed human delegator.
6. Preferred correction: identity-service-signed authorization tokens; the agent must not mint human-delegation claims.
7. eBPF lookup remained approximately flat through the tested 10M-entry experiment, but hash-map preallocation creates substantial memory/startup cost.
8. SQLite successfully modeled 1M control-plane records, but this is not production database validation.
9. Multi-gateway consistency, production revocation, full JWT-path capacity, realistic policy-class validation, enforcement-identity spoofing, soak testing, and rolling upgrades remain incomplete.

## 3. Test Priority

| Priority | Test | Objective |
|---|---|---|
| P0 | Identity-service-signed tokens | Eliminate delegation forgery |
| P0 | Full security regression | Prove the corrected credential model |
| P0 | Multi-gateway revocation | Measure actual stale-allow window |
| P0 | Enforcement-identity spoofing | Test the eBPF security boundary |
| P0 | Production JWT path | Measure real authorization capacity |
| P0 | Enterprise policy corpus | Validate the O(P) assumption |
| P1 | Multi-gateway consistency/partition | Measure stale policy behavior |
| P1 | RDS/config failure matrix | Remove configuration fail-opens |
| P1 | 24–72h soak | Find long-run failures |
| P1 | Rolling upgrade/recovery | Test lifecycle safety |
| P1 | Final prior-art/research-gap review | Determine whether research is closed |

## 4. RQ-P7-01 — Identity-Service-Signed Authorization Tokens

### Hypothesis

An AI agent must not be able to mint or modify claims asserting which human delegated authority to it.

Expected flow:

```text
Human
  |
  v
Identity / Authorization Service
  |
  | validates human + agent + delegation + policy
  | signs short-lived authorization token
  v
AI Agent
  |
  | presents token
  v
Gateway
  |
  +--> verifies service signature
  +--> validates claims
  +--> derives network/policy class
```

The agent must not possess the signing key used for authorization claims.

### Tests

- Valid baseline: expected ALLOW.
- Delegation swap (`act.human` only): expected DENY.
- Policy/network class tampering: expected DENY.
- Risk downgrade: expected DENY.
- Agent substitution: expected DENY.
- Stolen token from another workload/host/session: determine bearer vs proof-of-possession behavior.
- Prove the agent cannot mint an accepted authorization token.
- Key rotation: old/new keys, overlap, retirement, gateway refresh.
- Issuer/audience confusion: expected DENY.

**Acceptance:** unauthorized modifications are denied and a compromised agent cannot forge the human delegator.

## 5. RQ-P7-02 — Full Authorization Security Regression

Rerun at minimum:

1. policy-class tampering
2. network-class tampering
3. risk downgrade
4. key substitution
5. HS256 algorithm confusion
6. `alg=none`
7. expired token
8. not-yet-valid token
9. replay
10. cross-agent token
11. cross-tenant token
12. audience confusion
13. issuer confusion
14. delegation swap
15. token copied between workloads
16. token copied between hosts
17. malformed JWT
18. duplicated claims
19. duplicate headers
20. oversized token
21. key-rotation race
22. revoked credential
23. revoked agent
24. revoked human delegation

**Acceptance:** `0 unexpected ALLOW`. Every denial has an explicit reason.

## 6. RQ-P7-03 — Multi-Gateway Revocation

Use at least three gateways if possible:

```text
                 Control Plane
                /      |      \
              GW1     GW2     GW3
               |       |       |
             eBPF     eBPF    eBPF
```

Record:

```text
T0 = revocation committed
T1 = GW1 receives update
T2 = GW2 receives update
T3 = GW3 receives update
T4 = first enforcement denial
T5 = last enforcement denial
```

Repeat under normal traffic, high traffic, gateway restart, delayed gateway, control-plane delay, network partition/recovery, and simultaneous revocation of 1, 10K, 50K and 100K agents where practical.

Do not claim TTL alone gives sub-5-second revocation. If TTL is 60 seconds, measure the actual stale authorization window.

**Acceptance target:** maximum stale-allow <=5 seconds, or explicitly document the measured bound and consequence.

## 7. RQ-P7-04 — Enforcement-Identity Spoofing

For cgroup identity test:

- cgroup migration
- namespace changes
- privileged container
- hostNetwork
- host PID
- fork/exec
- restart
- cgroup deletion/recreation
- workload moving between classes

For socket mark test, if used:

- unprivileged process
- CAP_NET_ADMIN
- privileged container
- host process
- namespace boundaries
- modification before/after connect

**Acceptance:** an untrusted workload cannot obtain another policy class's enforcement identity and inherit its network privileges.

## 8. RQ-P7-05 — Production JWT Verification Path

Measure the complete path:

```text
HTTP request
 -> Authorization parsing
 -> Base64URL decoding
 -> JWT parsing
 -> Ed25519 verification
 -> claim validation
 -> issuer/audience validation
 -> key lookup
 -> revocation check
 -> policy lookup
 -> authorization decision
```

Measure requests/sec/core, p50, p95, p99, p99.9, CPU, memory, allocations, key-cache hit rate and revocation lookup cost across 1/2/4/8/16 workers where available.

Do not extrapolate multi-core performance from a single core without labeling it as extrapolation.

## 9. RQ-P7-06 — Enterprise Policy-Class Validation

Replace or supplement synthetic policy generation with realistic/sanitized enterprise-style data covering departments, tenants, agent types, destinations, ports, protocols, network zones, geography, risk, posture, exceptions, temporary access, rate limits and data classification.

Calculate:

```text
N
P_policy
P_network
P_network/N
connections
Destinations/class
eBPF map entries
exception distribution
```

Test 10K, 100K and 1M agents where practical.

**Critical question:** does realistic policy complexity cause `P_network ≈ N`? If yes, redesign the policy model; if no, document why.

## 10. RQ-P7-07 — Multi-Gateway Consistency and Partition

Create GW1/GW2/GW3 with identical policy, then deliberately create divergent state:

```text
GW1 = new policy
GW2 = old policy
GW3 = unavailable
```

Test policy changes, rollback, revocation, class migration, gateway restart, control-plane partition, delayed updates and malformed updates.

Measure:

```text
time-to-consistency
maximum stale-allow
maximum stale-deny
```

Determine fail-open/fail-closed behavior for every failure mode. Unexpected security fail-open is a failure.

## 11. RQ-P7-08 — RDS / Configuration Failure Matrix

Test valid update, atomic update, in-place update, malformed update, partial update, rollback, watcher failure, gateway restart during update, control-plane restart and gateway loss of control-plane connectivity.

Capture old config, new config, timestamps, effective time and decisions before/after. Identify the actual xDS/file propagation mechanism; do not assume atomic rename is universally sufficient.

## 12. RQ-P7-09 — 24–72 Hour Soak

Use realistic levels such as 10K/50K/100K simulated active agents. Do not claim 1M active-agent validation unless actually simulated.

Mix HTTP/1.1, HTTP/2, HTTP/3 where available, gRPC and relevant non-HTTP TCP. Inject token expiration, issuance, revocations, policy changes, class migration, gateway restarts, eBPF updates and config reloads.

Track RSS, CPU, FDs, sockets, threads, eBPF memory, DB connections, queues, latency, 4xx/5xx, authorization failures, unexpected allows/denies and policy divergence.

**Acceptance:** 0 unauthorized accesses, 0 unexpected bypasses, no unbounded memory growth, no FD leak, no gateway crash, no unrecovered policy divergence.

## 13. RQ-P7-10 — Rolling Upgrade and Recovery

Test old->new and new->old gateway versions while traffic, token rotation, policy changes, revocations and eBPF updates continue. Verify mixed-version fleets cannot create authorization bypasses.

## 14. RQ-P7-11 — Audit Integrity

Final audit records should correlate:

```text
human
agent
session
credential ID
policy class
network class
destination
decision
gateway
timestamp
request ID
```

Test retries, HTTP/2 multiplexing, HTTP/3, gateway restart, delayed/dropped logs and clock skew.

Explicitly distinguish:

```text
L7 audit attribution
!= L4 network attribution
!= cryptographic delegation proof
```

## 15. RQ-P7-12 — Final Threat Model

Evaluate external attackers, compromised AI agents, compromised workloads, compromised gateways, compromised control plane and network attackers.

For each record:

```text
threat
asset
attack
control
residual risk
```

Pay particular attention to token minting, delegation forgery, policy escalation, enforcement-class substitution, cgroup/mark manipulation, privileged containers and stolen credentials.

## 16. Evidence Requirements

For every test provide:

```text
Test ID
Environment
Software versions
Hardware
Configuration
Exact command
Input
Expected result
Observed result
Logs
Metrics
Failure
Root cause
Fix
Rerun result
```

Where possible include source code, configs, JSON results, logs, captures, eBPF source, benchmark output and database statistics.

## 17. Evidence Classification

Every result must be classified exactly as:

- **DEMONSTRATED** — actually executed and directly measured.
- **SUPPORTED** — strongly supported but not completely demonstrated in the target environment.
- **INFERRED** — reasonable conclusion without direct execution.
- **UNTESTED** — insufficient experiment.
- **DISPROVEN** — experiment demonstrates the hypothesis is false.

Never call an inferred result validated.

## 18. Required Final Results Table

| Research Question | Result | Evidence | Remaining Risk |
|---|---|---|---|
| Identity-service delegation | | | |
| Token security | | | |
| Revocation | | | |
| Multi-gateway consistency | | | |
| eBPF identity integrity | | | |
| JWT capacity | | | |
| Policy-class scalability | | | |
| RDS safety | | | |
| Soak stability | | | |
| Rolling upgrade | | | |
| Audit integrity | | | |
| Protocol necessity | | | |

## 19. Final Research Decision

Choose exactly one:

### A — RESEARCH CLOSED

Only if all P0 tests pass, no unexplained security bypass remains, authorization is fail-closed, revocation is within the defined bound, enforcement identity cannot be spoofed, policy-class scaling is acceptable, production authorization capacity is understood, and no fundamental protocol limitation remains.

### B — SYSTEMS RESEARCH REMAINS

If a genuinely new component/algorithm is necessary and existing mechanisms cannot provide the required property.

### C — MEASUREMENT PAPER

If the architecture works and no new mechanism is required, but measurements reveal a genuinely novel, reproducible systems result.

### D — PROTOCOL RESEARCH REOPENED

Only if a fundamental requirement cannot be satisfied with existing protocol/identity/network mechanisms and cannot reasonably be solved through architecture or implementation.

## 20. Anti-Bias Rule

The objective is to break the system, not prove it works. Actively search for silent ALLOW, wrong principal, wrong human, wrong tenant, wrong policy class, stale authorization, identity spoofing, fail-open behavior, configuration races, gateway divergence, revocation bypass and audit forgery.

If a test fails: reproduce it, explain it, classify it as architectural or implementation-specific, fix it if possible, rerun it, and report both failure and corrected result.

Never hide a failed experiment because a later fix makes it pass.

## 21. Final Deliverables

Produce:

```text
PHASE7_FINAL_REPORT.md
phase7_results.json
phase7_security_matrix.json
phase7_benchmark_results.json
phase7_policy_class_results.json
phase7_revocation_results.json
phase7_multigateway_results.json
phase7_ebpf_results.json
phase7_audit_results.json
```

If code is created:

```text
phase7/
  token/
  revocation/
  gateway/
  ebpf/
  policy/
  soak/
  audit/
```

The final report must include: executive summary, executed tests, impossible tests and why, results, failures, root causes, fixes, reruns, remaining risks, research-gap analysis, final architecture changes and final decision A/B/C/D.

## 22. Final Instruction to Claude

Do not stop after the first successful result. Do not extrapolate measured results without labeling them. Do not claim 1M active-agent validation from 1M database rows. Do not claim production scalability from SQLite. Do not claim multi-core crypto throughput from a single-core benchmark. Do not claim revocation is solved because token TTL exists. Do not claim human attribution is cryptographically secure unless the identity-service signing model is tested. Do not claim Cilium behavior from a custom eBPF program. Do not claim vendor support without authoritative current documentation.

**The objective is to determine whether this project has crossed the boundary from research into a defensible production architecture.**
