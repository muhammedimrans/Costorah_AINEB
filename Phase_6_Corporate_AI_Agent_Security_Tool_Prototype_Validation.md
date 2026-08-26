# Phase 6 — Corporate AI-Agent Security Tool: Prototype & Production Validation

## Scope

This is the continuation of the **separate corporate AI-agent network security project**. It is **not related to Zero Protocol**.

Phases 1–5 investigated whether a new protocol was required to bind AI-agent sessions to corporate-network traffic. The current direction is to validate and build a practical security platform using existing identity, gateway, policy, and kernel-enforcement mechanisms.

> **Phase 6 objective: prove that a corporate AI-agent security tool can securely identify, authorize, monitor, revoke, and enforce network access for large numbers of AI agents without requiring one network rule or connection per agent.**

---

# 1. Current Baseline

### Phase 1
Workload identity does not necessarily provide individual AI-agent session identity when sessions share runtime/network resources.

### Phase 2
Socket identity is not a reliable agent-session security anchor because sockets can be pooled, reused, multiplexed, inherited, and transferred.

### Phase 3
The original assumption that a new protocol was necessarily required for L7-to-L4 binding was weakened by existing gateway and enforcement mechanisms.

### Phase 4 / 4B
Real Envoy testing demonstrated protocol/resource effects:
- HTTP/1.1 uses substantially more connections under concurrency.
- HTTP/2 can maintain very few upstream connections while multiplexing many requests.
- TLS prevents an external L3/L4 observer from recovering HTTP/2 stream-level application identity.
- Policy/connection behavior is protocol-dependent.

### Phase 5
Real eBPF enforcement demonstrated kernel-level allow/deny enforcement at the socket/connect boundary.
Real cryptographic workload-proof testing demonstrated that identity verification can happen before policy evaluation.
Phase 5 also identified security-relevant configuration behaviors around Envoy route-cache handling and RDS propagation that must become explicit regression tests.

These findings should be treated as **validated behaviors requiring controlled regression tests**, not automatically as universal vulnerabilities.

---

# 2. Target Architecture

```text
                         CORPORATE USERS
                               |
                               v
                     +--------------------+
                     | Identity Provider  |
                     | AD / Entra / OIDC  |
                     +---------+----------+
                               |
                               v
                     +--------------------+
                     | Agent Registration |
                     | & Identity Service |
                     +---------+----------+
                               |
                               v
                     +--------------------+
                     | AI Agent Runtime   |
                     | Identity / Session |
                     | Delegation         |
                     +---------+----------+
                               |
                               v
                     +--------------------+
                     | Agent Security     |
                     | Gateway            |
                     | Identity Verify    |
                     | Policy Decision    |
                     | Risk Assessment    |
                     +---------+----------+
                               |
                    +----------+----------+
                    |                     |
                 HIGH RISK             NORMAL
                    |                     |
                    v                     v
             Per-principal          Policy-class
                isolation              pooling
                    |                     |
                    +----------+----------+
                               |
                               v
                     +--------------------+
                     | Network Enforcement|
                     | eBPF / Cilium /    |
                     | Firewall / SASE    |
                     +---------+----------+
                               |
                +--------------+--------------+
                |                             |
             Internet                    Internal Services
```

---

# 3. Core Components

## 3.1 Agent Identity Service

Track at minimum:

```text
human_id
agent_id
runtime_id
session_id
credential_id
policy_class
risk_level
status
created_at
expires_at
```

Responsibilities:
- agent registration,
- owner/delegating-user association,
- credential issuance/rotation,
- lifecycle,
- revocation.

## 3.2 Human → Agent → Session Model

Do not collapse these identities:

```text
Human
  |
  +-- Agent
        |
        +-- Runtime
              |
              +-- Session
                    |
                    +-- Request
```

The system must answer:

> Which human delegated this request, which agent executed it, which runtime executed it, and which session generated it?

---

# 4. Identity Verification

Use at least one real cryptographic identity mechanism:

- SPIFFE/SPIRE
- WIMSE/WPT
- enterprise OIDC/OAuth
- another enterprise workload-identity mechanism

Never treat a client-supplied header such as:

```text
X-Agent-Principal: alice
```

as authoritative identity.

A header may be a derived internal attribute only after verification.

Required chain:

```text
Human
  ↓
Agent
  ↓
Session
  ↓
Credential
  ↓
Gateway verification
  ↓
Principal
  ↓
Policy
  ↓
Enforcement
```

---

# 5. Agent Admission

### Approved internal agent

```text
valid identity
+
approved runtime
+
approved owner
+
approved posture
=
ALLOW
```

### Unknown external agent

```text
identity unknown
      ↓
DENY
```

### Known but unapproved agent

```text
identity valid
+
policy denied
=
DENY
```

---

# 6. Policy Engine

Use attribute-based policy rather than one rule per agent.

Example:

```text
human.department = finance
agent.type = research
agent.risk = medium
destination.category = public_web
data.classification = internal
```

Example policy:

```text
IF
  agent.risk = high
AND
  destination = production
THEN
  DENY
```

---

# 7. Policy Classes

Two agents may share an enforcement class only when:

```text
EffectivePolicy(A) == EffectivePolicy(B)
```

for every property relevant to that network enforcement boundary.

Example:

```text
CLASS_001
Internet: ALLOW
Production: DENY
Internal: ALLOW

CLASS_002
Internet: DENY
Production: DENY
Internal: ALLOW
```

Do not define policy classes solely from agent names.

---

# 8. High-Risk Isolation

High-risk agents should use per-principal isolation when required.

Examples:
- production access,
- privileged automation,
- financial systems,
- credential management,
- security administration,
- agents with elevated tool permissions.

```text
HIGH_RISK
   ↓
per-principal network isolation
```

---

# 9. Normal-Agent Pooling

Normal agents with identical effective network policy may use policy-class pooling:

```text
1,000 agents
        |
        +---- CLASS_A
        +---- CLASS_B
        +---- CLASS_C
        +---- CLASS_D
```

The goal is to avoid unnecessary per-agent network resources.

---

# 10. Hybrid Architecture

```text
                 Agents
                    |
          +---------+---------+
          |                   |
       HIGH RISK           NORMAL
          |                   |
          v                   v
    per-principal        policy-class
       isolation            pooling
          |                   |
          +---------+---------+
                    |
                    v
              Enforcement
```

Validate this architecture experimentally rather than assuming it is safe.

---

# 11. Route Integrity

The security chain must be:

```text
verify identity
      ↓
evaluate authorization
      ↓
select correct route
      ↓
enforce network policy
```

Never allow:

```text
route selected
      ↓
authorization identity changes
      ↓
old route silently reused
```

Phase 6 must include regression tests for the Phase 5 route-cache behavior.

Required test:

```text
High-risk agent
      ↓
verified
      ↓
dedicated route
      ↓
NOT shared route
```

---

# 12. Route Regression Tests

### Test A
Authorization identity is available before route selection.

Expected:

```text
correct route
```

### Test B
Authorization identity is injected after route selection without appropriate cache invalidation.

Expected:

```text
implementation must fail safely
```

### Test C
Correct route-cache invalidation.

Expected:

```text
correct route
```

Record:
- Envoy version,
- filter ordering,
- configuration,
- route-cache behavior,
- actual route,
- final enforcement decision.

Do not generalize one configuration's behavior to all Envoy deployments.

---

# 13. Configuration Update Safety

Treat policy distribution as a security mechanism.

Measure:

```text
policy update
   ↓
gateway
   ↓
enforcement
```

Record:
- propagation time,
- stale-policy window,
- update failures,
- rollback behavior,
- active policy version.

Use atomic configuration updates where required.

---

# 14. Fail-Closed Requirements

Explicitly define behavior for:

### Identity verification failure
```text
DENY
```

### Policy engine unavailable
Prefer:
```text
DENY
```
unless a bounded, explicitly designed cached-policy mode is required.

### Gateway unavailable
Use the required protected-boundary fail-safe behavior.

### Enforcement unavailable
Fail closed for protected resources where security requirements demand it.

### Policy update failure
Never silently assume the new policy is active.

---

# 15. Revocation

Implement:

```text
Agent
  ↓
ACTIVE
  ↓
REVOKED
  ↓
No new access
```

Test:
- new requests,
- existing connections,
- pooled connections,
- per-principal connections,
- cached policy,
- gateway restart,
- enforcement restart.

Measure:

```text
revocation_latency
maximum_stale_authorization_window
```

---

# 16. Continuous Risk

Agent risk must be able to change dynamically.

Example:

```text
NORMAL
  ↓
suspicious behavior
  ↓
HIGH_RISK
  ↓
per-principal isolation
```

Potential signals:
- unusual destinations,
- credential access,
- privilege escalation,
- excessive requests,
- unexpected tool usage,
- policy violations,
- threat intelligence,
- anomalous behavior.

Test policy-class migration during a live session.

---

# 17. Session Lifecycle

Implement:

```text
CREATE
  ↓
ACTIVE
  ↓
RISK_CHANGE
  ↓
POLICY_CHANGE
  ↓
EXPIRE / REVOKE
  ↓
TERMINATE
```

Every transition must create an auditable event.

---

# 18. Network Enforcement

Support:
- destination allow/deny,
- port restrictions,
- protocol restrictions,
- network segmentation,
- policy class,
- high-risk isolation.

Possible enforcement mechanisms:

```text
eBPF
Cilium
Linux firewall
NGFW
SASE
```

The policy decision should be independent of the specific enforcement backend.

---

# 19. eBPF Integration

Use eBPF for host-level enforcement where appropriate.

The data plane should receive a compact enforcement decision such as:

```text
ALLOW
DENY
POLICY_ID
```

The eBPF layer should not be expected to understand:
- WPT,
- JWT,
- HTTP headers,
- human identity,
- agent reasoning.

The gateway/control plane owns identity and policy semantics.

---

# 20. Security Boundary

Explicitly separate:

```text
L7 Gateway
=
identity + policy

L3/L4 Enforcement
=
network enforcement

Audit Plane
=
principal/request attribution

Control Plane
=
registration + policy + revocation
```

Do not force every layer to understand every identity attribute.

---

# 21. Audit Architecture

Every request should ideally produce:

```text
timestamp
human_id
agent_id
runtime_id
session_id
request_id
destination
policy_id
policy_version
risk_level
decision
enforcement_id
```

Example:

```json
{
  "human": "alice@corp",
  "agent": "agent-742",
  "session": "sess-88321",
  "destination": "api.example.com",
  "policy": "CLASS-004",
  "policy_version": 173,
  "decision": "ALLOW"
}
```

---

# 22. Attribution Model

Keep these separate:

### L7 audit attribution

```text
Who generated this request?
```

### Network attribution

```text
Which network flow carried this request?
```

### Enforcement attribution

```text
Which policy caused this flow to be allowed/denied?
```

Correlate these rather than pretending they are the same identity.

---

# 23. Observability

Provide:

### Agent dashboard

```text
Agent
Owner
Runtime
Session
Risk
Policy
Status
```

### Network dashboard

```text
Destination
Protocol
Connections
Policy
Decision
```

### Security dashboard

```text
Blocked agents
High-risk agents
Revocations
Policy violations
Fail-open alerts
```

---

# 24. Fail-Open Detection

Detect:

```text
verified principal
       ↓
expected policy
       ↓
actual route
```

If:

```text
expected_policy != actual_policy
```

generate a critical security event.

Also compare:

```text
expected_policy_version
        !=
active_policy_version
```

---

# 25. Policy Versioning

Every decision should reference:

```text
policy_id
policy_version
```

Example:

```text
CLASS-004
version = 173
```

This answers:

> Which exact policy version allowed this request?

---

# 26. Million-Agent Scalability

Test progressively:

```text
1,000
10,000
100,000
1,000,000
```

Measure:
- identities,
- sessions,
- policy objects,
- policy classes,
- connections,
- CPU,
- memory,
- event volume,
- policy-evaluation latency,
- revocation propagation,
- audit storage.

Do not assume one million agents means one million active connections.

---

# 27. Scalability Model

Prefer:

```text
Agent identities
       ↓
Attribute policy
       ↓
Policy classes
       ↓
Network enforcement
```

Potential hierarchy:

```text
Tenant
  ↓
Department
  ↓
Agent type
  ↓
Risk class
  ↓
Policy class
  ↓
Agent/session
```

---

# 28. Control Plane vs Data Plane

## Control plane

Handles:
- identity,
- registration,
- policy,
- risk,
- revocation,
- configuration,
- audit metadata.

## Data plane

Handles:
- request routing,
- network enforcement,
- connection policy,
- flow decisions.

Keep the data plane lightweight.

---

# 29. Availability

Avoid a single gateway.

Prototype:

```text
        +---------+
        | Gateway |
        +----+----+
             |
       +-----+-----+
       |           |
   Gateway A   Gateway B
       |           |
       +-----+-----+
             |
         Enforcement
```

Test:
- gateway failure,
- control-plane failure,
- policy-service failure,
- identity-service failure,
- enforcement failure.

---

# 30. Threat Model

Include:

### External attacker
Attempts to enter the corporate network as an unauthorized agent.

### Malicious agent
Valid identity but malicious behavior.

### Compromised agent
Legitimate agent runtime or credential compromised.

### Credential theft
Attacker obtains agent credentials.

### Gateway compromise
Identity/policy gateway compromised.

### Host compromise
Local host compromise.

### Root/kernel attacker
Treat kernel compromise as a trust-boundary breach unless stronger isolation exists.

### Policy manipulation
Attacker attempts to modify policy/configuration.

---

# 31. Required Attack Tests

Test:

1. forged agent identity,
2. stolen credential,
3. replayed credential,
4. expired credential,
5. cross-principal credential,
6. policy-class spoofing,
7. route-cache confusion,
8. stale policy,
9. revoked-agent reuse,
10. connection reuse,
11. HTTP/2 multiplexing confusion,
12. QUIC connection migration,
13. gateway failure,
14. policy-service failure,
15. enforcement failure.

For each record:

```text
attack
↓
security boundary
↓
detection
↓
enforcement
↓
failure behavior
```

---

# 32. Minimal Product API

Possible internal API:

```text
POST /agents/register
POST /agents/{id}/sessions
GET  /agents/{id}
POST /agents/{id}/revoke

POST /policy/evaluate
GET  /policy/classes
POST /policy/classes

GET  /events
GET  /flows
```

All security-sensitive APIs require authentication and authorization.

---

# 33. Registration Example

Input:

```json
{
  "agent_type": "research-agent",
  "owner": "alice@corp",
  "runtime": "runtime-991",
  "requested_capabilities": [
    "web",
    "approved_saas"
  ]
}
```

Output:

```json
{
  "agent_id": "agent-742",
  "policy_class": "CLASS-004",
  "risk": "normal",
  "status": "active"
}
```

---

# 34. Policy Decision Example

Input:

```json
{
  "human": "alice@corp",
  "agent": "agent-742",
  "session": "sess-88321",
  "destination": "example.com",
  "risk": "normal"
}
```

Output:

```json
{
  "decision": "ALLOW",
  "policy_id": "CLASS-004",
  "policy_version": 173,
  "enforcement_mode": "policy-class"
}
```

---

# 35. Production Safety Rules

The system must never silently:

- downgrade a high-risk agent to normal,
- reuse an old authorization route,
- continue a revoked session indefinitely,
- apply an outdated policy without visibility,
- accept an unverified principal,
- treat failed identity verification as allow,
- treat policy-service failure as allow without an explicit bounded design.

---

# 36. Phase 6 Test Matrix

| Area | Test | Expected |
|---|---|---|
| Identity | valid credential | ALLOW |
| Identity | invalid credential | DENY |
| Identity | replay | DENY |
| Identity | expiry | DENY |
| Identity | cross-principal token | DENY |
| Routing | high-risk agent | dedicated route |
| Routing | normal agent | policy class |
| Routing | stale route | fail closed |
| Policy | correct class | correct decision |
| Revocation | new request | DENY |
| Revocation | existing session | bounded stale window |
| eBPF | allowed destination | connect succeeds |
| eBPF | denied destination | connect denied |
| Pooling | same policy | share safely |
| Pooling | different policy | never share |
| Risk | normal → high | isolate |
| Audit | request | principal recoverable |
| Failure | gateway down | documented fail-safe |
| Failure | policy service down | documented fail-safe |
| Scale | 100K+ agents | measured |
| Scale | 1M identities | measured/projected |

---

# 37. Success Criteria

Phase 6 succeeds if the prototype demonstrates:

### Identity
- cryptographically verified agent identity,
- human delegation,
- session identity,
- credential lifecycle.

### Policy
- attribute-based policy,
- policy classes,
- high-risk isolation,
- dynamic policy changes.

### Enforcement
- actual network enforcement,
- correct allow/deny behavior,
- no cross-policy pooling.

### Security
- fail-closed behavior,
- bounded revocation,
- route integrity,
- policy-version integrity.

### Observability
- complete audit trail,
- useful flow correlation,
- security events.

### Scalability
- measured operation at large agent counts,
- bounded policy and connection overhead.

---

# 38. What Phase 6 Must NOT Do

Do not:

- invent a new protocol,
- assume every agent needs a unique connection,
- assume every agent can safely share a connection,
- assume L7 identity is automatically visible to L4,
- trust client-supplied identity headers,
- treat audit logs as equivalent to network attribution,
- claim Cilium behavior from a generic eBPF experiment,
- claim a universal Envoy vulnerability from one configuration,
- claim a new cryptographic standard is necessary.

---

# 39. Deliverables

Produce:

1. Complete architecture document
2. Threat model
3. Agent identity model
4. Human → agent → session model
5. Policy model
6. Policy-class model
7. Envoy configuration
8. eBPF/Cilium integration
9. Identity integration
10. Revocation implementation
11. Fail-open regression tests
12. Audit schema
13. Control-plane API
14. Data-plane design
15. Scalability benchmark
16. Security attack results
17. Availability/failure results
18. Prototype
19. Deployment model
20. Competitive comparison
21. Product requirements
22. Remaining technical risks

---

# 40. Final Phase 6 Decision

At the end of Phase 6, choose:

```text
PROTOTYPE → PILOT
```

or:

```text
PROTOTYPE → MORE ENGINEERING
```

or:

```text
RESEARCH GAP REOPENED
```

The third outcome should only be selected if implementation exposes a genuinely new technical problem.

---

# 41. Product Direction

If Phase 6 succeeds, the working product is a corporate AI-agent security platform:

```text
                 AI AGENT
                    |
                    v
             Identity Layer
                    |
                    v
             Session Layer
                    |
                    v
             Risk Engine
                    |
                    v
             Policy Engine
                    |
           +--------+--------+
           |                 |
       High Risk          Normal
           |                 |
           v                 v
      Per-Agent          Policy Class
       Isolation           Pooling
           |                 |
           +--------+--------+
                    |
                    v
             Network Layer
                    |
              eBPF / Cilium
                    |
          +---------+---------+
          |                   |
       Internet           Corporate
```

The product hypothesis is:

> **A corporate security control plane that understands the human → AI-agent → session relationship and safely translates that context into scalable network policy and enforcement.**

---

# 42. Final Principle

The first five phases tried to determine whether a new protocol was required.

Phase 6 should determine whether the **tool itself is practical**.

The target is:

> **Secure large numbers of AI-agent sessions in a corporate environment without requiring a unique network rule or connection for every agent, while preserving strong identity, policy correctness, revocation, auditability, and fail-closed enforcement.**

If existing components can deliver this safely:

> integrate them.

If implementation exposes a genuinely missing capability:

> research that capability.

Do not create a protocol merely because the original research started with one.
