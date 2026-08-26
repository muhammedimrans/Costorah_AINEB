# Phase 5 --- Final Technical Validation: Cilium/eBPF, Real Agent Identity, and HTTP/3/QUIC

## Project Scope

This research is for a **new corporate-network security tool for
managing and enforcing security policy around AI agents**.

It is **not related to Zero Protocol**.

The purpose of Phase 5 is to close the three major technical gaps
remaining after Phase 4B and determine whether the current research has
a defensible systems/security contribution.

Phase 4B used real Envoy 1.31.0, real TLS, real HTTP/2, and an upstream
wire observer.

The strongest current finding is:

> Encrypted HTTP/2 multiplexing can provide substantial
> connection/resource efficiency while preventing a downstream L3/L4
> observer from recovering individual application-level principal
> attribution.

Phase 4B also established:

-   HTTP/1.1 required substantially more upstream connections under
    concurrency.
-   HTTP/2 remained near the policy-class connection count.
-   HTTP/2 stream IDs were visible to a cleartext observer but
    completely opaque under TLS.
-   Envoy 1.31.0 did not expose `UPSTREAM_STREAM_ID`.
-   The tested stock `envoy.string` filter-state path did not partition
    the upstream pool by principal, including with TLS.
-   Correct RDS revocation worked after atomic configuration
    propagation.
-   An in-place RDS file update failed to propagate in the tested
    configuration.
-   Cilium/eBPF was not tested.
-   Real WPT/SPIFFE identity was not tested.
-   HTTP/3/QUIC was not tested.
-   Hybrid pooling was not tested.

The Phase 5 goal is **validation and falsification**, not protocol
design.

------------------------------------------------------------------------

# 1. Phase 5 Research Questions

## RQ1 --- Cilium/eBPF Enforcement

Can a real Cilium/eBPF enforcement datapath enforce the desired
corporate-network policy after Envoy has verified an AI-agent principal?

Specifically:

> Does Cilium provide an existing identity/enforcement mechanism that
> makes the Phase 4B attribution problem irrelevant?

If yes, the current research gap may be closed.

------------------------------------------------------------------------

## RQ2 --- Real Agent Identity

Does replacing a trusted test header with real cryptographic identity
change the architecture or the observed behavior?

Test:

-   SPIFFE/SVID
-   SPIFFE JWT-SVID
-   WIMSE/WPT
-   OAuth/OIDC where appropriate

Determine exactly where:

``` text
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
Network policy
```

is established.

------------------------------------------------------------------------

## RQ3 --- HTTP/3 / QUIC

Does the Phase 4B result generalize to HTTP/3/QUIC?

Investigate:

-   encrypted multiplexing
-   QUIC connection IDs
-   stream IDs
-   connection migration
-   network-observer visibility
-   connection pooling
-   policy-class pooling
-   attribution
-   enforcement

Do not assume TCP/HTTP2 results apply to QUIC.

------------------------------------------------------------------------

## RQ4 --- Hybrid Enforcement

Can a corporate network tool selectively use:

``` text
High-risk agents
      ↓
per-principal isolation

Normal agents
      ↓
policy-class pooling
```

while maintaining correct enforcement and acceptable infrastructure
cost?

------------------------------------------------------------------------

## RQ5 --- Final Research Gap

After these experiments:

> Is there still a meaningful technical problem that existing Envoy,
> Cilium, SPIFFE/SPIRE, WIMSE, service meshes, SASE products, and
> AI-agent security products do not adequately solve?

If no, stop.

If yes, define the smallest remaining problem.

Do not automatically propose a new protocol.

------------------------------------------------------------------------

# 2. Phase 5 Decision Tree

``` text
                    PHASE 5
                       |
          +------------+------------+
          |                         |
     Existing systems          Genuine gap
        solve it                  remains
          |                         |
          ▼                         ▼
   RESEARCH CLOSED          Define exact gap
                                      |
                              +-------+-------+
                              |               |
                         Engineering      Research
                          problem         contribution
                              |               |
                              ▼               ▼
                         Tool design      Measurement /
                                         systems paper
```

A protocol should only be considered if the experiments demonstrate a
genuinely missing interoperable interface.

------------------------------------------------------------------------

# 3. Experiment Environment

Build:

``` text
                         Corporate Agent
                               |
                               v
                    +----------------------+
                    | Agent Runtime        |
                    |                      |
                    | Agent A / B / C      |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Envoy / Agent Gateway|
                    |                      |
                    | Identity verification|
                    | Authorization        |
                    | Policy classification|
                    +----------+-----------+
                               |
                         TLS / HTTP2
                               |
                               v
                    +----------------------+
                    | Cilium / eBPF        |
                    | L3/L4 enforcement    |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Protected Service    |
                    +----------------------+
```

If available, add:

``` text
SPIFFE/SPIRE
WIMSE/WPT
OpenTelemetry
Cilium Hubble
```

------------------------------------------------------------------------

# 4. Test 1 --- Real Cilium/eBPF Baseline

## Objective

Determine whether Cilium already solves the remaining enforcement
problem.

Start with ordinary network identities.

Test:

``` text
Agent A → ALLOW
Agent B → DENY
Agent C → RESTRICT
```

where the three agents have different network identities.

Record:

-   Cilium policy
-   endpoint identity
-   flow logs
-   verdict
-   source/destination
-   connection
-   latency

------------------------------------------------------------------------

# 5. Test 2 --- Cilium With Policy-Class Pooling

Create:

``` text
Agent A ─┐
Agent B ─┼── policy class ALLOW
Agent C ─┘
```

and:

``` text
Agent D ─┐
Agent E ─┼── policy class DENY
Agent F ─┘
```

Test whether Cilium can correctly enforce:

``` text
A → ALLOW
B → ALLOW
C → ALLOW

D → DENY
E → DENY
F → DENY
```

while the principals in each class share upstream connections.

Measure:

-   number of connections
-   Cilium identities
-   enforcement verdicts
-   flow attribution
-   false allows
-   false denies

------------------------------------------------------------------------

# 6. Test 3 --- Same Network Identity, Different L7 Principal

This is the critical falsification test.

Create:

``` text
Alice
Bob
Carol
```

with:

``` text
same process
same IP
same network identity
same policy class
same HTTP/2 connection
```

but distinct application principals.

Ask:

> Can Cilium independently distinguish Alice, Bob and Carol?

If yes:

-   determine exactly how
-   determine whether it uses L7 inspection
-   determine whether it relies on Envoy metadata
-   determine whether it uses socket/cgroup identity
-   determine whether it requires separate endpoints

If no:

> Confirm the Phase 4B attribution boundary.

------------------------------------------------------------------------

# 7. Test 4 --- Cilium L7 Capabilities

Determine whether enabling Cilium L7 policy changes the result.

Compare:

### L4 only

``` text
Cilium
  ↓
5-tuple / network identity
```

### L7 aware

``` text
Cilium
  ↓
HTTP-aware policy
```

Determine whether the second architecture can recover the principal.

If yes, determine the cost:

-   proxying
-   TLS termination
-   CPU
-   latency
-   memory
-   protocol restrictions

Do not classify L7-aware enforcement as equivalent to a pure L3/L4
firewall.

------------------------------------------------------------------------

# 8. Test 5 --- Real SPIFFE/SPIRE Identity

Replace the trusted principal header.

Use:

``` text
SPIFFE/SPIRE
```

where possible.

Test:

``` text
Human A
   ↓
Agent A
   ↓
SPIFFE identity
   ↓
Envoy
```

and:

``` text
Human B
   ↓
Agent B
   ↓
SPIFFE identity
   ↓
Envoy
```

Determine:

-   credential issuance
-   credential lifetime
-   rotation
-   verification
-   identity propagation
-   policy classification

Important question:

> Does real cryptographic identity change the connection/attribution
> problem, or only make the identity verification trustworthy?

------------------------------------------------------------------------

# 9. Test 6 --- WIMSE/WPT

If a suitable implementation is available, repeat the experiment using
WIMSE/WPT.

Verify:

``` text
delegating principal
+
agent identity
+
session identity
+
request
```

Determine whether the verified WPT can be propagated into:

-   Envoy
-   policy engine
-   Cilium
-   network enforcement

Do not assume WPT provides network-layer enforcement.

The test must explicitly identify the boundary between:

``` text
verified application identity
```

and:

``` text
network enforcement identity
```

------------------------------------------------------------------------

# 10. Test 7 --- Identity Spoofing

Attempt to spoof:

-   principal
-   agent ID
-   session ID
-   policy class
-   WPT
-   SPIFFE identity

Expected result:

``` text
spoofed identity → rejected
```

Test whether policy classification occurs only after cryptographic
verification.

------------------------------------------------------------------------

# 11. Test 8 --- HTTP/3 / QUIC

Deploy Envoy with HTTP/3 where supported.

Test:

``` text
many principals
      ↓
few policy-class connections
      ↓
HTTP/3/QUIC
```

Record:

-   QUIC connection count
-   stream count
-   connection IDs
-   stream IDs
-   migration
-   TLS encryption
-   packet visibility
-   attribution

Compare against HTTP/2:

  Property            HTTP/1.1   HTTP/2   HTTP/3
  ------------------- ---------- -------- --------
  Multiplexing                            
  Encryption                              
  Stream visibility                       
  Connection count                        
  Attribution                             
  Migration                               

------------------------------------------------------------------------

# 12. Test 9 --- QUIC Connection Migration

This is mandatory if HTTP/3 is supported.

Change the client's network path where possible.

Determine whether:

``` text
connection ID
```

remains stable while:

``` text
source IP / port
```

changes.

Test whether the enforcement system can maintain correct policy.

Important question:

> Does QUIC make 5-tuple-based attribution even less reliable?

------------------------------------------------------------------------

# 13. Test 10 --- HTTP/3 Attribution

Attempt the same observation strategy used in Phase 4B.

Determine:

-   whether stream IDs are visible
-   whether connection IDs are visible
-   whether TLS hides application identity
-   whether a network observer can associate a stream with a principal
-   whether Envoy exposes a join key
-   whether any metadata can bridge the layers

Do not assume HTTP/2 conclusions automatically apply.

------------------------------------------------------------------------

# 14. Test 11 --- Hybrid Policy Architecture

Implement:

``` text
HIGH_RISK
   ↓
per-principal connection

NORMAL
   ↓
policy-class connection
```

Example:

``` text
1,000 agents

50 HIGH_RISK
950 NORMAL

4 NORMAL policy classes
```

Expected approximate connection structure:

``` text
50 individual
+
4 policy-class
=
54
```

Compare against:

``` text
1,000 individual
```

and:

``` text
4 policy-class
```

Measure:

-   enforcement correctness
-   attribution
-   connections
-   CPU
-   memory
-   latency
-   revocation

------------------------------------------------------------------------

# 15. Test 12 --- Risk Escalation

A normal pooled agent may become high-risk.

Test:

``` text
Agent A
NORMAL
  ↓
risk increases
  ↓
HIGH_RISK
  ↓
per-principal isolation
```

Determine:

-   connection migration
-   old connection reuse
-   policy propagation
-   stale authorization window
-   audit continuity

The transition must not create:

``` text
HIGH_RISK agent
      ↓
old shared connection
      ↓
NORMAL privileges
```

------------------------------------------------------------------------

# 16. Test 13 --- Revocation

Repeat Phase 4B revocation with real identity and Cilium.

Test:

``` text
Alice → ALLOW
Bob → ALLOW
```

Then:

``` text
Alice → REVOKED
Bob → ALLOW
```

Measure:

-   propagation time
-   connection behavior
-   Cilium policy update
-   Envoy policy update
-   stale requests
-   stale connections

Test both:

``` text
atomic configuration update
```

and:

``` text
in-place update
```

Document whether the in-place behavior is specific to the tested
Envoy/RDS configuration.

Do not generalize beyond the evidence.

------------------------------------------------------------------------

# 17. Test 14 --- Failure Modes

Test:

### Identity service unavailable

Expected:

``` text
fail closed
```

or explicitly document why another behavior is required.

### Policy service unavailable

Test:

-   new requests
-   existing connections
-   cached policies

### Envoy restart

Test identity and connection reconstruction.

### Cilium restart

Test enforcement continuity.

### SPIRE restart

Test existing and new credentials.

### WPT verification failure

Test whether requests are rejected.

------------------------------------------------------------------------

# 18. Test 15 --- Attack Scenarios

Test:

### A. Principal spoofing

### B. Agent identity spoofing

### C. Credential replay

### D. Stolen credential

### E. Session confusion

### F. Connection reuse after revocation

### G. HTTP/2 stream confusion

### H. QUIC connection migration abuse

### I. Policy-class collision

### J. Compromised gateway

### K. Compromised local agent

### L. Host-root attacker

For each attack identify:

``` text
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

------------------------------------------------------------------------

# 19. Test 16 --- Attribution vs Enforcement

Separate these properties rigorously.

## Enforcement correctness

Can the system correctly decide:

``` text
ALLOW
DENY
RESTRICT
```

?

## Attribution

Can the system identify:

``` text
exact human
+
exact agent
+
exact session
+
exact request
```

?

## Audit completeness

Can logs reconstruct:

``` text
human
agent
session
request
destination
decision
```

?

These are not the same property.

Build:

  Architecture      Enforcement   Network attribution   L7 audit
  ----------------- ------------- --------------------- ----------
  H1 policy-class                                       
  H2 policy-class                                       
  H2 + TLS                                              
  H3 + TLS                                              
  Per-principal                                         
  Hybrid                                                

------------------------------------------------------------------------

# 20. Test 17 --- Resource Scaling

Measure:

``` text
N = 10
100
1,000
10,000
```

and where possible:

``` text
50,000
100,000
```

Compare:

### Per-principal

``` text
connections
≈ N × concurrency
```

subject to actual Envoy pooling behavior.

### Policy-class

``` text
connections
≈ P × protocol/concurrency behavior
```

### Hybrid

``` text
connections
≈ high-risk principals
+
policy-class resources
```

Do not assume mathematical scaling before measurement.

Plot:

``` text
connections vs principals
connections vs concurrency
connections vs policy classes
```

------------------------------------------------------------------------

# 21. Test 18 --- Performance

Measure:

-   p50 latency
-   p95 latency
-   p99 latency
-   throughput
-   CPU
-   memory
-   file descriptors
-   connection creation
-   TLS handshakes
-   Cilium overhead
-   Envoy overhead

Compare:

``` text
H1 per-principal
H1 policy-class
H2 per-principal
H2 policy-class
H3 policy-class
hybrid
```

------------------------------------------------------------------------

# 22. Test 19 --- Corporate Network Scenario

Construct a realistic enterprise scenario:

``` text
Corporate user
      ↓
AI agent
      ↓
Corporate agent gateway
      ↓
Internet
```

Create policies:

``` text
Agent A
→ GitHub allowed
→ production blocked

Agent B
→ GitHub blocked
→ approved SaaS allowed

Agent C
→ internet denied
→ internal services only
```

Test whether these policies remain correct under:

-   HTTP/1.1
-   HTTP/2
-   HTTP/3
-   TLS
-   connection reuse
-   revocation
-   risk escalation

------------------------------------------------------------------------

# 23. External Agent Admission Scenario

Test the original enterprise requirement:

``` text
Internal approved agent
        ↓
Corporate boundary
        ↓
ALLOW
```

versus:

``` text
External/untrusted agent
        ↓
Corporate boundary
        ↓
DENY
```

Determine whether existing Zero Trust controls already solve this part.

The research should not claim that the new tool is required for ordinary
user/network authentication if existing controls already provide it.

Focus on the AI-agent-specific layer:

``` text
human
+
agent
+
delegation
+
session
+
runtime
+
policy
```

------------------------------------------------------------------------

# 24. Prior-Art Challenge

Re-check the final architecture against:

-   Envoy
-   Cilium
-   Tetragon
-   SPIFFE/SPIRE
-   WIMSE
-   Istio
-   service meshes
-   MCP security
-   A2A security
-   Microsoft
-   Palo Alto
-   Zscaler
-   Cisco
-   Fortinet
-   Check Point
-   Cloudflare
-   Okta
-   AI gateways
-   SASE

For each determine:

``` text
Identity
Session identity
Delegation
Connection partitioning
Policy enforcement
Network enforcement
Attribution
Revocation
Scaling
```

Classify evidence:

``` text
Documented
Demonstrated
Inferred
Unknown
```

Do not call a capability absent merely because marketing documentation
does not mention it.

------------------------------------------------------------------------

# 25. Critical Falsification Questions

Phase 5 must attempt to destroy the remaining research.

### F1

Can Cilium already distinguish the principals?

### F2

Can Envoy already preserve enough identity metadata to make the problem
disappear?

### F3

Can WIMSE already provide a standardized identity-to-enforcement
mechanism?

### F4

Can SPIFFE/SPIRE already solve the required binding?

### F5

Can HTTP/3 provide a transport-level attribution mechanism that
invalidates the HTTP/2 result?

### F6

Can existing AI gateways already provide the complete enterprise
architecture?

### F7

Is the connection/attribution trade-off already well understood in
existing literature?

### F8

Is the problem simply an unavoidable consequence of encryption and
multiplexing rather than a new systems problem?

If the answer to F8 is yes:

> Do not claim to have invented the phenomenon.

Instead identify whether the contribution is a useful measurement,
architecture, implementation, or operational control.

------------------------------------------------------------------------

# 26. Final Research Outcome

At the end of Phase 5, return exactly one:

``` text
RESEARCH CLOSED
```

or

``` text
MEASUREMENT PAPER OPPORTUNITY
```

or

``` text
SYSTEMS RESEARCH OPPORTUNITY
```

or

``` text
CORPORATE AI-AGENT SECURITY TOOL OPPORTUNITY
```

or, only with strong evidence:

``` text
PROTOCOL RESEARCH OPPORTUNITY
```

------------------------------------------------------------------------

# 27. If a Corporate Tool Opportunity Remains

If the experiments demonstrate a useful gap, do NOT immediately design a
protocol.

First define the tool as a set of capabilities:

``` text
1. Agent identity verification
2. Human → agent delegation tracking
3. Session tracking
4. Risk classification
5. Policy classification
6. L7 gateway enforcement
7. L3/L4 enforcement integration
8. Per-principal isolation for high-risk agents
9. Policy-class pooling for normal agents
10. Audit correlation
11. Revocation
12. Continuous risk escalation
13. Agent discovery
14. External-agent admission control
```

Determine which capabilities are:

``` text
existing technology
+
integration gap
+
genuine missing capability
```

Only the last category should become a research target.

------------------------------------------------------------------------

# 28. Deliverables

Produce:

1.  Phase 5 executive report
2.  Cilium/eBPF test configuration
3.  Cilium flow results
4.  Real identity test results
5.  WPT/SPIFFE results
6.  HTTP/3/QUIC results
7.  Hybrid pooling results
8.  Revocation results
9.  Risk-escalation results
10. Attack results
11. Scaling measurements
12. Performance measurements
13. Attribution measurements
14. Enforcement measurements
15. Prior-art matrix
16. Updated architecture
17. Remaining research gap
18. Final research classification
19. Recommendation for the corporate AI-agent security tool
20. Recommended Phase 6 only if evidence requires it

------------------------------------------------------------------------

# 29. Important Scope Rule

This project is a **separate corporate-network AI-agent security
research project**.

Do not reference, merge, reuse, or optimize the architecture for Zero
Protocol.

The target environment is:

``` text
Enterprise
   ↓
Users
   ↓
AI agents
   ↓
Agent runtimes
   ↓
Corporate network
   ↓
Internet / SaaS / internal services
```

The objective is to determine how a corporate network can:

-   identify trusted AI agents,
-   distinguish their sessions and delegation,
-   enforce network policy,
-   prevent unauthorized external agents,
-   monitor agent traffic,
-   revoke access,
-   handle millions of agents,
-   and maintain useful attribution without creating an impractical
    number of network connections.

------------------------------------------------------------------------

# 30. Final Principle

> **Do not build a new protocol unless Phase 5 demonstrates that
> existing identity, gateway, service-mesh, eBPF, and
> network-enforcement mechanisms cannot provide the required corporate
> AI-agent security capability.**

The goal is not to prove the original idea.

The goal is to discover the smallest technically real problem that
remains after four rounds of falsification.
