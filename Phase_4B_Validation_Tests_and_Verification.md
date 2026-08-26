# Phase 4B --- Validation Tests After Real Envoy Results

## Objective

Phase 4 real-Envoy testing changed the research direction.

The following results are now established on Envoy 1.31.0:

-   Principal-based partitioning through the tested stock `envoy.string`
    hashable-filter-state path did **not** work.
-   Per-principal cluster routing did partition connections correctly.
-   Policy-class routing produced connection counts proportional to the
    number of policy classes rather than the number of principals.
-   HTTP/1.1 upstream traffic achieved 100% exact network attribution in
    the tested setup.
-   HTTP/2 upstream traffic reduced connections substantially but
    produced significant attribution ambiguity.
-   Envoy audit logs retained principal identity for both protocols.

Phase 4B must validate the remaining uncertainties before making any
novelty or research-contribution claim.

## Current Hypothesis

> **Transport multiplexing, rather than pooling alone, determines the
> loss of network-layer principal attribution.**

The current observed result is:

``` text
HTTP/1.1
policy-class pooling
    ↓
serial requests per connection
    ↓
exact network attribution

HTTP/2
policy-class pooling
    ↓
multiple streams per connection
    ↓
substantial network attribution ambiguity
```

This hypothesis must be tested, not assumed.

------------------------------------------------------------------------

# 1. Phase 4B Research Questions

### RQ1 --- HTTP/2 Stream Correlation

Can HTTP/2 stream identifiers recover the attribution that was lost when
multiple principals shared one upstream connection?

### RQ2 --- TLS

Does enabling TLS change Envoy's connection-pool behavior or the
observed attribution characteristics?

### RQ3 --- Real L4 Enforcement

Does the result survive when the modeled 5-tuple enforcement is replaced
with actual Cilium/eBPF enforcement?

### RQ4 --- Real Identity

Does replacing the trusted principal header with a real identity
mechanism such as WIMSE/WPT or SPIFFE/SVID change the result?

### RQ5 --- Revocation and Policy Churn

What happens when a principal changes authorization while sharing a
policy-class connection?

### RQ6 --- Hybrid Pooling

Can high-risk principals receive exact attribution while low-risk
principals use policy-class pooling?

### RQ7 --- Attribution Recovery

Can OpenTelemetry, Envoy logs, HTTP/2 stream IDs, timestamps, connection
IDs, or other metadata recover exact principal attribution without
requiring one connection per principal?

### RQ8 --- Novelty

After these experiments, is there still a technically meaningful and
insufficiently solved research problem?

------------------------------------------------------------------------

# 2. Test Matrix

Run the following matrix where technically feasible:

  Test   Protocol   TLS   Identity             Pool key        L4 enforcement
  ------ ---------- ----- -------------------- --------------- ----------------
  A      HTTP/1.1   No    Header               Policy class    Modeled
  B      HTTP/2     No    Header               Policy class    Modeled
  C      HTTP/2     No    Header + stream ID   Policy class    Modeled
  D      HTTP/2     Yes   Header               Policy class    Modeled
  E      HTTP/2     Yes   Header + stream ID   Policy class    Modeled
  F      HTTP/2     Yes   Real identity        Policy class    Cilium
  G      HTTP/2     Yes   Real identity        Per principal   Cilium
  H      HTTP/2     Yes   Real identity        Policy class    Cilium
  I      HTTP/2     Yes   Real identity        Hybrid          Cilium

Do not fabricate results for unsupported configurations. Mark them
`NOT TESTED`.

------------------------------------------------------------------------

# 3. Test 1 --- HTTP/2 Stream-ID Correlation

## Goal

Determine whether the 89% attribution ambiguity observed under HTTP/2 is
merely an artifact of using:

``` text
5-tuple + timestamp
```

rather than the HTTP/2 stream identifier.

## Experiment

Generate traffic from multiple principals:

``` text
Alice
Bob
Carol
Dave
```

using the same:

-   downstream connection
-   upstream policy class
-   upstream HTTP/2 connection

Ensure multiple streams are concurrently active.

Record at Envoy:

-   principal
-   request ID
-   HTTP/2 stream ID
-   upstream connection
-   start time
-   end time
-   duration
-   destination

Record at the network observation point:

-   timestamp
-   5-tuple
-   connection identity if available
-   packet/segment timing
-   HTTP/2 stream ID if visible

## Test A

Cleartext HTTP/2.

Determine whether stream IDs allow exact mapping:

``` text
network event
      ↓
HTTP/2 stream
      ↓
request
      ↓
principal
```

## Test B

TLS-encrypted HTTP/2.

Determine whether the network observer can see the stream ID.

Expected question:

> Does TLS remove the stream-level observability needed for network-only
> attribution?

## Metrics

Calculate:

``` text
exact_attribution_rate
ambiguity_rate
unknown_rate
```

Compare:

``` text
5-tuple only
```

against:

``` text
5-tuple + stream ID
```

## Important

Do not claim that stream IDs solve network attribution unless the actual
enforcement/observer can obtain them at the relevant point.

------------------------------------------------------------------------

# 4. Test 2 --- TLS Validation

## Goal

Determine whether TLS changes the Envoy connection-pooling behavior.

The previous experiment used cleartext upstream traffic.

The pool-key mechanism being investigated is related to transport-socket
options, so TLS must be explicitly tested.

## Tests

Run:

### TLS + HTTP/1.1

``` text
policy-class pool
+
TLS
+
HTTP/1.1
```

### TLS + HTTP/2

``` text
policy-class pool
+
TLS
+
HTTP/2
```

### TLS + per-principal routing

Positive control.

## Measure

-   upstream connection count
-   connection reuse
-   protocol
-   policy class
-   principal
-   latency
-   attribution

## Acceptance

Determine whether TLS changes:

``` text
O(P)
```

connection scaling or the attribution result.

------------------------------------------------------------------------

# 5. Test 3 --- Real Cilium/eBPF Enforcement

## Goal

Replace the modeled L4 enforcement with an actual datapath.

Environment:

``` text
Agent clients
      ↓
Envoy
      ↓
Cilium/eBPF
      ↓
Protected service
```

The Cilium enforcement point must not consume:

-   HTTP principal headers
-   WPT
-   JWT
-   application identity

unless the experiment explicitly tests a L7-aware Cilium capability.

The baseline should use only L3/L4/network identity.

## Tests

### Test 3A --- Per-principal

``` text
Alice → ALLOW
Bob   → DENY
Carol → RESTRICT
```

with separate network identities/connections.

### Test 3B --- Policy-class

``` text
Alice + Bob + Carol
        ↓
same policy class
        ↓
shared upstream connection
```

Verify that enforcement remains correct.

### Test 3C --- Incorrect pooling control

Put principals with different policies on the same network
identity/connection.

Verify whether the enforcement point incorrectly treats them
identically.

This establishes the security boundary.

------------------------------------------------------------------------

# 6. Test 4 --- Real Workload Identity

Replace:

``` text
x-agent-principal: alice
```

with an actual verified identity.

Test one or more:

-   SPIFFE SVID
-   SPIFFE JWT-SVID
-   WIMSE WPT
-   OAuth/OIDC token
-   another cryptographically verifiable mechanism

The identity verifier must independently validate the credential.

Do not trust an arbitrary client-supplied identity header.

## Required identity chain

Demonstrate:

``` text
Human
  ↓
Agent
  ↓
Session
  ↓
Credential
  ↓
Envoy verification
  ↓
Principal
  ↓
Policy class
  ↓
Network enforcement
```

Record exactly where identity is verified.

------------------------------------------------------------------------

# 7. Test 5 --- Revocation

This is a security-critical test.

Initial state:

``` text
Alice → ALLOW
Bob   → ALLOW
```

Then revoke Alice:

``` text
Alice → DENY
Bob   → ALLOW
```

while both belong to the same policy class before revocation.

Measure:

-   time to enforcement
-   existing connection behavior
-   new request behavior
-   connection eviction
-   connection reuse
-   Envoy cache state
-   policy distribution delay
-   Cilium policy update delay

## Critical Question

If Alice and Bob share an upstream connection:

> How does the system prevent Alice from continuing to use Bob's
> authorization after Alice's policy changes?

Repeat:

``` text
ALLOW → DENY
DENY → ALLOW
LOW_RISK → HIGH_RISK
```

------------------------------------------------------------------------

# 8. Test 6 --- Policy-Class Safety

Define policy equivalence formally.

Two principals may share a connection only if:

``` text
Policy(A) == Policy(B)
```

for every property enforced at that network boundary.

Test equivalence across:

-   destination
-   protocol
-   port
-   region
-   data classification
-   rate limit
-   bandwidth
-   time
-   risk
-   user privilege
-   agent privilege
-   device posture
-   workload posture

Determine whether a stable policy class is practical.

------------------------------------------------------------------------

# 9. Test 7 --- Hybrid Pooling

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
100 principals
20 high-risk
80 normal

P = 4 policy classes
```

Compare:

### All per-principal

``` text
~100 connections
```

### All policy-class

``` text
~4 connections
```

### Hybrid

``` text
20 individual
+
4 policy classes
=
~24 connections
```

Measure:

-   connection count
-   attribution
-   enforcement correctness
-   CPU
-   memory
-   latency

Determine whether the hybrid architecture provides a useful trade-off.

------------------------------------------------------------------------

# 10. Test 8 --- Attribution Recovery

Under HTTP/2 policy-class pooling, test all available correlation
mechanisms:

-   HTTP/2 stream ID
-   Envoy request ID
-   downstream connection ID
-   upstream connection ID
-   trace ID
-   OpenTelemetry span ID
-   timestamps
-   source port
-   destination port
-   packet timing
-   byte ranges
-   gateway audit logs
-   Cilium flow logs

For each mechanism calculate:

``` text
exact attribution rate
ambiguity rate
correlation latency
correlation failures
```

Build:

  Signal          L7 available   L4 available   Exact attribution   TLS-safe
  --------------- -------------- -------------- ------------------- ----------
  Principal       Yes            No                                 
  Request ID                                                        
  Stream ID                                                         
  5-tuple                        Yes                                
  Timestamp                      Yes                                
  Trace ID                                                          
  Connection ID                                                     

Do not assume that a signal visible at Envoy is visible at the network
enforcement point.

------------------------------------------------------------------------

# 11. Test 9 --- Scale

Minimum target:

``` text
N = 10
N = 100
N = 1,000
N = 10,000
```

If resources permit:

``` text
N = 50,000
N = 100,000
```

Policy classes:

``` text
P = 1
P = 2
P = 4
P = 10
P = 50
P = 100
```

Measure:

``` text
connections
file descriptors
CPU
memory
latency
throughput
```

Validate:

``` text
per-principal:
connections ≈ O(N)
```

and:

``` text
policy-class:
connections ≈ O(P)
```

Do not extrapolate beyond measured data without labeling it as
extrapolation.

------------------------------------------------------------------------

# 12. Test 10 --- HTTP/1.1 Concurrency

The Phase 4 result showed:

``` text
HTTP/1.1
112 connections
1.0 exact attribution
```

Determine whether the 112 connections are caused by:

-   concurrency
-   connection pool configuration
-   keep-alive settings
-   max requests per connection
-   upstream service behavior

Run:

``` text
concurrency = 1
4
8
16
32
64
```

Measure:

``` text
connections vs concurrency
```

Determine whether:

``` text
HTTP/1.1 policy-class pooling
```

is actually:

``` text
O(concurrency)
```

rather than:

``` text
O(P)
```

This is important for the final scaling model.

------------------------------------------------------------------------

# 13. Test 11 --- HTTP/2 Concurrency

Repeat the same concurrency sweep:

``` text
1
4
8
16
32
64
128
```

Measure:

-   connections
-   concurrent streams
-   principals per connection
-   attribution
-   latency

Determine whether HTTP/2 provides a resource advantage at the cost of
attribution.

------------------------------------------------------------------------

# 14. Test 12 --- HTTP/3 / QUIC

If Envoy and the environment support it, repeat the experiment using
HTTP/3.

Investigate:

-   connection IDs
-   stream IDs
-   stream multiplexing
-   TLS
-   network observer visibility
-   connection reuse
-   policy-class pooling
-   attribution

The question is:

> Does QUIC improve, worsen, or fundamentally change the attribution
> problem?

Do not assume TCP results apply to QUIC.

------------------------------------------------------------------------

# 15. Test 13 --- Non-HTTP Traffic

Test:

-   raw TCP
-   UDP
-   non-HTTP application protocols

Determine whether policy-class pooling and attribution concepts apply.

If the architecture requires an L7 gateway, document this as an explicit
scope limitation.

------------------------------------------------------------------------

# 16. Test 14 --- Security Attacks

Attempt:

### A. Identity confusion

Alice attempts to reuse Bob's authorization.

### B. Pool-key collision

Two principals attempt to enter the same policy class despite different
effective policies.

### C. Stale authorization

Alice is revoked while the connection remains open.

### D. Request migration

A retry or connection failure causes a request to move to another
upstream connection.

### E. HTTP/2 stream confusion

Verify that stream identity cannot accidentally cross principals.

### F. Gateway compromise

Determine what happens if Envoy's identity verifier is compromised.

### G. Policy-service failure

Determine fail-open/fail-closed behavior.

------------------------------------------------------------------------

# 17. Phase 4B Metrics

Every experiment should report:

## Enforcement

``` text
correct_enforcement_rate
false_allow_rate
false_deny_rate
```

## Attribution

``` text
exact_attribution_rate
ambiguity_rate
unknown_rate
```

## Audit

``` text
audit_completeness
```

## Resource cost

``` text
upstream_connections
file_descriptors
CPU
memory
```

## Performance

``` text
p50
p95
p99
throughput
```

## Security

``` text
revocation_delay
policy_propagation_delay
stale_authorization_window
```

------------------------------------------------------------------------

# 18. Required Comparison

Produce this table from actual measurements:

  --------------------------------------------------------------------------------------------------------
  Architecture    Protocol   TLS       Connections Enforcement   Attribution   Audit         CPU    Memory
  --------------- ---------- ------- ------------- ------------- ------------- ------- --------- ---------
  Shared          H1         No                                                                  

  Policy-class    H1         No                                                                  

  Policy-class    H2         No                                                                  

  Policy-class    H2         Yes                                                                 

  Per-principal   H2         Yes                                                                 

  Hybrid          H2         Yes                                                                 
  --------------------------------------------------------------------------------------------------------

Do not fill missing cells with assumptions.

------------------------------------------------------------------------

# 19. Prior-Art Verification

Re-check the current research against primary sources.

Specifically investigate:

### Envoy

-   `Hashable`
-   `StringAccessorImpl`
-   transport socket options
-   connection pool key
-   shared filter state
-   ext_authz
-   connection pool partitioning

### Cilium

-   network identity
-   endpoint identity
-   eBPF enforcement
-   L7/L4 policy
-   socket identity

### WIMSE

-   WPT
-   workload identity
-   transaction identity
-   delegation
-   request identity

### SPIFFE/SPIRE

-   workload identity
-   SVID
-   Envoy integration
-   dynamic identity

### Service meshes

-   Istio
-   Linkerd
-   other workload-identity systems

### AI gateways

Research current capabilities of:

-   Microsoft
-   Palo Alto
-   Zscaler
-   Cisco
-   Fortinet
-   Check Point
-   Cloudflare
-   Okta
-   Envoy/agentgateway
-   Kong
-   Tyk
-   other major AI gateways

Classify every finding:

``` text
Documented
Demonstrated
Inferred
Unknown
```

Do not claim absence from documentation alone.

------------------------------------------------------------------------

# 20. Critical Prior-Art Question

Search specifically for:

-   multiplexed identity attribution
-   HTTP/2 identity attribution
-   principal-aware connection pooling
-   policy-aware connection pooling
-   workload identity connection pooling
-   identity-preserving multiplexing
-   connection amplification
-   per-user connection pooling
-   service mesh connection scaling
-   policy-equivalence classes
-   network attribution
-   flow-to-principal correlation

The specific hypothesis to challenge is:

> **The attribution cost of multiplexed security principals is a
> measurable function of the upstream protocol, and policy-class pooling
> can reduce connection cost while changing network-level attribution
> granularity.**

Determine whether this exact relationship has already been
characterized.

------------------------------------------------------------------------

# 21. What Would Falsify the Research?

The current research should be considered closed if:

1.  HTTP/2 stream-level information provides reliable network
    attribution in the actual enforcement architecture.
2.  Cilium/eBPF already provides equivalent principal attribution
    without requiring a new mechanism.
3.  Existing WIMSE/service-mesh mechanisms already solve the full
    identity-to-enforcement problem.
4.  Policy-class pooling with exact attribution is already a standard,
    documented technique.
5.  The observed H1/H2 difference disappears under realistic traffic.
6.  The O(P) scaling result does not survive realistic Envoy
    configurations.
7.  Revocation makes policy-class pooling unsafe in a way that
    eliminates its practical value.
8.  Existing commercial products already provide the same capability at
    enterprise scale.

If any of these happen, document the result rather than trying to
preserve the hypothesis.

------------------------------------------------------------------------

# 22. Required Final Decision

At the end of Phase 4B, return exactly one:

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
PROTOCOL RESEARCH OPPORTUNITY
```

Then explain the evidence.

------------------------------------------------------------------------

# 23. Recommended Order of Execution

Do not start with the expensive experiments.

Execute in this order:

### Step 1 --- HTTP/2 stream IDs

Cheapest and highest information value.

### Step 2 --- TLS + HTTP/2

Determine whether encryption changes the result.

### Step 3 --- HTTP/1.1 concurrency sweep

Determine the real resource curve.

### Step 4 --- HTTP/2 concurrency sweep

Determine the real multiplexing curve.

### Step 5 --- Real Cilium/eBPF

Close RQ3.

### Step 6 --- Real WPT/SPIFFE identity

Close RQ4.

### Step 7 --- xDS/revocation

Close the major security unknown.

### Step 8 --- Hybrid pooling

Determine whether a practical middle ground exists.

### Step 9 --- HTTP/3/QUIC

Only after the TCP findings are stable.

### Step 10 --- Prior-art challenge

Perform the final literature/vendor comparison using the actual
experimental results.

------------------------------------------------------------------------

# 24. Final Principle

Do not design a protocol yet.

The goal of Phase 4B is not to prove:

> "We need a new AI Agent Binding Protocol."

The goal is to determine:

> **What is the minimum technically unavoidable cost of preserving
> AI-agent security-principal attribution while maintaining efficient
> multiplexed network connections?**

If existing technology already achieves the desired result:

> stop.

If the result reveals a measurable systems trade-off:

> characterize it rigorously.

If the trade-off reveals a genuinely missing capability:

> define the smallest missing mechanism.

Only if that mechanism cannot be implemented through existing standards
or configuration should a new protocol be considered.
