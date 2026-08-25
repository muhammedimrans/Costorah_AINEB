# AI Agent Network Security Research

## Improved Research Plan, Competitive Gap Analysis, Open Research Questions, and Next-Phase Investigation

**Version:** 2.0\
**Date:** August 2026\
**Status:** Research working document\
**Baseline:** User-provided research document, supplemented with current
2026 web research.

------------------------------------------------------------------------

## 1. Purpose of This Document

This document updates the current research based on the existing
research document and additional competitive/standards research.

The goal is not to replace the existing work, but to:

1.  Preserve the strongest parts of the current research.
2.  Correct claims that have become too broad because the ecosystem has
    moved quickly.
3.  Clearly separate what is already solved from what remains uncertain.
4.  Identify the strongest research opportunities.
5.  Define experiments that can prove or disprove the proposed gaps.
6.  Establish how the research can be defended against Microsoft, Palo
    Alto Networks, Zscaler, Cisco, Fortinet, Check Point, Cloudflare,
    Okta, SPIFFE/SPIRE, WIMSE and IETF work.
7.  Identify the areas that still require deeper research before
    designing a new protocol.

------------------------------------------------------------------------

# 2. Current Research Thesis

## Recommended thesis

> **Existing AI-agent identity and authorization systems establish who
> an agent is and what it is allowed to do, but a remaining systems
> problem is translating that verified identity into a non-spoofable,
> instance-level network enforcement context. This research investigates
> a runtime- and kernel-assisted Agent Binding mechanism that
> individuates co-resident agent instances, associates their network
> flows with their verified identities and delegated capabilities, and
> exports a verifiable verdict consumable by heterogeneous network
> enforcement points.**

This is stronger than the original "AI Agent Firewall" concept.

------------------------------------------------------------------------

# 3. What We Are NOT Trying to Invent

The research should explicitly avoid claiming novelty for technologies
that already exist or are being standardized.

## Not the primary contribution

-   Human authentication
-   OAuth/OIDC
-   Workload identity
-   SPIFFE/SPIRE
-   Microsoft Entra Agent ID
-   Agent registries
-   Human-to-agent delegation
-   Short-lived credentials
-   MCP authentication
-   A2A authentication
-   WIMSE workload credentials
-   WIMSE Workload Proof Tokens
-   HTTP Message Signatures
-   AI gateways
-   AI firewalls
-   Runtime malware detection
-   SIEM
-   General Zero Trust

These should be treated as surrounding technologies that the proposed
mechanism can consume or integrate with.

------------------------------------------------------------------------

# 4. The Core Problem

The identity chain should be modeled as five separate layers:

``` text
Human Identity
      |
      | delegates
      v
Agent Identity
      |
      | instantiated as
      v
Agent Instance Identity
      |
      | executes as
      v
Runtime / Process Identity
      |
      | creates
      v
Network Flow Identity
```

The key research question is:

> **Can the identity of an exact running agent instance be reliably and
> cryptographically connected to the network flows it creates, and can
> that identity be turned into a network-enforceable verdict?**

This is narrower and more testable than "secure AI agents."

------------------------------------------------------------------------

# 5. Current Competitive Reality

## 5.1 Microsoft Entra Agent ID

Microsoft now provides:

-   agent identities
-   agent blueprints
-   owners and sponsors
-   lifecycle governance
-   Conditional Access
-   Identity Protection
-   network controls
-   OAuth-based patterns
-   MCP/A2A-related support
-   workload federation/sidecar approaches

Microsoft's architecture is strongly identity-plane oriented.

### What Microsoft already solves

``` text
Human
  |
Entra
  |
Agent Identity
  |
Authorization
  |
Governance
  |
Risk
```

### What remains important for this research

The research should not assume that Microsoft cannot create individual
agent identities.

Instead investigate:

``` text
Entra Agent Identity
       |
       v
Exact runtime instance
       |
       v
Process / kernel
       |
       v
Socket / flow
       |
       v
Firewall enforcement
```

The research question is the continuity of identity across those layers.

### Defensive position

> Microsoft provides the identity plane. The proposed research
> investigates the identity-to-network data-plane binding.

Source: Microsoft Entra Agent ID documentation.

------------------------------------------------------------------------

# 6. Palo Alto Networks

Prisma AIRS has expanded into:

-   agent discovery
-   agent identity
-   AI Agent Gateway
-   runtime protection
-   agent posture
-   MCP/tool security
-   endpoint protection
-   centralized AI security
-   agentic application protection

### What Palo Alto solves

A large portion of the lifecycle:

``` text
Discover
   |
Identify
   |
Authorize
   |
Inspect
   |
Protect
   |
Monitor
```

### Research implication

Do not build another AI gateway.

Instead investigate whether a vendor-neutral agent-instance binding can
be consumed by an AI gateway or firewall.

### Defensive position

> Prisma AIRS is a security platform. This research is a lower-level
> binding mechanism that could feed verified instance identity into such
> platforms.

------------------------------------------------------------------------

# 7. Zscaler

Zscaler has introduced agentic AI controls including:

-   AI Broker
-   MCP/A2A broker capabilities
-   agent registry
-   AI Access Graph
-   AI endpoint security
-   risk and intent controls
-   Zero Trust policy

### What Zscaler solves

Strong network and policy enforcement.

### Research implication

The research should ask:

> Can an external verifier provide Zscaler or another SASE platform with
> a trustworthy, independently verifiable identity for each local agent
> instance?

If yes, the proposed technology becomes an integration layer rather than
a competing SASE product.

------------------------------------------------------------------------

# 8. Cisco

Cisco's direction combines:

-   AI Defense
-   AI BOM
-   MCP controls
-   agent discovery
-   agent IAM
-   SASE
-   Zero Trust
-   firewall
-   observability
-   Agentic SOC

### Research implication

Cisco demonstrates that identity, network and security telemetry are
converging.

The open research question is whether a vendor-neutral mechanism can
connect:

``` text
Agent identity
      |
Runtime identity
      |
Network identity
      |
Enforcement
```

without requiring one vendor to own every layer.

------------------------------------------------------------------------

# 9. Fortinet

Fortinet has expanded FortiOS AI capabilities into:

-   Shadow AI discovery
-   AI-aware application control
-   MCP visibility
-   A2A visibility
-   AI-specific network controls
-   DLP
-   Security Fabric integration

### Research implication

The project should not claim novelty in "AI-aware firewalling."

Instead it should test whether Fortinet or a generic firewall can
consume a trusted agent-instance verdict independent of application
protocol.

------------------------------------------------------------------------

# 10. Check Point

Check Point has launched an AI Network Firewall aimed at:

-   AI discovery
-   agent interactions
-   AI traffic inspection
-   tool/API control
-   data exfiltration protection
-   AI security policy

### Research implication

This further confirms that:

> "AI firewall"

is not a sufficiently novel research thesis.

The research should move one layer deeper into identity-to-flow binding.

------------------------------------------------------------------------

# 11. Cloudflare

Cloudflare is treating agents as first-class network participants and
provides private networking and scoped connectivity for agents.

### Research implication

Cloudflare strengthens the argument that agent networking will become a
major infrastructure layer.

The open question remains whether a generic, vendor-neutral mechanism
can maintain instance-level attribution across heterogeneous
infrastructure.

------------------------------------------------------------------------

# 12. Okta

Okta has expanded into:

-   Agent as Principal
-   Agent Gateway
-   agent-to-agent connections
-   delegated identity
-   short-lived credentials
-   task-scoped authorization
-   auditability
-   identity continuity through agent delegation

### Research implication

Do not claim that human-to-agent binding is novel.

Instead:

``` text
Human
  |
Agent
  |
Agent Instance
  |
Runtime
  |
Network Flow
```

is the boundary to investigate.

------------------------------------------------------------------------

# 13. WIMSE

WIMSE is critical to the research.

Current WIMSE work includes:

-   Workload Identifier
-   Workload Credentials
-   WIMSE Architecture
-   Mutual TLS
-   HTTP Signatures
-   Workload Proof Token
-   AI-agent applicability work
-   attestation-related extensions
-   execution-context-token work

A WPT provides proof of possession of the private key associated with a
WIT and binds workload authentication to a specific HTTP request.

HTTP Signatures provide end-to-end HTTP authentication/integrity even
where TLS proxies or load balancers are present.

### Important conclusion

Do not reinvent WIMSE.

Use it as the upstream identity/authentication layer.

------------------------------------------------------------------------

# 14. IETF Agent Network Admission

The July 2026 Internet-Draft is the most important standards reference.

It explicitly states that application authentication alone does not
provide complete network admission control.

It identifies:

-   multiple agents sharing a host
-   one IP representing multiple security subjects
-   shared egress gateways
-   the need for agent-instance authentication
-   binding identity to enforceable traffic
-   admission before general reachability
-   lifecycle independence
-   revocation
-   non-bypassability
-   evidence/audit/privacy

The draft defines an Agent Binding as a time-bounded association between
an authenticated agent instance, credential key, relevant attributes and
an enforceable Network Context.

### Crucial limitation

The document is an Internet-Draft, not an RFC.

It does not define the complete protocol mechanism.

That leaves room for experimental implementation and protocol research.

------------------------------------------------------------------------

# 15. Revised Research Gaps

The current research should be divided into three primary gaps and
several secondary gaps.

## G1 --- Agent Instance Individuation

### Question

Can two or more concurrently running, otherwise identical agent
instances on the same host be independently identified?

Example:

``` text
Host
 |
 +-- Agent A
 +-- Agent B
 +-- Agent C
 +-- Browser
```

All may share:

-   user
-   executable
-   container image
-   UID
-   network namespace
-   IP

The system must still distinguish A, B and C.

### Why this matters

An agent identity that identifies only the application class is
insufficient if an individual instance is the security subject.

### What to research

-   process identity
-   PID
-   cgroup
-   namespace
-   container ID
-   runtime identity
-   workload identity
-   kernel labels
-   eBPF
-   SPIRE selectors
-   attestation
-   per-instance key generation
-   key protection
-   restart/clone semantics

------------------------------------------------------------------------

# 16. G2 --- Agent Instance to Network Flow Binding

### Question

Once an instance is identified, can its identity be cryptographically or
otherwise non-spoofably connected to:

-   socket
-   process
-   cgroup
-   namespace
-   virtual interface
-   security association
-   flow

?

### Example

``` text
Agent A
   |
   v
Process
   |
   v
Socket
   |
   v
Flow
```

The firewall must be able to establish:

``` text
Flow X belongs to Agent A
```

rather than merely:

``` text
Flow X came from IP 10.0.0.10
```

### Technologies to investigate

-   eBPF
-   Cilium
-   socket metadata
-   cgroup identity
-   network namespaces
-   tc
-   XDP
-   conntrack
-   Linux security hooks
-   SPIFFE/SPIRE
-   Envoy
-   sidecars
-   service mesh
-   per-agent network namespaces
-   virtual interfaces

------------------------------------------------------------------------

# 17. G3 --- Identity Verdict to Network Enforcement

This may be the strongest protocol-level opportunity.

Current flow:

``` text
Identity Provider
       |
       v
Verifier
       |
       X
       |
Firewall
```

The research proposes:

``` text
Identity / WIMSE
       |
       v
Verifier
       |
       v
Agent Binding Verdict
       |
       v
Enforcement Point
```

### Question

What is the minimum standardized information a network enforcement point
needs to enforce:

``` text
ALLOW
DENY
RESTRICT
QUARANTINE
```

for a specific agent instance?

### Research areas

-   verdict schema
-   cryptographic integrity
-   freshness
-   lifetime
-   revocation
-   policy ID
-   capability set
-   network context
-   destination scope
-   source scope
-   audit identifier
-   replay prevention
-   fail-open/fail-closed behavior

------------------------------------------------------------------------

# 18. Secondary Gap --- Pre-Reachability Admission

The IETF work identifies the need for constrained pre-admission
connectivity.

Research:

``` text
Unadmitted Agent
      |
      v
Restricted network
      |
      +--> identity service
      +--> credential service
      +--> attestation
      +--> remediation
      |
      v
Admission
      |
      v
Agent-specific network access
```

The novelty should not be "authentication before access."

The question is:

> How should verified agent identity and delegated capabilities control
> the transition from pre-admission to agent-specific network
> reachability?

------------------------------------------------------------------------

# 19. Secondary Gap --- Lifecycle and Instance Continuity

Agents can:

-   start
-   stop
-   restart
-   clone
-   migrate
-   suspend
-   resume
-   scale horizontally

Research:

``` text
Agent A
   |
   v
Instance A1
   |
restart
   |
   v
Instance A2
```

Should A2 inherit the same network binding?

Possible models:

### Model A

Every restart = new identity.

### Model B

Restart preserves identity if continuity proof exists.

### Model C

Identity remains but network binding must be reissued.

This needs experimentation.

------------------------------------------------------------------------

# 20. Secondary Gap --- Compromised Runtime

An authenticated agent can still be compromised.

Research:

``` text
Valid identity
     |
     v
Compromised process
     |
     v
Unexpected behavior
     |
     v
Risk engine
     |
     v
Restrict/revoke binding
```

Investigate:

-   runtime signals
-   prompt injection
-   tool poisoning
-   malicious browser content
-   credential theft
-   abnormal destination access
-   exfiltration
-   privilege escalation

This should be a secondary research track, not the core novelty claim.

------------------------------------------------------------------------

# 21. Secondary Gap --- Non-HTTP/L4

WIMSE HTTP Signatures solve application-level HTTP authentication,
including environments with TLS proxies/load balancers.

Do not claim that WIMSE "cannot solve non-HTTP."

Instead investigate:

> How should verified agent-instance identity be associated with
> arbitrary L4 flows where there is no HTTP message carrying
> application-level proof?

Test:

-   TCP
-   UDP
-   QUIC
-   DNS
-   database protocols
-   SSH
-   custom binary protocols

------------------------------------------------------------------------

# 22. Secondary Gap --- Shared Gateway

This remains important, but it should be tested rather than assumed
unsolved.

Scenario:

``` text
Agent A --\
Agent B ----> Proxy ----> Internet
Agent C --/
```

Investigate whether identity survives:

-   NAT
-   reverse proxies
-   forward proxies
-   service meshes
-   load balancers
-   HTTP/2
-   HTTP/3
-   QUIC
-   connection pooling

For HTTP, WIMSE HTTP Signatures already provides important
application-level mechanisms.

The remaining question is the network-enforcement representation.

------------------------------------------------------------------------

# 23. Secondary Gap --- Policy Compression at Million-Agent Scale

A million-agent deployment cannot create a million independent firewall
rules.

Research:

``` text
1,000,000 agent identities
        |
        v
Policy classes
        |
        +--> developer-agent
        +--> finance-agent
        +--> research-agent
        +--> production-agent
```

Identity remains unique.

Policy should be reusable.

Investigate:

-   attribute-based access control
-   capability classes
-   policy templates
-   hierarchical policies
-   dynamic policy evaluation
-   revocation lists
-   policy caching
-   distributed policy engines

------------------------------------------------------------------------

# 24. Proposed Architecture

``` text
                       HUMAN
                         |
                   Enterprise IdP
                         |
                  Authenticate once
                         |
                         v
                 Agent Registration
                         |
                         v
                  Agent Identity
                         |
                         v
                  Agent Runtime
                         |
                 Instance Key/Proof
                         |
                         v
                 Network Admission
                         |
                  +------+------+
                  |             |
                  v             v
              Verifier      Risk Engine
                  |             |
                  +------+------+
                         |
                  Agent Binding
                    Verdict
                         |
                         v
               Enforcement Adapter
                         |
          +--------------+--------------+
          |              |              |
        Cilium         Envoy         NGFW/SASE
          |              |              |
          +--------------+--------------+
                         |
                       Network
```

------------------------------------------------------------------------

# 25. Recommended Architectural Boundary

The most defensible architecture is:

``` text
+------------------------------------------------+
| EXISTING IDENTITY / AUTHENTICATION             |
|                                                |
| Microsoft Entra | Okta | SPIFFE/SPIRE | WIMSE |
| OAuth | WIT | WPT | HTTP Signatures           |
+----------------------------+-------------------+
                             |
                     Verified identity
                             |
                             v
+------------------------------------------------+
| RESEARCH CONTRIBUTION                          |
|                                                |
| Agent Instance Individuation                   |
| Runtime -> Instance Binding                    |
| Instance -> Flow Binding                       |
| Agent Binding Verdict                          |
| Enforcement Adapter                            |
+----------------------------+-------------------+
                             |
                             v
+------------------------------------------------+
| EXISTING ENFORCEMENT                           |
|                                                |
| Cilium | Envoy | Firewall | SASE | NGFW       |
+------------------------------------------------+
```

This prevents the project from reinventing existing protocols.

------------------------------------------------------------------------

# 26. Proposed Binding Verdict

Conceptual only:

``` json
{
  "binding_id": "bind-123",
  "agent_instance_id": "instance-789",
  "principal_id": "user-456",
  "runtime_id": "runtime-55",
  "network_context": "nc-8272",
  "capabilities": [
    "internet.read",
    "github.read"
  ],
  "policy_id": "research-agent-v1",
  "decision": "allow",
  "issued_at": 1780000000,
  "expires_at": 1780000900,
  "nonce": "random-value",
  "verifier": "verifier.example",
  "signature": "..."
}
```

This is not proposed as the final protocol format.

The format should be designed only after experiments establish what
information enforcement points actually require.

------------------------------------------------------------------------

# 27. Do Not Build a New TCP

The research should remain above TCP/IP.

Preferred model:

``` text
Application
   |
WIMSE/OAuth/etc.
   |
Agent Binding Layer
   |
TLS/QUIC
   |
TCP/UDP/IP
```

The contribution is the identity-to-network relationship, not a new
transport protocol.

------------------------------------------------------------------------

# 28. Phase 0 --- Prior-Art Verification

Before protocol design, verify every claim.

### Questions

1.  Can Microsoft Entra identify separate running instances?
2.  Can SPIRE identify separate identical agent processes?
3.  Can WIMSE credentials distinguish those instances?
4.  Can WPT provide request-level proof?
5.  Can HTTP Signatures preserve identity through TLS proxies?
6.  Can Cilium identify individual agent processes?
7.  Can Envoy consume process/workload identity?
8.  Can a firewall consume that identity?
9.  Can an agent be revoked without affecting another agent on the same
    host?
10. Can the same be done across NAT/shared gateways?

### Deliverable

A formal prior-art matrix.

------------------------------------------------------------------------

# 29. Phase 1 --- Co-Resident Agent Experiment

Run:

``` text
Host
 |
 +-- Agent A
 +-- Agent B
 +-- Agent C
 +-- Agent D
```

Use:

-   same binary
-   same user
-   same image
-   same namespace where possible
-   same IP
-   same destination

Measure whether the baseline can independently identify A/B/C/D.

This is the first critical experiment.

------------------------------------------------------------------------

# 30. Phase 2 --- Runtime Identity

Introduce:

-   cgroups
-   namespaces
-   process IDs
-   runtime IDs
-   per-instance keys
-   SPIRE/SPIRE selectors
-   attestation if available

Test:

``` text
Agent A != Agent B
```

at the runtime layer.

------------------------------------------------------------------------

# 31. Phase 3 --- Kernel Flow Binding

Use:

-   eBPF
-   Cilium
-   socket identity
-   cgroup hooks
-   network namespaces

Goal:

``` text
Agent A
  |
  v
Socket A
  |
  v
Flow A
```

and:

``` text
Agent B
  |
  v
Socket B
  |
  v
Flow B
```

even when:

``` text
Source IP A = Source IP B
```

------------------------------------------------------------------------

# 32. Phase 4 --- WIMSE Integration

Use WIMSE as the upstream proof system.

Test:

``` text
Agent Instance
      |
WIT/WPT
      |
Verifier
      |
Binding Engine
```

Do not create another workload credential.

------------------------------------------------------------------------

# 33. Phase 5 --- Verdict Enforcement

Create an enforcement adapter.

Example:

``` text
Binding Verdict
      |
      +--> Cilium policy
      |
      +--> Envoy policy
      |
      +--> firewall API
```

Test:

``` text
Agent A -> ALLOW
Agent B -> DENY
```

while both run on the same host.

This is the central proof-of-concept.

------------------------------------------------------------------------

# 34. Phase 6 --- Adversarial Testing

Test:

### Spoofing

Agent B claims Agent A identity.

Expected:

``` text
DENY
```

### Replay

Old binding reused.

Expected:

``` text
DENY
```

### Cloning

Agent image cloned.

Expected:

``` text
New instance requires valid continuity/admission
```

### Process injection

Unauthorized process attempts to use Agent A network context.

Expected:

``` text
DENY
```

### Direct bypass

Agent tries another interface/route.

Expected:

``` text
DENY
```

### Binding theft

Private key copied.

Expected:

``` text
Proof-of-possession + runtime binding prevents unauthorized use
```

if the chosen key protection actually provides that guarantee.

------------------------------------------------------------------------

# 35. Phase 7 --- Shared Infrastructure

Test:

``` text
Agent A --\
Agent B ----> NAT
Agent C --/       |
                  v
                Proxy
                  |
                  v
               Gateway
                  |
                  v
               Internet
```

Test:

-   HTTP/1.1
-   HTTP/2
-   HTTP/3
-   QUIC
-   connection pooling
-   load balancing

Measure whether attribution survives.

------------------------------------------------------------------------

# 36. Phase 8 --- Non-HTTP

Test:

-   TCP
-   UDP
-   DNS
-   database connections
-   SSH
-   custom protocols

Determine which identity mechanisms are reusable.

------------------------------------------------------------------------

# 37. Phase 9 --- Scale

Simulate:

``` text
10
100
1,000
10,000
100,000
1,000,000
```

Measure:

-   identity issuance rate
-   binding issuance rate
-   policy lookup latency
-   CPU
-   memory
-   network overhead
-   control-plane traffic
-   revocation latency
-   storage
-   enforcement throughput

------------------------------------------------------------------------

# 38. Phase 10 --- Compare Against Competitors

The comparison should be experimental where possible.

### Baselines

1.  Microsoft Entra Agent ID
2.  Okta agent identity/gateway
3.  SPIFFE/SPIRE
4.  WIMSE
5.  Cilium
6.  Envoy/agentgateway
7.  Zscaler/Palo Alto/Cisco/Fortinet/Check Point capabilities where test
    access is available

Do not claim a vendor cannot do something solely because public
documentation does not describe it.

Use:

``` text
Publicly documented
Experimentally verified
Unknown
```

instead of:

``` text
Supports
Does not support
```

when evidence is incomplete.

------------------------------------------------------------------------

# 39. Research Metrics

## Attribution accuracy

``` text
Correctly attributed flows
--------------------------
Total flows
```

## False attribution rate

``` text
Flows attributed to wrong agent
--------------------------------
Total flows
```

## Isolation effectiveness

Can Agent A be blocked while Agent B remains connected?

## Revocation latency

``` text
Revoke
  |
  v
Time until traffic is blocked
```

## Admission latency

``` text
Admission request
  |
  v
Binding active
```

## Overhead

Measure:

-   CPU
-   memory
-   latency
-   throughput

## Scalability

Measure:

``` text
Agents/sec
Bindings/sec
Verdicts/sec
Revocations/sec
```

------------------------------------------------------------------------

# 40. Research Success Criteria

The research should be considered successful if it demonstrates all of
the following:

### S1

Two otherwise identical co-resident agent instances can be independently
identified.

### S2

Their network flows can be independently attributed.

### S3

The attribution cannot be spoofed by another local process under the
threat model.

### S4

One agent can be blocked while another continues.

### S5

The mechanism survives shared IP addressing.

### S6

The mechanism works with at least one proxy/gateway scenario.

### S7

The mechanism integrates with existing WIMSE/workload identity rather
than replacing it.

### S8

The mechanism can export a verifiable verdict to an enforcement point.

### S9

Credential renewal does not require repeated human authentication.

### S10

The mechanism scales without one firewall rule per agent.

------------------------------------------------------------------------

# 41. What Could Still Be Researched?

## High priority

### R1 --- Exact agent-instance identity

**Status:** Open/needs experiment.

### R2 --- Runtime-to-kernel identity mapping

**Status:** Open/needs experiment.

### R3 --- Kernel flow binding

**Status:** Open/needs experiment.

### R4 --- Identity-to-enforcement verdict

**Status:** Strong protocol opportunity.

### R5 --- Per-agent isolation on shared host/IP

**Status:** Strong experiment opportunity.

### R6 --- Revocation of one agent without affecting others

**Status:** Strong experiment opportunity.

------------------------------------------------------------------------

# 42. Medium Priority

### R7 --- Shared proxy/gateway

Important but partially addressed at application layer.

### R8 --- HTTP/2/HTTP/3

Important validation area.

### R9 --- Non-HTTP flows

Potential protocol-extension area.

### R10 --- Agent lifecycle

Important for production-grade design.

### R11 --- Runtime attestation

Potential trust-strengthening mechanism.

### R12 --- Agent cloning/migration

Important for cloud/Kubernetes deployments.

------------------------------------------------------------------------

# 43. Long-Term Research

### R13 --- Agent-to-agent delegated network admission

Example:

``` text
Agent A
  |
delegates
  v
Agent B
  |
delegates
  v
Agent C
```

The network should know:

``` text
C authorized by B
B authorized by A
A authorized by user
```

### R14 --- Cross-cloud admission

``` text
Azure
AWS
GCP
On-prem
Kubernetes
```

### R15 --- Federated enterprise admission

Different companies may need to trust each other's agents without
sharing their entire identity systems.

### R16 --- Privacy-preserving attribution

The network may need to know:

``` text
Authorized Agent Class X
```

without learning unnecessary user/prompt information.

------------------------------------------------------------------------

# 44. Strongest Novelty Candidate

The strongest potential contribution is not:

> "AI agents need identities."

It is:

> **A mechanism for preserving a cryptographically verifiable
> relationship from an authenticated AI-agent instance through its
> runtime and kernel-level execution context to an enforceable network
> identity, and for exporting that relationship as a verifiable policy
> verdict to heterogeneous network enforcement points.**

This has three components:

``` text
Instance identity
       +
Flow binding
       +
Enforcement verdict
```

------------------------------------------------------------------------

# 45. How to Defend Against "Microsoft Already Does This"

Response:

> Microsoft provides enterprise agent identity, governance and access
> control. This research does not replace those capabilities. It
> investigates the runtime/kernel/data-plane binding required to
> associate an exact running instance with enforceable network traffic.

------------------------------------------------------------------------

# 46. How to Defend Against "Palo Alto Already Does This"

Response:

> Palo Alto provides an integrated AI security and gateway platform. The
> research focuses on a vendor-neutral identity-to-network binding
> primitive that could be consumed by such a gateway.

------------------------------------------------------------------------

# 47. How to Defend Against "Zscaler Already Does This"

Response:

> Zscaler provides Zero Trust network enforcement and AI brokers. The
> research investigates how an independently verifiable agent-instance
> identity can be passed from an identity/runtime layer into network
> enforcement without requiring the network vendor to own the complete
> identity stack.

------------------------------------------------------------------------

# 48. How to Defend Against "Okta Already Does This"

Response:

> Okta provides agent identity, delegation and gateway capabilities. The
> research focuses on the lower-level association between the running
> instance and network flow, particularly on a shared host or shared
> network context.

------------------------------------------------------------------------

# 49. How to Defend Against "IETF Is Already Solving It"

Response:

> The IETF Agent Network Admission draft formally defines use cases and
> requirements. It does not define the concrete mechanism for
> implementing instance-to-flow binding and enforcement verdict
> propagation. The research implements and evaluates candidate
> mechanisms against those requirements.

This is a critical distinction.

------------------------------------------------------------------------

# 50. Recommended Final Research Structure

The eventual paper should use this structure:

``` text
1. Introduction
2. Problem Statement
3. Threat Model
4. Existing Ecosystem
5. Standards Landscape
6. Competitive Analysis
7. Gap Analysis
8. System Requirements
9. Proposed Architecture
10. Agent Instance Model
11. Flow Binding Model
12. Binding Verdict Model
13. Enforcement Integration
14. Security Analysis
15. Prototype
16. Experimental Methodology
17. Results
18. Performance
19. Limitations
20. Comparison with Existing Work
21. Future Work
22. Conclusion
```

------------------------------------------------------------------------

# 51. Critical Research Questions Before Protocol Design

Do not proceed to a final protocol until these questions have
experimental answers:

1.  What exactly makes Agent A different from Agent B?
2.  Can that distinction survive process restart?
3.  Can another process impersonate the identity?
4.  Can the identity be mapped to a socket?
5.  Can the socket identity be mapped to a flow?
6.  Can the mapping survive NAT?
7.  Can it survive a proxy?
8.  Can it survive HTTP/2 multiplexing?
9.  Can it work for non-HTTP?
10. Can the firewall consume the identity?
11. Can one agent be revoked independently?
12. Can the system operate without per-agent IP addresses?
13. Can it scale to one million agents?
14. What information must the enforcement point actually receive?
15. What can be delegated to existing WIMSE/SPIFFE/OAuth components?

These questions should drive the next phase.

------------------------------------------------------------------------

# 52. Recommended Immediate Experiment

The most valuable first prototype is deliberately small.

``` text
One Linux host

Agent A
Agent B
Agent C

same:
- user
- executable
- container image
- network
- destination
```

Baseline:

``` text
SPIRE/SPIFFE
+
Cilium/eBPF
+
Envoy/agentgateway
```

Then measure:

``` text
Can the system distinguish A/B/C?
```

Next:

``` text
Agent A -> DENY
Agent B -> ALLOW
Agent C -> ALLOW
```

If this cannot be done reliably with the baseline, introduce the
proposed binding mechanism.

This gives the research a falsifiable hypothesis.

------------------------------------------------------------------------

# 53. Current Research Position

The market has largely converged on:

``` text
Agent Discovery
+
Agent Identity
+
Delegation
+
Authorization
+
AI Gateway
+
Runtime Security
+
Zero Trust
```

The strongest remaining systems question is:

``` text
Exact Agent Instance
        |
        v
Runtime
        |
        v
Kernel
        |
        v
Network Flow
        |
        v
Enforcement Verdict
```

That is where the research should concentrate.

------------------------------------------------------------------------

# 54. Final Recommendation

The project should currently be described as:

> **Research into scalable identity-to-network enforcement for
> autonomous AI-agent instances, with emphasis on distinguishing
> co-resident instances, binding their identities to kernel-level
> network flows, and providing verifiable enforcement decisions to
> existing network security infrastructure.**

The project should **not yet claim that the mechanism is novel**.

Instead:

> **The hypothesis is that existing identity and application-layer proof
> mechanisms do not by themselves provide a standardized, interoperable
> way to independently bind co-resident AI-agent instances to
> enforceable network contexts.**

The experiments must prove or disprove that hypothesis.

------------------------------------------------------------------------

# 55. Primary Research References

## Microsoft

Microsoft Entra Agent ID\
https://learn.microsoft.com/en-us/entra/agent-id/

## IETF Agent Network Admission

Use Cases and Requirements for Network Admission of AI Agent Instances\
https://datatracker.ietf.org/doc/draft-shang-agent-network-admission-01

## IETF WIMSE

WIMSE documents\
https://datatracker.ietf.org/wg/wimse/documents/

## WIMSE Workload Proof Token

https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/

## WIMSE HTTP Signatures

https://datatracker.ietf.org/doc/draft-ietf-wimse-http-signature/

## Palo Alto Networks

Prisma AIRS\
https://www.paloaltonetworks.com/

## Zscaler

Agentic AI / AI Broker\
https://www.zscaler.com/

## Cisco

AI Defense\
https://www.cisco.com/

## Fortinet

AI Security / FortiOS\
https://www.fortinet.com/

## Check Point

AI Network Firewall\
https://www.checkpoint.com/

## Cloudflare

Agent networking / Cloudflare Mesh\
https://www.cloudflare.com/

## Okta

AI Agent Identity\
https://www.okta.com/

------------------------------------------------------------------------

# 56. Version-Control Recommendation

Maintain the research in three separate documents going forward:

### `01-research-landscape.md`

Competitors, standards, papers, products, and prior art.

### `02-research-gap.md`

Only unresolved problems and hypotheses.

### `03-protocol-design.md`

Only after experiments validate the gaps.

This prevents the protocol design from becoming anchored to assumptions
that later turn out to be already solved.

------------------------------------------------------------------------

# 57. Current Status

  Workstream                  Status
  --------------------------- --------------------------------------
  Problem definition          Strong
  Competitive research        Strong, continue updating
  Standards research          Strong, continue WIMSE/IETF tracking
  G1 instance individuation   **Needs experiment**
  G2 flow binding             **Needs experiment**
  G3 enforcement verdict      **Primary research opportunity**
  Pre-admission               Secondary
  Lifecycle                   Secondary
  Non-HTTP                    Secondary
  Shared gateway              Validation required
  Protocol design             **Do not finalize yet**
  Prototype                   **Next step**
  Performance benchmark       Pending
  Security proof              Pending
  Standards proposal          Future

------------------------------------------------------------------------

## Bottom line

The research is now in a much better position than the original "AI
firewall" idea.

The **highest-value next step is not another literature review and not
immediately designing a new protocol**.

It is to build a small experimental baseline around:

**SPIFFE/SPIRE + WIMSE + Cilium/eBPF + Envoy/agentgateway**

and test the central claim:

> **Can two otherwise identical AI-agent instances running on the same
> host be independently identified, cryptographically associated with
> their network flows, and independently admitted/blocked by a network
> enforcement point?**

If the baseline cannot do this cleanly, the result gives us the
empirical foundation for the proposed binding layer. If the baseline can
do it, we identify exactly which pieces already solve the problem and
pivot the research accordingly.
