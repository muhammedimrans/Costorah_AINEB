# AI Agent Network Security Research

## Current Architecture, Competitive Landscape, Research Gaps, Challenges, Defensibility, and Research Roadmap

**Research status:** August 2026\
**Purpose:** Working research document for an enterprise security
architecture focused on autonomous AI-agent identity, network admission,
traffic attribution, monitoring, and enforcement.

------------------------------------------------------------------------

## 1. Executive Summary

The original project idea was:

> Allow trusted AI agents inside an enterprise to access approved
> Internet and internal resources while preventing unknown/external AI
> agents from entering the enterprise network, with firewall-like
> monitoring and enforcement.

Research across Microsoft, Palo Alto Networks, Zscaler, Cisco, Fortinet,
Check Point, Cloudflare, Okta, NIST, and IETF shows that a large portion
of this problem is now actively addressed by commercial products and
standards work.

Therefore, the project should **not** be positioned as:

-   "an AI firewall"
-   "AI-agent authentication"
-   "binding an AI agent to a human user"
-   "an AI-agent registry"
-   "short-lived agent credentials"

Those capabilities already exist in various forms.

The strongest remaining research opportunity is narrower:

> **Create a scalable mechanism that cryptographically binds a specific
> running AI-agent instance to an enforceable network context and
> preserves that attribution through shared hosts, NAT, proxies, shared
> egress gateways, and multiplexed HTTP/2/HTTP/3 connections---without
> requiring recurring human authentication.**

This is directly aligned with a July 2026 IETF Internet-Draft on network
admission of AI-agent instances. The draft identifies the problem but
explicitly does not define a new Agent-ID format, authentication
protocol, OAuth grant, or routing extension.

The proposed research should therefore focus on the missing mechanism
rather than reinventing the surrounding identity and security stack.

------------------------------------------------------------------------

# 2. Original Proposed Architecture

The initial concept was:

``` text
                         AD / Entra ID
                              |
                        Human identity
                              |
                       User approves once
                              |
                              v
                   Agent Registration
                    & Delegation Service
                              |
                       Agent Identity
                              |
                              v
                    Agent Identity Authority
                              |
                    Automatic credentials
                              |
             +----------------+----------------+
             |                |                |
             v                v                v
          Agent A          Agent B          Agent N
             |                |                |
             +----------------+----------------+
                              |
                        Agent traffic
                              |
                              v
                   +----------------------+
                   |  Agent Security      |
                   |      Gateway         |
                   |----------------------|
                   | Identity             |
                   | Admission            |
                   | Flow attribution      |
                   | Policy               |
                   | Risk                  |
                   | Monitoring            |
                   | Enforcement           |
                   +----------+-----------+
                              |
                  +-----------+-----------+
                  |                       |
                  v                       v
             Enterprise                Internet
              resources
```

The user experience is intended to be:

``` text
User authenticates once
        |
        v
User approves/registers agent
        |
        v
Agent receives delegated authority
        |
        v
Credentials renew automatically
        |
        v
Agent operates without repeated user authentication
```

------------------------------------------------------------------------

# 3. Design Principles

## 3.1 Human authentication should not be repeated

The human should authenticate and approve an agent once.

The infrastructure should handle:

-   credential acquisition
-   credential rotation
-   renewal
-   revocation
-   policy evaluation
-   traffic enforcement

The user should not have to authenticate every 15 minutes.

## 3.2 Agent identity must remain distinct from user identity

The relationship should be:

``` text
Human
  |
  | delegates
  v
Agent
  |
  | executes
  v
Agent Instance
  |
  | generates
  v
Network Flow
```

Not:

``` text
Human == Agent
```

This distinction is essential for attribution and revocation.

## 3.3 Identity is not enough

A legitimate agent can be compromised.

Therefore:

``` text
Identity
+
Delegated capability
+
Runtime context
+
Network context
+
Behavior
=
Security decision
```

## 3.4 Do not replace TCP/IP

The research should not start with a new TCP-like protocol.

The preferred model is an overlay/control mechanism using existing:

-   TLS
-   QUIC
-   HTTP
-   OAuth/OIDC
-   workload identity
-   mTLS
-   service meshes
-   network gateways
-   Zero Trust controls

The research question is what additional binding mechanism is needed
between agent identity and network enforcement.

------------------------------------------------------------------------

# 4. Current Competitive Landscape

## 4.1 Microsoft Entra Agent ID / Agent 365

### What Microsoft already solves

Microsoft Entra Agent ID provides first-class agent identity constructs,
agent identity blueprints, owners/sponsors, lifecycle management,
Conditional Access, Identity Protection, network controls, audit
logging, OAuth patterns, MCP and A2A support.

Agent blueprints act as templates for one or more agent identities.
Microsoft also supports non-Microsoft agents through sidecars and
workload identity federation.

Microsoft's current architecture distinguishes:

-   agent identity blueprint
-   agent identity
-   optional agent user account
-   owner/sponsor relationships
-   autonomous agents
-   on-behalf-of agents

It also supports automatic credential rotation through managed
identities and background operation patterns.

### Strategic decision Microsoft appears to have made

Microsoft is extending existing Entra identity infrastructure instead of
creating a completely independent identity system.

The design uses familiar service-principal infrastructure but adds
agent-specific semantics and delegation.

### What this means for our research

Do not claim:

> "AI agents need identity."

That is solved.

Do not claim:

> "AI agents need to be associated with owners."

That is also solved.

### Remaining area

The important unresolved question is:

> How does the identity of one exact running agent instance become a
> non-spoofable network enforcement context when multiple agents share a
> host, IP, proxy, gateway, or multiplexed connection?

### Source

Microsoft Entra Agent ID:
https://learn.microsoft.com/en-us/entra/agent-id/

------------------------------------------------------------------------

# 5. Palo Alto Networks

## Prisma AIRS

Palo Alto's Prisma AIRS 3.0 covers a broad AI security lifecycle:

``` text
Discovery
    |
Identity
    |
Gateway
    |
Runtime
    |
Endpoint
    |
Governance
```

It includes:

-   agent identity security
-   AI Agent Gateway
-   runtime security
-   agent interaction governance
-   MCP/tool-call controls
-   endpoint protection
-   discovery
-   centralized policies
-   traceability

Palo Alto's newer AI Gateway capability acts as a centralized
proxy/control plane for AI traffic and supports monitoring and policy
enforcement.

### Strategic decision

Palo Alto is combining AI security with its existing network, endpoint,
cloud, and runtime-security platforms rather than treating agent
security as an isolated identity problem.

### Strength

Very strong coverage of:

-   agent discovery
-   runtime protection
-   tool interaction
-   gateway enforcement
-   agent identity
-   behavioral security

### Remaining research question

Palo Alto provides extensive proprietary controls, but a vendor-neutral
mechanism for preserving exact agent-instance identity through shared
network infrastructure remains an open research area.

### Source

https://www.paloaltonetworks.com/blog/2026/03/prisma-airs-3-0-autonomous-ai/

------------------------------------------------------------------------

# 6. Zscaler

## Zscaler Zero Trust for Agentic AI

Zscaler has introduced:

-   AI Broker
-   MCP broker
-   A2A broker
-   Agent Registry
-   AI Access Graph
-   AI Endpoint Security
-   AI Protect
-   risk analysis
-   intent-based detection
-   fine-grained Zero Trust policy

Zscaler explicitly identifies agentic AI as a control-plane problem
involving:

-   ephemeral identities
-   non-human identities
-   sub-agents
-   MCP/A2A
-   rapidly changing permissions
-   data-flow visibility

The AI Broker sits inline and enforces policies across agent
interactions.

### Strategic decision

Zscaler is extending the existing Zero Trust Exchange rather than
building a separate network.

This is important because it gives Zscaler a natural enforcement
position.

### Strength

Very strong at:

-   network enforcement
-   inline inspection
-   Zero Trust
-   agent registry
-   data-access graph
-   MCP/A2A visibility
-   risk-based access

### Remaining research question

The strongest potential gap is still the cryptographically trustworthy
association:

``` text
Agent Instance
        |
        v
Network Context
        |
        v
Specific Flow
```

especially when several agents share:

-   host
-   IP
-   NAT
-   egress gateway
-   connection pools
-   HTTP/2 or HTTP/3 multiplexing

### Source

https://www.zscaler.com/press/zscaler-unveils-new-product-innovations-secure-agentic-ai

------------------------------------------------------------------------

# 7. Cisco

## Cisco AI Defense + SASE + Zero Trust for Agents

Cisco's 2026 strategy includes:

-   AI Defense
-   AI BOM
-   MCP Catalog
-   agent discovery
-   agentic IAM
-   real-time guardrails
-   MCP visibility
-   MCP policy control
-   adaptive risk protection
-   SASE integration
-   Agent Runtime SDK
-   secure agent frameworks
-   Agentic SOC
-   Hybrid Mesh Firewall

Cisco explicitly describes the goal as both:

> Protecting agents from the world

and:

> Protecting the world from agents.

Cisco also states that 85% of surveyed major enterprise customers were
experimenting with AI agents while only 5% had moved agentic technology
into production.

### Strategic decision

Cisco is integrating agent security into its existing:

-   network
-   security
-   identity
-   observability
-   Splunk
-   SASE
-   firewall

ecosystem.

### Strength

Excellent cross-domain telemetry and enforcement potential.

### Remaining research area

Cisco provides many of the required components, but a generic,
vendor-neutral protocol for exact agent-instance-to-network-flow binding
is still not established.

### Source

https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2026/m03/cisco-reimagines-security-for-the-agentic-workforce.html

------------------------------------------------------------------------

# 8. Fortinet

## FortiOS 8.0

Fortinet has added:

-   AI attack-surface visibility
-   Shadow AI detection
-   AI-aware application control
-   MCP visibility
-   A2A visibility
-   AI-specific logs
-   DLP
-   endpoint telemetry
-   adaptive ZTNA
-   AI-aware firewall controls

Fortinet specifically provides detection and visibility into MCP and A2A
interactions.

### Strategic decision

Fortinet is extending the traditional firewall/Security Fabric rather
than replacing the network-security architecture.

### Strength

Fortinet is strong at:

``` text
Network
+
Firewall
+
DLP
+
Endpoint
+
SASE
+
AI protocol visibility
```

### Remaining research area

Traditional network enforcement still requires a trustworthy way to know
which exact agent instance created a flow when many agents share a
network identity.

### Source

https://www.fortinet.com/corporate/about-us/newsroom/press-releases/2026/fortinet-introduces-fortios-8-expand-secure-networking-with-secure-ai-controls-fabric-based-ai-agents-flexible-sase-and-simplified-sdwan

------------------------------------------------------------------------

# 9. Check Point

## AI Network Firewall

Check Point launched an AI Network Firewall in July 2026.

It is designed to:

-   discover AI agents
-   understand agent interactions
-   control agent access
-   inspect AI traffic
-   protect against data exfiltration
-   control MCP/tool interactions
-   protect AI applications
-   detect malicious prompts and agent behavior

### Strategic decision

Check Point is putting AI understanding directly into the existing
firewall enforcement point.

This is important because the firewall already sits at a location where
traffic can be allowed or denied.

### Strength

This is probably the closest commercial implementation to the original
idea of an "AI firewall."

### Research implication

Do not position the project as:

> "Build an AI-aware firewall."

That market is already active.

Instead investigate the lower-level identity-to-flow problem.

### Source

https://blog.checkpoint.com/security/introducing-the-industrys-first-ai-network-firewall/

------------------------------------------------------------------------

# 10. Cloudflare

Cloudflare Mesh provides private networking for:

-   humans
-   agents
-   nodes
-   Workers
-   multicloud infrastructure

Cloudflare explicitly positions Mesh as infrastructure for AI agents
that need access to private databases and APIs.

Cloudflare also provides scoped permissions and OAuth-oriented controls
for agents.

### Strategic decision

Cloudflare is treating AI agents as first-class network participants.

Instead of forcing agents through legacy VPNs/manual tunnels, it
provides a secure private networking fabric.

### Strength

Very strong at:

-   global connectivity
-   private networking
-   agent identity
-   scoped access
-   cloud infrastructure
-   large-scale deployment

### Remaining research area

Again, the precise cryptographic attribution of a flow to an individual
agent instance under shared/multiplexed network conditions remains an
interesting standards-level problem.

### Source

https://www.cloudflare.com/en-gb/press/press-releases/2026/cloudflare-launches-mesh-to-secure-the-ai-agent-lifecycle/

------------------------------------------------------------------------

# 11. Okta

Okta has moved heavily into agent identity.

Current capabilities include:

-   Agent as Principal
-   Agent Gateway
-   Agent-to-Agent Connections
-   delegated identity
-   short-lived credentials
-   task-scoped authorization
-   human-to-agent accountability
-   multi-agent delegation chains
-   credential isolation

Okta's Agent Gateway provides an inline policy enforcement point in
front of enterprise resources.

Okta also emphasizes that background agents should not require users to
maintain active sessions indefinitely.

### Strategic decision

Okta is making the agent a first-class security principal and carrying
identity through the agent delegation chain.

### Strength

Very strong in:

``` text
Identity
+
Delegation
+
Authorization
+
Short-lived credentials
+
Agent-to-agent chains
```

### Remaining research area

Okta is primarily an identity/control-plane solution. The harder
research question remains the network-layer association between an agent
instance and enforceable traffic, particularly in shared network
infrastructure.

### Sources

https://www.okta.com/blog/product-innovations/

https://www.okta.com/en-in/blog/ai/okta-securing-ai-agent-identity/

------------------------------------------------------------------------

# 12. IETF

## Network Admission of AI Agent Instances

This is the most important standards development for this research.

The July 2026 Internet-Draft explicitly identifies:

> Application-layer authentication cannot by itself provide complete
> network admission control.

It highlights the exact scenario:

``` text
Host
 |
 +-- Agent A
 +-- Agent B
 +-- Agent C
 +-- Ordinary process
 |
 +-- Same IP
 |
 +-- Shared egress gateway
```

Traditional network admission can authenticate the device/user but
cannot reliably distinguish which agent generated subsequent traffic.

The draft defines the concept of an:

**Agent Binding**

which associates:

``` text
Agent Instance
+
Credential Key
+
Security attributes
+
Network Context
```

with a finite lifetime.

It also requires:

-   instance authentication
-   proof of possession
-   freshness
-   binding to enforceable traffic
-   shared-gateway attribution
-   admission before general reachability
-   lifecycle management
-   revocation
-   non-bypassability
-   audit/privacy
-   agent-to-agent considerations

### Extremely important limitation

The IETF draft is an **Internet-Draft, not an RFC or approved
standard**.

It explicitly does not define:

-   a new Agent-ID format
-   authentication protocol
-   OAuth grant
-   routing extension

This means the requirements are being formalized, but the actual
protocol mechanism remains open.

### Source

https://datatracker.ietf.org/doc/draft-shang-agent-network-admission/

------------------------------------------------------------------------

# 13. NIST

NIST launched an AI Agent Standards Initiative in 2026 with pillars
around:

-   industry-led standards
-   community protocols
-   research
-   secure and interoperable agent ecosystems

NIST is also researching software/AI agent identity and authorization.

### Strategic direction

NIST is not trying to create one proprietary product.

It is helping establish an ecosystem of interoperable standards and
security practices.

### Research implication

A protocol proposal should align with:

-   Zero Trust
-   workload identity
-   least privilege
-   verifiable identity
-   interoperability
-   privacy
-   auditability

### Source

https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure

------------------------------------------------------------------------

# 14. Competitive Landscape Summary

  -----------------------------------------------------------------------------------------------------------------------
  Capability         Microsoft   Palo Alto Zscaler   Cisco     Fortinet   Check     Cloudflare   Okta      IETF
                                                                          Point                            
  ------------------ ----------- --------- --------- --------- ---------- --------- ------------ --------- --------------
  Agent discovery    Strong      Strong    Strong    Strong    Strong     Strong    Partial      Strong    Requirements

  Agent identity     Strong      Strong    Strong    Strong    Partial    Strong    Strong       Strong    Requirements

  Human -\> Agent    Strong      Strong    Strong    Strong    Partial    Partial   Strong       Strong    Discussed

  Delegation         Strong      Strong    Strong    Strong    Partial    Partial   Strong       Strong    Discussed

  Short-lived        Strong      Strong    Strong    Partial   Partial    Partial   Strong       Strong    Required
  credentials                                                                                              

  Agent registry     Strong      Strong    Strong    Strong    Strong     Strong    Partial      Strong    N/A

  AI                 Strong      Strong    Strong    Strong    Strong     Strong    Strong       Gateway   N/A
  gateway/firewall                                                                                         

  MCP/A2A            Strong      Strong    Strong    Strong    Strong     Strong    Strong       Strong    Emerging

  Runtime security   Strong      Strong    Strong    Strong    Strong     Strong    Partial      Partial   N/A

  Behavioral risk    Strong      Strong    Strong    Strong    Strong     Strong    Partial      Strong    N/A

  Agent-to-agent     Strong      Strong    Strong    Strong    Strong     Strong    Partial      Strong    Requirements
  governance                                                                                               

  Network admission  Partial     Strong    Strong    Strong    Strong     Strong    Strong       Partial   **Core focus**

  Exact              Partial     Partial   Partial   Partial   Partial    Partial   Partial      Partial   **Identified
  agent-instance -\>                                                                                       gap**
  network binding                                                                                          

  Shared IP/gateway  Partial     Partial   Partial   Partial   Partial    Partial   Partial      Partial   **Identified
  attribution                                                                                              gap**

  Vendor-neutral     No          No        No        No        No         No        No           No        **Not
  protocol                                                                                                 defined**
  -----------------------------------------------------------------------------------------------------------------------

"Partial" here means the vendor has adjacent controls or can correlate
context, not that the product necessarily lacks the capability entirely.
Public product documentation does not expose enough implementation
detail to claim a definitive absence.

------------------------------------------------------------------------

# 15. What the Competitors Are Converging On

The market is converging on a common architecture:

``` text
Agent Discovery
      |
      v
Agent Identity
      |
      v
Authorization
      |
      v
AI Gateway / Broker
      |
      v
Runtime / Behavior Security
      |
      v
Network Enforcement
      |
      v
SIEM / Audit
```

The strategic difference is where each vendor starts.

### Microsoft

Starts with:

``` text
Identity
```

### Okta

Starts with:

``` text
Identity + Delegation
```

### Zscaler

Starts with:

``` text
Zero Trust Network + AI Broker
```

### Palo Alto

Starts with:

``` text
Full AI Security Lifecycle
```

### Cisco

Starts with:

``` text
Network + Security + Observability
```

### Fortinet

Starts with:

``` text
Firewall + Security Fabric
```

### Check Point

Starts with:

``` text
Firewall + AI inspection
```

### Cloudflare

Starts with:

``` text
Global network + private agent connectivity
```

### IETF

Starts with:

``` text
Standards-level network admission requirements
```

------------------------------------------------------------------------

# 16. What Problems Are Still Hard?

## Challenge 1: Agent-instance attribution

This is the strongest gap.

Suppose:

``` text
Laptop
10.10.10.20

Agent A
Agent B
Agent C
Browser
Malware
```

all use:

``` text
10.10.10.20
```

A traditional firewall cannot reliably infer which process created a
packet.

An unprotected:

``` text
X-Agent-ID: Agent-A
```

header is spoofable.

The research problem is:

> How can the network obtain a cryptographically trustworthy, per-agent
> identity that maps to enforceable traffic?

------------------------------------------------------------------------

# 17. Challenge 2: Shared gateways

Consider:

``` text
Agent A ----+
Agent B ----+
Agent C ----+--> Proxy --> Internet
Agent D ----+
```

The external destination sees the proxy.

Even if the gateway knows the originating agent, that identity can be
lost when requests are:

-   pooled
-   proxied
-   NATed
-   multiplexed
-   load balanced

The IETF draft specifically calls out HTTP/2 and HTTP/3 multiplexing.

Research question:

> How do we preserve agent attribution across shared network
> infrastructure without allocating a unique IP address to every agent?

------------------------------------------------------------------------

# 18. Challenge 3: Agent lifecycle

Agents can be:

-   created
-   cloned
-   restarted
-   migrated
-   suspended
-   terminated

A static binding can accidentally survive the original agent.

Example:

``` text
Agent A
   |
   | Network Context 123
   |
terminated
   |
   v
Agent B starts
   |
   | accidentally inherits
   v
Network Context 123
```

This must be prevented.

An agent binding must have:

-   lifetime
-   nonce/freshness
-   key continuity
-   renewal
-   revocation
-   migration rules

------------------------------------------------------------------------

# 19. Challenge 4: Agent-to-agent delegation

Example:

``` text
User
 |
Agent A
 |
Agent B
 |
Agent C
 |
Database
```

The security system needs to answer:

> Who ultimately authorized Agent C?

A useful chain is:

``` text
Human
  |
  v
Agent A
  |
  v
Agent B
  |
  v
Agent C
```

Every delegation should reduce or preserve authority, never silently
increase it.

------------------------------------------------------------------------

# 20. Challenge 5: Non-bypassability

A beautiful identity protocol is useless if the agent can simply bypass
the enforcement point.

Possible bypasses:

``` text
Agent
 |
 +--> Approved gateway
 |
 +--> Direct NIC
 |
 +--> VPN
 |
 +--> Alternate proxy
 |
 +--> IPv6 path
 |
 +--> Cloud metadata route
```

Therefore the system must control the complete network path.

This is why the research must include:

-   routing
-   network namespaces
-   egress controls
-   endpoint enforcement
-   firewall
-   proxy
-   service mesh
-   cloud networking

------------------------------------------------------------------------

# 21. Challenge 6: Privacy

If the system records:

``` text
User
Agent
Prompt
Destination
Action
Data
```

it can become a very powerful surveillance system.

The research should therefore separate:

``` text
Identity attribution
```

from:

``` text
Full content inspection
```

and minimize collection.

Potential model:

``` text
Normal:
Flow metadata

Suspicious:
Detailed metadata

High risk:
Deep inspection
```

------------------------------------------------------------------------

# 22. Challenge 7: Scale

The target could be:

``` text
1M agents
10M agents
100M agent instances
```

You cannot maintain:

``` text
1 unique firewall rule per agent
```

Instead:

``` text
Agent Identity
      |
      v
Policy class
      |
      v
Shared enforcement policy
```

Example:

``` text
100,000 research agents
        |
        v
RESEARCH-INTERNET policy
```

Individual identity remains unique, but policy is aggregated.

------------------------------------------------------------------------

# 23. Proposed Research Opportunity

## Working name

**Agent Network Binding Protocol (ANBP)**

This is a research name only.

The protocol should not replace TCP, TLS, OAuth, or workload identity.

It should provide one missing relationship:

``` text
Agent Instance
      |
      | cryptographic proof
      v
Network Binding
      |
      | enforceable context
      v
Network Flow
```

------------------------------------------------------------------------

# 24. Proposed protocol stack

``` text
+--------------------------------+
| Application                   |
| HTTP / MCP / A2A / APIs       |
+--------------------------------+
| Agent Network Binding Layer   |
| Identity / Capability /       |
| Network Context / Proof       |
+--------------------------------+
| TLS / QUIC                    |
+--------------------------------+
| TCP / UDP / IP                |
+--------------------------------+
```

The binding layer can initially be implemented as an overlay rather than
a new transport protocol.

------------------------------------------------------------------------

# 25. Proposed Agent Binding Object

Conceptual structure:

``` json
{
  "agent_id": "agt-123",
  "agent_instance_id": "inst-789",
  "principal_id": "user-456",
  "organization_id": "org-001",
  "runtime_id": "runtime-55",
  "capabilities": [
    "internet.read",
    "github.read"
  ],
  "network_context": "nc-8272",
  "issued_at": "timestamp",
  "expires_at": "timestamp",
  "nonce": "fresh-value",
  "public_key": "agent-key",
  "policy_id": "research-agent-v1",
  "signature": "cryptographic-proof"
}
```

This is conceptual and not a proposed standard format yet.

------------------------------------------------------------------------

# 26. Proposed admission flow

``` text
Agent
  |
  | 1. Request admission
  v
Network Admission Function
  |
  | 2. Verify agent key
  | 3. Verify delegation
  | 4. Verify runtime
  | 5. Evaluate policy
  | 6. Create network context
  v
Enforcement Point
  |
  | 7. Install binding
  v
Network
```

The user is not involved in every renewal.

------------------------------------------------------------------------

# 27. Automatic lifecycle

``` text
Human approves agent
        |
        v
Agent identity created
        |
        v
Credential issued
        |
        v
Network binding installed
        |
        v
Agent operates
        |
        +-----> automatic renewal
        |
        +-----> risk increases
        |           |
        |           v
        |        restrict
        |
        +-----> credential revoked
                    |
                    v
                  block
```

------------------------------------------------------------------------

# 28. External Agent Scenario

``` text
External Agent
      |
      v
Enterprise Network
      |
      v
Admission Point
      |
      +-- Valid enterprise agent binding? NO
      |
      v
    BLOCK
```

An external attacker cannot simply claim:

``` text
Agent-ID: company-agent-123
```

because identity is bound to cryptographic proof and an enforceable
network context.

------------------------------------------------------------------------

# 29. Authorized Internal Agent Scenario

``` text
Internal Agent
      |
      v
Agent identity
      |
      v
Valid binding
      |
      v
Policy:
  Internet = ALLOW
  Internal DB = DENY
      |
      +----> Internet: ALLOW
      |
      +----> Internal DB: BLOCK
```

------------------------------------------------------------------------

# 30. Compromised Agent Scenario

``` text
Agent
  |
  v
Legitimate identity
  |
  v
Compromised through prompt injection/tool poisoning
  |
  v
Unexpected network behavior
  |
  v
Risk Engine
  |
  v
High Risk
  |
  +--> restrict network
  +--> revoke binding
  +--> terminate session
  +--> alert SOC
```

The user can remain active.

Only the agent can be revoked.

------------------------------------------------------------------------

# 31. How to Defend the Research Against Competitors

A reviewer may say:

> "Microsoft already has Agent ID."

Answer:

> Yes. The proposed work does not attempt to replace agent identity. It
> investigates the missing network-level binding between an
> authenticated agent instance and enforceable network traffic.

A reviewer may say:

> "Zscaler already has an AI Broker."

Answer:

> The proposed work is not another AI gateway. It defines a
> vendor-neutral mechanism for preserving agent-instance identity across
> shared network infrastructure, including shared IP addresses, proxies,
> NAT, egress gateways and multiplexed connections.

A reviewer may say:

> "Okta already carries user identity through the agent."

Answer:

> User-to-agent delegation is necessary but not sufficient for network
> admission. The research focuses on mapping the resulting agent
> identity to a network context that can be enforced before general
> network reachability.

A reviewer may say:

> "IETF is already working on this."

Answer:

> Correct. The IETF draft formalizes the use cases and requirements but
> explicitly does not define a new Agent-ID format, authentication
> protocol, OAuth grant, or routing extension. The research can
> therefore investigate concrete mechanisms and experimental
> implementations while remaining aligned with the draft.

------------------------------------------------------------------------

# 32. Strongest Novelty Claim

Avoid:

> "A new AI firewall."

Use:

> **"A scalable mechanism for cryptographically binding an autonomous
> AI-agent instance to an enforceable network context, preserving
> attribution across shared hosts, NAT, proxies, shared egress gateways
> and multiplexed connections while supporting delegated human authority
> and automatic credential lifecycle."**

That is substantially narrower and more defensible.

------------------------------------------------------------------------

# 33. Threat Model

The research should explicitly defend against:

### T1 --- External unknown agent

``` text
Internet -> Internal network
```

Expected result:

``` text
BLOCK
```

### T2 --- Unauthorized local agent

``` text
Trusted laptop
     |
Unknown local agent
```

Expected result:

``` text
BLOCK
```

### T3 --- Agent identity spoofing

Attacker sends another agent's ID.

Expected:

``` text
BLOCK
```

### T4 --- Credential replay

Old binding is reused.

Expected:

``` text
BLOCK
```

### T5 --- Agent cloning

Agent image is cloned.

Expected:

``` text
New instance requires new binding
```

unless continuity is explicitly proven.

### T6 --- Shared IP ambiguity

Several agents share one IP.

Expected:

``` text
Each flow remains attributable
```

### T7 --- Shared proxy

Several agents share one gateway.

Expected:

``` text
Per-agent attribution survives proxying
```

### T8 --- HTTP/2/HTTP/3 multiplexing

Multiple agent requests share a connection.

Expected:

``` text
Request -> Agent identity remains attributable
```

### T9 --- Direct bypass

Agent tries another route.

Expected:

``` text
BLOCK
```

### T10 --- Compromised agent

Agent identity remains valid but behavior becomes malicious.

Expected:

``` text
Risk escalation
+
Restriction/revocation
```

------------------------------------------------------------------------

# 34. Proposed Evaluation

Build a prototype with:

``` text
10 agents
100 agents
1,000 agents
10,000 agents
100,000 agents
1,000,000 simulated agents
```

Test:

### Identity attribution

Can the system identify the exact agent instance?

### Shared-host attribution

Can it distinguish:

``` text
Agent A
Agent B
Browser
```

using one host/IP?

### Shared-gateway attribution

Can it distinguish agents behind one proxy?

### Multiplexing

Can it preserve attribution through HTTP/2/HTTP/3?

### Revocation

How quickly does blocking take effect?

### Scale

Measure:

-   CPU
-   memory
-   events/sec
-   policy evaluation latency
-   gateway throughput
-   storage volume
-   credential issuance rate

### Usability

Measure:

``` text
Human authentication events
```

Target:

``` text
One initial approval
+
automatic lifecycle
```

------------------------------------------------------------------------

# 35. Research Deliverables

The project should produce:

1.  **Threat model**
2.  **Architecture**
3.  **Agent identity model**
4.  **Delegation model**
5.  **Agent Binding specification**
6.  **Network Context model**
7.  **Admission protocol**
8.  **Credential lifecycle**
9.  **Shared-gateway mechanism**
10. **Traffic attribution mechanism**
11. **Revocation model**
12. **Privacy model**
13. **Prototype**
14. **Performance benchmark**
15. **Comparison against existing systems**
16. **Security analysis**
17. **Potential standards proposal**

------------------------------------------------------------------------

# 36. Recommended Development Phases

## Phase 1 --- Research

Study:

-   NIST Zero Trust
-   NIST AI Agent Standards Initiative
-   IETF Agent Network Admission
-   OAuth 2.0/OIDC
-   SPIFFE/SPIRE
-   WIMSE
-   MCP
-   A2A
-   EAP-TLS
-   mTLS
-   service meshes
-   network access control
-   SASE

## Phase 2 --- Baseline

Build:

``` text
AD/Entra
+
Agent identity
+
Gateway
+
Firewall
```

Measure limitations.

## Phase 3 --- Agent binding

Introduce:

``` text
Agent Instance
       |
       v
Network Context
```

## Phase 4 --- Shared infrastructure

Test:

``` text
multiple agents
        |
        v
one host
        |
        v
one IP
        |
        v
one gateway
```

## Phase 5 --- Multiplexing

Test:

-   HTTP/2
-   HTTP/3
-   QUIC
-   proxy pools

## Phase 6 --- Security

Test:

-   spoofing
-   replay
-   cloning
-   credential theft
-   bypass
-   malicious agent
-   compromised runtime

## Phase 7 --- Scale

Simulate millions of agents.

## Phase 8 --- Standards/paper

Compare results against:

-   Microsoft Agent ID
-   Okta
-   Zscaler
-   Palo Alto
-   Cisco
-   Fortinet
-   Check Point
-   Cloudflare
-   IETF requirements

------------------------------------------------------------------------

# 37. Key Strategic Decision

The research should **not compete head-on** with:

``` text
Microsoft
Palo Alto
Zscaler
Cisco
Fortinet
Check Point
Okta
Cloudflare
```

Instead it should provide a mechanism that these systems could
potentially consume.

Think:

``` text
Existing products
      |
      +------------------+
      |                  |
      v                  v
Identity              Firewall
      |                  |
      +--------+---------+
               |
               v
       Agent Binding Layer
               |
               v
      Network Enforcement
```

The proposed mechanism could become a common layer between identity
providers and network enforcement products.

------------------------------------------------------------------------

# 38. Most Important Research Gap

The strongest gap is:

## "Identity-to-network binding"

Current systems are very good at:

``` text
Who is the agent?
```

and increasingly good at:

``` text
What is the agent allowed to do?
```

and:

``` text
Is the agent behaving suspiciously?
```

The harder question is:

> **Which exact network traffic belongs to that exact running agent
> instance?**

Especially when:

``` text
10 agents
  |
1 host
  |
1 IP
  |
1 proxy
  |
1 HTTP/2 connection
```

The network must still distinguish:

``` text
Request 1 -> Agent A
Request 2 -> Agent B
Request 3 -> Agent C
```

without relying on a spoofable header.

------------------------------------------------------------------------

# 39. Secondary Research Gap

## "Pre-reachability agent admission"

Current application identity generally happens at the application layer.

The research should investigate:

``` text
Agent
 |
Admission
 |
Network Context
 |
Reachability
 |
Application Authorization
```

rather than:

``` text
Agent
 |
Network
 |
Reachability
 |
Application authentication
```

This provides a defense layer before the agent can scan, probe or reach
protected resources.

------------------------------------------------------------------------

# 40. Third Research Gap

## "Universal attribution across heterogeneous infrastructure"

The mechanism should work across:

``` text
On-prem
Azure
AWS
GCP
Kubernetes
VMs
Laptops
Branch networks
SASE
Proxies
Service meshes
Firewalls
Cloud gateways
```

The identity should not disappear simply because traffic crosses:

``` text
NAT
Proxy
Load balancer
Gateway
Service mesh
Cloud boundary
```

This is likely more difficult than creating the identity itself.

------------------------------------------------------------------------

# 41. Final Architecture

The refined architecture is:

``` text
                         HUMAN
                           |
                     AD / Entra / IdP
                           |
                     Authenticate once
                           |
                           v
                  +-------------------+
                  | Agent Registration|
                  | & Delegation      |
                  +---------+---------+
                            |
                      Agent Identity
                            |
                            v
                  +-------------------+
                  | Agent Identity    |
                  | Authority         |
                  +---------+---------+
                            |
                     Agent credential
                            |
                            v
                  +-------------------+
                  | Agent Runtime     |
                  |                   |
                  | Agent Instance    |
                  +---------+---------+
                            |
                     Admission proof
                            |
                            v
                  +-------------------+
                  | Network Admission |
                  | Function          |
                  +---------+---------+
                            |
                    Agent Binding
                            |
                            v
                  +-------------------+
                  | Network Context   |
                  +---------+---------+
                            |
                            v
                  +-------------------+
                  | Enforcement Point |
                  |                   |
                  | Firewall          |
                  | Proxy             |
                  | Gateway           |
                  | SASE              |
                  +---------+---------+
                            |
                    +-------+-------+
                    |               |
                    v               v
               Enterprise       Internet
                Resources
```

Control plane:

``` text
                    CONTROL PLANE
                         |
        +----------------+----------------+
        |                |                |
        v                v                v
   Agent Registry    Policy Engine    Risk Engine
        |                |                |
        +----------------+----------------+
                         |
                   Revocation
                         |
                         v
                  Enforcement Points
```

------------------------------------------------------------------------

# 42. Final Position

The research opportunity is **real, but it is not "AI firewall."**

The market has already moved strongly toward:

``` text
Agent Identity
Agent Registry
Agent Authorization
AI Gateway
Agent Runtime Security
MCP/A2A Security
AI Firewall
Zero Trust
```

The most defensible research opportunity is:

> **Agent-instance-to-network-context binding.**

Specifically:

> **A scalable, cryptographically verifiable, vendor-neutral mechanism
> that allows a network enforcement point to identify and enforce policy
> for the exact AI-agent instance responsible for traffic---even when
> many agents share hosts, IP addresses, NAT, proxies, gateways, or
> multiplexed connections---while maintaining delegated human authority
> and automatic credential lifecycle.**

This is especially timely because the IETF has now formally documented
this problem in an active 2026 Internet-Draft, while explicitly leaving
the concrete protocol mechanism undefined.

The research should therefore move from:

**"Can we build an AI firewall?"**

to:

**"Can we create a standardizable agent-to-network binding mechanism
that existing identity providers, gateways, firewalls, SASE platforms
and AI security products can consume?"**

That is the stronger research thesis.

------------------------------------------------------------------------

# 43. Primary References

## Microsoft

Microsoft Entra Agent ID\
https://learn.microsoft.com/en-us/entra/agent-id/

Microsoft Entra Agent ID design patterns\
https://learn.microsoft.com/en-us/entra/agent-id/concept-agent-id-design-patterns

Microsoft Entra security for AI\
https://learn.microsoft.com/en-us/entra/agent-id/security-for-ai-overview

Authentication protocols for agents\
https://learn.microsoft.com/en-us/entra/agent-id/agent-oauth-protocols

## Palo Alto Networks

Prisma AIRS 3.0\
https://www.paloaltonetworks.com/blog/2026/03/prisma-airs-3-0-autonomous-ai/

## Zscaler

Zero Trust for Agentic AI\
https://www.zscaler.com/press/zscaler-unveils-new-product-innovations-secure-agentic-ai

## Cisco

Cisco AI Defense and Agentic Security\
https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2026/m03/cisco-reimagines-security-for-the-agentic-workforce.html

## Fortinet

FortiOS 8.0 AI Security\
https://www.fortinet.com/corporate/about-us/newsroom/press-releases/2026/fortinet-introduces-fortios-8-expand-secure-networking-with-secure-ai-controls-fabric-based-ai-agents-flexible-sase-and-simplified-sdwan

## Check Point

AI Network Firewall\
https://blog.checkpoint.com/security/introducing-the-industrys-first-ai-network-firewall/

## Cloudflare

Cloudflare Mesh\
https://www.cloudflare.com/en-gb/press/press-releases/2026/cloudflare-launches-mesh-to-secure-the-ai-agent-lifecycle/

## Okta

Okta AI Agent Security\
https://www.okta.com/en-in/blog/ai/okta-securing-ai-agent-identity/

Okta Product Innovation Hub\
https://www.okta.com/blog/product-innovations/

## IETF

Network Admission of AI Agent Instances\
https://datatracker.ietf.org/doc/draft-shang-agent-network-admission/

## NIST

AI Agent Standards Initiative\
https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure
