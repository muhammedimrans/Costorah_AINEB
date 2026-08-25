# Phase 2 Deep Research Query --- AI Agent Instance Identity & Network Enforcement

**Purpose:** Deep technical prior-art, standards, implementation, and
falsification research following the Phase 1 co-resident agent
experiment.

**Recommended working protocol name:** **AIBP --- AI Agent Binding
Protocol**

**Alternative names considered:** - **AIBP --- AI Agent Binding
Protocol** --- recommended; simple, descriptive, protocol-oriented. -
**AINS --- Agent Instance Network Security** --- better as a research
area/product name, less suitable for a protocol. - **AIB --- Agent
Identity Binding** --- concise, but too generic. - **AIBEP --- Agent
Identity Binding & Enforcement Protocol** --- technically precise, but
cumbersome. - **ANBP --- Agent Network Binding Protocol** --- good
alternative, but broader than the current research. - **AISBP --- Agent
Instance Security Binding Protocol** --- precise but awkward.

### Recommended choice

> **AIBP --- AI Agent Binding Protocol**

Use **AIBP** as a working name only until the prior-art investigation
confirms that the name does not conflict with an existing
protocol/project. The protocol should not be finalized until the
experiments establish that a protocol-level contribution is actually
necessary.

------------------------------------------------------------------------

# Claude Research Query --- Phase 2 Deep Research

We are conducting a systems/security research project on **AI-agent
instance identity and network enforcement**.

I have already completed Phase 1 experiments on Linux using a
mock/faithful reproduction of SPIRE workload-attestor selector behavior.
The attached research artifacts are:

-   `PHASE1_REPORT.md`
-   `results.json`
-   `attestor.py`
-   `run_experiment.py`

**Read all four files first and treat them as experimental evidence. Do
not assume their conclusions are correct without verification.**

------------------------------------------------------------------------

# Phase 1 Findings to Investigate

The experiment found:

1.  Four co-resident identical agent processes received the same SPIRE
    selector set and same SPIFFE ID despite having different kernel
    PIDs.
2.  Adding a distinguishing argv/principal label did not change the
    SPIRE selector set.
3.  The tested discriminator inventory had no attribute that
    simultaneously:
    -   varies between instances,
    -   is kernel-authoritative/non-forgeable by the workload,
    -   and is predictable/admissible in a pre-authored SPIRE
        registration entry.
4.  Local `/proc` inspection could attribute separate process-based
    flows correctly using socket inodes.
5.  However, when four agent sessions were implemented as threads inside
    **one process**, all sessions shared the same PID while their
    sockets remained distinct.
6.  This suggests that **socket/session identity may be a stronger
    network anchor than process identity**.
7.  One real container per agent instance appears to provide
    individuation through container identity, but arbitrary per-instance
    cgroups do not automatically become SPIRE selectors.
8.  PID reuse was observed under high process churn, demonstrating that
    PID alone is not a durable identity.
9.  G3 --- transferring a verified identity verdict into a real network
    enforcement point --- has not yet been tested.

The current hypothesis is therefore:

> **The difficult problem is not simply "AI-agent identity." It is
> preserving a trustworthy identity relationship from an exact agent
> session/instance through runtime and kernel-level execution context to
> a network socket/flow, and then making that identity enforceable by a
> network security control.**

------------------------------------------------------------------------

# Research Task

Perform a **deep technical prior-art and experimental-design
investigation** to determine whether this research gap is genuinely
novel.

Do NOT simply search for "AI agent security." Investigate the specific
technical chain:

``` text
Human / Delegating Principal
       ↓
Agent Identity
       ↓
Agent Instance / Session
       ↓
Runtime / Process / Thread
       ↓
Socket
       ↓
Network Flow
       ↓
Network Enforcement Point
```

I need to know exactly where existing technologies already solve this
chain and where they do not.

------------------------------------------------------------------------

# 1. Verify the Phase 1 Experiment

Critically review:

-   `attestor.py`
-   `run_experiment.py`
-   `results.json`
-   `PHASE1_REPORT.md`

Determine:

1.  Does the reproduction accurately represent real SPIRE
    workload-attestor behavior?
2.  Are the claims about SPIRE registration entries accurate?
3.  Is the conclusion that the usable-selector intersection is empty
    logically sound?
4.  Are there SPIRE selectors, APIs, workload-attestor mechanisms,
    registration-entry mechanisms, or plugins that could invalidate this
    conclusion?
5.  Does SPIRE have any supported mechanism for identifying:
    -   individual process instances?
    -   threads?
    -   individual agent sessions?
    -   dynamically created workloads?
    -   runtime-generated identities?
6.  Is the single-process/multiple-agent-session case actually a known
    limitation?
7.  Could SPIRE solve the problem through custom workload attestation
    without changing the architecture?

Clearly distinguish:

**Stock SPIRE capability**

vs.

**Custom SPIRE plugin**

vs.

**Architectural workaround**

vs.

**Fundamentally different protocol/mechanism**

------------------------------------------------------------------------

# 2. Investigate Socket-Level Identity

Research whether Linux provides a trustworthy mechanism for binding:

``` text
Agent Session
      ↓
Thread/process/runtime
      ↓
Socket
      ↓
Network Flow
```

Investigate in depth:

-   `bpf_get_socket_cookie`
-   cgroup hooks
-   `connect4`
-   `connect6`
-   `sock_ops`
-   `sk_lookup`
-   `cgroup/connect4`
-   `cgroup/connect6`
-   `SO_COOKIE`
-   socket inode
-   cgroup ID
-   `task_struct`
-   PID
-   TID
-   PID namespace
-   network namespace
-   process credentials
-   eBPF maps
-   Linux Security Modules
-   seccomp
-   Landlock
-   SELinux/AppArmor
-   Cilium
-   Tetragon
-   Envoy
-   agentgateway
-   service meshes
-   per-agent network namespaces
-   virtual interfaces

Determine:

> **Can a socket be cryptographically or kernel-authoritatively
> associated with an agent session in a way that another process cannot
> spoof?**

Also investigate the lifetime and semantics of socket cookies:

-   uniqueness
-   reuse
-   lifetime
-   visibility
-   namespace behavior
-   race conditions
-   fork behavior
-   thread behavior
-   socket duplication
-   `dup()`
-   `SCM_RIGHTS`
-   inherited sockets
-   connection pooling
-   socket migration
-   transparent proxying

------------------------------------------------------------------------

# 3. Investigate the Single-Process Multi-Agent Problem

This is the most important scenario.

Consider:

``` text
One Agent Runtime Process
|
+-- Session A → Socket A
+-- Session B → Socket B
+-- Session C → Socket C
+-- Session D → Socket D
```

All sessions may share:

-   PID
-   UID
-   executable
-   container
-   network namespace
-   IP

But each represents a different human/delegation context.

Investigate whether existing technologies can distinguish these
sessions.

Search specifically for:

-   agent session identity
-   workload identity per request
-   per-request workload identity
-   per-thread workload identity
-   socket-bound identity
-   connection-bound identity
-   execution context identity
-   agent session credentials
-   runtime session isolation
-   delegated identity per connection

Determine whether any existing standard already solves this.

------------------------------------------------------------------------

# 4. Investigate WIMSE Deeply

Research current WIMSE work, including:

-   Workload Identity
-   Workload Identifier
-   Workload Credentials
-   Workload Proof Token
-   HTTP Message Signatures
-   execution-context-token
-   attestation
-   delegation
-   workload-to-workload authentication

Determine exactly what WIMSE solves at:

## Application layer

``` text
HTTP request → workload identity
```

## Transport layer

``` text
TLS / mTLS → workload identity
```

## Runtime layer

``` text
process/session → workload identity
```

## Network layer

``` text
socket/flow → workload identity
```

## Enforcement layer

``` text
workload identity → firewall/SASE decision
```

Identify precisely which transitions WIMSE defines and which it does
not.

Do not simply say "WIMSE doesn't solve it." Identify the relevant
mechanisms and limitations from the actual specifications/drafts.

------------------------------------------------------------------------

# 5. Investigate SPIFFE/SPIRE Alternatives

Research:

-   SPIFFE/SPIRE
-   Workload API
-   Delegated Identity API
-   workload attestors
-   PID-based attestation
-   Unix attestor
-   Docker/Kubernetes attestors
-   custom attestors
-   selectors
-   dynamic registration
-   node attestation
-   workload identity rotation

Find whether there is an existing way to make identity:

``` text
instance-specific
+
kernel-authoritative
+
dynamically generated
+
securely bound to a socket
```

without requiring one container per agent.

------------------------------------------------------------------------

# 6. Investigate Cilium/eBPF/Tetragon

Determine exactly what Cilium and Tetragon already provide for:

-   process identity
-   cgroup identity
-   socket identity
-   network policy
-   process-to-network correlation
-   runtime identity
-   Kubernetes workload identity
-   security enforcement
-   per-process network policy
-   per-socket enforcement

Important question:

> **Can Cilium/Tetragon already independently enforce network policy for
> two sessions inside the same process?**

If yes, explain how.

If no, explain exactly where the limitation is.

------------------------------------------------------------------------

# 7. Investigate Envoy and agentgateway

Determine whether Envoy/agentgateway can:

-   receive workload identity
-   receive WPT
-   verify HTTP signatures
-   identify individual agent sessions
-   propagate identity
-   attach identity to connections
-   enforce policies per agent
-   distinguish multiple agents inside one process
-   expose verified identity to an external firewall

Determine whether agentgateway already solves G3.

------------------------------------------------------------------------

# 8. Investigate Commercial Competitors

Deeply investigate current 2026 capabilities of:

-   Microsoft Entra Agent ID
-   Microsoft Agent 365
-   Palo Alto Prisma AIRS
-   Zscaler AI Broker
-   Cisco AI Defense
-   Fortinet AI security
-   Check Point AI Network Firewall
-   Cloudflare Mesh / agent networking
-   Okta Agent Identity / Agent Gateway

For each, answer:

1.  Can it identify an individual agent instance?
2.  Can it distinguish multiple agents inside one process?
3.  Can it distinguish multiple sessions inside one agent runtime?
4.  Can it bind identity to a socket?
5.  Can it bind identity to L3/L4 flows?
6.  Can it enforce per-agent network policy?
7.  Can it independently block Agent A while Agent B continues?
8.  Does it work behind NAT?
9.  Does it work through proxies?
10. Does it work with HTTP/2 multiplexing?
11. Does it work with HTTP/3/QUIC?
12. Does it work for non-HTTP protocols?
13. Does it require one container per agent?
14. Does it require one process per agent?
15. Does it require vendor-specific infrastructure?

For every answer classify evidence as:

-   **Documented**
-   **Demonstrated**
-   **Inferred**
-   **Unknown**

Do not mark a capability "unsupported" simply because public
documentation does not mention it.

------------------------------------------------------------------------

# 9. Investigate Academic Research

Search academic papers and security research for:

-   workload identity
-   process-to-flow attribution
-   socket identity
-   per-process network policy
-   per-thread network identity
-   microservice identity
-   confidential workloads
-   agent identity
-   autonomous agent security
-   AI agent network security
-   execution context identity
-   capability-based networking
-   network admission control
-   kernel-level identity
-   eBPF identity
-   socket-bound credentials

Identify whether:

``` text
Agent Session → Socket → Flow → Enforcement
```

has already been published.

If it has, explain exactly how our research differs.

------------------------------------------------------------------------

# 10. Investigate Existing Linux Security Mechanisms

Determine whether these already provide the proposed functionality:

-   SELinux
-   AppArmor
-   Landlock
-   seccomp
-   cgroups
-   namespaces
-   systemd sandboxing
-   auditd
-   eBPF LSM
-   Tetragon
-   nftables
-   iptables
-   tc
-   XDP
-   conntrack

Specifically ask:

> **Can Linux already create a trustworthy per-agent-session network
> identity without a new protocol?**

This is a critical falsification test.

------------------------------------------------------------------------

# 11. Investigate Alternative Architectures

Compare:

### Architecture A --- One container per agent

### Architecture B --- One process per agent

### Architecture C --- One runtime process with multiple agent sessions

### Architecture D --- One network namespace per agent

### Architecture E --- One virtual interface per agent

### Architecture F --- Per-agent socket identity using eBPF

### Architecture G --- Application-layer WIMSE identity

### Architecture H --- Combined

``` text
WIMSE
+
Runtime identity
+
Socket cookie
+
Enforcement verdict
```

Compare:

-   security
-   scalability
-   performance
-   operational complexity
-   portability
-   cloud support
-   Kubernetes support
-   ability to handle millions of agents
-   ability to support shared runtime processes

------------------------------------------------------------------------

# 12. Investigate the "Socket as Security Anchor" Hypothesis

This is the new central hypothesis from Phase 1.

Determine whether:

> **A socket is the correct primitive for binding an agent session to a
> network flow.**

Investigate:

-   socket lifetime
-   cookie uniqueness
-   socket duplication
-   inherited sockets
-   `fork()`
-   threads
-   async runtimes
-   connection pooling
-   HTTP/2 streams
-   HTTP/3 streams
-   QUIC connections
-   TLS termination
-   proxies
-   NAT
-   load balancers
-   service mesh sidecars

Critically determine whether the socket remains a reliable security
boundary.

If not, identify the correct primitive.

Possible alternatives:

``` text
socket
connection
stream
request
cgroup
namespace
process
thread
cryptographic session
execution context
```

------------------------------------------------------------------------

# 13. Investigate G3 --- Enforcement Verdict

Determine how a verified identity could reach:

-   Linux firewall
-   Cilium
-   Envoy
-   agentgateway
-   Palo Alto
-   Fortinet
-   Check Point
-   Zscaler
-   Cisco
-   Cloudflare

without requiring every vendor to implement a completely new identity
system.

Research possible mechanisms:

-   signed verdict
-   local agent
-   eBPF map
-   Unix socket
-   gRPC
-   policy API
-   SPIFFE identity
-   OAuth token
-   WPT
-   capability token
-   network policy label
-   dynamic firewall rule

Determine the minimum protocol needed.

------------------------------------------------------------------------

# 14. Security Analysis

Attack the proposed architecture.

Investigate:

-   socket-cookie theft
-   socket FD theft
-   `SCM_RIGHTS`
-   `dup()`
-   process injection
-   thread impersonation
-   credential theft
-   key theft
-   replay
-   PID reuse
-   TOCTOU
-   cgroup escape
-   namespace escape
-   privileged process attack
-   eBPF tampering
-   verifier compromise
-   enforcement-point compromise
-   malicious local root

Identify exactly what security boundary the architecture assumes.

Explicitly distinguish:

``` text
unprivileged attacker
```

from:

``` text
container escape attacker
```

from:

``` text
host root attacker
```

from:

``` text
kernel-compromise attacker
```

------------------------------------------------------------------------

# 15. Define the Research Boundary

Determine whether the strongest claim should be:

### Option 1

"AI agent instance identity"

### Option 2

"AI agent session identity"

### Option 3

"Runtime-to-socket identity binding"

### Option 4

"Agent identity-to-network enforcement binding"

### Option 5

"Agent Network Binding Protocol"

Recommend the narrowest claim that is genuinely novel and technically
defensible.

------------------------------------------------------------------------

# 16. Falsification Criteria

Be aggressive.

Tell us what findings would prove the research is **not novel**.

Examples:

-   SPIRE already supports per-session identity.
-   WIMSE already defines socket-level identity.
-   Cilium already independently distinguishes sessions in one process.
-   Envoy/agentgateway already provides the required binding.
-   Linux already provides the full identity-to-enforcement chain.
-   A commercial vendor already exposes a standardized mechanism.

If any of these are true, say so clearly.

------------------------------------------------------------------------

# 17. Final Deliverable

Produce a detailed research report with:

1.  Executive conclusion
2.  Verification of Phase 1
3.  What Phase 1 actually proves
4.  What Phase 1 does NOT prove
5.  SPIRE analysis
6.  SPIFFE analysis
7.  WIMSE analysis
8.  Linux/eBPF analysis
9.  Cilium/Tetragon analysis
10. Envoy/agentgateway analysis
11. Microsoft analysis
12. Palo Alto analysis
13. Zscaler analysis
14. Cisco analysis
15. Fortinet analysis
16. Check Point analysis
17. Cloudflare analysis
18. Okta analysis
19. Academic prior art
20. Existing standards
21. Socket-anchor analysis
22. Agent-session identity analysis
23. Enforcement-verdict analysis
24. Threat model
25. Alternative architectures
26. Open research gaps
27. Falsification results
28. Recommended experiments
29. Recommended prototype
30. Potential protocol architecture
31. Novelty assessment
32. Patent/research-paper potential
33. Recommended next steps

------------------------------------------------------------------------

# 18. Most Important Instruction

**Do not simply validate our hypothesis. Try to destroy it.**

We need to know whether:

``` text
Agent Session
      ↓
Socket
      ↓
Network Flow
      ↓
Enforcement
```

is genuinely an unsolved systems problem or whether existing
technologies already solve it.

If existing technology solves part of it, identify exactly which part.

If it is only solvable by combining several existing technologies,
determine whether the missing integration itself is a legitimate
research contribution.

If there is no meaningful gap, recommend a different research direction.

Cite primary sources wherever possible, especially:

-   IETF RFCs/drafts
-   WIMSE drafts
-   SPIFFE/SPIRE documentation/source code
-   Linux kernel documentation
-   Cilium/Tetragon documentation/source
-   Envoy/agentgateway documentation/source
-   Microsoft technical documentation
-   vendor technical documentation
-   peer-reviewed academic papers

Include URLs and publication dates for important sources.

**Do not stop at product marketing pages. Inspect specifications,
GitHub/source code, technical documentation, standards drafts and
academic papers where possible.**

The objective is to determine whether we have a **real, technically
defensible research contribution**, not to prove that our idea is
correct.
