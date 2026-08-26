# Phase 3 Research — L7 Identity → Network Enforcement

## Research Context

We are conducting systems/security research into AI-agent network security.

Phase 1 investigated whether co-resident AI-agent instances could be individually identified using existing workload identity mechanisms.

Phase 2 deliberately tried to falsify the Phase 1 conclusions and the proposed “socket as security anchor” architecture.

Phase 2 conclusion:

> A socket is NOT a reliable security identity anchor for an AI-agent session.

The experiments demonstrated that different principals can share one pooled TCP socket, multiplexed streams can share one socket, a keep-alive socket can serve different principals, `SO_COOKIE` remains the same across `dup()` and `fork()`, and a socket can be transferred through `SCM_RIGHTS` while retaining the same socket identity.

Therefore socket identity is a transport/capability object, not a reliable identity for a higher-level agent session.

Read the Phase 2 artifacts first:
- `PHASE2_REPORT.md`
- `results_falsification.json`
- `falsify_socket_anchor.py`

Phase 1 artifacts may also be available:
- `PHASE1_REPORT.md`
- `results.json`
- `attestor.py`
- `run_experiment.py`

## New Research Question

> If the application layer has already authenticated and verified the exact AI-agent session/principal, how can that identity be converted into an enforceable network security decision when the network layer cannot independently distinguish the principals?

Target architecture:

```text
Human / Delegating Principal
          |
          v
     Agent Session
          |
          v
   WIMSE / WPT / OAuth
          |
          v
 Application / Agent Gateway
          |
          | Verified Agent Identity
          v
   Identity-to-Enforcement
        Translation
          |
          v
 Network Enforcement Point
          |
    +-----+-----+
    |     |     |
  Cilium  NGFW  SASE
```

Critical case:

```text
Alice Agent Session ----Bob Agent Session -------> Same Agent Runtime
Carol Agent Session ----/
          |
       Same PID
       Same IP
       Same TCP connection
       Same socket
```

Yet:

```text
Alice → ALLOW
Bob   → DENY
Carol → RESTRICT
```

may be required.

## Important Instruction

Do NOT assume this is a new problem. Try to destroy the hypothesis again.

Determine whether existing standards, Linux mechanisms, service meshes, AI gateways, network firewalls, or commercial products already solve the exact L7-to-L3/L4 translation problem.

If they do, identify precisely how. If they partially solve it, identify the remaining gap. If nobody solves it, determine the minimum missing interface.

## Research Areas

### 1. WIMSE
Deeply investigate WIMSE Architecture, Workload Identity, Workload Identifier, Workload Credentials, WPT, HTTP Message Signatures, transaction tokens, execution-context-token, delegation and AI-agent applicability.

Determine exactly what WIMSE solves at application, transport, runtime, network and enforcement layers. Determine whether WIMSE defines a standardized identity-to-network-enforcement interface.

### 2. WPT End-to-End Experiment
Design/execute an experiment where Agent A and Agent B share the same process, socket and IP but use different WPT/principal identities. Verify identity at an agent gateway and determine how that identity can reach Cilium/eBPF, Envoy, nftables or a firewall.

Target:
```text
Alice → ALLOW
Bob   → DENY
```
over the same underlying connection.

### 3. Cilium / eBPF / Tetragon
Investigate process, cgroup, socket, network-policy and runtime identity. Determine whether Cilium/Tetragon can independently enforce different policy for two L7 principals sharing one TCP connection and whether externally verified identities can become network-policy inputs.

### 4. Envoy / agentgateway
Investigate external authorization, dynamic metadata, request/stream identity, RBAC, xDS, WASM, WPT verification and propagation. Determine whether L7 identity can cause downstream L3/L4 enforcement.

### 5. SECMARK / CONNSECMARK / SELinux
Investigate whether security labels can already provide:
```text
Application identity
      ↓
Security label
      ↓
Network packet
      ↓
Enforcement
```
Determine request/connection granularity, HTTP/2 behavior, cryptographic identity support, delegated human identity, proxy behavior and dynamic external labeling.

### 6. Cisco TrustSec / SGT
Research identity → SGT → network policy. Compare granularity, cryptographic protection, delegation, proxy behavior and AI-agent applicability.

### 7. Cloud / SASE / Firewall Enforcement
Investigate Microsoft, Palo Alto, Zscaler, Cisco, Fortinet, Check Point, Cloudflare and Okta. For each determine whether externally verified agent-session identity can become a network-enforceable decision. Classify evidence as Documented, Demonstrated, Inferred or Unknown.

### 8. AI Gateways
Research agentgateway, Envoy, Kong, Tyk, LiteLLM, Microsoft AI gateways, Palo Alto, Zscaler, Cloudflare, Cisco and other major enterprise AI gateways. Determine whether they already implement identity → request policy → network enforcement.

### 9. MCP
Research MCP authorization, OAuth, resource indicators, delegated access, session identity, MCP gateways, Streamable HTTP and connection reuse. Determine what MCP solves at L7 and what remains at network enforcement.

### 10. A2A
Research agent identity, delegation, task identity, capability negotiation and whether A2A provides network enforcement semantics.

### 11. SPIFFE / SPIRE
Focus on SPIFFE identity → network enforcement. Investigate SVIDs, mTLS, JWT-SVID, Workload API, Envoy/Cilium integration and dynamic policy.

### 12. Identity-to-Network Translation
Compare:
- signed verdict
- capability token
- security label
- dynamic network identity
- local enforcement daemon
- cryptographic request identity

Determine the minimum semantic interface an enforcement point actually needs. Do not design a complete protocol yet.

### 13. Request vs Connection vs Stream Enforcement
Analyze whether network enforcement can operate at the same granularity as the security principal:
```text
TCP connection
  +-- HTTP/2 stream A → Alice
  +-- HTTP/2 stream B → Bob
  +-- HTTP/2 stream C → Carol
```
Can L3/L4 enforcement independently enforce A/B/C without becoming application-aware?

### 14. Fundamental Boundary Question
Try to falsify:
> If multiple security principals share one encrypted multiplexed connection, an L3/L4 enforcement point cannot independently enforce request-level authorization without receiving an identity signal from the application layer or becoming an application-aware proxy.

### 15. Threat Model
Analyze external agents, compromised legitimate agents, prompt injection, malicious tools/MCP servers, compromised gateways, compromised local processes, host root and kernel compromise.

### 16. Enterprise Admission
Determine whether existing Zero Trust systems already completely solve external-agent blocking and internal-agent admission. Analyze the combination of human identity, agent identity, session, delegation, posture, admission and runtime risk.

### 17. Million-Agent Scale
Research how identity-to-enforcement can scale to 1M+ agents and 10M+ sessions without one firewall rule per agent. Investigate ABAC, capability policies, policy caching, distributed enforcement, hierarchical identities, short-lived verdicts and revocation.

### 18. Prototype
Design the smallest reproducible prototype:
```text
Linux
+
SPIFFE/SPIRE
+
WIMSE/WPT
+
Agent Gateway
+
Cilium/eBPF
+
Envoy
```
Test two principals sharing process/socket/IP but having different verified application identities.

### 19. Compare Architectures
Compare:
1. L7-only
2. L3/L4-only
3. L7 + L3/L4
4. Application-aware firewall

Evaluate security, visibility, scalability, latency, protocol support, HTTP/2, HTTP/3, QUIC, non-HTTP and failure modes.

## Falsification Criteria

Treat the research gap as closed if:
1. WIMSE already specifies the complete identity-to-network enforcement interface.
2. Cilium already consumes request-level agent identity and enforces it independently.
3. Envoy/agentgateway already provides the complete standardized mechanism.
4. Commercial AI gateways provide vendor-neutral L7-to-L3 enforcement.
5. SECMARK/CONNSECMARK provides equivalent semantics.
6. MCP/A2A defines network-level enforcement semantics.
7. A standard mechanism works with multiplexed connections without application cooperation.

If any is true, explicitly state:
> The proposed research gap is closed.

## Final Deliverable

Produce:
1. Executive conclusion
2. Phase 1 → Phase 2 evolution
3. What the socket experiment proves
4. What it does not prove
5. WIMSE analysis
6. WPT analysis
7. MCP analysis
8. A2A analysis
9. SPIFFE/SPIRE analysis
10. Cilium/eBPF analysis
11. Envoy/agentgateway analysis
12. SELinux/SECMARK analysis
13. TrustSec/SGT analysis
14. Microsoft analysis
15. Palo Alto analysis
16. Zscaler analysis
17. Cisco analysis
18. Fortinet analysis
19. Check Point analysis
20. Cloudflare analysis
21. Okta analysis
22. AI gateway landscape
23. L7 → L3/L4 translation mechanisms
24. Request vs stream vs connection enforcement
25. Threat model
26. Fundamental boundary analysis
27. Scalability
28. Prototype design
29. Experimental plan
30. Falsification results
31. Remaining research gap
32. Novelty assessment
33. Recommended paper contribution
34. Whether a protocol is justified
35. Recommended next steps

## Most Important Instruction

Try to destroy the remaining G3 hypothesis.

We no longer want to prove:
> We need a new AI Agent Binding Protocol.

We want to determine:
> Once an AI-agent session has been cryptographically verified at Layer 7, is there a genuine unsolved systems problem in making that identity enforceable at network boundaries that cannot observe the Layer-7 identity?

If yes:
1. Precisely define the missing interface.
2. Explain why existing mechanisms do not provide it.
3. Build the smallest prototype.
4. Compare against SECMARK, TrustSec, Cilium, Envoy, WIMSE and commercial AI gateways.
5. Only then determine whether a new protocol/interface is justified.

If no:
> Recommend abandoning this research direction and identify the closest genuinely open problem.

Do not optimize for confirming our idea. Optimize for finding the truth.
