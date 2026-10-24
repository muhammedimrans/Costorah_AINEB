# AI Security Gateway — Product Roadmap & Architecture Decision Record

**Status:** Working baseline / architecture proposal  
**Last updated:** 2026-10-24  
**Purpose:** Preserve the product decisions, architecture, technology options, security principles, and implementation roadmap so development can resume later without repeating discovery.

> This document records the decisions made so far and marks unresolved choices as open. It is a planning document, not a claim that the system has already been implemented or security-certified.

## 1. Executive summary

We plan to build a commercial security gateway for websites and web applications across industries. Customers will use it to protect selected routes and APIs against common web attacks, abusive traffic, automated abuse, endpoint enumeration, and suspicious access patterns.

The product will combine established open-source gateway/WAF components with our own customer experience and security-management capabilities. We should **reuse rather than rewrite** the low-level gateway and WAF.

**Working architecture direction**
- Use **Apache APISIX** as the primary reverse proxy/API gateway.
- Evaluate **OWASP Coraza** as the WAF engine, using its APISIX/Proxy-Wasm integration and OWASP Core Rule Set (CRS) where compatibility testing confirms it is suitable.
- Run the customer-facing **data plane in the customer's own environment** (initially Docker; Kubernetes later).
- Build our own **control plane** for onboarding, policies, events, health, analytics, and billing.
- Start with API/route protection and a **monitor-only** rollout; website-page protection can follow.
- Keep the first milestone small: prove routing, inspection, rate limiting, event generation, policy changes, rollback, and basic latency/correctness.

The product's differentiator is not merely bundling APISIX and Coraza. It is the guided setup, endpoint-specific policy workflow, safe enforcement, useful behavioral signals, understandable events, customer-controlled deployment, and operational experience.

## 2. Product vision and intended users

### 2.1 Vision
Provide an approachable security layer that customers can place in front of their existing web application without rewriting the application itself.

### 2.2 Target customers
Broadly applicable to websites and web apps across industries, including SaaS, commerce, marketplaces, business applications, and API-first products. The product is **not limited to AI companies**.

### 2.3 Core problems to address
- Common HTTP/web application attacks.
- Repeated or unusually frequent requests.
- Login and password-reset abuse.
- API enumeration and suspicious endpoint discovery.
- Scraping or automation patterns that violate a customer's policy.
- Lack of a simple way to set and review security policy per route.
- Poor visibility into why a request was flagged or blocked.

### 2.4 Honest product boundaries
- No detection system can perfectly distinguish every human from every bot or AI agent.
- IP address and User-Agent alone should not be sufficient grounds for a permanent block.
- A gateway cannot prevent an authorized user from copying data they are legitimately allowed to receive.
- WAF rules reduce risk but do not replace secure application design, authentication/authorization, patching, or incident response.
- Product claims must reflect tested capabilities; do not claim perfect protection, compliance, or certification without evidence.

## 3. User journey and how the product should work

1. A customer creates an account in the management dashboard.
2. The customer registers a site/application and its environment.
3. The product guides the customer through deploying the gateway in the customer's cloud or infrastructure.
4. The customer configures the upstream application/backend and verifies health checks.
5. The customer selects the routes/endpoints to protect, for example:
   - `/api/login`
   - `/api/password/reset`
   - `/api/payment/create`
   - `/api/products/*`
   - `/api/admin/*`
   - `/public/*`
6. Each protected route receives a policy. Initial modes:
   - **Monitor:** detect and record, but do not block.
   - **Challenge:** apply a challenge only where a suitable challenge mechanism exists and is compatible with the client.
   - **Rate Limit:** constrain request rates by route and appropriate identity/key.
   - **Block:** deny traffic that meets a defined rule or risk threshold.
7. The gateway forwards requests through inspection and route policies to the existing backend.
8. The dashboard displays events, rule matches, policy decisions, gateway health, and relevant trends.
9. The customer reviews monitor-mode results and tunes rules to reduce false positives.
10. The customer explicitly enables enforcement, with rollback available.
11. Policy updates are validated, signed, versioned, and applied safely to the customer-hosted gateway.
12. If the management plane is temporarily unavailable, the gateway continues with the last known-good policy. Behavior during policy expiry or critical failure must be defined per customer and route.

## 4. High-level architecture

```text
                         OUR CONTROL PLANE
       +--------------------------------------------------+
       | Web Dashboard / Customer & Site Management       |
       | Authentication, RBAC/MFA, Billing (later)        |
       | Policy API + Validation + Versioning             |
       | Security Events, Analytics, Audit Trail          |
       +------------------------+-------------------------+
                                |
                    Authenticated, signed policy sync
                    and minimized telemetry (opt-in/config)
                                |
                 CUSTOMER'S CLOUD / DATA PLANE
       +--------------------------------------------------+
       | Public traffic -> TLS/edge -> Apache APISIX       |
       |                           |                       |
       |                   Coraza WAF connector            |
       |                   + OWASP CRS (evaluated)         |
       |                           |                       |
       |                   Rate limits / route rules       |
       |                           |                       |
       |                   Custom detection component      |
       |                           |                       |
       |                    Existing application           |
       +--------------------------------------------------+
```

This is a logical view. The exact process/container topology for APISIX, its configuration store, Coraza, and custom detection remains a technical validation task. Do not assume that the connector is production-ready for every version simply because it exists.

### 4.1 Control plane
Responsibilities:
- Customer, organization, site, environment, and gateway registration.
- Route inventory and route-specific policy management.
- Policy validation, versioning, approval, rollout, and rollback.
- Security event viewing and search.
- Gateway health and deployment status.
- Tenant isolation, role-based access, and audit logs.
- Subscription/usage management later.

The dashboard can be hosted in our cloud. It should not need to proxy customer traffic or receive full request bodies.

### 4.2 Data plane
Responsibilities:
- Receive and proxy customer HTTP(S) traffic.
- Apply routing and upstream health behavior.
- Invoke WAF inspection and common attack rules.
- Enforce route-specific rate limits and policy modes.
- Emit sanitized security events and health metrics.
- Continue using the last known-good policy when the control plane is unreachable.

Data-plane deployment should be customer-hosted so request processing and sensitive payloads remain in the customer's environment by default.

### 4.3 Policy synchronization
- Authenticate the gateway to the control plane.
- Sign policy bundles and verify signatures at the gateway.
- Validate policy schema and supported capabilities before activation.
- Use monotonically versioned policy bundles and retain the last known-good version.
- Support staged rollout, explicit rollback, and audit history.
- Minimize outbound connectivity and permissions.
- Never accept arbitrary unsigned executable code or unvalidated configuration from the control plane.

## 5. Architecture Decision Records (ADRs)

### ADR-001 — Product scope
**Status:** Accepted as initial direction  
**Decision:** Build a general-purpose web/API security gateway, not a product restricted to AI services. Start with APIs and selected routes; expand to general website pages after API protection is reliable.  
**Reason:** Narrow initial implementation keeps the first release testable while the broader market remains available.  
**Consequences:** Route matching, HTTP compatibility, and API-focused tests are first-class requirements.

### ADR-002 — Deployment model
**Status:** Accepted as initial direction  
**Decision:** Customer-hosted data plane; centrally managed control plane hosted by us.  
**Reason:** Customer traffic can stay in the customer's infrastructure and the product can manage policies centrally.  
**Consequences:** Must design secure gateway identity, signed policy updates, outbound-only control connectivity where practical, offline operation, versioning, and tenant isolation. Some customers may later require fully self-hosted management.

### ADR-003 — Gateway foundation
**Status:** Proposed; validate in prototype  
**Decision:** Use Apache APISIX as the primary reverse proxy/API gateway rather than building one from scratch.  
**Reason:** Reuse mature routing/gateway capabilities and focus proprietary work on product features.  
**Consequences:** Track upstream releases, configure rather than fork core where possible, and maintain compatibility tests.

### ADR-004 — WAF foundation
**Status:** Proposed; validate in prototype  
**Decision:** Evaluate OWASP Coraza with its APISIX/Proxy-Wasm connector and OWASP CRS.  
**Reason:** Reuse an open-source WAF and standard rule set.  
**Consequences:** Verify supported versions, build/package requirements, body inspection limits, performance, false positives, rule updates, and failure behavior before selecting production versions.

### ADR-005 — Reverse-proxy model
**Status:** Accepted as initial direction  
**Decision:** Reverse proxy is the primary deployment model, with selected route protection. API-only protection can be a simplified configuration; direct SDK-only protection is not the first approach.  
**Reason:** Centralized inspection avoids requiring code changes in each customer application.  
**Consequences:** Preserve headers, methods, query strings, body handling, TLS behavior, cookies, redirects, CORS, compression, streaming, uploads, WebSockets where supported, and timeouts.

### ADR-006 — Rollout and enforcement
**Status:** Accepted  
**Decision:** Begin in monitor-only mode, then move selected routes to enforcement after review.  
**Reason:** Avoid disrupting legitimate production traffic while rules are tuned.  
**Consequences:** Every event should include an explainable reason; provide route-level mode, exception controls, audit trail, and rollback.

### ADR-007 — Custom product value
**Status:** Accepted as product direction  
**Decision:** Build proprietary onboarding, policy UX, risk/event explanation, analytics, health monitoring, and later billing. Prefer custom plugins/adapters and a separate control plane over modifying APISIX core.  
**Reason:** This creates differentiated product value and reduces long-term maintenance burden.  
**Consequences:** Keep interfaces between our services and open-source components explicit and testable.

### ADR-008 — Data handling and privacy
**Status:** Accepted as design requirement  
**Decision:** Do not log secrets or full request bodies by default. Collect the minimum event fields needed for security analysis and make telemetry configurable.  
**Reason:** Reduce privacy, compliance, and breach impact.  
**Consequences:** Redact passwords, authorization headers, cookies, tokens, payment data, and other sensitive values; define retention and deletion policies.

### ADR-009 — Initial packaging
**Status:** Accepted for MVP  
**Decision:** Start with Docker Compose for repeatable local and customer evaluation; plan Kubernetes support after the container topology and operational behavior are validated.  
**Reason:** Docker is the fastest way to prove the integration.  
**Consequences:** Pin image/dependency versions, use health checks and non-root execution where possible, and externalize secrets/configuration.

### ADR-010 — Detection claims
**Status:** Accepted  
**Decision:** Combine WAF rule matches, rate/behavioral signals, and customer policy; do not claim perfect bot or AI-agent classification.  
**Reason:** Signals are probabilistic and context-dependent.  
**Consequences:** Use explainable scores, thresholds, observation periods, allowlists/exceptions, and customer-visible reasons. Never rely on IP/User-Agent alone for high-impact automated blocking.

### ADR-011 — Licensing
**Status:** Required work item  
**Decision:** Prefer upstream open-source components and avoid unnecessary forks. Review the exact licence and notices for every version and transitive dependency before distribution.  
**Reason:** Commercial use may be permitted, but obligations depend on the precise component/version and distribution model.  
**Consequences:** Maintain a software bill of materials (SBOM), licence inventory, notices, and an update process. Obtain legal review before commercial launch. This is not legal advice.

### ADR-012 — Pricing and packaging
**Status:** Open  
**Decision:** No final pricing has been selected.  
**Options to test:** Pricing by protected domains, gateways, request volume, advanced detection, log retention, support/SLA, or deployment tier.  
**Next step:** Interview target customers and test willingness to pay before setting final tiers.

## 6. Proposed technology stack

The following is a recommended starting stack, not a claim that all choices have been finalized.

| Layer | Initial recommendation | Status / notes |
|---|---|---|
| Reverse proxy/API gateway | Apache APISIX | Proposed; validate version and configuration model |
| WAF engine | OWASP Coraza | Proposed; verify APISIX connector compatibility |
| WAF rules | OWASP Core Rule Set (CRS) | Evaluate tuning and false-positive behavior |
| Packaging | Docker + Docker Compose | MVP |
| Orchestration | Kubernetes | Later, after Docker prototype |
| Control-plane API | Python + FastAPI | Candidate; not finalized |
| Control-plane UI | React + TypeScript | Candidate; not finalized |
| Policy/event database | PostgreSQL | Candidate; not finalized |
| Cache/queue | Redis or a message broker only if needed | Defer until requirements justify it |
| Authentication | OIDC-compatible identity provider; MFA for administrators | Select during control-plane design |
| Secrets | Platform secret manager in production | Never commit credentials |
| Metrics | Prometheus-compatible metrics | Validate component integration |
| Dashboards | Grafana for engineering/operations initially; product UI later | Optional |
| Logs | Structured JSON, redacted | Keep security events distinct from raw access logs |
| CI | Automated lint, unit, integration, security, and compatibility tests | Required |
| Image/dependency scanning | Container and dependency scanning; SBOM generation | Required before release |
| Infrastructure as Code | Terraform is a candidate | Optional for first local prototype |
| API tests | curl plus automated integration tests | Start simple |
| Load tests | k6 or equivalent | Before any production claim |

**Important:** APISIX commonly uses etcd for configuration/state in its traditional deployment model. Choose the exact topology and version from official documentation. Do not expose internal admin/configuration interfaces publicly.

## 7. Initial endpoint policy model

| Route | Example risks | Suggested starting mode |
|---|---|---|
| `/api/login` | Brute-force patterns, credential stuffing signals | Monitor, then carefully rate-limit |
| `/api/password/reset` | Repeated reset requests, enumeration | Monitor, then rate-limit |
| `/api/payment/create` | Abusive request bursts, malformed payloads | Monitor; preserve application authentication and validation |
| `/api/products/*` | Excessive enumeration/scraping | Monitor and measure first |
| `/api/admin/*` | Unauthorized access attempts | WAF plus strong upstream authentication/authorization; do not rely on WAF alone |
| `/public/*` | High-volume automated requests | Monitor; apply limits only with clear business rules |

These are examples, not universal defaults. Customer traffic, identity model, route sensitivity, and legitimate usage determine the final policy.

## 8. Detection and event design

### 8.1 Initial signals
- WAF rule ID, category, and matched location (with sensitive values redacted).
- Requests per time window by route and appropriate identity key.
- Repeated authentication failures, when the upstream exposes a safe signal.
- Repeated 404s or method/path probing indicative of endpoint enumeration.
- Request rate and burst patterns.
- Invalid or suspicious protocol/input patterns.
- Route sensitivity and customer-defined policy.
- Gateway health and policy version.

### 8.2 Risk score
A later scoring component can combine multiple independent signals into a score and an explanation. Begin with transparent rules/weighted signals rather than claiming machine-learning accuracy before data exists.

Every detection event should answer:
- What happened?
- Which route/site was affected?
- Which rule or signal fired?
- When did it happen?
- What action was taken?
- Which policy version was active?
- What evidence is safe to show?
- How can an administrator tune or reverse the decision?

### 8.3 Actions
- **Monitor:** record event, pass request.
- **Rate Limit:** throttle based on route and appropriate key.
- **Challenge:** use only where supported and compatible with API clients.
- **Block:** deny when a well-tested policy matches.
- **Allow/exception:** narrow, auditable exception for known legitimate behavior.

Avoid making “challenge” a generic action for every API: many non-browser clients cannot complete browser challenges.

## 9. Security, reliability, and compatibility requirements

### 9.1 Security
- TLS for external and management communication.
- Strong gateway identity and credential rotation.
- Least-privilege container/runtime permissions.
- RBAC and MFA for privileged dashboard users.
- Tenant isolation in every database query, event, cache key, and policy path.
- Signed and versioned policy bundles.
- Input/schema validation before policy activation.
- Secrets and sensitive headers/body fields redacted from logs.
- Retention, export, and deletion controls.
- Audit logs for administrator actions and policy changes.
- SBOM, vulnerability scanning, and dependency update process.
- Independent security review and penetration testing before production launch.

### 9.2 Reliability
- Last-known-good policy remains active when the control plane is unavailable.
- Health/readiness checks for gateway, WAF connector, configuration store, and backend.
- Explicit policy for what happens if WAF inspection fails. Do not silently fail open for protected sensitive routes.
- Define per-customer fail-open/fail-closed behavior with clear availability/security trade-offs.
- Policy validation and staged rollout.
- One-step rollback to a known-good policy.
- Resource limits and protection against inspection exhaustion.
- Backpressure and bounded event queues so logging cannot exhaust gateway memory.
- Backup/restore plan for control-plane data.

### 9.3 HTTP/application compatibility test matrix
Verify at minimum:
- GET, POST, PUT, PATCH, DELETE and OPTIONS.
- Query strings and repeated query parameters.
- Header forwarding and hop-by-hop header handling.
- Cookies, redirects, CORS and preflight.
- JSON and form bodies; configured maximum body sizes.
- Compressed responses and content negotiation.
- Large uploads and streaming responses.
- WebSockets or other upgrade protocols if in scope.
- Timeouts, retries, connection pooling and upstream health.
- TLS termination and upstream TLS verification.
- Correct status codes and response bodies.
- Latency and throughput with WAF on/off.
- Legitimate traffic false positives.
- Malformed and controlled attack-test requests.
- Behavior during gateway restart, policy update, connector failure, and control-plane outage.

## 10. Repository layout proposal

```text
security-gateway/
├── README.md
├── LICENSES.md
├── SECURITY.md
├── CONTRIBUTING.md
├── docker-compose.yml
├── .env.example
├── docs/
│   ├── PRODUCT_REQUIREMENTS.md
│   ├── ARCHITECTURE.md
│   ├── ROADMAP.md
│   ├── THREAT_MODEL.md
│   ├── RUNBOOK.md
│   └── adr/
├── deploy/
│   ├── apisix/
│   ├── coraza/
│   └── demo-backend/
├── control-plane/
│   ├── api/
│   ├── web/
│   └── migrations/
├── detection/
├── policy-schema/
├── tests/
│   ├── integration/
│   ├── security/
│   ├── compatibility/
│   └── load/
└── scripts/
```

This is a proposed layout; do not create all services/folders before the first working integration. Start with `deploy/`, a sample backend, and tests.

## 11. Phased implementation roadmap

### Phase 0 — Validate assumptions
**Goal:** Reduce integration and product risk before substantial implementation.

Tasks:
- Choose and pin candidate APISIX, Coraza connector, Coraza, and CRS versions.
- Read the licences and release notes for those exact versions.
- Confirm connector support and build/package steps.
- Write down the initial deployment topology.
- Define the first demo backend and success criteria.

**Exit criteria:** A reproducible, version-pinned plan exists; known integration gaps and unsupported protocols are documented.

### Phase 1 — Gateway + backend in Docker
**Goal:** Prove routing before adding security complexity.

Tasks:
- Run APISIX and its required configuration store in Docker Compose.
- Run a small demo backend with a health endpoint and sample API routes.
- Configure one route through APISIX to the backend.
- Test success, error responses, headers, and health checks.

**Exit criteria:** Requests consistently pass through APISIX to the expected backend; direct access to the demo backend is restricted where the deployment design requires it.

### Phase 2 — Add Coraza and CRS
**Goal:** Inspect requests without disrupting normal traffic.

Tasks:
- Build/pull the connector-compatible components according to the selected integration guide.
- Enable Coraza and CRS in monitor/logging mode.
- Use controlled test cases to confirm expected rule matches.
- Tune rule exclusions narrowly and document every exclusion.
- Measure baseline latency and resource use.

**Exit criteria:** A known benign request passes; a controlled test request triggers an expected detection event; false positives can be identified and tuned; version and rule update procedures are documented.

### Phase 3 — Route policies and rate limiting
**Goal:** Apply policies to selected endpoints.

Tasks:
- Add route-level configuration for monitor and rate-limit behavior.
- Test `/api/login`, `/api/password/reset`, and `/api/products/*` in the demo.
- Verify policy changes and rollback.
- Ensure policies do not depend on spoofable client-supplied headers unless trusted proxies are configured correctly.

**Exit criteria:** Route-specific policies work; normal traffic remains correct; policy changes are reversible and auditable.

### Phase 4 — Event schema and detection
**Goal:** Produce useful, safe, explainable security events.

Tasks:
- Define structured event schema.
- Redact secrets and sensitive values.
- Add rate-pattern and endpoint-enumeration signals.
- Include route, time, action, reason/rule ID, and policy version.
- Bound event buffers and test overload behavior.

**Exit criteria:** Events are understandable and safe to store; repeated test patterns generate consistent events; event pipeline failure does not crash or exhaust the gateway.

### Phase 5 — Control-plane API and database
**Goal:** Manage customers, gateways, policies, and events.

Tasks:
- Implement authentication and tenant-scoped authorization.
- Add organization/site/environment/gateway records.
- Store versioned policies and audit events.
- Build policy validation and signed bundle delivery.
- Implement gateway health/last-seen and last-known-good behavior.

**Exit criteria:** A gateway can authenticate and retrieve only its intended configuration; policy bundles are validated, versioned, and signature-checked; cross-tenant access tests pass.

### Phase 6 — Dashboard and onboarding
**Goal:** Make the product usable without requiring manual configuration expertise.

Tasks:
- Build customer onboarding and deployment instructions.
- Show gateway status and route inventory.
- Provide policy editor with Monitor as the default.
- Show security events, explanations, and filters.
- Add policy preview, staged enforcement, and rollback.
- Add administrator audit history.

**Exit criteria:** A test customer can deploy, configure, observe, and safely roll back without editing internal source code.

### Phase 7 — Hardening and pilot
**Goal:** Prepare for a limited, controlled customer pilot.

Tasks:
- Run compatibility, load, resilience, and security tests.
- Test upgrade and rollback procedures.
- Produce SBOM and licence notices.
- Review threat model and complete independent security assessment.
- Define support, incident response, data retention, backup, and recovery procedures.
- Pilot with non-critical routes and explicit customer approval.

**Exit criteria:** No unresolved critical/high-severity defects in the pilot scope; performance and failure behavior are measured and documented; operational runbooks and rollback have been exercised.

### Phase 8 — Kubernetes, scale, and commercial features
**Goal:** Expand deployment and commercial readiness after the MVP works.

Potential tasks:
- Kubernetes/Helm deployment.
- High availability and autoscaling.
- Advanced analytics and optional integrations.
- Additional website protection features.
- Usage metering, subscription tiers, billing, and support tiers.
- Customer-hosted control plane for customers who require it.

## 12. MVP definition and acceptance criteria

The MVP is **not** a polished dashboard or a claim of complete bot prevention. It is a reproducible security gateway prototype that can safely inspect and control selected routes.

MVP must demonstrate:
1. Docker Compose starts the gateway, required configuration store, WAF integration, and demo backend.
2. A normal request reaches the expected backend and returns the expected response.
3. Coraza/CRS detects at least one controlled test case.
4. Monitor mode logs a detection without blocking the request.
5. A configured rate limit behaves as expected.
6. A route policy can be changed and rolled back.
7. Security events redact secrets.
8. A control-plane outage does not erase the last known-good policy.
9. Basic latency/resource measurements are recorded.
10. Rebuild and setup steps work from a clean checkout.

## 13. Risks and mitigations

| Risk | Mitigation |
|---|---|
| APISIX–Coraza connector incompatibility or maturity issue | Pin versions, verify support, create integration tests before building product features |
| WAF false positives | Monitor first, explain rule matches, tune narrowly, stage enforcement |
| Performance overhead | Benchmark with WAF on/off, limit body inspection, define resource caps |
| Customer traffic exposure | Customer-hosted data plane, minimize telemetry, redact sensitive fields |
| Control plane compromise | Signed policies, least privilege, gateway-side validation, audit trail, rollback |
| Unsafe failure mode | Explicit fail-open/fail-closed decision per route/customer; test connector failure |
| Open-source licence noncompliance | Version-specific review, SBOM, notices, legal review |
| Bot/AI detection overclaim | Use explainable multi-signal risk and honest product claims |
| Scope expansion | API-first MVP, dashboard only after gateway/WAF integration works |
| Difficult customer onboarding | Guided deployment, health checks, diagnostics, rollback |

## 14. Business model — hypotheses, not decisions

Possible pricing dimensions to validate:
- Number of protected domains/sites.
- Number of gateway deployments/environments.
- Request volume or bandwidth.
- Advanced detection and policy features.
- Event retention and analytics.
- Support and SLA.
- Managed versus customer-hosted options.

Do not finalize pricing until customer interviews and pilot usage show which value metric customers understand and will pay for.

## 15. Open decisions and questions to resolve later

1. Product name, domain, and branding.
2. Exact APISIX/Coraza/Proxy-Wasm/CRS versions and integration packaging.
3. Whether the WAF connector meets required performance and production-readiness criteria.
4. Control-plane framework and database (FastAPI/React/PostgreSQL are candidates, not final decisions).
5. Exact policy schema and rule evaluation order.
6. How to handle trusted client IPs behind load balancers/CDNs.
7. How challenges work for browsers versus API clients.
8. Per-route fail-open/fail-closed policy.
9. Telemetry fields, retention, region, and customer opt-out controls.
10. Initial customer segment and pilot plan.
11. Pricing and packaging.
12. Compliance and legal obligations for target markets.
13. Kubernetes/Helm timeline.
14. Whether a self-hosted control plane is required for early customers.

## 16. First session checklist for when development resumes

Start here; do not start by designing the full dashboard.

- [ ] Create the repository and add this roadmap as `docs/ROADMAP.md` or `README.md`.
- [ ] Create `docker-compose.yml` for APISIX and its required configuration store, using official version-compatible examples.
- [ ] Add a minimal demo backend with `/health`, `/api/login`, and `/api/products`.
- [ ] Configure APISIX to proxy one route to the backend.
- [ ] Add automated smoke tests with `curl` or a test runner.
- [ ] Record component versions and licences.
- [ ] Add Coraza connector and CRS in monitor mode.
- [ ] Confirm one benign request passes and one controlled security test is detected.
- [ ] Add route-level rate limiting.
- [ ] Record latency, false positives, and failure behavior.
- [ ] Only then design the policy API and dashboard.

## 17. Official project references

- Apache APISIX: https://github.com/apache/apisix
- APISIX documentation: https://apisix.apache.org/docs/
- APISIX–Coraza integration article: https://apisix.apache.org/blog/2024/02/13/apisix-owasp-coraza-core-ruleset/
- Coraza WAF: https://github.com/corazawaf/coraza
- Coraza documentation: https://www.coraza.io/docs/
- Coraza Proxy-Wasm connector: https://github.com/corazawaf/coraza-proxy-wasm
- OWASP Core Rule Set: https://coreruleset.org/
- OWASP Coraza project: https://owasp.org/projects/coraza-web-application-firewall

## Final decision snapshot

**Build:** A general-purpose security gateway for selected web/API routes.  
**Initial data plane:** Customer-hosted Docker deployment.  
**Gateway:** Apache APISIX (proposed; validate versions).  
**WAF:** OWASP Coraza + OWASP CRS via a compatible connector (validate before production).  
**Approach:** Reuse upstream projects, build our own control plane and differentiated user experience.  
**Rollout:** Monitor first, enforce gradually, provide rollback.  
**First milestone:** A reproducible Docker prototype with routing, WAF detection, rate limiting, sanitized events, and measurable compatibility/latency.  
**Not decided yet:** Final name, final production topology, exact versions, pricing, compliance scope, and production-readiness status.
