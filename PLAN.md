# Private LLM Gateway Implementation Plan

This plan is the implementation source of truth for the early repository. Keep it aligned with `README.md`: the README explains what the project is and why it exists; this file explains what to build, in what order, and what must be true before each phase is considered complete.

## Product Scope

Private LLM Gateway is a standalone privacy and security gateway for self-hosted LLM inference backends.

Primary targets:

- vLLM
- SGLang

Reference targets after the MVP:

- Hugging Face TGI
- llama.cpp-compatible OpenAI servers
- LocalAI-style OpenAI servers

Initial non-goals:

- replacing vLLM, SGLang, or any inference engine
- implementing model execution
- claiming cryptographic private inference
- providing a hosted SaaS control plane
- treating a malicious backend as solved

## Design Principles

- Make the gateway the only public inference entry point.
- Allowlist routes instead of blocklisting dangerous endpoints.
- Default to no prompt or completion logging.
- Keep observability metadata-only unless a developer explicitly enables a local debugging mode.
- Treat prompt text, completion text, tool output, uploaded documents, media URLs, crash dumps, and cache state as sensitive.
- Prefer simple, inspectable policy files over implicit behavior.
- Make local Docker Compose examples runnable before adding Kubernetes complexity.
- Keep backend adapters thin and preserve OpenAI-compatible request and response semantics.

## Target Repository Layout

```text
gateway/             core HTTP service and proxy runtime
providers/           vLLM, SGLang, and later TGI/llama.cpp adapters
middleware/          request IDs, endpoint allowlisting, redaction, limits
auth/                API key, JWT/OIDC, and mTLS identity handling
policy/              tenant, model, privacy-class, and routing policy
observability/       metadata-only logs, metrics, and trace filters
config/              example gateway policies and schemas
deploy/compose/      runnable local vLLM and SGLang stacks
deploy/k8s/          Kubernetes manifests and hardening overlays
scripts/pki/         development CA and certificate generation
benchmarks/          privacy-control overhead tests
docs/                configuration, threat model, hardening, comparison, operations notes
tests/               unit and integration tests
```

The layout can be introduced incrementally. Do not create empty directories without a file that explains or exercises their purpose.

## Phase 0: Project Skeleton And Decisions

Status: implemented.

Goal: create a buildable, testable project skeleton with clear implementation choices.

Build:

- Gateway runtime decision and rationale.
- Core package/module structure.
- Local dependency setup.
- Formatting, linting, and test commands.
- Minimal config schema for server, auth, routes, privacy, limits, and observability.
- Example config files with placeholder-only secrets.
- Documented environment variables.
- Initial CI for linting and unit tests.

Acceptance criteria:

- A fresh checkout can install dependencies and run tests.
- Example config validates successfully.
- README quick-start commands refer only to files that exist or are clearly marked as planned.
- The repository layout in README and this plan describe the same target structure.

## Phase 1: Secure Proxy MVP

Status: implemented.

Goal: ship a local gateway that can safely proxy OpenAI-compatible requests to vLLM and SGLang with privacy-preserving defaults.

Build:

- OpenAI-compatible reverse proxy for `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, and `/v1/models`.
- Endpoint allowlisting with deny-by-default behavior.
- vLLM backend adapter.
- SGLang backend adapter.
- API-key authentication with per-key tenant metadata.
- TLS support at the gateway.
- Request ID generation and downstream propagation.
- No-log mode that never writes prompt or completion bodies.
- Metadata-only access logs containing request ID, tenant, route, backend, model, status, latency, and token counts when available.
- Basic request limits for body size, `max_tokens`, `n`, and timeout.
- Docker Compose example for gateway plus vLLM.
- Docker Compose example for gateway plus SGLang.
- Minimal policy/config schema with examples.

Acceptance criteria:

- A developer can run the vLLM Compose stack and send an OpenAI-compatible request through the gateway.
- A developer can run the SGLang Compose stack and send an OpenAI-compatible request through the gateway.
- Requests to non-allowlisted paths are denied before reaching the backend.
- Missing or invalid API keys are denied before reaching the backend.
- Logs do not contain prompt bodies, completion bodies, authorization headers, cookies, or API keys.
- Tests cover auth, endpoint allowlisting, metadata-only logging, and backend routing.
- README quick-start commands match the checked-in Compose files.

## Phase 2: Production Hardening

Status: implemented.

Goal: add the controls needed for real deployment without changing the Phase 1 privacy defaults.

Build:

- Optional client-certificate authentication for service-to-service callers.
- Gateway-to-backend HTTPS and optional mTLS settings.
- API key management module for issuing, updating, revoking, and rotating gateway keys.
- Dynamic API key updates without gateway restart, through safe config reload or a protected admin path.
- Hashed API key storage so plaintext keys are only shown once at issuance.
- JWT verification with configurable issuer, audience, and JWKS source.
- OIDC integration hooks for deployments that need identity-provider-backed tokens.
- Per-tenant rate limits and request quotas.
- Redaction middleware for logs and optional before-forward redaction.
- Configurable detector rules for bearer tokens, API keys, PEM blocks, passwords, emails, SSNs, credit-card-like strings, and custom regexes.
- Kubernetes manifests for gateway plus private backend Services.
- NetworkPolicy examples that allow backend ingress only from the gateway.
- Prometheus metrics with a fixed allowlist of low-cardinality labels.
- OpenTelemetry filtering so traces do not include prompt or completion text.

Acceptance criteria:

- mTLS can be enabled locally with certificates generated by `scripts/pki/`.
- API keys can be issued, modified, revoked, and rotated without restarting the gateway.
- Dynamic key updates fail closed on invalid key records and never log plaintext key material.
- JWT validation rejects wrong issuer, wrong audience, expired token, and unknown signing key.
- Redaction tests prove sensitive patterns are removed from logs and traces.
- Kubernetes examples expose only the gateway, not raw backend ports.
- Metrics labels cannot include prompt text, completion text, request bodies, user-provided strings, or unbounded IDs.

## Phase 3: Privacy-Aware Routing

Status: implemented.

Goal: make privacy class a first-class policy dimension.

Build:

- Tenant-to-backend routing policy.
- Model allowlists per tenant.
- Privacy classes: `standard`, `sensitive`, and `restricted`.
- Local-only routing policy for `restricted` traffic.
- Policy rule that blocks external providers for sensitive or restricted traffic.
- Optional `redact_before_forward` by tenant, route, or privacy class.
- Privacy-safe audit logs with configurable retention.
- Admin-facing policy validation command.

Acceptance criteria:

- Requests can be routed by tenant, model, and privacy class.
- `restricted` requests cannot route to external or non-local backends.
- Policy validation fails closed for unknown backend names, unknown privacy classes, missing auth bindings, and impossible route rules.
- Audit logs remain metadata-only.

## Phase 4: Advanced Security

Goal: add higher-assurance deployment patterns while clearly labeling their limitations.

Build:

- Service mesh examples for strict mTLS.
- Confidential-computing deployment notes.
- Remote-attestation integration experiments.
- Signed policy file verification.
- Secret-scanning CI.
- Container vulnerability scanning CI.
- Benchmark automation for TLS, mTLS, JWT, proxying, redaction, and service mesh overhead.

Acceptance criteria:

- Advanced docs distinguish transport security, no-log discipline, confidential computing, and cryptographic private inference.
- Benchmarks report TTFT, end-to-end latency, output throughput, gateway CPU overhead, memory overhead, streaming overhead, TLS handshake overhead, and warm-connection impact.
- CI fails on committed high-confidence secrets.
- CI reports container scan results for published example images.

## Consistency Rules

- When a feature moves between phases here, update the README roadmap in the same change.
- When quick-start commands change here, update README quick start in the same change.
- When a directory is added to the target layout here, update README repository layout in the same change.
- When a threat model changes in README, update this plan if the implementation scope changes.
- Keep examples privacy-safe by default: no prompt logging, no public backend ports, no plaintext secrets in committed config.
