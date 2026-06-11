# AGENTS.md

This file gives repo-local instructions for AI coding agents working on Private LLM Gateway.

## Project Intent

Private LLM Gateway is a privacy and security gateway for self-hosted LLM inference backends, especially vLLM and SGLang. Treat it as a gateway, policy, deployment, and hardening project. Do not turn it into a model-serving engine.

Use `PLAN.md` as the implementation source of truth and `README.md` as the product-facing overview. Keep both consistent in the same change whenever scope, commands, phases, or layout change.

## Security Defaults

- Deny requests by default unless the endpoint is explicitly allowlisted.
- Never log prompt bodies, completion bodies, uploaded file contents, tool outputs, authorization headers, cookies, API keys, or backend credentials by default.
- Treat request and response bodies as sensitive even in tests.
- Prefer metadata-only logs and metrics: request ID, tenant, route, backend, model, status, and latency. Include token counts only when available without storing prompt or completion text.
- Do not use user-provided text as metric labels or trace attributes.
- Strip or mask sensitive headers before logging and before forwarding unless a backend credential is explicitly required.
- Keep raw vLLM, SGLang, and worker ports private in examples.
- Do not commit secrets, example real tokens, private certificates, generated keys, or machine-specific paths.
- API key management must store hashes or references, not plaintext keys. Plaintext keys may be displayed only once during issuance.

## Implementation Guidance

- Preserve OpenAI-compatible request and response semantics unless a documented policy blocks or modifies a request.
- Keep provider adapters thin. Shared auth, policy, redaction, limits, and observability logic belongs in gateway middleware or shared modules.
- Implement policy checks before forwarding to a backend.
- Fail closed on invalid config, unknown backends, unknown privacy classes, missing auth bindings, and malformed policies.
- Keep local examples runnable before adding production overlays.
- Add tests for security-sensitive behavior whenever changing auth, routing, redaction, logging, metrics, or deployment templates.
- Dynamic auth updates must be tested without requiring a gateway restart.
- Avoid adding dependencies for simple middleware unless they materially reduce risk or complexity.

## Documentation Rules

- Update `README.md` when user-facing commands, phases, supported backends, or deployment assumptions change.
- Update `PLAN.md` when implementation order, acceptance criteria, target layout, or feature scope changes.
- Keep threat-model language precise. Do not claim cryptographic privacy, confidential computing, or malicious-backend protection unless that feature exists and is documented with limitations.
- Prefer concrete examples over broad claims.

## Testing Expectations

For code changes, run the narrowest meaningful test set first, then broader tests if the change touches shared behavior.

Minimum expected coverage by area:

- auth: valid key, invalid key, missing key, tenant metadata mapping
- endpoint allowlisting: allowed route, denied route, wrong method
- logging: prompt/completion/header secrets absent from logs
- redaction: detector positives and false-positive-sensitive cases
- routing: tenant/model/privacy-class decisions and fail-closed errors
- deployment templates: backend ports are private and secrets are not committed

If tests cannot be run, state exactly why in the final response.

## File Hygiene

- Keep generated certificates, keys, model caches, benchmark outputs, and local environment files out of Git.
- Use placeholder values such as `example-token` only when clearly non-secret.
- Prefer ASCII in source and docs unless a file already uses another character set for a reason.
- Do not make unrelated formatting churn in large Markdown files.
