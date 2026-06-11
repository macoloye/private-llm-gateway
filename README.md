# Private LLM Gateway

Private LLM Gateway is a small, privacy-focused HTTP gateway for self-hosted
OpenAI-compatible inference servers such as vLLM and SGLang.

It gives applications one protected OpenAI-style API endpoint while keeping the
actual inference servers on a private network. Instead of exposing raw vLLM or
SGLang ports to clients, you publish the gateway, require authentication there,
enforce routing and privacy policy there, and forward only approved requests to
the configured backend.

The gateway is useful when you want to:

- Put API-key or JWT authentication in front of local LLM backends.
- Expose only selected OpenAI-compatible endpoints.
- Route tenants and models to specific backends.
- Keep sensitive traffic on local backends instead of external providers.
- Apply basic request limits before work reaches GPU servers.
- Generate request IDs, metrics, access logs, and metadata-only audit logs.
- Add TLS or mutual TLS at the public gateway and backend connection layers.

```text
                +--------------------------------------------+
                |            Application / Client            |
                |        API key, optional TLS client        |
                +---------------------+----------------------+
                                      |
                         OpenAI-compatible API
                                      |
                   +------------------v------------------+
                   |         Private LLM Gateway         |
                   |  authn, endpoint allowlist, limits  |
                   |  routing policy, logs, request IDs  |
                   +---------------+---------------+-----+
                                   |               |
                          private net              | private net
                                   |               |
                     +-------------v----+   +------v-------------+
                     |   vLLM backend   |   |   SGLang backend   |
                     | OpenAI-compatible|   | OpenAI-compatible  |
                     +-------------+----+   +------+-------------+
                                   |               |
                                   | GPU runtime   | GPU runtime
                                   |               |
                           +-------v-------+ +----v----------+
                           | GPU worker(s) | | GPU worker(s) |
                           +---------------+ +---------------+
```

## What It Does

The gateway accepts a subset of the OpenAI API, checks the request, chooses a
backend, forwards the request, and returns the backend response to the caller.

Supported gateway endpoints:

- `POST /v1/chat/completions`
- `POST /v1/completions`
- `POST /v1/embeddings`
- `GET /v1/models`
- `GET /healthz`
- `GET /metrics`
- `POST /admin/api-keys` when dynamic key management is configured

For normal inference requests, the gateway performs this flow:

1. Creates or propagates an `X-Request-Id`.
2. Authenticates the caller with an API key or JWT.
3. Parses the JSON request body.
4. Resolves the tenant, requested model, and requested privacy class.
5. Checks tenant policy, model allowlists, backend allowlists, and endpoint allowlists.
6. Enforces request limits such as body size, `max_tokens`, `n`, timeout, and tenant quotas.
7. Optionally redacts configured patterns before forwarding.
8. Strips client authentication headers before forwarding to the backend.
9. Sends the request to the selected OpenAI-compatible backend.
10. Returns the backend status, headers, body, and `X-Request-Id`.
11. Emits access logs, audit logs, and Prometheus metrics.

## Key Concepts

### Routes

A route names one backend service. Each route declares:

- The backend URL, such as `http://vllm:8000`.
- Which model names the route can serve.
- Which HTTP paths and methods are allowed.
- Whether the backend is local or external.
- Optional backend HTTPS or mTLS settings.
- Optional backend API-key injection with `backend_api_key_env`.

Requests to non-allowlisted paths return `403` before they reach a backend.
Requests for unknown models fail before forwarding.

### Tenants

Authenticated callers map to a tenant. A tenant policy can restrict:

- Which models the tenant may request.
- Which backends the tenant may use.
- Which privacy classes the tenant may request.

Static API keys can define `allowed_models`. Dynamic hashed API keys and JWTs can
also carry tenant and model information.

### Privacy Classes

The built-in privacy classes are:

- `standard`: normal routing policy.
- `sensitive`: cannot route to a backend marked `local: false`.
- `restricted`: requires a local backend.

A request can specify a privacy class with either:

- `X-Privacy-Class: restricted`
- A JSON body field named `privacy_class` or `privacyClass`

If no privacy class is supplied, the gateway uses
`policy.default_privacy_class`.

Privacy classes can also turn on redaction before forwarding. In the development
config, `sensitive` and `restricted` requests use `redact_before_forward: true`.

### Redaction

Redaction is regex-based. It can be used in two places:

- Log redaction: removes matching text before writing access logs in `all` mode.
- Before-forward redaction: removes matching text from the request body before it
  is sent to the backend.

Before-forward redaction changes what the model sees. Use it only when that is
the intended behavior.

### Observability

The gateway provides:

- `GET /healthz` for a simple health check.
- `GET /metrics` for Prometheus text metrics.
- JSON access logs to stdout and optionally to a file.
- Optional metadata-only audit logs with retention.

Metrics deliberately use low-cardinality labels. Request IDs, tenants, prompts,
completions, and request bodies are not metric labels.

## Quick Start

From the repository root:

```sh
cd private-llm-gateway
```

Run the test suite:

```sh
make test
```

Run all local checks:

```sh
make check
```

Start the gateway with the development config:

```sh
export TEAM_A_API_KEY=example-team-a-key
python3 -m gateway --config config/gateway.dev.json
```

The development config listens on `0.0.0.0:8080`, uses colored terminal output,
and writes metadata access logs to `logs/gateway.log`.

Send a chat request:

```sh
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'Authorization: Bearer example-team-a-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen-local","messages":[{"role":"user","content":"hello"}],"max_tokens":32}'
```

Send the same request with a stricter privacy class:

```sh
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'Authorization: Bearer example-team-a-key' \
  -H 'Content-Type: application/json' \
  -H 'X-Privacy-Class: restricted' \
  -d '{"model":"qwen-local","messages":[{"role":"user","content":"hello"}],"max_tokens":32}'
```

Check health and metrics:

```sh
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/metrics
```

The default development config expects these backend service names:

- `http://vllm:8000` for model `qwen-local`
- `http://sglang:30000` for model `llama-local`

For a real local request, run one of the Compose examples or update
`config/gateway.dev.json` so the route backend URL points at your running
OpenAI-compatible server.

## Docker Compose

Run the gateway with a vLLM backend:

```sh
docker compose -f deploy/compose/vllm.yaml up --build
```

Run the gateway with an SGLang backend:

```sh
docker compose -f deploy/compose/sglang.yaml up --build
```

The backend services use Docker `expose`, not host `ports`, so only the gateway
is published to the host. This is intentional: clients should talk to the gateway
only.

## Configuration And Authentication

The development config lives at [config/gateway.dev.json](config/gateway.dev.json).
Detailed configuration, authentication, backend API-key, TLS, limits, and logging
instructions live in [docs/configuration.md](docs/configuration.md).

Validate the config and routing policy before deployment:

```sh
python3 -m gateway validate-policy --config config/gateway.dev.json
```

Configuration selection:

- `auth`: credentials accepted from gateway clients.
- `routes[].backend_api_key_env`: credentials sent from the gateway to a backend.
- `policy`: tenant, model, backend, privacy-class, and routing rules.
- `limits`: body size, generation limits, timeout, and tenant quotas.
- `privacy` and `logging`: metadata-only logs, audit logs, and redaction behavior.

Do not commit real secrets.

## Metrics

`GET /metrics` returns Prometheus text metrics.

The metric labels are intentionally limited to route values, backend names, and
status families. This avoids leaking high-cardinality or sensitive data into the
metrics backend.

## Kubernetes

Example manifests live in [deploy/k8s](deploy/k8s):

- `gateway.yaml`: gateway Deployment and Service example.
- `backend-private.yaml`: private backend Service example.
- `networkpolicy.yaml`: example NetworkPolicy to keep backend access private.

The intended deployment shape is:

- Public or internal clients can reach the gateway Service.
- Backend Services are reachable only from the gateway.
- Raw vLLM or SGLang backend ports are not exposed publicly.

## Development

Run all checks:

```sh
make check
```

Run the CLI help:

```sh
python3 -m gateway --help
python3 -m gateway validate-policy --help
```

Repository layout:

```text
gateway/             gateway runtime
config/              JSON configs
docs/                configuration and operations notes
deploy/compose/      vLLM and SGLang Compose examples
deploy/k8s/          gateway, private backend Service, and NetworkPolicy examples
scripts/pki/         local certificate helper
tests/               unit and integration tests
PLAN.md              implementation plan
AGENTS.md            coding-agent instructions
```

## Status

Implemented capabilities include:

- Python stdlib gateway runtime.
- JSON config loader and validator.
- Static API-key auth.
- Hashed dynamic API-key management.
- JWT verification with local JWKS files.
- Endpoint allowlisting.
- Per-tenant rate limits and quotas.
- Log redaction and optional before-forward redaction.
- Prometheus metrics.
- Privacy-aware routing policy.
- Metadata-only audit logs.
- Kubernetes examples with private backend Services.
- vLLM and SGLang Compose examples.
- Access-log modes.
- Integration tests with a stub backend.

See [PLAN.md](PLAN.md) for the implementation roadmap and
[AGENTS.md](AGENTS.md) for repo-local coding-agent rules.

## Security Limits

Private LLM Gateway reduces deployment-level risk by centralizing
authentication, routing policy, endpoint exposure, logging, and network
boundaries. It is not a substitute for confidential computing, encrypted
inference, secure hardware attestation, or a trustworthy backend.

Do not expose raw vLLM or SGLang ports publicly. Keep backend ports private and
make the gateway the only entry point for clients.
