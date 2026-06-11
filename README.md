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

## Configuration

The development config lives at [config/gateway.dev.json](config/gateway.dev.json).

Validate the config and routing policy before deployment:

```sh
python3 -m gateway validate-policy --config config/gateway.dev.json
```

Minimal config shape:

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8080,
    "tls": {
      "enabled": false,
      "cert_file": "certs/server.crt",
      "key_file": "certs/server.key"
    }
  },
  "auth": {
    "api_keys": [
      {
        "id": "team-a",
        "tenant": "team-a",
        "key_env": "TEAM_A_API_KEY",
        "allowed_models": ["qwen-local"]
      }
    ]
  },
  "routes": [
    {
      "name": "vllm-local",
      "backend": "http://vllm:8000",
      "local": true,
      "models": ["qwen-local"],
      "allowed_endpoints": [
        {"path": "/v1/chat/completions", "methods": ["POST"]},
        {"path": "/v1/models", "methods": ["GET"]}
      ]
    }
  ],
  "privacy": {
    "access_log": "metadata"
  },
  "policy": {
    "default_privacy_class": "standard",
    "tenants": [
      {
        "tenant": "team-a",
        "allowed_models": ["qwen-local"],
        "allowed_backends": ["vllm-local"],
        "privacy_classes": ["standard", "sensitive", "restricted"]
      }
    ],
    "routing_rules": [
      {
        "tenant": "team-a",
        "model": "qwen-local",
        "privacy_class": "standard",
        "backend": "vllm-local"
      },
      {
        "tenant": "team-a",
        "model": "qwen-local",
        "privacy_class": "sensitive",
        "backend": "vllm-local"
      },
      {
        "tenant": "team-a",
        "model": "qwen-local",
        "privacy_class": "restricted",
        "backend": "vllm-local"
      }
    ]
  }
}
```

Important config rules:

- Configure at least one auth source: `auth.api_keys`, `auth.api_key_file`, or enabled JWT.
- Static API keys can read secrets from environment variables with `key_env`.
- Dynamic API keys are stored as PBKDF2 hashes when `auth.api_key_file` is configured.
- Each route must declare model names and allowed endpoints.
- Set route `local` to `false` for external providers.
- `sensitive` and `restricted` traffic cannot use external routes.
- When `policy` is configured, each tenant should have model, backend, and privacy-class allowlists.
- `routing_rules` choose the exact backend for a tenant, model, and privacy class.
- If no matching routing rule exists, the gateway chooses the first allowed route that can serve the model.
- Real secrets should not be committed.

## Authentication

### Static API Keys

Static API keys are configured in `auth.api_keys`. A key can be stored directly
with `key`, read from an environment variable with `key_env`, or stored as a hash
with `key_hash`.

Example:

```json
{
  "auth": {
    "api_keys": [
      {
        "id": "team-a",
        "tenant": "team-a",
        "key_env": "TEAM_A_API_KEY",
        "allowed_models": ["qwen-local"]
      }
    ]
  }
}
```

Clients can send the key as either:

```text
Authorization: Bearer <key>
```

or:

```text
X-Api-Key: <key>
```

### Dynamic Hashed API Keys

For production-style key management, configure:

```json
{
  "auth": {
    "api_key_file": "config/api-keys.local.json",
    "admin_api_key_env": "GATEWAY_ADMIN_API_KEY"
  }
}
```

Then set the admin key and use the protected admin endpoint:

```sh
export GATEWAY_ADMIN_API_KEY=replace-with-admin-secret

curl http://127.0.0.1:8080/admin/api-keys \
  -H 'Authorization: Bearer replace-with-admin-secret' \
  -H 'Content-Type: application/json' \
  -d '{"action":"issue","id":"team-b","tenant":"team-b","allowed_models":["qwen-local"]}'
```

Supported actions:

- `issue`: create a new key and return the plaintext once.
- `rotate`: replace an existing key and return the new plaintext once.
- `update`: update tenant, allowed models, or revoked status.
- `revoke`: mark a key as revoked.

The gateway reloads the key file when it changes. If the key file contains
invalid records, dynamic keys are rejected.

### JWT

JWT auth is configured with `auth.jwt.enabled`, `issuer`, `audience`, and a local
JWKS file. The current stdlib verifier supports HS256 `oct` JWKS keys. OIDC
discovery fields are parsed as integration hooks for deployments that resolve
JWKS externally.

## TLS And mTLS

Generate local development certificates:

```sh
scripts/pki/dev-ca.sh
```

Then set `server.tls.enabled` to `true` and keep `cert_file` and `key_file`
pointed at the generated files.

For service-to-service client certificates, configure the server TLS block:

```json
{
  "server": {
    "tls": {
      "enabled": true,
      "cert_file": "certs/server.crt",
      "key_file": "certs/server.key",
      "client_ca_file": "certs/dev-ca.crt",
      "require_client_cert": true
    }
  }
}
```

For gateway-to-backend HTTPS or mTLS, use an `https://` backend URL and route
level TLS files:

```json
{
  "routes": [
    {
      "name": "vllm-secure",
      "backend": "https://vllm:8443",
      "tls_ca_file": "certs/dev-ca.crt",
      "tls_cert_file": "certs/client.crt",
      "tls_key_file": "certs/client.key",
      "models": ["qwen-local"],
      "allowed_endpoints": [
        {"path": "/v1/chat/completions", "methods": ["POST"]}
      ]
    }
  ]
}
```

## Limits

The `limits` block controls basic request and backend protections:

```json
{
  "limits": {
    "max_request_body_bytes": 1048576,
    "max_output_tokens": 2048,
    "max_n": 4,
    "timeout_seconds": 120,
    "per_tenant_requests_per_minute": 120,
    "per_tenant_requests_per_day": 10000
  }
}
```

Limit behavior:

- Bodies larger than `max_request_body_bytes` return `413`.
- `max_tokens` above `max_output_tokens` returns `400`.
- `n` above `max_n` returns `400`.
- Backend requests that exceed `timeout_seconds` return `504`.
- Tenant quota failures return `429`.
- Per-tenant quota values of `0` disable that quota.

## Logs

The gateway prints access logs to the terminal. If `logging.file` or `--log-file`
is set, it also writes JSON lines to a `.log` file.

Override logging from the CLI:

```sh
python3 -m gateway \
  --config config/gateway.dev.json \
  --log-file logs/gateway.log \
  --color always
```

Access-log modes:

- `off`: no access logs.
- `metadata`: safe default; logs request ID, tenant, route, backend, model,
  privacy class, status, latency, and token counts when available.
- `all`: debug mode; logs metadata plus request and response bodies. This can
  include prompts and completions, so use it only in local development.

Authorization headers, cookies, and API keys are not logged in any mode.

Example metadata log:

```json
{"request_id":"req_abc","tenant":"team-a","route":"/v1/chat/completions","backend":"vllm-local","model":"qwen-local","privacy_class":"restricted","status":200,"latency_ms":84,"input_tokens":12,"output_tokens":8}
```

Config:

```json
{
  "privacy": {
    "access_log": "metadata",
    "audit_log_file": "logs/audit.log",
    "audit_retention_days": 30
  },
  "logging": {
    "color": "always",
    "file": "logs/gateway.log"
  }
}
```

Color modes are `auto`, `always`, and `never`. File logs never include ANSI color
codes. Audit logs are always metadata-only and never include prompt or completion
bodies.

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
