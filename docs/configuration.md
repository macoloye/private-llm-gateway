# Configuration And Authentication

## Files

- Development config: `config/gateway.dev.json`
- Test config: `config/gateway.test.json`
- Dynamic local API keys: `config/api-keys.local.json`

Validate before running:

```sh
python3 -m gateway validate-policy --config config/gateway.dev.json
```

## Configuration Selection

- `server`: gateway bind address, port, and public TLS.
- `auth`: caller authentication for clients that call the gateway.
- `routes`: backend URLs, served models, endpoint allowlists, backend TLS, and backend credentials.
- `privacy`: log mode, audit log path, and redaction behavior.
- `policy`: tenant, model, backend, privacy-class, and routing rules.
- `redaction`: regex rules for log redaction or before-forward redaction.
- `logging`: terminal/file log destination and color mode.
- `limits`: body size, generation limits, timeout, and tenant quotas.

## Gateway Client Authentication

`auth` controls who may call the gateway.

Choose one or more:

- Static keys: `auth.api_keys`
- Dynamic hashed keys: `auth.api_key_file`
- JWT: `auth.jwt.enabled`

Static key example:

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

Clients may send either:

```text
Authorization: Bearer <gateway-client-key>
```

or:

```text
X-Api-Key: <gateway-client-key>
```

Prefer `key_env` or `key_hash` over plaintext `key`.

## Dynamic Hashed API Keys

Configure:

```json
{
  "auth": {
    "api_key_file": "config/api-keys.local.json",
    "admin_api_key_env": "GATEWAY_ADMIN_API_KEY"
  }
}
```

Issue a key:

```sh
export GATEWAY_ADMIN_API_KEY=replace-with-admin-secret

curl http://127.0.0.1:8080/admin/api-keys \
  -H 'Authorization: Bearer replace-with-admin-secret' \
  -H 'Content-Type: application/json' \
  -d '{"action":"issue","id":"team-b","tenant":"team-b","allowed_models":["qwen-local"]}'
```

Actions:

- `issue`: create a key and return plaintext once.
- `rotate`: replace a key and return plaintext once.
- `update`: update tenant, allowed models, or revoked status.
- `revoke`: mark a key revoked.

The gateway reloads the key file when it changes.

## JWT

Set `auth.jwt.enabled`, `issuer`, `audience`, and `jwks_file`.

The current stdlib verifier supports HS256 `oct` JWKS keys. OIDC discovery fields are parsed as integration hooks for deployments that resolve JWKS externally.

## Backend Authentication

`routes[].backend_api_key_env` controls how the gateway authenticates to a backend such as vLLM. It is separate from `auth`, which authenticates gateway clients.

For vLLM started with:

```sh
vllm serve "$model_path" --api-key token-abc123
```

configure the route:

```json
{
  "name": "vllm-local",
  "backend": "http://127.0.0.1:8000",
  "backend_api_key_env": "VLLM_API_KEY",
  "local": true,
  "models": ["qwen-local"],
  "allowed_endpoints": [
    {"path": "/v1/chat/completions", "methods": ["POST"]},
    {"path": "/v1/completions", "methods": ["POST"]},
    {"path": "/v1/embeddings", "methods": ["POST"]},
    {"path": "/v1/models", "methods": ["GET"]}
  ]
}
```

Run:

```sh
export VLLM_API_KEY=token-abc123
python3 -m gateway --config config/gateway.dev.json
```

The gateway forwards:

```text
Authorization: Bearer token-abc123
```

## Routing Policy

Required policy links:

- Client key or JWT maps to a tenant.
- Tenant allows requested model.
- Tenant allows selected backend.
- Tenant allows requested privacy class.
- Route declares the requested model.
- Route allowlists the requested endpoint and method.

Fail-closed behavior:

- Unknown backend: reject config.
- Unknown model in auth or policy: reject config.
- Unknown privacy class: reject config.
- Sensitive or restricted traffic to external backend: reject config or request.

## TLS And mTLS

Generate development certs:

```sh
scripts/pki/dev-ca.sh
```

Public gateway TLS uses `server.tls`.

Gateway-to-backend HTTPS or mTLS uses route-level fields:

- `backend`: must start with `https://`
- `tls_ca_file`
- `tls_cert_file`
- `tls_key_file`

## Limits

`limits` fields:

- `max_request_body_bytes`: larger bodies return `413`.
- `max_output_tokens`: excessive `max_tokens` returns `400`.
- `max_n`: excessive `n` returns `400`.
- `timeout_seconds`: slow backends return `504`.
- `per_tenant_requests_per_minute`: quota failures return `429`; `0` disables.
- `per_tenant_requests_per_day`: quota failures return `429`; `0` disables.

## Logs

Access-log modes:

- `off`: no access logs.
- `metadata`: request ID, tenant, route, backend, model, privacy class, status, latency, and token counts when available.
- `all`: debug only; may include prompts and completions.

Authorization headers, cookies, API keys, prompt bodies, completion bodies, uploaded file contents, tool outputs, and backend credentials must not be logged by default.

File logs use `logging.file` or `--log-file`. Audit logs are metadata-only.

