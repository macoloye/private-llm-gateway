# Private Inference Gateway

Private Inference Gateway is a privacy-focused gateway for self-hosted OpenAI-compatible inference servers such as vLLM and SGLang.

Use it when you want applications to call one protected gateway instead of exposing raw inference-server ports directly.

```text
                ┌────────────────────────────────────────────┐
                │            Application / Client            │
                │        API key, optional TLS client        │
                └─────────────────────┬──────────────────────┘
                                      │
                         OpenAI-compatible API
                                      │
                   ┌──────────────────▼──────────────────┐
                   │      Private Inference Gateway      │
                   │  authn • endpoint allowlist • limits│
                   │  access-log modes • request IDs     │
                   └───────────────┬───────────────┬─────┘
                                   │               │
                          private net              │ private net
                                   │               │
                     ┌─────────────▼────┐   ┌──────▼─────────────┐
                     │   vLLM backend   │   │   SGLang backend   │
                     │ OpenAI-compatible│   │ OpenAI-compatible  │
                     └─────────────┬────┘   └──────┬─────────────┘
                                   │               │
                                   │ GPU runtime   │ GPU runtime
                                   │               │
                           ┌───────▼───────┐ ┌────▼──────────┐
                           │ GPU worker(s) │ │ GPU worker(s) │
                           └───────────────┘ └───────────────┘
```

## What It Does

- Proxies OpenAI-compatible requests to configured backends.
- Supports `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, and `/v1/models`.
- Requires API-key authentication before forwarding.
- Allows only configured endpoints and denies everything else.
- Routes requests by model name.
- Enforces basic request limits: body size, `max_tokens`, `n`, and backend timeout.
- Generates and propagates `X-Request-Id`.
- Strips client auth headers before forwarding to the backend.
- Supports access-log modes: `off`, `metadata`, and `all`.
- Supports gateway TLS through config.

It does not make an untrusted backend cryptographically blind. The backend still receives plaintext prompts.

## Status

Phase 0 and Phase 1 are implemented:

- Python stdlib gateway runtime
- JSON config loader
- API-key auth
- endpoint allowlisting
- vLLM and SGLang Compose examples
- access-log modes
- integration tests with a stub backend

See [PLAN.md](PLAN.md) for the implementation roadmap and [AGENTS.md](AGENTS.md) for repo-local coding-agent rules.

## Quick Start

Run tests:

```sh
make test
```

Run the gateway locally:

```sh
export TEAM_A_API_KEY=example-team-a-key
python3 -m gateway --config config/gateway.dev.json
```

The dev config uses colored terminal output and writes metadata access logs to `logs/gateway.log`.

Override logging from the CLI:

```sh
python3 -m gateway \
  --config config/gateway.dev.json \
  --log-file logs/gateway.log \
  --color always
```

Send a request:

```sh
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'Authorization: Bearer example-team-a-key' \
  -H 'Content-Type: application/json' \
  -d '{"model":"qwen-local","messages":[{"role":"user","content":"hello"}],"max_tokens":32}'
```

The default dev config expects these backend service names:

- `http://vllm:8000` for model `qwen-local`
- `http://sglang:30000` for model `llama-local`

For a real local request, run one of the Compose examples or update `config/gateway.dev.json` to point at your backend.

## Docker Compose

Run with vLLM:

```sh
docker compose -f deploy/compose/vllm.yaml up --build
```

Run with SGLang:

```sh
docker compose -f deploy/compose/sglang.yaml up --build
```

The backend services use `expose`, not `ports`, so only the gateway is published to the host.

## Configuration

The development config lives at [config/gateway.dev.json](config/gateway.dev.json).

Minimal shape:

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
      "models": ["qwen-local"],
      "allowed_endpoints": [
        {"path": "/v1/chat/completions", "methods": ["POST"]},
        {"path": "/v1/models", "methods": ["GET"]}
      ]
    }
  ],
  "privacy": {
    "access_log": "metadata"
  }
}
```

Important config rules:

- API keys can be read from environment variables with `key_env`.
- Each route must declare model names and allowed endpoints.
- Requests for unknown models fail before forwarding.
- Requests to non-allowlisted paths return `403`.
- Real secrets should not be committed.

## TLS

Generate local development certificates:

```sh
scripts/pki/dev-ca.sh
```

Then set `server.tls.enabled` to `true` and keep `cert_file` and `key_file` pointed at the generated files.

mTLS is planned for Phase 2.

## Logs

The gateway prints colored access logs to the terminal. If `logging.file` or `--log-file` is set, it also writes plain JSON lines to a `.log` file.

Access-log modes:

- `off`: no access logs.
- `metadata`: safe default; logs request ID, tenant, route, backend, model, status, latency, and token counts when available.
- `all`: debug mode; logs metadata plus request and response bodies. This can include prompts and completions, so use it only in local development.

Authorization headers, cookies, and API keys are not logged in any mode.

Example:

```json
{"request_id":"req_abc","tenant":"team-a","route":"/v1/chat/completions","backend":"vllm-local","model":"qwen-local","status":200,"latency_ms":84,"input_tokens":12,"output_tokens":8}
```

Config:

```json
{
  "privacy": {
    "access_log": "metadata"
  },
  "logging": {
    "color": "always",
    "file": "logs/gateway.log"
  }
}
```

Color modes are `auto`, `always`, and `never`. File logs never include ANSI color codes.

## Development

Run all checks:

```sh
make check
```

Run the CLI help:

```sh
python3 -m gateway --help
```

Current repository layout:

```text
gateway/             gateway runtime
config/              JSON configs
deploy/compose/      vLLM and SGLang Compose examples
scripts/pki/         local certificate helper
tests/               unit and integration tests
PLAN.md              implementation plan
AGENTS.md            coding-agent instructions
idea.md              research notes
```

## Roadmap

- Phase 2: mTLS, JWT/OIDC, per-tenant rate limits, redaction middleware, Kubernetes templates, and safe metrics.
- Phase 3: privacy classes, tenant-to-backend routing, local-only routing, and policy validation.
- Phase 4: service-mesh examples, confidential-computing notes, attestation experiments, signed policies, and security CI.

## Security Limits

Private Inference Gateway reduces deployment-level risk. It is not a substitute for confidential computing, encrypted inference, secure hardware attestation, or a trustworthy backend.

Do not expose raw vLLM or SGLang ports publicly. Keep backend ports private and make the gateway the public entry point.
