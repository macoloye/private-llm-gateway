from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """Raised when gateway configuration is invalid."""


@dataclass(frozen=True)
class TLSConfig:
    enabled: bool = False
    cert_file: str | None = None
    key_file: str | None = None
    client_ca_file: str | None = None
    require_client_cert: bool = False


@dataclass(frozen=True)
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    tls: TLSConfig = field(default_factory=TLSConfig)


@dataclass(frozen=True)
class APIKey:
    id: str
    secret: str
    tenant: str
    allowed_models: tuple[str, ...] = ()
    secret_hash: str | None = None
    revoked: bool = False


@dataclass(frozen=True)
class JWTConfig:
    enabled: bool = False
    issuer: str | None = None
    audience: str | None = None
    jwks_file: str | None = None
    tenant_claim: str = "tenant"
    allowed_models_claim: str = "allowed_models"


@dataclass(frozen=True)
class OIDCConfig:
    enabled: bool = False
    discovery_url: str | None = None
    client_id: str | None = None


@dataclass(frozen=True)
class AuthConfig:
    api_keys: tuple[APIKey, ...]
    api_key_file: str | None = None
    admin_api_key_env: str | None = None
    jwt: JWTConfig = field(default_factory=JWTConfig)
    oidc: OIDCConfig = field(default_factory=OIDCConfig)


@dataclass(frozen=True)
class AllowedEndpoint:
    path: str
    methods: tuple[str, ...]


@dataclass(frozen=True)
class RouteConfig:
    name: str
    backend: str
    models: tuple[str, ...]
    allowed_endpoints: tuple[AllowedEndpoint, ...]
    backend_api_key_env: str | None = None
    tls_ca_file: str | None = None
    tls_cert_file: str | None = None
    tls_key_file: str | None = None


@dataclass(frozen=True)
class PrivacyConfig:
    access_log: str = "metadata"
    redact_logs: bool = True
    redact_before_forward: bool = False


@dataclass(frozen=True)
class RedactionRule:
    name: str
    pattern: str
    replacement: str = "[REDACTED]"


@dataclass(frozen=True)
class RedactionConfig:
    enabled: bool = True
    rules: tuple[RedactionRule, ...] = ()


@dataclass(frozen=True)
class LimitsConfig:
    max_request_body_bytes: int = 1_048_576
    max_output_tokens: int = 2048
    max_n: int = 4
    timeout_seconds: int = 120
    per_tenant_requests_per_minute: int = 0
    per_tenant_requests_per_day: int = 0


@dataclass(frozen=True)
class LoggingConfig:
    color: str = "auto"
    file: str | None = None


@dataclass(frozen=True)
class GatewayConfig:
    server: ServerConfig
    auth: AuthConfig
    routes: tuple[RouteConfig, ...]
    privacy: PrivacyConfig
    redaction: RedactionConfig
    limits: LimitsConfig
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def load_config(path: str | os.PathLike[str]) -> GatewayConfig:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON in {path}: {exc}") from exc

    return parse_config(raw)


def parse_config(raw: dict[str, Any]) -> GatewayConfig:
    server_raw = raw.get("server", {})
    tls_raw = server_raw.get("tls", {})
    server = ServerConfig(
        host=str(server_raw.get("host", "0.0.0.0")),
        port=_non_negative_int(server_raw.get("port", 8080), "server.port"),
        tls=TLSConfig(
            enabled=bool(tls_raw.get("enabled", False)),
            cert_file=tls_raw.get("cert_file"),
            key_file=tls_raw.get("key_file"),
            client_ca_file=tls_raw.get("client_ca_file"),
            require_client_cert=bool(tls_raw.get("require_client_cert", False)),
        ),
    )
    if server.tls.enabled and (not server.tls.cert_file or not server.tls.key_file):
        raise ConfigError("server.tls.cert_file and server.tls.key_file are required when TLS is enabled")
    if server.tls.require_client_cert and not server.tls.client_ca_file:
        raise ConfigError("server.tls.client_ca_file is required when client certificates are required")

    auth_raw = raw.get("auth", {})
    auth = AuthConfig(
        api_keys=tuple(_parse_api_key(item) for item in auth_raw.get("api_keys", [])),
        api_key_file=auth_raw.get("api_key_file"),
        admin_api_key_env=auth_raw.get("admin_api_key_env"),
        jwt=_parse_jwt(auth_raw.get("jwt", {})),
        oidc=_parse_oidc(auth_raw.get("oidc", {})),
    )
    if not auth.api_keys and not auth.api_key_file and not auth.jwt.enabled:
        raise ConfigError("auth must configure api_keys, api_key_file, or enabled jwt")

    routes = tuple(_parse_route(item) for item in raw.get("routes", []))
    if not routes:
        raise ConfigError("routes must contain at least one backend route")

    all_models = {model for route in routes for model in route.models}
    for api_key in auth.api_keys:
        unknown = set(api_key.allowed_models) - all_models
        if unknown:
            raise ConfigError(f"api key {api_key.id} references unknown models: {sorted(unknown)}")

    privacy_raw = raw.get("privacy", {})
    access_log = str(privacy_raw.get("access_log", "metadata"))
    if access_log not in {"off", "metadata", "all"}:
        raise ConfigError("privacy.access_log must be one of: off, metadata, all")
    privacy = PrivacyConfig(
        access_log=access_log,
        redact_logs=bool(privacy_raw.get("redact_logs", True)),
        redact_before_forward=bool(privacy_raw.get("redact_before_forward", False)),
    )

    redaction_raw = raw.get("redaction", {})
    redaction = RedactionConfig(
        enabled=bool(redaction_raw.get("enabled", True)),
        rules=tuple(_parse_redaction_rule(item) for item in redaction_raw.get("rules", [])),
    )

    limits_raw = raw.get("limits", {})
    limits = LimitsConfig(
        max_request_body_bytes=_positive_int(limits_raw.get("max_request_body_bytes", 1_048_576), "limits.max_request_body_bytes"),
        max_output_tokens=_positive_int(limits_raw.get("max_output_tokens", 2048), "limits.max_output_tokens"),
        max_n=_positive_int(limits_raw.get("max_n", 4), "limits.max_n"),
        timeout_seconds=_positive_int(limits_raw.get("timeout_seconds", 120), "limits.timeout_seconds"),
        per_tenant_requests_per_minute=_non_negative_int(
            limits_raw.get("per_tenant_requests_per_minute", 0), "limits.per_tenant_requests_per_minute"
        ),
        per_tenant_requests_per_day=_non_negative_int(
            limits_raw.get("per_tenant_requests_per_day", 0), "limits.per_tenant_requests_per_day"
        ),
    )

    logging_raw = raw.get("logging", {})
    color = str(logging_raw.get("color", "auto"))
    if color not in {"auto", "always", "never"}:
        raise ConfigError("logging.color must be one of: auto, always, never")
    logging = LoggingConfig(color=color, file=logging_raw.get("file"))

    return GatewayConfig(
        server=server,
        auth=auth,
        routes=routes,
        privacy=privacy,
        redaction=redaction,
        limits=limits,
        logging=logging,
    )


def _parse_api_key(raw: dict[str, Any]) -> APIKey:
    key_id = str(raw.get("id", "")).strip()
    tenant = str(raw.get("tenant", key_id)).strip()
    secret = raw.get("key")
    secret_hash = raw.get("key_hash")
    if not secret and raw.get("key_env"):
        secret = os.environ.get(str(raw["key_env"]))
    if not key_id:
        raise ConfigError("auth.api_keys[].id is required")
    if not tenant:
        raise ConfigError(f"auth.api_keys[{key_id}].tenant is required")
    if not secret and not secret_hash:
        raise ConfigError(f"auth.api_keys[{key_id}] must set key, key_env, or key_hash")
    return APIKey(
        id=key_id,
        secret=str(secret or ""),
        tenant=tenant,
        allowed_models=tuple(str(model) for model in raw.get("allowed_models", [])),
        secret_hash=str(secret_hash) if secret_hash else None,
        revoked=bool(raw.get("revoked", False)),
    )


def _parse_jwt(raw: dict[str, Any]) -> JWTConfig:
    enabled = bool(raw.get("enabled", False))
    issuer = raw.get("issuer")
    audience = raw.get("audience")
    jwks_file = raw.get("jwks_file")
    if enabled and (not issuer or not audience or not jwks_file):
        raise ConfigError("auth.jwt issuer, audience, and jwks_file are required when JWT auth is enabled")
    return JWTConfig(
        enabled=enabled,
        issuer=str(issuer) if issuer else None,
        audience=str(audience) if audience else None,
        jwks_file=str(jwks_file) if jwks_file else None,
        tenant_claim=str(raw.get("tenant_claim", "tenant")),
        allowed_models_claim=str(raw.get("allowed_models_claim", "allowed_models")),
    )


def _parse_oidc(raw: dict[str, Any]) -> OIDCConfig:
    enabled = bool(raw.get("enabled", False))
    discovery_url = raw.get("discovery_url")
    client_id = raw.get("client_id")
    if enabled and (not discovery_url or not client_id):
        raise ConfigError("auth.oidc discovery_url and client_id are required when OIDC is enabled")
    return OIDCConfig(enabled=enabled, discovery_url=discovery_url, client_id=client_id)


def _parse_redaction_rule(raw: dict[str, Any]) -> RedactionRule:
    name = str(raw.get("name", "")).strip()
    pattern = str(raw.get("pattern", "")).strip()
    replacement = str(raw.get("replacement", "[REDACTED]"))
    if not name:
        raise ConfigError("redaction.rules[].name is required")
    if not pattern:
        raise ConfigError(f"redaction rule {name} requires pattern")
    return RedactionRule(name=name, pattern=pattern, replacement=replacement)


def _parse_route(raw: dict[str, Any]) -> RouteConfig:
    name = str(raw.get("name", "")).strip()
    backend = str(raw.get("backend", "")).strip()
    models = tuple(str(model) for model in raw.get("models", []))
    endpoints = tuple(_parse_endpoint(item) for item in raw.get("allowed_endpoints", []))
    if not name:
        raise ConfigError("routes[].name is required")
    if not backend:
        raise ConfigError(f"route {name} requires backend")
    if not models:
        raise ConfigError(f"route {name} requires at least one model")
    if not endpoints:
        raise ConfigError(f"route {name} requires allowed_endpoints")
    if not backend.startswith(("http://", "https://")):
        raise ConfigError(f"route {name} backend must start with http:// or https://")
    return RouteConfig(
        name=name,
        backend=backend.rstrip("/"),
        models=models,
        allowed_endpoints=endpoints,
        backend_api_key_env=raw.get("backend_api_key_env"),
        tls_ca_file=raw.get("tls_ca_file"),
        tls_cert_file=raw.get("tls_cert_file"),
        tls_key_file=raw.get("tls_key_file"),
    )


def _parse_endpoint(raw: dict[str, Any]) -> AllowedEndpoint:
    path = str(raw.get("path", "")).strip()
    methods = tuple(str(method).upper() for method in raw.get("methods", []))
    if not path.startswith("/"):
        raise ConfigError("allowed endpoint path must start with /")
    if not methods:
        raise ConfigError(f"allowed endpoint {path} requires methods")
    return AllowedEndpoint(path=path, methods=methods)


def _positive_int(value: Any, name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if parsed <= 0:
        raise ConfigError(f"{name} must be greater than zero")
    return parsed


def _non_negative_int(value: Any, name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if parsed < 0:
        raise ConfigError(f"{name} must be zero or greater")
    return parsed
