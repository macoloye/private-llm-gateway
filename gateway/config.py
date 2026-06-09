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


@dataclass(frozen=True)
class AuthConfig:
    api_keys: tuple[APIKey, ...]


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


@dataclass(frozen=True)
class PrivacyConfig:
    access_log: str = "metadata"


@dataclass(frozen=True)
class LimitsConfig:
    max_request_body_bytes: int = 1_048_576
    max_output_tokens: int = 2048
    max_n: int = 4
    timeout_seconds: int = 120


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
        ),
    )
    if server.tls.enabled and (not server.tls.cert_file or not server.tls.key_file):
        raise ConfigError("server.tls.cert_file and server.tls.key_file are required when TLS is enabled")

    auth = AuthConfig(api_keys=tuple(_parse_api_key(item) for item in raw.get("auth", {}).get("api_keys", [])))
    if not auth.api_keys:
        raise ConfigError("auth.api_keys must contain at least one key")

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
    privacy = PrivacyConfig(access_log=access_log)

    limits_raw = raw.get("limits", {})
    limits = LimitsConfig(
        max_request_body_bytes=_positive_int(limits_raw.get("max_request_body_bytes", 1_048_576), "limits.max_request_body_bytes"),
        max_output_tokens=_positive_int(limits_raw.get("max_output_tokens", 2048), "limits.max_output_tokens"),
        max_n=_positive_int(limits_raw.get("max_n", 4), "limits.max_n"),
        timeout_seconds=_positive_int(limits_raw.get("timeout_seconds", 120), "limits.timeout_seconds"),
    )

    logging_raw = raw.get("logging", {})
    color = str(logging_raw.get("color", "auto"))
    if color not in {"auto", "always", "never"}:
        raise ConfigError("logging.color must be one of: auto, always, never")
    logging = LoggingConfig(color=color, file=logging_raw.get("file"))

    return GatewayConfig(server=server, auth=auth, routes=routes, privacy=privacy, limits=limits, logging=logging)


def _parse_api_key(raw: dict[str, Any]) -> APIKey:
    key_id = str(raw.get("id", "")).strip()
    tenant = str(raw.get("tenant", key_id)).strip()
    secret = raw.get("key")
    if not secret and raw.get("key_env"):
        secret = os.environ.get(str(raw["key_env"]))
    if not key_id:
        raise ConfigError("auth.api_keys[].id is required")
    if not tenant:
        raise ConfigError(f"auth.api_keys[{key_id}].tenant is required")
    if not secret:
        raise ConfigError(f"auth.api_keys[{key_id}] must set key or key_env")
    return APIKey(
        id=key_id,
        secret=str(secret),
        tenant=tenant,
        allowed_models=tuple(str(model) for model in raw.get("allowed_models", [])),
    )


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
