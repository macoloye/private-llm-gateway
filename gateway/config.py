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
    local: bool = True
    backend_api_key_env: str | None = None
    tls_ca_file: str | None = None
    tls_cert_file: str | None = None
    tls_key_file: str | None = None
    redact_before_forward: bool | None = None


@dataclass(frozen=True)
class PrivacyConfig:
    access_log: str = "metadata"
    redact_logs: bool = True
    redact_before_forward: bool = False
    audit_log_file: str | None = None
    audit_retention_days: int = 30


@dataclass(frozen=True)
class PrivacyClassPolicy:
    name: str
    redact_before_forward: bool | None = None


@dataclass(frozen=True)
class TenantPolicy:
    tenant: str
    allowed_models: tuple[str, ...]
    allowed_backends: tuple[str, ...]
    privacy_classes: tuple[str, ...] = ("standard",)
    redact_before_forward: bool | None = None


@dataclass(frozen=True)
class RoutingPolicyRule:
    tenant: str
    model: str
    privacy_class: str
    backend: str
    redact_before_forward: bool | None = None


@dataclass(frozen=True)
class RedactBeforeForwardPolicy:
    tenants: tuple[str, ...] = ()
    routes: tuple[str, ...] = ()
    privacy_classes: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyConfig:
    enabled: bool = False
    default_privacy_class: str = "standard"
    privacy_classes: tuple[PrivacyClassPolicy, ...] = (
        PrivacyClassPolicy("standard"),
        PrivacyClassPolicy("sensitive"),
        PrivacyClassPolicy("restricted"),
    )
    tenants: tuple[TenantPolicy, ...] = ()
    routing_rules: tuple[RoutingPolicyRule, ...] = ()
    redact_before_forward: RedactBeforeForwardPolicy = field(default_factory=RedactBeforeForwardPolicy)


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
    policy: PolicyConfig = field(default_factory=PolicyConfig)
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
        audit_log_file=privacy_raw.get("audit_log_file"),
        audit_retention_days=_positive_int(privacy_raw.get("audit_retention_days", 30), "privacy.audit_retention_days"),
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

    policy = _parse_policy(raw.get("policy", {}), auth, routes)

    return GatewayConfig(
        server=server,
        auth=auth,
        routes=routes,
        privacy=privacy,
        redaction=redaction,
        limits=limits,
        policy=policy,
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
        local=bool(raw.get("local", True)),
        backend_api_key_env=raw.get("backend_api_key_env"),
        tls_ca_file=raw.get("tls_ca_file"),
        tls_cert_file=raw.get("tls_cert_file"),
        tls_key_file=raw.get("tls_key_file"),
        redact_before_forward=raw.get("redact_before_forward"),
    )


def _parse_endpoint(raw: dict[str, Any]) -> AllowedEndpoint:
    path = str(raw.get("path", "")).strip()
    methods = tuple(str(method).upper() for method in raw.get("methods", []))
    if not path.startswith("/"):
        raise ConfigError("allowed endpoint path must start with /")
    if not methods:
        raise ConfigError(f"allowed endpoint {path} requires methods")
    return AllowedEndpoint(path=path, methods=methods)


def _parse_policy(raw: dict[str, Any], auth: AuthConfig, routes: tuple[RouteConfig, ...]) -> PolicyConfig:
    if not raw:
        return PolicyConfig()

    privacy_classes = tuple(_parse_privacy_class(item) for item in raw.get("privacy_classes", []))
    if not privacy_classes:
        privacy_classes = PolicyConfig().privacy_classes
    class_names = {item.name for item in privacy_classes}
    if class_names != {"standard", "sensitive", "restricted"}:
        raise ConfigError("policy.privacy_classes must define exactly: standard, sensitive, restricted")

    default_privacy_class = str(raw.get("default_privacy_class", "standard")).strip()
    if default_privacy_class not in class_names:
        raise ConfigError(f"policy.default_privacy_class references unknown privacy class: {default_privacy_class}")

    tenants = tuple(_parse_tenant_policy(item) for item in raw.get("tenants", []))
    rules = tuple(_parse_routing_rule(item) for item in raw.get("routing_rules", raw.get("routes", [])))
    redact_policy = _parse_redact_before_forward_policy(raw.get("redact_before_forward", {}))
    policy = PolicyConfig(
        enabled=True,
        default_privacy_class=default_privacy_class,
        privacy_classes=privacy_classes,
        tenants=tenants,
        routing_rules=rules,
        redact_before_forward=redact_policy,
    )
    _validate_policy(policy, auth, routes)
    return policy


def _parse_privacy_class(raw: dict[str, Any] | str) -> PrivacyClassPolicy:
    if isinstance(raw, str):
        name = raw.strip()
        redact = None
    else:
        name = str(raw.get("name", "")).strip()
        redact = raw.get("redact_before_forward")
    if name not in {"standard", "sensitive", "restricted"}:
        raise ConfigError(f"unknown privacy class: {name}")
    return PrivacyClassPolicy(name=name, redact_before_forward=redact)


def _parse_tenant_policy(raw: dict[str, Any]) -> TenantPolicy:
    tenant = str(raw.get("tenant", "")).strip()
    if not tenant:
        raise ConfigError("policy.tenants[].tenant is required")
    return TenantPolicy(
        tenant=tenant,
        allowed_models=tuple(str(item) for item in raw.get("allowed_models", [])),
        allowed_backends=tuple(str(item) for item in raw.get("allowed_backends", [])),
        privacy_classes=tuple(str(item) for item in raw.get("privacy_classes", ["standard"])),
        redact_before_forward=raw.get("redact_before_forward"),
    )


def _parse_routing_rule(raw: dict[str, Any]) -> RoutingPolicyRule:
    tenant = str(raw.get("tenant", "")).strip()
    model = str(raw.get("model", "")).strip()
    privacy_class = str(raw.get("privacy_class", "")).strip()
    backend = str(raw.get("backend", "")).strip()
    if not tenant or not model or not privacy_class or not backend:
        raise ConfigError("policy.routing_rules[] requires tenant, model, privacy_class, and backend")
    return RoutingPolicyRule(
        tenant=tenant,
        model=model,
        privacy_class=privacy_class,
        backend=backend,
        redact_before_forward=raw.get("redact_before_forward"),
    )


def _parse_redact_before_forward_policy(raw: dict[str, Any] | bool) -> RedactBeforeForwardPolicy:
    if isinstance(raw, bool):
        return RedactBeforeForwardPolicy(privacy_classes=("standard", "sensitive", "restricted") if raw else ())
    return RedactBeforeForwardPolicy(
        tenants=tuple(str(item) for item in raw.get("tenants", [])),
        routes=tuple(str(item) for item in raw.get("routes", [])),
        privacy_classes=tuple(str(item) for item in raw.get("privacy_classes", [])),
    )


def _validate_policy(policy: PolicyConfig, auth: AuthConfig, routes: tuple[RouteConfig, ...]) -> None:
    backends = {route.name: route for route in routes}
    all_models = {model for route in routes for model in route.models}
    class_names = {item.name for item in policy.privacy_classes}
    tenant_map = {tenant.tenant: tenant for tenant in policy.tenants}
    auth_tenants = {api_key.tenant for api_key in auth.api_keys}

    if len(tenant_map) != len(policy.tenants):
        raise ConfigError("policy.tenants contains duplicate tenant entries")
    if not policy.tenants:
        raise ConfigError("policy.tenants must contain at least one tenant when policy is configured")
    if auth_tenants and (missing := auth_tenants - set(tenant_map)):
        raise ConfigError(f"policy is missing tenant auth bindings for: {sorted(missing)}")
    if not auth.api_key_file and not auth.jwt.enabled and (missing := set(tenant_map) - auth_tenants):
        raise ConfigError(f"policy tenants have no auth bindings: {sorted(missing)}")

    for tenant in policy.tenants:
        if not tenant.allowed_models:
            raise ConfigError(f"policy tenant {tenant.tenant} requires allowed_models")
        if not tenant.allowed_backends:
            raise ConfigError(f"policy tenant {tenant.tenant} requires allowed_backends")
        unknown_models = set(tenant.allowed_models) - all_models
        if unknown_models:
            raise ConfigError(f"policy tenant {tenant.tenant} references unknown models: {sorted(unknown_models)}")
        unknown_backends = set(tenant.allowed_backends) - set(backends)
        if unknown_backends:
            raise ConfigError(f"policy tenant {tenant.tenant} references unknown backend names: {sorted(unknown_backends)}")
        unknown_classes = set(tenant.privacy_classes) - class_names
        if unknown_classes:
            raise ConfigError(f"policy tenant {tenant.tenant} references unknown privacy classes: {sorted(unknown_classes)}")
    for name in (*policy.redact_before_forward.tenants,):
        if name not in tenant_map:
            raise ConfigError(f"policy.redact_before_forward.tenants references unknown tenant: {name}")
    for name in policy.redact_before_forward.routes:
        if name not in backends:
            raise ConfigError(f"policy.redact_before_forward.routes references unknown backend name: {name}")
    for name in policy.redact_before_forward.privacy_classes:
        if name not in class_names:
            raise ConfigError(f"policy.redact_before_forward.privacy_classes references unknown privacy class: {name}")

    seen_rules: set[tuple[str, str, str]] = set()
    for rule in policy.routing_rules:
        key = (rule.tenant, rule.model, rule.privacy_class)
        if key in seen_rules:
            raise ConfigError(f"duplicate policy route rule for tenant={rule.tenant} model={rule.model} privacy_class={rule.privacy_class}")
        seen_rules.add(key)
        if rule.tenant not in tenant_map:
            raise ConfigError(f"policy route rule references unknown tenant: {rule.tenant}")
        if rule.backend not in backends:
            raise ConfigError(f"policy route rule references unknown backend name: {rule.backend}")
        if rule.privacy_class not in class_names:
            raise ConfigError(f"policy route rule references unknown privacy class: {rule.privacy_class}")
        tenant = tenant_map[rule.tenant]
        backend = backends[rule.backend]
        if rule.model not in tenant.allowed_models or rule.model not in backend.models:
            raise ConfigError(f"impossible policy route rule for tenant={rule.tenant} model={rule.model} backend={rule.backend}")
        if rule.backend not in tenant.allowed_backends or rule.privacy_class not in tenant.privacy_classes:
            raise ConfigError(f"policy route rule is outside tenant {rule.tenant} allowlist")
        if rule.privacy_class in {"sensitive", "restricted"} and not backend.local:
            raise ConfigError(f"policy route rule cannot send {rule.privacy_class} traffic to external backend {rule.backend}")


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
