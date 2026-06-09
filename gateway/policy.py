from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gateway.config import GatewayConfig, RouteConfig, RoutingPolicyRule, TenantPolicy


PRIVACY_CLASSES = {"standard", "sensitive", "restricted"}


@dataclass(frozen=True)
class RouteDecision:
    route: RouteConfig
    privacy_class: str
    redact_before_forward: bool


class PolicyDenied(Exception):
    pass


class PolicyResolver:
    def __init__(self, config: GatewayConfig) -> None:
        self._config = config
        self._routes = {route.name: route for route in config.routes}
        self._tenant_policies = {tenant.tenant: tenant for tenant in config.policy.tenants}
        self._rules = {
            (rule.tenant, rule.model, rule.privacy_class): rule
            for rule in config.policy.routing_rules
        }
        self._class_redaction = {
            item.name: item.redact_before_forward
            for item in config.policy.privacy_classes
        }

    def privacy_class_for_payload(self, payload: dict[str, Any], header_value: str | None) -> str:
        supplied = header_value or payload.get("privacy_class") or payload.get("privacyClass")
        privacy_class = str(supplied or self._config.policy.default_privacy_class).strip().lower()
        if privacy_class not in PRIVACY_CLASSES:
            raise PolicyDenied("unknown privacy class")
        return privacy_class

    def resolve(self, *, tenant: str, model: str, privacy_class: str) -> RouteDecision:
        if not self._config.policy.enabled:
            route = self._legacy_route(model)
            return RouteDecision(
                route=route,
                privacy_class=privacy_class,
                redact_before_forward=_first_bool(route.redact_before_forward, self._config.privacy.redact_before_forward),
            )

        tenant_policy = self._tenant_policies.get(tenant)
        if not tenant_policy:
            raise PolicyDenied("tenant has no routing policy")
        if model not in tenant_policy.allowed_models:
            raise PolicyDenied("model is not allowed for tenant")
        if privacy_class not in tenant_policy.privacy_classes:
            raise PolicyDenied("privacy class is not allowed for tenant")

        rule = self._rules.get((tenant, model, privacy_class))
        route = self._route_from_rule_or_allowlist(rule, tenant_policy, model, privacy_class)
        if route.name not in tenant_policy.allowed_backends:
            raise PolicyDenied("backend is not allowed for tenant")
        if privacy_class in {"sensitive", "restricted"} and not route.local:
            raise PolicyDenied("privacy class cannot route to external backend")
        if privacy_class == "restricted" and not route.local:
            raise PolicyDenied("restricted traffic requires a local backend")

        return RouteDecision(
            route=route,
            privacy_class=privacy_class,
            redact_before_forward=self._redact_before_forward(tenant_policy, rule, route, privacy_class),
        )

    def route_for_models_endpoint(self, tenant: str, privacy_class: str) -> RouteDecision:
        if not self._config.policy.enabled:
            return RouteDecision(self._config.routes[0], privacy_class, self._config.privacy.redact_before_forward)
        tenant_policy = self._tenant_policies.get(tenant)
        if not tenant_policy:
            raise PolicyDenied("tenant has no routing policy")
        if privacy_class not in tenant_policy.privacy_classes:
            raise PolicyDenied("privacy class is not allowed for tenant")
        for backend in tenant_policy.allowed_backends:
            route = self._routes[backend]
            if privacy_class in {"sensitive", "restricted"} and not route.local:
                continue
            return RouteDecision(
                route=route,
                privacy_class=privacy_class,
                redact_before_forward=self._redact_before_forward(tenant_policy, None, route, privacy_class),
            )
        raise PolicyDenied("no backend route for requested tenant and privacy class")

    def _legacy_route(self, model: str) -> RouteConfig:
        for route in self._config.routes:
            if model in route.models:
                return route
        raise PolicyDenied("no backend route for requested model")

    def _route_from_rule_or_allowlist(
        self,
        rule: RoutingPolicyRule | None,
        tenant_policy: TenantPolicy,
        model: str,
        privacy_class: str,
    ) -> RouteConfig:
        if rule:
            return self._routes[rule.backend]
        for backend in tenant_policy.allowed_backends:
            route = self._routes[backend]
            if privacy_class in {"sensitive", "restricted"} and not route.local:
                continue
            if model in route.models:
                return route
        raise PolicyDenied("no backend route for requested model")

    def _redact_before_forward(
        self,
        tenant_policy: TenantPolicy,
        rule: RoutingPolicyRule | None,
        route: RouteConfig,
        privacy_class: str,
    ) -> bool:
        policy = self._config.policy.redact_before_forward
        class_value = self._class_redaction.get(privacy_class)
        return _first_bool(
            rule.redact_before_forward if rule else None,
            tenant_policy.redact_before_forward,
            route.redact_before_forward,
            class_value,
            True if tenant_policy.tenant in policy.tenants else None,
            True if route.name in policy.routes else None,
            True if privacy_class in policy.privacy_classes else None,
            self._config.privacy.redact_before_forward,
        )


def _first_bool(*values: bool | None) -> bool:
    for value in values:
        if value is not None:
            return bool(value)
    return False
