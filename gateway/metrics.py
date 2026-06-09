from __future__ import annotations

from collections import defaultdict


class MetricsRegistry:
    def __init__(self) -> None:
        self._requests: dict[tuple[str, str, str], int] = defaultdict(int)
        self._latency_ms: dict[tuple[str, str, str], int] = defaultdict(int)

    def observe(self, *, route: str, backend: str, status: int, latency_ms: int) -> None:
        family = f"{status // 100}xx" if status else "unknown"
        key = (_route_label(route), _safe_label(backend), family)
        self._requests[key] += 1
        self._latency_ms[key] += latency_ms

    def prometheus(self) -> bytes:
        lines = [
            "# HELP pig_requests_total Gateway requests by route, backend, and status family.",
            "# TYPE pig_requests_total counter",
        ]
        for (route, backend, status_family), count in sorted(self._requests.items()):
            lines.append(
                f'pig_requests_total{{route="{route}",backend="{backend}",status_family="{status_family}"}} {count}'
            )
        lines.extend(
            [
                "# HELP pig_request_latency_ms_total Sum of gateway request latency in milliseconds.",
                "# TYPE pig_request_latency_ms_total counter",
            ]
        )
        for (route, backend, status_family), total in sorted(self._latency_ms.items()):
            lines.append(
                f'pig_request_latency_ms_total{{route="{route}",backend="{backend}",status_family="{status_family}"}} {total}'
            )
        return ("\n".join(lines) + "\n").encode("utf-8")


def _route_label(route: str) -> str:
    allowed = {
        "/healthz",
        "/metrics",
        "/v1/chat/completions",
        "/v1/completions",
        "/v1/embeddings",
        "/v1/models",
    }
    return route if route in allowed else "other"


def _safe_label(value: str) -> str:
    if not value or value == "-":
        return "none"
    return "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in value)[:64]
