from __future__ import annotations

from typing import Any

from gateway.redaction import Redactor


SENSITIVE_TRACE_KEYS = {
    "prompt",
    "messages",
    "completion",
    "choices",
    "request_body",
    "response_body",
    "authorization",
    "cookie",
    "api_key",
}


def filter_trace_attributes(attributes: dict[str, Any], redactor: Redactor | None = None) -> dict[str, Any]:
    filtered: dict[str, Any] = {}
    for key, value in attributes.items():
        lower = key.lower()
        if any(part in lower for part in SENSITIVE_TRACE_KEYS):
            filtered[key] = "[REDACTED]"
        elif isinstance(value, str) and redactor:
            filtered[key] = redactor.text(value)
        else:
            filtered[key] = value
    return filtered
