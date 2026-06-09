from __future__ import annotations

import re

from gateway.config import RedactionConfig


DEFAULT_RULES: tuple[tuple[str, str], ...] = (
    ("bearer_token", r"(?i)\bbearer\s+[a-z0-9._~+/=-]{12,}"),
    ("api_key", r"\b(?:sk|pig)_[A-Za-z0-9_-]{16,}\b"),
    ("pem_block", r"-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----"),
    ("password", r"(?i)\b(password|passwd|pwd)\s*[:=]\s*[^\s,;\"'{}\[\]]+"),
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ("ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
    ("credit_card", r"\b(?:\d[ -]*?){13,19}\b"),
)


class Redactor:
    def __init__(self, config: RedactionConfig) -> None:
        self.enabled = config.enabled
        rules = [(name, pattern, "[REDACTED]") for name, pattern in DEFAULT_RULES]
        rules.extend((rule.name, rule.pattern, rule.replacement) for rule in config.rules)
        self._rules = tuple((name, re.compile(pattern, re.DOTALL), replacement) for name, pattern, replacement in rules)

    def text(self, value: str) -> str:
        if not self.enabled or not value:
            return value
        redacted = value
        for _, pattern, replacement in self._rules:
            redacted = pattern.sub(replacement, redacted)
        return redacted

    def bytes(self, value: bytes) -> bytes:
        if not self.enabled or not value:
            return value
        try:
            decoded = value.decode("utf-8")
        except UnicodeDecodeError:
            return value
        return self.text(decoded).encode("utf-8")
