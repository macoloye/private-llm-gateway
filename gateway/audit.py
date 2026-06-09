from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


class AuditLogger:
    def __init__(self, path: str | None, retention_days: int) -> None:
        self._path = Path(path) if path else None
        self._retention_days = retention_days
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._prune_if_expired()

    def write(self, **fields: Any) -> None:
        if not self._path:
            return
        clean = {
            key: value
            for key, value in fields.items()
            if value is not None and key not in {"request_body", "response_body", "prompt", "completion"}
        }
        clean["timestamp"] = int(time.time())
        with self._path.open("a", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(clean, separators=(",", ":")) + "\n")

    def _prune_if_expired(self) -> None:
        if not self._path or not self._path.exists():
            return
        max_age = self._retention_days * 24 * 60 * 60
        if max_age <= 0:
            return
        age = time.time() - self._path.stat().st_mtime
        if age > max_age:
            self._path.write_text("", encoding="utf-8")
