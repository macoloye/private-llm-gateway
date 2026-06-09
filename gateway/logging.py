from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import sys
from typing import Any, TextIO


RESET = "\033[0m"
BOLD = "\033[1m"
BLUE = "\033[34m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
DIM = "\033[2m"


@dataclass(frozen=True)
class LoggerOptions:
    color: bool = True
    file_path: str | None = None
    stream: TextIO = sys.stdout


class GatewayLogger:
    def __init__(self, options: LoggerOptions | None = None) -> None:
        self.options = options or LoggerOptions()
        self._file: TextIO | None = None
        if self.options.file_path:
            path = Path(self.options.file_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            self._file = path.open("a", encoding="utf-8")

    def close(self) -> None:
        if self._file:
            self._file.close()
            self._file = None

    def info(self, message: str) -> None:
        self._write_terminal(f"{self._tag('INFO', BLUE)} {message}")

    def error(self, message: str) -> None:
        self._write_terminal(f"{self._tag('ERROR', RED)} {message}", stream=sys.stderr)

    def access(self, **fields: Any) -> None:
        clean = {key: value for key, value in fields.items() if value is not None}
        if self._file:
            self._file.write(json.dumps(clean, separators=(",", ":")) + "\n")
            self._file.flush()
        self._write_terminal(self._format_access(clean))

    def access_off(self) -> None:
        return

    def _format_access(self, fields: dict[str, Any]) -> str:
        status = int(fields.get("status", 0))
        color = GREEN if status < 400 else YELLOW if status < 500 else RED
        status_text = self._paint(str(status), color)
        request_id = self._paint(str(fields.get("request_id", "-")), CYAN)
        tenant = fields.get("tenant", "-")
        route = fields.get("route", "-")
        backend = fields.get("backend", "-")
        latency = fields.get("latency_ms", "-")
        model = fields.get("model", "-")
        privacy_class = fields.get("privacy_class", "-")
        tokens = ""
        if "input_tokens" in fields or "output_tokens" in fields:
            tokens = f" tokens={fields.get('input_tokens', '-')}/{fields.get('output_tokens', '-')}"
        body_fields = ""
        if "request_body" in fields or "response_body" in fields:
            body_fields = f" request_body={fields.get('request_body', '')} response_body={fields.get('response_body', '')}"
        return (
            f"{self._tag('ACCESS', BLUE)} {status_text} "
            f"id={request_id} tenant={tenant} route={route} "
            f"backend={backend} model={model} privacy_class={privacy_class} latency={latency}ms{tokens}{body_fields}"
        )

    def _tag(self, value: str, color: str) -> str:
        return self._paint(f"[{value}]", color, bold=True)

    def _paint(self, value: str, color: str, *, bold: bool = False) -> str:
        if not self.options.color:
            return value
        prefix = f"{BOLD if bold else ''}{color}"
        return f"{prefix}{value}{RESET}"

    def _write_terminal(self, message: str, *, stream: TextIO | None = None) -> None:
        target = stream or self.options.stream
        target.write(message + "\n")
        target.flush()


def color_enabled(mode: str, stream: TextIO = sys.stdout) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    return stream.isatty()
