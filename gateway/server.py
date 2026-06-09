from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
import secrets
import ssl
import time
from typing import Any
from urllib.parse import urlparse

from gateway.config import APIKey, GatewayConfig, RouteConfig
from gateway.logging import GatewayLogger, LoggerOptions, color_enabled

SENSITIVE_REQUEST_HEADERS = {
    "authorization",
    "cookie",
    "x-api-key",
    "proxy-authorization",
}

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def run_gateway(config: GatewayConfig, logger: GatewayLogger | None = None) -> None:
    logger = logger or GatewayLogger(
        LoggerOptions(
            color=color_enabled(config.logging.color),
            file_path=config.logging.file,
        )
    )
    handler = make_handler(config, logger)
    server = ThreadingHTTPServer((config.server.host, config.server.port), handler)
    if config.server.tls.enabled:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(config.server.tls.cert_file, config.server.tls.key_file)
        server.socket = context.wrap_socket(server.socket, server_side=True)

    scheme = "https" if config.server.tls.enabled else "http"
    logger.info(f"private-inference-gateway listening on {scheme}://{config.server.host}:{config.server.port}")
    if config.logging.file:
        logger.info(f"metadata access log file: {config.logging.file}")
    try:
        server.serve_forever()
    finally:
        logger.close()


def make_handler(config: GatewayConfig, logger: GatewayLogger | None = None) -> type[BaseHTTPRequestHandler]:
    logger = logger or GatewayLogger(LoggerOptions(color=False))

    class GatewayHandler(BaseHTTPRequestHandler):
        server_version = "PrivateInferenceGateway/0.1"

        def do_GET(self) -> None:
            self._handle()

        def do_POST(self) -> None:
            self._handle()

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _handle(self) -> None:
            started = time.monotonic()
            request_id = self.headers.get("X-Request-Id") or f"req_{secrets.token_hex(12)}"
            tenant = "-"
            backend_name = "-"
            model = "-"
            status = HTTPStatus.INTERNAL_SERVER_ERROR
            input_tokens = None
            output_tokens = None
            body: bytes = b""
            response_body: bytes | None = None

            try:
                if self.path == "/healthz" and self.command == "GET":
                    status = HTTPStatus.OK
                    self._write_json(status, {"status": "ok", "request_id": request_id}, request_id)
                    return

                body = self._read_body()
                payload = self._parse_json_body(body)
                model = str(payload.get("model", ""))

                route = self._select_route(model)
                backend_name = route.name

                if not self._is_endpoint_allowed(route):
                    status = HTTPStatus.FORBIDDEN
                    self._write_json(status, {"error": {"message": "endpoint is not allowed"}}, request_id)
                    return

                api_key = self._authenticate()
                if api_key is None:
                    status = HTTPStatus.UNAUTHORIZED
                    self._write_json(status, {"error": {"message": "missing or invalid API key"}}, request_id)
                    return
                tenant = api_key.tenant

                if model and api_key.allowed_models and model not in api_key.allowed_models:
                    status = HTTPStatus.FORBIDDEN
                    self._write_json(status, {"error": {"message": "model is not allowed for tenant"}}, request_id)
                    return

                limit_error = self._validate_limits(payload, len(body))
                if limit_error:
                    status = HTTPStatus.BAD_REQUEST
                    self._write_json(status, {"error": {"message": limit_error}}, request_id)
                    return

                response_status, response_headers, response_body = self._forward(route, body, request_id)
                status = HTTPStatus(response_status)
                input_tokens, output_tokens = _usage_from_response(response_body)
                self._write_backend_response(response_status, response_headers, response_body, request_id)
            except PayloadTooLarge:
                status = HTTPStatus.REQUEST_ENTITY_TOO_LARGE
                self._write_json(status, {"error": {"message": "request body is too large"}}, request_id)
            except BadJSON:
                status = HTTPStatus.BAD_REQUEST
                self._write_json(status, {"error": {"message": "request body must be JSON"}}, request_id)
            except NoRoute:
                status = HTTPStatus.BAD_REQUEST
                self._write_json(status, {"error": {"message": "no backend route for requested model"}}, request_id)
            except TimeoutError:
                status = HTTPStatus.GATEWAY_TIMEOUT
                self._write_json(status, {"error": {"message": "backend request timed out"}}, request_id)
            except OSError:
                status = HTTPStatus.BAD_GATEWAY
                self._write_json(status, {"error": {"message": "backend request failed"}}, request_id)
            finally:
                latency_ms = round((time.monotonic() - started) * 1000)
                if config.privacy.access_log != "off":
                    fields = {
                        "request_id": request_id,
                        "tenant": tenant,
                        "route": self.path,
                        "backend": backend_name,
                        "model": model,
                        "status": int(status),
                        "latency_ms": latency_ms,
                        "input_tokens": input_tokens,
                        "output_tokens": output_tokens,
                    }
                    if config.privacy.access_log == "all":
                        fields["request_body"] = _safe_body_text(body)
                        fields["response_body"] = _safe_body_text(response_body or b"")
                    logger.access(**fields)

        def _read_body(self) -> bytes:
            content_length = int(self.headers.get("Content-Length", "0") or "0")
            if content_length > config.limits.max_request_body_bytes:
                raise PayloadTooLarge
            return self.rfile.read(content_length)

        def _parse_json_body(self, body: bytes) -> dict[str, Any]:
            if self.command == "GET":
                return {}
            try:
                parsed = json.loads(body.decode("utf-8") if body else "{}")
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BadJSON from exc
            if not isinstance(parsed, dict):
                raise BadJSON
            return parsed

        def _select_route(self, model: str) -> RouteConfig:
            if self.command == "GET" and self.path == "/v1/models":
                return config.routes[0]
            for route in config.routes:
                if model in route.models:
                    return route
            raise NoRoute

        def _is_endpoint_allowed(self, route: RouteConfig) -> bool:
            path = urlparse(self.path).path
            return any(endpoint.path == path and self.command in endpoint.methods for endpoint in route.allowed_endpoints)

        def _authenticate(self) -> APIKey | None:
            supplied = _extract_api_key(self.headers.get("Authorization"), self.headers.get("X-Api-Key"))
            if not supplied:
                return None
            for api_key in config.auth.api_keys:
                if secrets.compare_digest(supplied, api_key.secret):
                    return api_key
            return None

        def _validate_limits(self, payload: dict[str, Any], body_size: int) -> str | None:
            if body_size > config.limits.max_request_body_bytes:
                return "request body is too large"
            max_tokens = payload.get("max_tokens")
            if max_tokens is not None and _as_int(max_tokens) > config.limits.max_output_tokens:
                return "max_tokens exceeds configured limit"
            n = payload.get("n")
            if n is not None and _as_int(n) > config.limits.max_n:
                return "n exceeds configured limit"
            return None

        def _forward(self, route: RouteConfig, body: bytes, request_id: str) -> tuple[int, dict[str, str], bytes]:
            parsed = urlparse(route.backend)
            connection_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
            port = parsed.port
            connection = connection_cls(parsed.hostname, port, timeout=config.limits.timeout_seconds)
            path = _join_backend_path(parsed.path, self.path)
            headers = _forward_headers(self.headers, request_id)
            if route.backend_api_key_env:
                backend_key = os.environ.get(route.backend_api_key_env)
                if backend_key:
                    headers["Authorization"] = f"Bearer {backend_key}"
            connection.request(self.command, path, body=body if self.command != "GET" else None, headers=headers)
            response = connection.getresponse()
            response_body = response.read()
            response_headers = {key: value for key, value in response.getheaders()}
            connection.close()
            return response.status, response_headers, response_body

        def _write_json(self, status: int | HTTPStatus, payload: dict[str, Any], request_id: str) -> None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(int(status))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Request-Id", request_id)
            self.end_headers()
            self.wfile.write(body)

        def _write_backend_response(
            self,
            status: int,
            response_headers: dict[str, str],
            response_body: bytes,
            request_id: str,
        ) -> None:
            self.send_response(status)
            for key, value in response_headers.items():
                lower = key.lower()
                if lower in HOP_BY_HOP_HEADERS or lower in {"content-length", "server", "date"}:
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("X-Request-Id", request_id)
            self.end_headers()
            self.wfile.write(response_body)

    return GatewayHandler


class PayloadTooLarge(Exception):
    pass


class BadJSON(Exception):
    pass


class NoRoute(Exception):
    pass


def _extract_api_key(authorization: str | None, x_api_key: str | None) -> str | None:
    if authorization:
        parts = authorization.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1]
    if x_api_key:
        return x_api_key.strip()
    return None


def _forward_headers(headers: Any, request_id: str) -> dict[str, str]:
    forwarded: dict[str, str] = {
        "X-Request-Id": request_id,
        "Content-Type": headers.get("Content-Type", "application/json"),
    }
    for key, value in headers.items():
        lower = key.lower()
        if lower in SENSITIVE_REQUEST_HEADERS or lower in HOP_BY_HOP_HEADERS:
            continue
        if lower in {"host", "content-length"}:
            continue
        forwarded[key] = value
    return forwarded


def _join_backend_path(base_path: str, request_path: str) -> str:
    base = base_path.rstrip("/")
    if not base:
        return request_path
    return f"{base}{request_path}"


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _usage_from_response(body: bytes) -> tuple[int | None, int | None]:
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, None
    if not isinstance(payload, dict):
        return None, None
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        return None, None
    prompt = usage.get("prompt_tokens")
    completion = usage.get("completion_tokens")
    return (_as_int(prompt) if prompt is not None else None, _as_int(completion) if completion is not None else None)


def _safe_body_text(body: bytes) -> str:
    if not body:
        return ""
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return f"<{len(body)} binary bytes>"
