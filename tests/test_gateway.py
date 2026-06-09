from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import base64
import hashlib
import hmac
import http.client
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest

from gateway.auth import APIKeyStore, JWTVerifier, issue_api_key, rotate_api_key, update_api_key
from gateway.config import parse_config
from gateway.logging import GatewayLogger, LoggerOptions
from gateway.metrics import MetricsRegistry
from gateway.redaction import Redactor
from gateway.server import make_handler
from gateway.tracing import filter_trace_attributes


class StubBackendHandler(BaseHTTPRequestHandler):
    received_headers: dict[str, str] = {}
    received_path = ""

    def do_POST(self) -> None:
        StubBackendHandler.received_path = self.path
        StubBackendHandler.received_headers = {key: value for key, value in self.headers.items()}
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        payload = json.loads(body.decode("utf-8"))
        response = {
            "id": "chatcmpl-test",
            "object": "chat.completion",
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            "usage": {"prompt_tokens": 3, "completion_tokens": 1, "total_tokens": 4},
            "model": payload["model"],
        }
        self._write(response)

    def do_GET(self) -> None:
        StubBackendHandler.received_path = self.path
        response = {"object": "list", "data": [{"id": "test-model", "object": "model"}]}
        self._write(response)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _write(self, payload: dict[str, object]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class GatewayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.backend = ThreadingHTTPServer(("127.0.0.1", 0), StubBackendHandler)
        cls.backend_thread = threading.Thread(target=cls.backend.serve_forever, daemon=True)
        cls.backend_thread.start()

        cls.config_raw = {
            "server": {"host": "127.0.0.1", "port": 0, "tls": {"enabled": False}},
            "auth": {
                "api_keys": [
                    {
                        "id": "test-key",
                        "tenant": "test-tenant",
                        "key": "test-secret",
                        "allowed_models": ["test-model"],
                    }
                ]
            },
            "routes": [
                {
                    "name": "stub-backend",
                    "backend": f"http://127.0.0.1:{cls.backend.server_port}",
                    "models": ["test-model"],
                    "allowed_endpoints": [
                        {"path": "/v1/chat/completions", "methods": ["POST"]},
                        {"path": "/v1/models", "methods": ["GET"]},
                    ],
                }
            ],
            "privacy": {"access_log": "metadata"},
            "limits": {"max_request_body_bytes": 10000, "max_output_tokens": 64, "max_n": 2, "timeout_seconds": 5},
        }
        cls.gateway_log = io.StringIO()
        cls.logger = GatewayLogger(LoggerOptions(color=True, stream=cls.gateway_log))
        cls.gateway = cls._make_server("metadata", cls.logger)
        cls.gateway_thread = threading.Thread(target=cls.gateway.serve_forever, daemon=True)
        cls.gateway_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.gateway.shutdown()
        cls.backend.shutdown()
        cls.gateway.server_close()
        cls.backend.server_close()
        cls.logger.close()

    @classmethod
    def make_config(cls, access_log: str):
        raw = dict(cls.config_raw)
        raw["privacy"] = {"access_log": access_log}
        return parse_config(raw)

    @classmethod
    def _make_server(cls, access_log: str, logger: GatewayLogger) -> ThreadingHTTPServer:
        return ThreadingHTTPServer(("127.0.0.1", 0), make_handler(cls.make_config(access_log), logger))

    def make_gateway(self, access_log: str, stream: io.StringIO):
        logger = GatewayLogger(LoggerOptions(color=False, stream=stream))
        server = self._make_server(access_log, logger)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, logger

    def request_to_port(
        self,
        port: int,
        method: str,
        path: str,
        body: dict[str, object] | None = None,
        key: str | None = "test-secret",
    ):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        encoded = json.dumps(body).encode("utf-8") if body is not None else None
        conn.request(method, path, body=encoded, headers=headers)
        response = conn.getresponse()
        response_body = response.read()
        conn.close()
        return response.status, response_body, dict(response.getheaders())

    def request(self, method: str, path: str, body: dict[str, object] | None = None, key: str | None = "test-secret"):
        return self.request_to_port(self.gateway.server_port, method, path, body, key)

    def test_config_accepts_access_log_modes(self) -> None:
        for mode in ("off", "metadata", "all"):
            self.assertEqual(self.make_config(mode).privacy.access_log, mode)

    def test_config_accepts_phase2_tls_and_limit_fields(self) -> None:
        raw = dict(self.config_raw)
        raw["server"] = {
            "host": "127.0.0.1",
            "port": 0,
            "tls": {
                "enabled": True,
                "cert_file": "certs/server.crt",
                "key_file": "certs/server.key",
                "client_ca_file": "certs/dev-ca.crt",
                "require_client_cert": True,
            },
        }
        raw["routes"] = [
            {
                **self.config_raw["routes"][0],
                "backend": "https://127.0.0.1:443",
                "tls_ca_file": "certs/dev-ca.crt",
                "tls_cert_file": "certs/client.crt",
                "tls_key_file": "certs/client.key",
            }
        ]
        raw["limits"] = {**self.config_raw["limits"], "per_tenant_requests_per_minute": 60, "per_tenant_requests_per_day": 1000}

        config = parse_config(raw)

        self.assertTrue(config.server.tls.require_client_cert)
        self.assertEqual(config.routes[0].tls_cert_file, "certs/client.crt")
        self.assertEqual(config.limits.per_tenant_requests_per_minute, 60)

    def test_config_rejects_unknown_access_log_mode(self) -> None:
        raw = dict(self.config_raw)
        raw["privacy"] = {"access_log": "verbose"}
        with self.assertRaises(ValueError):
            parse_config(raw)

    def test_proxies_allowed_openai_request(self) -> None:
        status, body, headers = self.request(
            "POST",
            "/v1/chat/completions",
            {"model": "test-model", "messages": [{"role": "user", "content": "secret prompt"}], "max_tokens": 8},
        )

        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["model"], "test-model")
        self.assertEqual(StubBackendHandler.received_path, "/v1/chat/completions")
        self.assertIn("X-Request-Id", headers)

    def test_rejects_missing_api_key_before_forwarding(self) -> None:
        status, body, _ = self.request(
            "POST",
            "/v1/chat/completions",
            {"model": "test-model", "messages": []},
            key=None,
        )

        self.assertEqual(status, 401)
        self.assertIn("invalid API key", body.decode("utf-8"))

    def test_allows_models_endpoint_without_body_model(self) -> None:
        status, body, _ = self.request("GET", "/v1/models")

        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["data"][0]["id"], "test-model")

    def test_rejects_non_allowlisted_endpoint(self) -> None:
        status, body, _ = self.request(
            "POST",
            "/v1/internal",
            {"model": "test-model", "messages": []},
        )

        self.assertEqual(status, 403)
        self.assertIn("endpoint is not allowed", body.decode("utf-8"))

    def test_rejects_expensive_generation_parameters(self) -> None:
        status, body, _ = self.request(
            "POST",
            "/v1/chat/completions",
            {"model": "test-model", "messages": [], "max_tokens": 999},
        )

        self.assertEqual(status, 400)
        self.assertIn("max_tokens exceeds", body.decode("utf-8"))

    def test_does_not_forward_client_authorization_header(self) -> None:
        self.request(
            "POST",
            "/v1/chat/completions",
            {"model": "test-model", "messages": []},
        )

        self.assertNotIn("Authorization", StubBackendHandler.received_headers)

    def test_metadata_access_log_excludes_bodies_and_secrets(self) -> None:
        self.request(
            "POST",
            "/v1/chat/completions",
            {"model": "test-model", "messages": [{"role": "user", "content": "do-not-log-this"}]},
        )

        log_output = self.gateway_log.getvalue()
        self.assertIn("test-tenant", log_output)
        self.assertIn("stub-backend", log_output)
        self.assertNotIn("do-not-log-this", log_output)
        self.assertNotIn("test-secret", log_output)
        self.assertIn("\033[", log_output)

    def test_access_log_off_suppresses_access_output(self) -> None:
        stream = io.StringIO()
        server, logger = self.make_gateway("off", stream)
        try:
            self.request_to_port(
                server.server_port,
                "POST",
                "/v1/chat/completions",
                {"model": "test-model", "messages": [{"role": "user", "content": "off-mode-secret"}]},
            )
        finally:
            server.shutdown()
            server.server_close()
            logger.close()

        self.assertEqual(stream.getvalue(), "")

    def test_access_log_all_includes_request_and_response_bodies(self) -> None:
        stream = io.StringIO()
        server, logger = self.make_gateway("all", stream)
        try:
            self.request_to_port(
                server.server_port,
                "POST",
                "/v1/chat/completions",
                {"model": "test-model", "messages": [{"role": "user", "content": "all-mode-body"}]},
            )
        finally:
            server.shutdown()
            server.server_close()
            logger.close()

        log_output = stream.getvalue()
        self.assertIn("request_body=", log_output)
        self.assertIn("response_body=", log_output)
        self.assertIn("all-mode-body", log_output)
        self.assertIn('"content": "ok"', log_output)

    def test_file_logs_are_metadata_json_without_color(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gateway.log"
            logger = GatewayLogger(LoggerOptions(color=True, file_path=str(path), stream=io.StringIO()))
            logger.access(
                request_id="req_test",
                tenant="team-a",
                route="/v1/chat/completions",
                backend="stub",
                model="test-model",
                status=200,
                latency_ms=12,
            )
            logger.close()

            line = path.read_text(encoding="utf-8").strip()
            self.assertEqual(json.loads(line)["request_id"], "req_test")
            self.assertNotIn("\033[", line)

    def test_file_log_all_writes_body_json_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gateway.log"
            logger = GatewayLogger(LoggerOptions(color=True, file_path=str(path), stream=io.StringIO()))
            logger.access(
                request_id="req_test",
                tenant="team-a",
                route="/v1/chat/completions",
                backend="stub",
                model="test-model",
                status=200,
                latency_ms=12,
                request_body='{"messages":["debug"]}',
                response_body='{"choices":[]}',
            )
            logger.close()

            event = json.loads(path.read_text(encoding="utf-8").strip())
            self.assertEqual(event["request_body"], '{"messages":["debug"]}')
            self.assertEqual(event["response_body"], '{"choices":[]}')

    def test_dynamic_api_keys_are_hashed_reloaded_revoked_and_rotated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "keys.json"
            first = issue_api_key(path, key_id="dynamic-a", tenant="tenant-a", allowed_models=("test-model",))

            raw = path.read_text(encoding="utf-8")
            self.assertNotIn(first, raw)
            self.assertIn("pbkdf2_sha256", raw)

            config = parse_config({**self.config_raw, "auth": {"api_key_file": str(path)}})
            store = APIKeyStore(config.auth)
            principal = store.authenticate(first)
            self.assertIsNotNone(principal)
            self.assertEqual(principal.tenant, "tenant-a")

            update_api_key(path, key_id="dynamic-a", revoked=True)
            self.assertIsNone(store.authenticate(first))

            second = rotate_api_key(path, key_id="dynamic-a")
            self.assertNotEqual(first, second)
            self.assertIsNotNone(store.authenticate(second))

    def test_admin_api_key_path_updates_keys_without_restart(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            key_file = str(Path(tmp) / "keys.json")
            os.environ["TEST_GATEWAY_ADMIN_KEY"] = "admin-secret"
            raw = {
                **self.config_raw,
                "auth": {
                    "api_key_file": key_file,
                    "admin_api_key_env": "TEST_GATEWAY_ADMIN_KEY",
                },
            }
            logger = GatewayLogger(LoggerOptions(color=False, stream=io.StringIO()))
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(parse_config(raw), logger))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                status, body, _ = self.request_to_port(
                    server.server_port,
                    "POST",
                    "/admin/api-keys",
                    {"action": "issue", "id": "dynamic-a", "tenant": "tenant-a", "allowed_models": ["test-model"]},
                    key="admin-secret",
                )
                issued = json.loads(body)["key"]
                self.assertEqual(status, 201)
                self.assertNotIn(issued, Path(key_file).read_text(encoding="utf-8"))

                status, _, _ = self.request_to_port(
                    server.server_port,
                    "POST",
                    "/v1/chat/completions",
                    {"model": "test-model", "messages": []},
                    key=issued,
                )
                self.assertEqual(status, 200)

                status, _, _ = self.request_to_port(
                    server.server_port,
                    "POST",
                    "/admin/api-keys",
                    {"action": "revoke", "id": "dynamic-a"},
                    key="admin-secret",
                )
                self.assertEqual(status, 200)
                status, _, _ = self.request_to_port(
                    server.server_port,
                    "POST",
                    "/v1/chat/completions",
                    {"model": "test-model", "messages": []},
                    key=issued,
                )
                self.assertEqual(status, 401)
            finally:
                server.shutdown()
                server.server_close()
                logger.close()
                os.environ.pop("TEST_GATEWAY_ADMIN_KEY", None)

    def test_invalid_dynamic_key_file_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "keys.json"
            key = issue_api_key(path, key_id="dynamic-a", tenant="tenant-a")
            config = parse_config({**self.config_raw, "auth": {"api_key_file": str(path)}})
            store = APIKeyStore(config.auth)
            self.assertIsNotNone(store.authenticate(key))

            path.write_text('{"api_keys":[{"id":"broken"}]}\n', encoding="utf-8")
            self.assertIsNone(store.authenticate(key))

    def test_jwt_validation_rejects_wrong_issuer_audience_expiry_and_unknown_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            secret = b"jwt-test-secret"
            jwks = Path(tmp) / "jwks.json"
            jwks.write_text(json.dumps({"keys": [{"kty": "oct", "kid": "kid-a", "k": _b64(secret)}]}), encoding="utf-8")
            config = parse_config(
                {
                    **self.config_raw,
                    "auth": {
                        "jwt": {
                            "enabled": True,
                            "issuer": "issuer-a",
                            "audience": "gateway",
                            "jwks_file": str(jwks),
                        }
                    },
                }
            )
            verifier = JWTVerifier(config.auth.jwt)
            valid = _jwt(secret, "kid-a", {"iss": "issuer-a", "aud": "gateway", "exp": int(time.time()) + 60, "tenant": "team-a"})
            self.assertEqual(verifier.verify(valid).tenant, "team-a")  # type: ignore[union-attr]

            wrong_issuer = _jwt(secret, "kid-a", {"iss": "issuer-b", "aud": "gateway", "exp": int(time.time()) + 60, "tenant": "team-a"})
            wrong_audience = _jwt(secret, "kid-a", {"iss": "issuer-a", "aud": "other", "exp": int(time.time()) + 60, "tenant": "team-a"})
            expired = _jwt(secret, "kid-a", {"iss": "issuer-a", "aud": "gateway", "exp": int(time.time()) - 1, "tenant": "team-a"})
            unknown_key = _jwt(secret, "kid-b", {"iss": "issuer-a", "aud": "gateway", "exp": int(time.time()) + 60, "tenant": "team-a"})

            self.assertIsNone(verifier.verify(wrong_issuer))
            self.assertIsNone(verifier.verify(wrong_audience))
            self.assertIsNone(verifier.verify(expired))
            self.assertIsNone(verifier.verify(unknown_key))

    def test_redaction_removes_sensitive_patterns_from_logs_and_forwarding_text(self) -> None:
        config = parse_config(
            {
                **self.config_raw,
                "redaction": {"rules": [{"name": "internal", "pattern": "project-[0-9]+", "replacement": "[PROJECT]"}]},
            }
        )
        redactor = Redactor(config.redaction)
        text = "Bearer sk_abcdefghijklmnopqrstuvwxyz password=secret user@example.com 4111-1111-1111-1111 project-123"

        redacted = redactor.text(text)

        self.assertNotIn("sk_abcdefghijklmnopqrstuvwxyz", redacted)
        self.assertNotIn("password=secret", redacted)
        self.assertNotIn("user@example.com", redacted)
        self.assertNotIn("4111-1111-1111-1111", redacted)
        self.assertIn("[PROJECT]", redacted)

    def test_trace_filter_removes_prompt_completion_and_auth_attributes(self) -> None:
        redactor = Redactor(parse_config(self.config_raw).redaction)

        filtered = filter_trace_attributes(
            {
                "request_body": '{"prompt":"secret"}',
                "authorization": "Bearer sk_abcdefghijklmnopqrstuvwxyz",
                "model": "test-model",
                "email": "user@example.com",
            },
            redactor,
        )

        self.assertEqual(filtered["request_body"], "[REDACTED]")
        self.assertEqual(filtered["authorization"], "[REDACTED]")
        self.assertEqual(filtered["model"], "test-model")
        self.assertEqual(filtered["email"], "[REDACTED]")

    def test_metrics_use_fixed_low_cardinality_labels(self) -> None:
        metrics = MetricsRegistry()
        metrics.observe(route="/v1/chat/completions?prompt=secret", backend="stub backend/1", status=200, latency_ms=7)

        output = metrics.prometheus().decode("utf-8")

        self.assertIn('route="other"', output)
        self.assertIn('backend="stub_backend_1"', output)
        self.assertIn('status_family="2xx"', output)
        self.assertNotIn("prompt=secret", output)

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwt(secret: bytes, kid: str, claims: dict[str, object]) -> str:
    header = _b64(json.dumps({"alg": "HS256", "kid": kid}, separators=(",", ":")).encode("utf-8"))
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = _b64(hmac.new(secret, signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


if __name__ == "__main__":
    unittest.main()
