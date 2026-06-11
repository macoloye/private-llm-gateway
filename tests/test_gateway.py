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
from gateway.__main__ import main as gateway_main
from gateway.config import parse_config
from gateway.logging import GatewayLogger, LoggerOptions
from gateway.metrics import MetricsRegistry
from gateway.redaction import Redactor
from gateway.server import make_handler
from gateway.tracing import filter_trace_attributes


class StubBackendHandler(BaseHTTPRequestHandler):
    received_headers: dict[str, str] = {}
    received_path = ""
    received_body = ""

    def do_POST(self) -> None:
        StubBackendHandler.received_path = self.path
        StubBackendHandler.received_headers = {key: value for key, value in self.headers.items()}
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        StubBackendHandler.received_body = body.decode("utf-8")
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


class SlowBackendHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        time.sleep(2)
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


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
        extra_headers: dict[str, str] | None = None,
    ):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        if extra_headers:
            headers.update(extra_headers)
        encoded = json.dumps(body).encode("utf-8") if body is not None else None
        conn.request(method, path, body=encoded, headers=headers)
        response = conn.getresponse()
        response_body = response.read()
        conn.close()
        return response.status, response_body, dict(response.getheaders())

    def request(self, method: str, path: str, body: dict[str, object] | None = None, key: str | None = "test-secret"):
        return self.request_to_port(self.gateway.server_port, method, path, body, key)

    def policy_config_raw(self) -> dict[str, object]:
        return {
            **self.config_raw,
            "routes": [
                {
                    **self.config_raw["routes"][0],
                    "name": "external-openai",
                    "backend": f"http://127.0.0.1:{self.backend.server_port}/external",
                    "models": ["test-model"],
                    "local": False,
                },
                {
                    **self.config_raw["routes"][0],
                    "name": "local-vllm",
                    "backend": f"http://127.0.0.1:{self.backend.server_port}/local",
                    "models": ["test-model"],
                    "local": True,
                },
            ],
            "policy": {
                "default_privacy_class": "standard",
                "tenants": [
                    {
                        "tenant": "test-tenant",
                        "allowed_models": ["test-model"],
                        "allowed_backends": ["external-openai", "local-vllm"],
                        "privacy_classes": ["standard", "sensitive", "restricted"],
                    }
                ],
                "routing_rules": [
                    {
                        "tenant": "test-tenant",
                        "model": "test-model",
                        "privacy_class": "standard",
                        "backend": "external-openai",
                    },
                    {
                        "tenant": "test-tenant",
                        "model": "test-model",
                        "privacy_class": "sensitive",
                        "backend": "local-vllm",
                        "redact_before_forward": True,
                    },
                    {
                        "tenant": "test-tenant",
                        "model": "test-model",
                        "privacy_class": "restricted",
                        "backend": "local-vllm",
                    },
                ],
            },
        }

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

    def test_config_rejects_incomplete_tls_and_accepts_oidc_hooks(self) -> None:
        raw = dict(self.config_raw)
        raw["server"] = {"tls": {"enabled": True, "cert_file": "certs/server.crt"}}
        with self.assertRaisesRegex(ValueError, "cert_file and server.tls.key_file"):
            parse_config(raw)

        raw = {
            **self.config_raw,
            "auth": {
                **self.config_raw["auth"],
                "oidc": {
                    "enabled": True,
                    "discovery_url": "https://issuer.example.invalid/.well-known/openid-configuration",
                    "client_id": "gateway",
                },
            },
        }
        config = parse_config(raw)
        self.assertTrue(config.auth.oidc.enabled)
        self.assertEqual(config.auth.oidc.client_id, "gateway")

    def test_config_reports_unset_api_key_env(self) -> None:
        raw = dict(self.config_raw)
        raw["auth"] = {
            "api_keys": [
                {
                    "id": "team-a",
                    "tenant": "team-a",
                    "key_env": "TEST_TEAM_A_API_KEY_UNSET",
                }
            ]
        }
        with self.assertRaisesRegex(ValueError, "auth.api_keys\\[team-a\\].key_env TEST_TEAM_A_API_KEY_UNSET is not set"):
            parse_config(raw)

    def test_config_rejects_unknown_access_log_mode(self) -> None:
        raw = dict(self.config_raw)
        raw["privacy"] = {"access_log": "verbose"}
        with self.assertRaises(ValueError):
            parse_config(raw)

    def test_policy_routes_by_tenant_model_and_privacy_class(self) -> None:
        stream = io.StringIO()
        logger = GatewayLogger(LoggerOptions(color=False, stream=stream))
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(parse_config(self.policy_config_raw()), logger))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, _, _ = self.request_to_port(
                server.server_port,
                "POST",
                "/v1/chat/completions",
                {"model": "test-model", "messages": []},
            )
            self.assertEqual(status, 200)
            self.assertEqual(StubBackendHandler.received_path, "/external/v1/chat/completions")

            status, _, _ = self.request_to_port(
                server.server_port,
                "POST",
                "/v1/chat/completions",
                {"model": "test-model", "messages": [], "privacy_class": "restricted"},
            )
            self.assertEqual(status, 200)
            self.assertEqual(StubBackendHandler.received_path, "/local/v1/chat/completions")
            self.assertIn("privacy_class=restricted", stream.getvalue())
        finally:
            server.shutdown()
            server.server_close()
            logger.close()

    def test_policy_redacts_sensitive_requests_before_forwarding(self) -> None:
        logger = GatewayLogger(LoggerOptions(color=False, stream=io.StringIO()))
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(parse_config(self.policy_config_raw()), logger))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, _, _ = self.request_to_port(
                server.server_port,
                "POST",
                "/v1/chat/completions",
                {
                    "model": "test-model",
                    "privacy_class": "sensitive",
                    "messages": [
                        {
                            "role": "user",
                            "content": "email user@example.com password=secret",
                        }
                    ],
                },
            )
            self.assertEqual(status, 200)
            self.assertEqual(StubBackendHandler.received_path, "/local/v1/chat/completions")
            self.assertNotIn("user@example.com", StubBackendHandler.received_body)
            self.assertNotIn("password=secret", StubBackendHandler.received_body)
            self.assertIn("[REDACTED]", StubBackendHandler.received_body)
        finally:
            server.shutdown()
            server.server_close()
            logger.close()

    def test_policy_rejects_restricted_external_route(self) -> None:
        raw = self.policy_config_raw()
        policy = dict(raw["policy"])  # type: ignore[arg-type]
        rules = list(policy["routing_rules"])  # type: ignore[index]
        rules[2] = {**rules[2], "backend": "external-openai"}
        policy["routing_rules"] = rules
        raw["policy"] = policy

        with self.assertRaisesRegex(ValueError, "restricted traffic to external backend|send restricted traffic to external backend"):
            parse_config(raw)

    def test_policy_validation_fails_closed_for_bad_bindings_and_unknowns(self) -> None:
        raw = self.policy_config_raw()
        policy = dict(raw["policy"])  # type: ignore[arg-type]
        tenants = list(policy["tenants"])  # type: ignore[index]
        tenants[0] = {**tenants[0], "tenant": "unknown-tenant"}
        policy["tenants"] = tenants
        raw["policy"] = policy
        with self.assertRaisesRegex(ValueError, "missing tenant auth bindings"):
            parse_config(raw)

        raw = self.policy_config_raw()
        policy = dict(raw["policy"])  # type: ignore[arg-type]
        tenants = list(policy["tenants"])  # type: ignore[index]
        tenants[0] = {**tenants[0], "privacy_classes": ["standard", "classified"]}
        policy["tenants"] = tenants
        raw["policy"] = policy
        with self.assertRaisesRegex(ValueError, "unknown privacy classes"):
            parse_config(raw)

        raw = self.policy_config_raw()
        policy = dict(raw["policy"])  # type: ignore[arg-type]
        rules = list(policy["routing_rules"])  # type: ignore[index]
        rules[0] = {**rules[0], "backend": "missing-backend"}
        policy["routing_rules"] = rules
        raw["policy"] = policy
        with self.assertRaisesRegex(ValueError, "unknown backend name"):
            parse_config(raw)

        raw = self.policy_config_raw()
        policy = dict(raw["policy"])  # type: ignore[arg-type]
        rules = list(policy["routing_rules"])  # type: ignore[index]
        rules[0] = {**rules[0], "model": "missing-model"}
        policy["routing_rules"] = rules
        raw["policy"] = policy
        with self.assertRaisesRegex(ValueError, "impossible policy route rule|outside tenant"):
            parse_config(raw)

    def test_audit_log_is_metadata_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audit_path = Path(tmp) / "audit.log"
            raw = self.policy_config_raw()
            raw["privacy"] = {"access_log": "metadata", "audit_log_file": str(audit_path)}
            logger = GatewayLogger(LoggerOptions(color=False, stream=io.StringIO()))
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(parse_config(raw), logger))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                status, _, _ = self.request_to_port(
                    server.server_port,
                    "POST",
                    "/v1/chat/completions",
                    {"model": "test-model", "messages": [{"role": "user", "content": "audit-secret"}], "privacy_class": "sensitive"},
                )
                self.assertEqual(status, 200)
            finally:
                server.shutdown()
                server.server_close()
                logger.close()

            event = json.loads(audit_path.read_text(encoding="utf-8").strip())
            self.assertEqual(event["tenant"], "test-tenant")
            self.assertEqual(event["privacy_class"], "sensitive")
            self.assertNotIn("audit-secret", audit_path.read_text(encoding="utf-8"))

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

    def test_proxies_all_phase1_openai_endpoints(self) -> None:
        raw = dict(self.config_raw)
        route = dict(self.config_raw["routes"][0])
        route["allowed_endpoints"] = [
            {"path": "/v1/chat/completions", "methods": ["POST"]},
            {"path": "/v1/completions", "methods": ["POST"]},
            {"path": "/v1/embeddings", "methods": ["POST"]},
            {"path": "/v1/models", "methods": ["GET"]},
        ]
        raw["routes"] = [route]
        logger = GatewayLogger(LoggerOptions(color=False, stream=io.StringIO()))
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(parse_config(raw), logger))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for endpoint in ("/v1/chat/completions", "/v1/completions", "/v1/embeddings"):
                status, body, _ = self.request_to_port(server.server_port, "POST", endpoint, {"model": "test-model"})
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body)["model"], "test-model")
                self.assertEqual(StubBackendHandler.received_path, endpoint)

            status, body, _ = self.request_to_port(server.server_port, "GET", "/v1/models")
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["object"], "list")
        finally:
            server.shutdown()
            server.server_close()
            logger.close()

    def test_request_id_is_propagated_downstream_and_back_to_client(self) -> None:
        status, _, headers = self.request_to_port(
            self.gateway.server_port,
            "POST",
            "/v1/chat/completions",
            {"model": "test-model", "messages": []},
            extra_headers={"X-Request-Id": "req_client_supplied"},
        )

        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Request-Id"], "req_client_supplied")
        self.assertEqual(StubBackendHandler.received_headers["X-Request-Id"], "req_client_supplied")

    def test_rejects_missing_api_key_before_forwarding(self) -> None:
        StubBackendHandler.received_path = "not-forwarded"
        status, body, _ = self.request(
            "POST",
            "/v1/chat/completions",
            {"model": "test-model", "messages": []},
            key=None,
        )

        self.assertEqual(status, 401)
        self.assertIn("invalid API key", body.decode("utf-8"))
        self.assertEqual(StubBackendHandler.received_path, "not-forwarded")

    def test_rejects_invalid_api_key_before_forwarding(self) -> None:
        StubBackendHandler.received_path = "not-forwarded"
        status, body, _ = self.request(
            "POST",
            "/v1/chat/completions",
            {"model": "test-model", "messages": []},
            key="wrong-secret",
        )

        self.assertEqual(status, 401)
        self.assertIn("invalid API key", body.decode("utf-8"))
        self.assertEqual(StubBackendHandler.received_path, "not-forwarded")

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

        status, body, _ = self.request(
            "POST",
            "/v1/chat/completions",
            {"model": "test-model", "messages": [], "n": 99},
        )
        self.assertEqual(status, 400)
        self.assertIn("n exceeds", body.decode("utf-8"))

    def test_rejects_oversized_body_before_forwarding(self) -> None:
        StubBackendHandler.received_path = "not-forwarded"
        raw = dict(self.config_raw)
        raw["limits"] = {**self.config_raw["limits"], "max_request_body_bytes": 20}
        logger = GatewayLogger(LoggerOptions(color=False, stream=io.StringIO()))
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(parse_config(raw), logger))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, body, _ = self.request_to_port(
                server.server_port,
                "POST",
                "/v1/chat/completions",
                {"model": "test-model", "messages": [{"role": "user", "content": "large"}]},
            )
            self.assertEqual(status, 413)
            self.assertIn("too large", body.decode("utf-8"))
            self.assertEqual(StubBackendHandler.received_path, "not-forwarded")
        finally:
            server.shutdown()
            server.server_close()
            logger.close()

    def test_backend_timeout_returns_gateway_timeout(self) -> None:
        slow_backend = ThreadingHTTPServer(("127.0.0.1", 0), SlowBackendHandler)
        slow_thread = threading.Thread(target=slow_backend.serve_forever, daemon=True)
        slow_thread.start()
        raw = dict(self.config_raw)
        raw["routes"] = [{**self.config_raw["routes"][0], "backend": f"http://127.0.0.1:{slow_backend.server_port}"}]
        raw["limits"] = {**self.config_raw["limits"], "timeout_seconds": 1}
        logger = GatewayLogger(LoggerOptions(color=False, stream=io.StringIO()))
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(parse_config(raw), logger))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, body, _ = self.request_to_port(
                server.server_port,
                "POST",
                "/v1/chat/completions",
                {"model": "test-model", "messages": []},
            )
            self.assertEqual(status, 504)
            self.assertIn("timed out", body.decode("utf-8"))
        finally:
            server.shutdown()
            slow_backend.shutdown()
            server.server_close()
            slow_backend.server_close()
            logger.close()

    def test_per_tenant_rate_limit_blocks_excess_requests(self) -> None:
        raw = dict(self.config_raw)
        raw["limits"] = {**self.config_raw["limits"], "per_tenant_requests_per_minute": 1}
        logger = GatewayLogger(LoggerOptions(color=False, stream=io.StringIO()))
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(parse_config(raw), logger))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, _, _ = self.request_to_port(server.server_port, "POST", "/v1/chat/completions", {"model": "test-model", "messages": []})
            self.assertEqual(status, 200)

            status, body, _ = self.request_to_port(server.server_port, "POST", "/v1/chat/completions", {"model": "test-model", "messages": []})
            self.assertEqual(status, 429)
            self.assertIn("rate limit", body.decode("utf-8"))
        finally:
            server.shutdown()
            server.server_close()
            logger.close()

    def test_does_not_forward_client_authorization_header(self) -> None:
        self.request(
            "POST",
            "/v1/chat/completions",
            {"model": "test-model", "messages": []},
        )

        self.assertNotIn("Authorization", StubBackendHandler.received_headers)

    def test_backend_api_key_env_is_used_without_leaking_client_key(self) -> None:
        os.environ["TEST_BACKEND_API_KEY"] = "backend-secret"
        raw = dict(self.config_raw)
        raw["routes"] = [{**self.config_raw["routes"][0], "backend_api_key_env": "TEST_BACKEND_API_KEY"}]
        logger = GatewayLogger(LoggerOptions(color=False, stream=io.StringIO()))
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(parse_config(raw), logger))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, _, _ = self.request_to_port(server.server_port, "POST", "/v1/chat/completions", {"model": "test-model", "messages": []})
            self.assertEqual(status, 200)
            self.assertEqual(StubBackendHandler.received_headers["Authorization"], "Bearer backend-secret")
            self.assertNotEqual(StubBackendHandler.received_headers["Authorization"], "Bearer test-secret")
        finally:
            server.shutdown()
            server.server_close()
            logger.close()
            os.environ.pop("TEST_BACKEND_API_KEY", None)

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

    def test_admin_api_key_path_requires_admin_auth_and_post(self) -> None:
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
                status, _, _ = self.request_to_port(server.server_port, "POST", "/admin/api-keys", {"action": "issue"}, key=None)
                self.assertEqual(status, 401)

                status, _, _ = self.request_to_port(server.server_port, "GET", "/admin/api-keys", key="admin-secret")
                self.assertEqual(status, 405)
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

    def test_disabled_jwt_does_not_require_jwks_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing_jwks = Path(tmp) / "missing-jwks.json"
            config = parse_config(
                {
                    **self.config_raw,
                    "auth": {
                        **self.config_raw["auth"],
                        "jwt": {
                            "enabled": False,
                            "issuer": "issuer-a",
                            "audience": "gateway",
                            "jwks_file": str(missing_jwks),
                        },
                    },
                }
            )

            verifier = JWTVerifier(config.auth.jwt)

            self.assertIsNone(verifier.verify("not-a-token"))

    def test_jwt_auth_allows_gateway_request_with_claim_model_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            secret = b"jwt-test-secret"
            jwks = Path(tmp) / "jwks.json"
            jwks.write_text(json.dumps({"keys": [{"kty": "oct", "kid": "kid-a", "k": _b64(secret)}]}), encoding="utf-8")
            raw = {
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
            logger = GatewayLogger(LoggerOptions(color=False, stream=io.StringIO()))
            server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(parse_config(raw), logger))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            token = _jwt(
                secret,
                "kid-a",
                {
                    "iss": "issuer-a",
                    "aud": "gateway",
                    "exp": int(time.time()) + 60,
                    "tenant": "jwt-tenant",
                    "allowed_models": ["test-model"],
                },
            )
            try:
                status, _, _ = self.request_to_port(
                    server.server_port,
                    "POST",
                    "/v1/chat/completions",
                    {"model": "test-model", "messages": []},
                    key=token,
                )
                self.assertEqual(status, 200)
            finally:
                server.shutdown()
                server.server_close()
                logger.close()

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

    def test_metrics_endpoint_is_metadata_only_after_prompt_request(self) -> None:
        self.request(
            "POST",
            "/v1/chat/completions",
            {"model": "test-model", "messages": [{"role": "user", "content": "metrics-secret"}]},
        )

        status, body, headers = self.request_to_port(self.gateway.server_port, "GET", "/metrics", key=None)

        self.assertEqual(status, 200)
        self.assertIn("text/plain", headers["Content-Type"])
        output = body.decode("utf-8")
        self.assertIn("pig_requests_total", output)
        self.assertNotIn("metrics-secret", output)

    def test_policy_validation_command_accepts_test_config(self) -> None:
        self.assertEqual(gateway_main(["validate-policy", "--config", "config/gateway.test.json"]), 0)

    def test_compose_examples_publish_only_gateway_ports(self) -> None:
        for path in (Path("deploy/compose/vllm.yaml"), Path("deploy/compose/sglang.yaml")):
            text = path.read_text(encoding="utf-8")
            self.assertIn("gateway:", text)
            self.assertIn('ports:\n      - "8080:8080"', text)
            self.assertIn("expose:", text)
            self.assertNotIn('8000:8000', text)
            self.assertNotIn('30000:30000', text)

    def test_kubernetes_examples_keep_backend_private_and_network_policy_scoped(self) -> None:
        gateway = Path("deploy/k8s/gateway.yaml").read_text(encoding="utf-8")
        backend = Path("deploy/k8s/backend-private.yaml").read_text(encoding="utf-8")
        network_policy = Path("deploy/k8s/networkpolicy.yaml").read_text(encoding="utf-8")

        self.assertIn("type: LoadBalancer", gateway)
        self.assertIn("type: ClusterIP", backend)
        self.assertNotIn("type: LoadBalancer", backend)
        self.assertIn("name: backend-ingress-only-from-gateway", network_policy)
        self.assertIn("app: gateway", network_policy)
        self.assertIn("app: vllm", network_policy)

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
