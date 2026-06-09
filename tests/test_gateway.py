from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest

from gateway.config import parse_config
from gateway.logging import GatewayLogger, LoggerOptions
from gateway.server import make_handler


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


if __name__ == "__main__":
    unittest.main()
