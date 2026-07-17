from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from wsgiref.simple_server import WSGIServer, WSGIRequestHandler, make_server

from packages.shared.workforce_os.auth import APIKeyStore, JWTSigner
from services.identity.app import create_app


class QuietHandler(WSGIRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return


class MutableClock:
    def __init__(self, current: datetime) -> None:
        self.current = current

    def now(self) -> datetime:
        return self.current

    def advance(self, *, seconds: int) -> None:
        self.current += timedelta(seconds=seconds)


@contextmanager
def serve(app):
    server: WSGIServer = make_server("127.0.0.1", 0, app, handler_class=QuietHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def request_json(base_url: str, method: str, path: str, payload: dict[str, object] | None = None, headers: dict[str, str] | None = None):
    data = None
    request_headers = dict(headers or {})
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        request_headers["Content-Type"] = "application/json"

    request = urllib.request.Request(f"{base_url}{path}", data=data, method=method, headers=request_headers)
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


class IdentityServiceIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = MutableClock(datetime(2026, 7, 17, tzinfo=UTC))
        self.store = APIKeyStore(hash_secret="test-api-key-secret", now=self.clock.now)
        self.signer = JWTSigner(secret="test-jwt-secret", ttl_seconds=3600, now=self.clock.now)

    def test_create_key_and_issue_token_returns_required_claims(self) -> None:
        with serve(create_app(store=self.store, signer=self.signer)) as base_url:
            status, created = request_json(
                base_url,
                "POST",
                "/v1/auth/keys",
                {"name": "integration", "sub": "service-client", "tenant_id": "tenant-a"},
            )
            self.assertEqual(status, 201)
            self.assertTrue(created["api_key"].startswith("wfos_"))

            status, token_response = request_json(
                base_url,
                "POST",
                "/v1/auth/token",
                {"api_key": created["api_key"]},
            )
            self.assertEqual(status, 200)
            self.assertEqual(token_response["expires_in"], 3600)

        claims = self.signer.decode(token_response["access_token"])
        self.assertEqual(claims.tenant_id, "tenant-a")
        self.assertEqual(claims.subject, "service-client")
        self.assertEqual(claims.expires_at - claims.issued_at, 3600)

    def test_token_endpoint_rejects_missing_api_key(self) -> None:
        with serve(create_app(store=self.store, signer=self.signer)) as base_url:
            status, response = request_json(base_url, "POST", "/v1/auth/token", {})
        self.assertEqual(status, 400)
        self.assertEqual(response["detail"], "api_key is required")

    def test_token_endpoint_rejects_invalid_api_key(self) -> None:
        with serve(create_app(store=self.store, signer=self.signer)) as base_url:
            status, response = request_json(base_url, "POST", "/v1/auth/token", {"api_key": "wfos_invalid"})
        self.assertEqual(status, 401)
        self.assertEqual(response["detail"], "Invalid API key")

    def test_key_creation_rejects_invalid_payload(self) -> None:
        with serve(create_app(store=self.store, signer=self.signer)) as base_url:
            status, response = request_json(base_url, "POST", "/v1/auth/keys", {"tenant_id": "tenant-a"})
        self.assertEqual(status, 400)
        self.assertEqual(response["detail"], "sub is required")
