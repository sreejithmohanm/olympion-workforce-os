from __future__ import annotations

import base64
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
        self.store = APIKeyStore(now=self.clock.now)
        self.signer = JWTSigner(ttl_seconds=3600, now=self.clock.now)

    def _admin_headers(self, tenant_id: str = "tenant-a", subject: str = "admin") -> dict[str, str]:
        token, _ = self.signer.issue_token(tenant_id=tenant_id, subject=subject)
        return {"Authorization": "Bearer " + token}

    def test_create_key_and_issue_token_returns_required_claims(self) -> None:
        with serve(create_app(store=self.store, signer=self.signer)) as base_url:
            status, created = request_json(
                base_url,
                "POST",
                "/v1/auth/keys",
                {"name": "integration", "sub": "service-client"},
                headers=self._admin_headers("tenant-a"),
            )
            self.assertEqual(status, 201)
            self.assertTrue(created["api_key"].startswith("wfos_"))
            self.assertEqual(created["tenant_id"], "tenant-a")

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

    def test_key_creation_requires_auth(self) -> None:
        with serve(create_app(store=self.store, signer=self.signer)) as base_url:
            status, response = request_json(base_url, "POST", "/v1/auth/keys", {"name": "test"})
        self.assertEqual(status, 401)

    def test_create_key_defaults_sub_to_jwt_subject(self) -> None:
        with serve(create_app(store=self.store, signer=self.signer)) as base_url:
            status, created = request_json(
                base_url,
                "POST",
                "/v1/auth/keys",
                {"name": "no-sub"},
                headers=self._admin_headers("tenant-b", "caller"),
            )
        self.assertEqual(status, 201)
        self.assertEqual(created["sub"], "caller")
        self.assertEqual(created["tenant_id"], "tenant-b")

    def test_list_keys_returns_metadata_only(self) -> None:
        with serve(create_app(store=self.store, signer=self.signer)) as base_url:
            request_json(
                base_url,
                "POST",
                "/v1/auth/keys",
                {"name": "key-one", "sub": "svc"},
                headers=self._admin_headers("tenant-a"),
            )
            request_json(
                base_url,
                "POST",
                "/v1/auth/keys",
                {"name": "key-two", "sub": "svc"},
                headers=self._admin_headers("tenant-a"),
            )
            status, response = request_json(
                base_url,
                "GET",
                "/v1/auth/keys",
                headers=self._admin_headers("tenant-a"),
            )
        self.assertEqual(status, 200)
        self.assertEqual(len(response["keys"]), 2)
        for key in response["keys"]:
            self.assertIn("id", key)
            self.assertIn("name", key)
            self.assertIn("created_at", key)
            self.assertIn("last_used", key)
            self.assertNotIn("api_key", key)
            self.assertNotIn("key_hash", key)

    def test_list_keys_scoped_to_tenant(self) -> None:
        with serve(create_app(store=self.store, signer=self.signer)) as base_url:
            request_json(
                base_url,
                "POST",
                "/v1/auth/keys",
                {"name": "a-key", "sub": "svc"},
                headers=self._admin_headers("tenant-a"),
            )
            request_json(
                base_url,
                "POST",
                "/v1/auth/keys",
                {"name": "b-key", "sub": "svc"},
                headers=self._admin_headers("tenant-b"),
            )
            status, response = request_json(
                base_url,
                "GET",
                "/v1/auth/keys",
                headers=self._admin_headers("tenant-a"),
            )
        self.assertEqual(status, 200)
        self.assertEqual(len(response["keys"]), 1)
        self.assertEqual(response["keys"][0]["name"], "a-key")

    def test_delete_key_revokes_immediately(self) -> None:
        with serve(create_app(store=self.store, signer=self.signer)) as base_url:
            _, created = request_json(
                base_url,
                "POST",
                "/v1/auth/keys",
                {"name": "to-revoke", "sub": "svc"},
                headers=self._admin_headers("tenant-a"),
            )
            key_id = created["id"]
            api_key = created["api_key"]

            del_status, _ = request_json(
                base_url,
                "DELETE",
                f"/v1/auth/keys/{key_id}",
                headers=self._admin_headers("tenant-a"),
            )
            self.assertEqual(del_status, 200)

            token_status, token_response = request_json(
                base_url,
                "POST",
                "/v1/auth/token",
                {"api_key": api_key},
            )
        self.assertEqual(token_status, 401)
        self.assertEqual(token_response["detail"], "Invalid API key")

    def test_delete_key_returns_404_for_unknown_key(self) -> None:
        with serve(create_app(store=self.store, signer=self.signer)) as base_url:
            status, response = request_json(
                base_url,
                "DELETE",
                "/v1/auth/keys/nonexistent",
                headers=self._admin_headers("tenant-a"),
            )
        self.assertEqual(status, 404)
        self.assertEqual(response["detail"], "API key not found")

    def test_delete_key_returns_404_for_other_tenant_key(self) -> None:
        with serve(create_app(store=self.store, signer=self.signer)) as base_url:
            _, created = request_json(
                base_url,
                "POST",
                "/v1/auth/keys",
                {"name": "private", "sub": "svc"},
                headers=self._admin_headers("tenant-a"),
            )
            key_id = created["id"]

            status, response = request_json(
                base_url,
                "DELETE",
                f"/v1/auth/keys/{key_id}",
                headers=self._admin_headers("tenant-b"),
            )
        self.assertEqual(status, 404)
        self.assertEqual(response["detail"], "API key not found")

    def test_jwks_endpoint_returns_public_key(self) -> None:
        with serve(create_app(store=self.store, signer=self.signer)) as base_url:
            status, response = request_json(base_url, "GET", "/.well-known/jwks.json")
        self.assertEqual(status, 200)
        self.assertIn("keys", response)
        self.assertEqual(len(response["keys"]), 1)
        key = response["keys"][0]
        self.assertEqual(key["kty"], "RSA")
        self.assertEqual(key["alg"], "RS256")
        self.assertEqual(key["use"], "sig")
        self.assertIn("n", key)
        self.assertIn("e", key)
        self.assertIn("kid", key)

    def test_jwks_endpoint_is_public(self) -> None:
        with serve(create_app(store=self.store, signer=self.signer)) as base_url:
            status, response = request_json(base_url, "GET", "/.well-known/jwks.json")
        self.assertEqual(status, 200)

    def test_token_is_signed_with_rs256(self) -> None:
        with serve(create_app(store=self.store, signer=self.signer)) as base_url:
            _, created = request_json(
                base_url,
                "POST",
                "/v1/auth/keys",
                {"name": "rs256-test", "sub": "svc"},
                headers=self._admin_headers("tenant-a"),
            )
            _, token_response = request_json(
                base_url,
                "POST",
                "/v1/auth/token",
                {"api_key": created["api_key"]},
            )

        token = token_response["access_token"]
        header_segment = token.split(".")[0]
        padding_chars = "=" * (-len(header_segment) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_segment + padding_chars))
        self.assertEqual(header["alg"], "RS256")
        self.assertEqual(header["typ"], "JWT")

