from __future__ import annotations

import io
import unittest
from datetime import UTC, datetime, timedelta
from typing import Any

from packages.shared.workforce_os.auth import APIKeyStore, AuthContext, AuthenticationError, AuthMiddleware, JWTSigner
from tests.test_identity_service import MutableClock


class AuthUtilityUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = MutableClock(datetime(2026, 7, 17, tzinfo=UTC))
        self.store = APIKeyStore(now=self.clock.now)
        self.signer = JWTSigner(ttl_seconds=60, now=self.clock.now)

    def test_api_keys_are_stored_hashed_and_validate(self) -> None:
        record, api_key = self.store.create_key(tenant_id="tenant-a", subject="unit-test")
        self.assertNotEqual(record.key_hash, api_key)
        validated = self.store.validate_key(api_key)
        self.assertIsNotNone(validated)
        self.assertEqual(validated.tenant_id, "tenant-a")
        self.assertEqual(validated.subject, "unit-test")

    def test_jwt_decode_rejects_tampered_signature(self) -> None:
        token, _ = self.signer.issue_token(tenant_id="tenant-a", subject="unit-test")
        header, claims, _ = token.split(".")
        tampered = ".".join((header, claims, "tampered"))
        with self.assertRaisesRegex(AuthenticationError, "Invalid token signature"):
            self.signer.decode(tampered)

    def test_jwt_decode_rejects_expired_token(self) -> None:
        token, _ = self.signer.issue_token(tenant_id="tenant-a", subject="unit-test")
        self.clock.advance(seconds=61)
        with self.assertRaisesRegex(AuthenticationError, "Token expired"):
            self.signer.decode(token)


class AuthContextTests(unittest.TestCase):
    def test_user_id_is_alias_for_subject(self) -> None:
        ctx = AuthContext(tenant_id="tenant-a", subject="svc-account", issued_at=0, expires_at=9999)
        self.assertEqual(ctx.user_id, "svc-account")
        self.assertEqual(ctx.user_id, ctx.subject)

    def test_tenant_id_accessible(self) -> None:
        ctx = AuthContext(tenant_id="tenant-b", subject="user-1", issued_at=0, expires_at=9999)
        self.assertEqual(ctx.tenant_id, "tenant-b")


class AuthMiddlewareContextInjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = MutableClock(datetime(2026, 7, 17, tzinfo=UTC))
        self.signer = JWTSigner(ttl_seconds=60, now=self.clock.now)
        self.captured_environ: dict[str, Any] = {}

        def inner_app(environ: dict[str, Any], start_response: Any):
            self.captured_environ = environ
            start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", "2")])
            return [b"{}"]

        self.middleware = AuthMiddleware(inner_app, self.signer, public_paths={"/health"})

    def _make_environ(self, authorization: str | None = None, path: str = "/protected") -> dict[str, Any]:
        environ: dict[str, Any] = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": path,
            "wsgi.input": io.BytesIO(b""),
            "CONTENT_LENGTH": "0",
        }
        if authorization is not None:
            environ["HTTP_AUTHORIZATION"] = authorization
        return environ

    def _start_response(self, status: str, headers: list) -> None:
        self.last_status = status

    def test_middleware_injects_tenant_id_and_user_id_into_environ(self) -> None:
        token, _ = self.signer.issue_token(tenant_id="tenant-a", subject="svc-client")
        environ = self._make_environ(authorization="Bearer " + token)
        self.middleware(environ, self._start_response)

        self.assertEqual(self.captured_environ.get("workforce.tenant_id"), "tenant-a")
        self.assertEqual(self.captured_environ.get("workforce.user_id"), "svc-client")

    def test_middleware_injects_auth_context_into_environ(self) -> None:
        token, _ = self.signer.issue_token(tenant_id="tenant-a", subject="svc-client")
        environ = self._make_environ(authorization="Bearer " + token)
        self.middleware(environ, self._start_response)

        auth = self.captured_environ.get("workforce.auth")
        self.assertIsInstance(auth, AuthContext)
        self.assertEqual(auth.tenant_id, "tenant-a")
        self.assertEqual(auth.user_id, "svc-client")

    def test_middleware_returns_401_for_missing_token(self) -> None:
        environ = self._make_environ()
        self.middleware(environ, self._start_response)
        self.assertEqual(self.last_status, "401 Unauthorized")
        self.assertNotIn("workforce.user_id", self.captured_environ)
        self.assertNotIn("workforce.tenant_id", self.captured_environ)

    def test_middleware_returns_401_for_expired_token(self) -> None:
        token, _ = self.signer.issue_token(tenant_id="tenant-a", subject="svc-client")
        self.clock.advance(seconds=61)
        environ = self._make_environ(authorization="Bearer " + token)
        self.middleware(environ, self._start_response)
        self.assertEqual(self.last_status, "401 Unauthorized")

    def test_middleware_returns_401_for_invalid_token(self) -> None:
        environ = self._make_environ(authorization="******")
        self.middleware(environ, self._start_response)
        self.assertEqual(self.last_status, "401 Unauthorized")

    def test_middleware_skips_auth_for_public_paths(self) -> None:
        environ = self._make_environ(path="/health")
        self.middleware(environ, self._start_response)
        self.assertEqual(self.last_status, "200 OK")
        self.assertNotIn("workforce.auth", self.captured_environ)
        self.assertNotIn("workforce.user_id", self.captured_environ)
        self.assertNotIn("workforce.tenant_id", self.captured_environ)
