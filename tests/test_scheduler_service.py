from __future__ import annotations

import unittest
from datetime import UTC, datetime

from packages.shared.workforce_os.auth import APIKeyStore, JWTSigner
from services.identity.app import create_app as create_identity_app
from services.scheduler.app import create_app as create_scheduler_app
from tests.test_identity_service import MutableClock, request_json, serve


class SchedulerServiceIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = MutableClock(datetime(2026, 7, 17, tzinfo=UTC))
        self.store = APIKeyStore(now=self.clock.now)
        self.signer = JWTSigner(secret="test-jwt-secret", ttl_seconds=3600, now=self.clock.now)

    def _issue_token(self, tenant_id: str = "tenant-a", subject: str = "service-client") -> str:
        with serve(create_identity_app(store=self.store, signer=self.signer)) as base_url:
            _, created = request_json(
                base_url,
                "POST",
                "/v1/auth/keys",
                {"sub": subject, "tenant_id": tenant_id},
            )
            status, token_response = request_json(
                base_url,
                "POST",
                "/v1/auth/token",
                {"api_key": created["api_key"]},
            )
        self.assertEqual(status, 200)
        return token_response["access_token"]

    def test_protected_endpoint_rejects_missing_token(self) -> None:
        with serve(create_scheduler_app(signer=self.signer)) as base_url:
            status, response = request_json(base_url, "GET", "/v1/tenants/tenant-a/jobs")
        self.assertEqual(status, 401)
        self.assertEqual(response["detail"], "Missing bearer token")

    def test_protected_endpoint_rejects_invalid_token(self) -> None:
        invalid_token = ".".join(("broken", "token", "value"))
        with serve(create_scheduler_app(signer=self.signer)) as base_url:
            status, response = request_json(
                base_url,
                "GET",
                "/v1/tenants/tenant-a/jobs",
                headers={"Authorization": "Bearer " + invalid_token},
            )
        self.assertEqual(status, 401)
        self.assertEqual(response["detail"], "Invalid token signature")

    def test_protected_endpoint_rejects_expired_token(self) -> None:
        token = self._issue_token()
        self.clock.advance(seconds=3601)

        with serve(create_scheduler_app(signer=self.signer)) as base_url:
            status, response = request_json(
                base_url,
                "GET",
                "/v1/tenants/tenant-a/jobs",
                headers={"Authorization": "Bearer " + token},
            )
        self.assertEqual(status, 401)
        self.assertEqual(response["detail"], "Token expired")

    def test_protected_endpoint_enforces_tenant_isolation(self) -> None:
        token = self._issue_token(tenant_id="tenant-a")

        with serve(create_scheduler_app(signer=self.signer)) as base_url:
            status, response = request_json(
                base_url,
                "GET",
                "/v1/tenants/tenant-b/jobs",
                headers={"Authorization": "Bearer " + token},
            )
        self.assertEqual(status, 403)
        self.assertEqual(response["detail"], "Tenant mismatch")

    def test_protected_endpoint_accepts_valid_token_for_matching_tenant(self) -> None:
        token = self._issue_token(tenant_id="tenant-a", subject="scheduler-client")

        with serve(create_scheduler_app(signer=self.signer)) as base_url:
            status, response = request_json(
                base_url,
                "GET",
                "/v1/tenants/tenant-a/jobs",
                headers={"Authorization": "Bearer " + token},
            )
        self.assertEqual(status, 200)
        self.assertEqual(response["sub"], "scheduler-client")
        self.assertEqual(response["tenant_id"], "tenant-a")
