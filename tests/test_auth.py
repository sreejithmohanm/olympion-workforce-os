from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from packages.shared.workforce_os.auth import APIKeyStore, AuthenticationError, JWTSigner
from tests.test_identity_service import MutableClock


class AuthUtilityUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = MutableClock(datetime(2026, 7, 17, tzinfo=UTC))
        self.store = APIKeyStore(hash_secret="test-api-key-secret", now=self.clock.now)
        self.signer = JWTSigner(secret="test-jwt-secret", ttl_seconds=60, now=self.clock.now)

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
